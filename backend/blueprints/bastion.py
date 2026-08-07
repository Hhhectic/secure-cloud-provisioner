"""Builds a complete bastion architecture in one operation.

Every other part of this tool provisions one resource and audits it. This
composes them into an arrangement that is known to be correct, which is a
different kind of thing: the security of a bastion setup is not in any single
resource but in the relationships between six of them. A user can create every
piece individually, correctly, and still end up with something insecure because
the private instance went in the public subnet.

What gets built:

    network             one VPC, a public subnet routed to the internet and a
                        private subnet routed nowhere
    bastion-key         generated locally, public half imported
    private-key         the same, separately, so compromising the bastion does
                        not hand over the private machine
    bastion-sg          SSH from this machine's address only
    private-sg          SSH from bastion-sg only, not from any address
    bastion-host        public subnet, public address
    private-instance    private subnet, no public address

Two protections that fail differently. The security group survives the bastion's
address changing. The subnet routing survives someone attaching a public address
to the wrong machine. Either alone leaves a gap the other covers.

Everything is free except the two instances, which are t3.micro and free-tier
eligible. build() can be asked to skip them.
"""

from pathlib import Path

from aws import instances as ec2i
from aws import key_pairs as kp
from aws import security_groups as sg
from aws import vpcs

BASTION_KEY = "bastion-key"
PRIVATE_KEY = "private-key"


class BuildFailed(Exception):
    """Carries what was created before the failure, so it can be cleaned up."""

    def __init__(self, message, created):
        self.created = created
        super().__init__(message)


def _find_subnet(settings, role):
    for subnet in settings.get("subnets", []):
        if subnet.get("declared_role") == role:
            return subnet
    return None


def build(ec2, name, region="us-east-1", report=print, with_instances=True,
          key_directory="~/.ssh", public_keys=None):
    """Builds the whole arrangement. Returns (ok, result, problems).

    result carries every identifier created, in the order created, so a caller
    that fails partway can tell the user exactly what exists rather than
    leaving them to find it in the console. Nothing here rolls back on its own:
    silently destroying half-built infrastructure is a worse failure than
    leaving it and saying so, particularly when one of the pieces is a machine
    that might already be doing something.
    """
    created = {"order": []}
    problems = []

    def record(kind, identifier):
        created[kind] = identifier
        created["order"].append((kind, identifier))

    # ---- The network -----------------------------------------------------
    report("Creating the network...")
    ok, vpc_id, vpc_problems = vpcs.create_vpc(ec2, name, region=region)
    if not ok:
        return False, created, [vpc_id]
    record("vpc", vpc_id)
    problems.extend(vpc_problems)

    layout = vpcs.read_vpc_for_scanning(ec2, vpc_id)
    public = _find_subnet(layout, "public")
    private = _find_subnet(layout, "private")

    if not public or not private:
        return False, created, [
            "The network was created but is missing a subnet, so nothing can "
            f"be placed in it. Remove {vpc_id} and try again."
        ]

    report(f"  network      {vpc_id}")
    report(f"  public       {public['subnet_id']}  {public['cidr']}")
    report(f"  private      {private['subnet_id']}  {private['cidr']}")

    # ---- Keys ------------------------------------------------------------
    #
    # Two separate pairs on purpose. One would work. Two means that if the
    # bastion is compromised, whatever is taken from it does not also open the
    # private machine - the same least-privilege reasoning as the security
    # groups, applied to credentials.
    #
    # public_keys, when given, is {BASTION_KEY: material, PRIVATE_KEY: ...}
    # and nothing is generated here at all. That is the only way this can be
    # driven over HTTP: generate_locally writes private keys to the disk of
    # whatever machine runs it, which from a terminal is the user's own and
    # from a web request is the server's. A caller that already holds the
    # secret sends the public halves and keeps the rest.
    if public_keys:
        report("\nImporting the public keys supplied by the caller...")
    else:
        report("\nGenerating key pairs on this machine...")

    for key_name in (BASTION_KEY, PRIVATE_KEY):
        full_name = f"{name}-{key_name}"
        private_path = None

        if public_keys:
            material = public_keys.get(key_name)
            if not material:
                return False, created, [
                    f"No public key was supplied for {key_name}. Generate the "
                    "pair where the private half should live and send only "
                    "the public part."
                ]
        else:
            generated, material, private_path = kp.generate_locally(
                full_name, directory=key_directory
            )
            if not generated:
                return False, created, [
                    f"Could not create {full_name}: {material}"
                ]

        imported, result, key_problems = kp.import_key_pair(
            ec2, full_name, material
        )
        if not imported:
            return False, created, [f"Could not register {full_name}: {result}"]

        record(key_name, full_name)
        problems.extend(key_problems)
        report(f"  {key_name:<12} {full_name}")
        if private_path:
            report(f"               private half at {private_path}")

    # ---- Security groups -------------------------------------------------
    report("\nCreating firewall rules...")
    try:
        my_address = sg.my_public_ip() + "/32"
    except OSError:
        return False, created, [
            "Could not work out this machine's public address, so the bastion "
            "rule cannot be written. Check your internet connection."
        ]

    ok, bastion_sg, sg_problems = sg.create_security_group(
        ec2, f"{name}-bastion-sg",
        "Bastion. SSH from one address only.", vpc_id,
        [{"protocol": "tcp", "from_port": 22, "to_port": 22,
          "source": my_address}],
    )
    if not ok:
        return False, created, [f"Could not create the bastion group: {bastion_sg}"]
    record("bastion_sg", bastion_sg)
    problems.extend(sg_problems)
    report(f"  bastion-sg   {bastion_sg}  SSH from {my_address}")

    ok, private_sg, sg_problems = sg.create_security_group(
        ec2, f"{name}-private-sg",
        "Private. SSH from the bastion group only.", vpc_id,
        [{"protocol": "tcp", "from_port": 22, "to_port": 22,
          "source": f"sg:{bastion_sg}"}],
    )
    if not ok:
        return False, created, [f"Could not create the private group: {private_sg}"]
    record("private_sg", private_sg)
    problems.extend(sg_problems)
    report(f"  private-sg   {private_sg}  SSH from {bastion_sg} only")

    if not with_instances:
        report("\nSkipping the machines. Nothing here is costing anything.")
        return True, created, problems

    # ---- Machines --------------------------------------------------------
    report("\nLaunching machines...")

    ok, bastion_id, launch_problems = ec2i.launch_instance(
        ec2, f"{name}-bastion", region=region,
        key_name=created[BASTION_KEY],
        security_group_ids=[bastion_sg],
        subnet_id=public["subnet_id"],
        assign_public_ip=True,
    )
    if not ok:
        return False, created, [f"Could not launch the bastion: {bastion_id}"]
    record("bastion_instance", bastion_id)
    problems.extend(launch_problems)
    report(f"  bastion      {bastion_id}  public subnet, public address")

    ok, private_id, launch_problems = ec2i.launch_instance(
        ec2, f"{name}-private", region=region,
        key_name=created[PRIVATE_KEY],
        security_group_ids=[private_sg],
        subnet_id=private["subnet_id"],
        assign_public_ip=False,
    )
    if not ok:
        return False, created, [
            f"Could not launch the private machine: {private_id}. The bastion "
            f"({bastion_id}) is running and billing."
        ]
    record("private_instance", private_id)
    problems.extend(launch_problems)
    report(f"  private      {private_id}  private subnet, no public address")

    return True, created, problems


def connection_details(ec2, created):
    """Returns what someone needs to actually get in, once addresses exist.

    Separate from build because addresses are assigned as machines start, so
    this is worth calling a minute later rather than immediately.
    """
    bastion_id = created.get("bastion_instance")
    private_id = created.get("private_instance")

    if not bastion_id or not private_id:
        return None

    bastion = ec2i.read_instance_for_scanning(ec2, bastion_id)
    private = ec2i.read_instance_for_scanning(ec2, private_id)

    if not bastion or not private:
        return None

    return {
        "bastion_public_ip": bastion.get("public_ip"),
        "private_ip": private.get("private_ip"),
        "bastion_key": created.get(BASTION_KEY),
        "private_key": created.get(PRIVATE_KEY),
    }


def connection_instructions(details, key_directory="~/.ssh"):
    """Formats the connection details as commands to paste."""
    if not details or not details.get("bastion_public_ip"):
        return ["Addresses are assigned as the machines start. Scan them in a "
                "moment to see the connection details."]

    folder = Path(key_directory).expanduser()
    bastion_key = folder / details["bastion_key"]
    private_key = folder / details["private_key"]

    return [
        "Load both keys into your SSH agent:",
        "",
        '    eval "$(ssh-agent -s)"',
        f"    ssh-add {bastion_key}",
        f"    ssh-add {private_key}",
        "",
        "Then reach the private machine through the bastion in one command:",
        "",
        f"    ssh -J ec2-user@{details['bastion_public_ip']} "
        f"ec2-user@{details['private_ip']}",
        "",
        "That is ProxyJump. It tunnels through the bastion without the bastion",
        "ever seeing your keys. Agent forwarding (ssh -A) also works and is",
        "worse: anyone with root on the bastion could use your forwarded agent",
        "to authenticate as you elsewhere, for as long as you stay connected.",
    ]


def teardown_instructions(created):
    """What has to be removed, in order, and why it is two steps.

    Names the things rather than an interface. This is printed by the command
    line and rendered in the web page, and the menu numbers it used to give
    were wrong in one of them from the moment the second one existed.

    Two steps because the pieces are not all in the same place. A network
    cascade takes everything inside the VPC; key pairs are account-level and
    survive it untouched, so a teardown that stopped at the cascade would
    leave two of them behind and look complete.
    """
    vpc_id = created.get("vpc")
    keys = [created[role] for role in (BASTION_KEY, PRIVATE_KEY)
            if created.get(role)]
    lines = []

    if vpc_id:
        lines.append(f"1. Delete the network {vpc_id} and everything inside "
                     "it.")
        lines.append("   That is both machines, both subnets, both route "
                     "tables, the")
        lines.append("   internet gateway and both firewall groups.")
        lines.append("")

    if keys:
        lines.append(f"{'2' if vpc_id else '1'}. Delete the key pairs. They "
                     "are not part of the network and")
        lines.append("   survive it:")
        for name in keys:
            lines.append(f"       {name}")
        lines.append("")

    lines.append("The private key files are on your own machine. This tool "
                 "never had")
    lines.append("them and cannot remove them; that part is yours.")

    return lines
