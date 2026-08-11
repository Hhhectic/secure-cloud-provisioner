"""Command Line Interface runner.

Orchestrates provisioning, auditing, fixing, and cleaning cloud resources.

Both resource types follow the same five-step menu on purpose. Once the shapes
match here, the FastAPI layer can dispatch on resource type and reuse one set of
endpoints instead of growing a parallel set per resource.
"""

import random
import string
import time
from pathlib import Path

# Before anything reads a credential. See environment.py: nothing in backend/
# used to read .env, so credentials put where every instruction here says to
# put them reached the root Azure app and not this one.
import environment

environment.load()

from aws.security_groups import (
    get_client as ec2_client,
    get_default_vpc,
    create_security_group,
    list_security_groups,
    read_group_for_scanning,
    apply_fix as fix_sg,
    delete_security_group,
    cleanup_all_managed_groups,
)
from aws.s3_buckets import (
    get_client as s3_client,
    create_bucket,
    list_buckets,
    read_bucket_for_scanning,
    apply_fix as fix_bucket,
    delete_bucket,
    cleanup_all_managed_buckets,
    PermissionDenied,
)
from aws import key_pairs
from aws import security_groups
from aws import snapshots
from aws import alarms
from aws import vpcs
from api import registry
from az.common import AzureNotConfigured
from blueprints import bastion
from scanner.rules import check_firewall_rules
from scanner.s3_rules import check_bucket_settings
from scanner.common import (print_warnings, fixable, summarize, worst_level,
                            CRITICAL)

REGION = "us-east-1"


def _choose(items, label_fn, prompt):
    """Prints a numbered list and returns the chosen item, or None."""
    if not items:
        return None
    for idx, item in enumerate(items):
        print(f"[{idx}] {label_fn(item)}")
    raw = input(f"\n{prompt}: ").strip()
    if not raw.isdigit() or int(raw) >= len(items):
        print("Not a valid selection.")
        return None
    return items[int(raw)]


def _network_label(network):
    """Names a network and its ID, without saying the ID twice.

    A network with no Name tag is listed under its own ID, so appending the ID
    again reads as though something has gone wrong.
    """
    if network["name"].startswith(network["id"]):
        return network["name"]
    return f"{network['name']} ({network['id']})"


def _choose_network(ec2, purpose):
    """Asks which network to put something in. Returns a VPC ID, or None.

    Every resource here lives in one network and cannot be moved between them
    afterwards, so this is asked first and asked explicitly. The menus used to
    reach for the account's default VPC without mentioning it, which is how a
    tool that exists to explain exposure ends up making the most consequential
    placement decision silently.
    """
    networks = registry.VPC.list_all(ec2, only_ours=False)
    if not networks:
        print("\nNo networks exist in this region. Create one under 5 first.")
        return None

    if len(networks) == 1:
        print(f"\nOne network exists, so {purpose} goes in "
              f"{_network_label(networks[0])}.")
        return networks[0]["id"]

    print(f"\nWhich network should {purpose} go in?")
    chosen = _choose(networks, _network_label, "Select network")
    if not chosen:
        return None

    default_id, _ = get_default_vpc(ec2)
    if chosen["id"] == default_id:
        print("\n  That is the network AWS created for the account. Every")
        print("  subnet in it reaches the internet, so there is nowhere in it")
        print("  to put something that should not be reachable. Fine for a")
        print("  test, and worth knowing before it holds anything.")

    return chosen["id"]


def _choose_subnet(ec2, vpc_id):
    """Asks which subnet to launch into. Returns the subnet, or None.

    The subnet decides more about a machine's exposure than its firewall does:
    a firewall rule can be edited afterwards, and a machine in a subnet with no
    route to the internet cannot be reached from outside no matter what anyone
    later gets wrong. Choosing it deserves the routing spelled out.
    """
    settings = registry.VPC.read(ec2, vpc_id)
    subnets = (settings or {}).get("subnets") or []

    if not subnets:
        print("\nThat network has no subnets, so there is nowhere in it to")
        print("launch a machine.")
        return None

    def label(subnet):
        reach = ("reaches the internet" if subnet["reaches_internet"]
                 else "no route out")
        auto = (", hands out public addresses"
                if subnet["auto_assign_public_ip"] else "")
        return (f"{subnet['name']:<24} {subnet['cidr']:<16} "
                f"{subnet['availability_zone']:<12} {reach}{auto}")

    print("\nWhich subnet? This is what decides whether the machine can be")
    print("reached from outside at all.")
    return _choose(subnets, label, "Select subnet")


def _report(warnings):
    """Prints scan results plus a severity tally."""
    print("\n--- Scan Results ---")
    print_warnings(warnings)
    if warnings:
        counts = summarize(warnings)
        print(
            f"\n{counts['critical']} critical, "
            f"{counts['warning']} warning, {counts['info']} informational"
        )


def _describe_instance(settings):
    """Prints the facts you need to actually use a server.

    Findings alone are not enough to work with a machine. Without the
    addresses printed here you cannot connect to it, and the tool sends you
    to the AWS console for something it already knows.
    """
    print("\n--- Server ---")
    print(f"  name:           {settings.get('name')}")
    print(f"  id:             {settings.get('instance_id')}")
    print(f"  state:          {settings.get('state')}")
    print(f"  type:           {settings.get('instance_type')}")
    print(f"  network:        {settings.get('vpc_id') or 'unknown'}")
    print(f"  subnet:         {settings.get('subnet_id') or 'unknown'}")
    print(f"  private address: {settings.get('private_ip') or 'not assigned yet'}")
    print(f"  public address:  {settings.get('public_ip') or 'none'}")
    print(f"  key pair:       {settings.get('key_name') or 'none'}")

    usage = settings.get("cpu_usage")
    if usage:
        print(f"  processor:      {usage['average']:.1f}% average over "
              f"{usage['hours']}h, {usage['peak']:.1f}% peak")
    else:
        print("  processor:      no readings yet (they take about 5 minutes)")

    public_ip = settings.get("public_ip")
    private_ip = settings.get("private_ip")
    key_name = settings.get("key_name")

    if public_ip and key_name:
        print(f"\n  Connect directly:")
        print(f"    ssh -i ~/.ssh/{key_name} ec2-user@{public_ip}")
        print(f"\n  Or use it as a jump host to reach a private machine:")
        print(f"    ssh -J ec2-user@{public_ip} ec2-user@<private address>")
    elif private_ip and key_name:
        print(f"\n  No public address, so reach it through a jump host:")
        print(f"    ssh -J ec2-user@<bastion public address> "
              f"ec2-user@{private_ip}")
    elif not key_name:
        print("\n  No key pair attached, so SSH is not possible. Use EC2")
        print("  Instance Connect or Session Manager if you need a shell.")


def _offer_fixes(warnings, apply, target):
    """Offers to run every fixable warning against the given resource."""
    actionable = fixable(warnings)
    if not actionable:
        return
    print(f"\n{len(actionable)} of these can be fixed automatically.")
    if input("Apply fixes now? (y/N): ").strip().lower() != "y":
        return
    for w in actionable:
        ok, msg = apply(target, w)
        print(f"  [{'ok' if ok else 'failed'}] {msg}")


def _ask_for_source(ec2, vpc_id, verbose=True):
    """Asks who should be allowed in, and returns a scanner-shaped source.

    The four options are deliberately ordered safest first. "Anywhere" is last
    and spelled out, because a menu that offers it alongside the others as an
    equal choice is a menu that invites it.
    """
    # Spelled out the first time, then abbreviated. Reprinting five lines
    # before every rule buries the answers already given in a wall of menu.
    if verbose:
        print("\n  Who should be allowed to connect?")
        print("  [0] just this machine (your current public address)")
        print("  [1] anything in another security group (the bastion pattern)")
        print("  [2] a specific address or range you type")
        print("  [3] anywhere on the internet")
        prompt = "  Select (0-3): "
    else:
        prompt = ("  From? [0] this machine  [1] another group  "
                  "[2] typed address  [3] anywhere: ")

    # Asked again rather than falling through to a default. Anything unmatched
    # used to become option 0, so a mistyped 4 quietly wrote a different rule
    # from the one asked for - and on this menu the difference between the
    # options is the difference between one address and the whole internet.
    while True:
        choice = input(prompt).strip()
        if choice in ("0", "1", "2", "3"):
            break
        print("  Pick a number from 0 to 3.")

    if choice == "1":
        # Only groups in the same network. A rule may name a group as its
        # source, but AWS rejects one that names a group in another network,
        # and the error it returns says only that the parameter is invalid.
        groups = [g for g in registry.SECURITY_GROUP.list_all(ec2, only_ours=False)
                  if g.get("vpc_id") == vpc_id]
        if not groups:
            print("  No security groups exist in this network to point at yet.")
            print("  A rule cannot name a group from another network.")
            return None
        for idx, g in enumerate(groups):
            print(f"  [{idx}] {g['name']} ({g['id']})")
        raw = input("  Select the group traffic may come from: ").strip()
        if not raw.isdigit() or int(raw) >= len(groups):
            print("  No group chosen.")
            return None
        return f"sg:{groups[int(raw)]['id']}"

    if choice == "2":
        typed = input("  Address or range (for example 203.0.113.4/32): ").strip()
        return typed or None

    if choice == "3":
        print("  That means every computer on the internet may attempt to")
        print("  connect. The scanner will flag it, which is the point.")
        return "0.0.0.0/0"

    try:
        return security_groups.my_public_ip() + "/32"
    except OSError:
        print("  Could not work out your public address. Type one instead.")
        return None


def _ask_for_rules(ec2, vpc_id):
    """Collects inbound rules one at a time.

    The menu is printed in full once and abbreviated afterwards, with the
    rules chosen so far shown above the prompt. Repeating seven lines of menu
    before every rule pushes the answers already given off the screen, which
    is how someone loses track of what they are building.
    """
    common = {"1": ("SSH", 22), "2": ("Remote desktop", 3389),
              "3": ("Web (HTTPS)", 443), "4": ("Web (HTTP)", 80)}
    rules = []

    print("\nAdd inbound rules, one at a time:")
    for key, (label, port) in common.items():
        print(f"[{key}] {label} - port {port}")
    print("[5] something else")
    print("[ ] done")

    while True:
        if rules:
            print("\nSo far:")
            for r in rules:
                print(f"  port {r['from_port']} from {r['source']}")
            prompt = ("Another? [1] SSH  [2] RDP  [3] HTTPS  [4] HTTP  "
                      "[5] other, or enter to finish: ")
        else:
            prompt = "\nSelect, or press enter to finish: "

        choice = input(prompt).strip()
        if not choice:
            return rules

        if choice in common:
            port = common[choice][1]
        elif choice == "5":
            raw = input("  Port number: ").strip()
            if not raw.isdigit() or not 0 <= int(raw) <= 65535:
                print("  A port is a number from 0 to 65535.")
                continue
            port = int(raw)
        else:
            print("  Pick 1 to 5, or press enter to finish.")
            continue

        source = _ask_for_source(ec2, vpc_id, verbose=not rules)
        if not source:
            print("  Skipped that rule.")
            continue

        # Said now rather than discovered at creation. AWS refuses the whole
        # request if a permission repeats, so without this the group is created
        # with none of its rules and the reason arrives as one line of error.
        if any(r["from_port"] == port and r["source"] == source for r in rules):
            print(f"  Port {port} from {source} is already on the list.")
            continue

        rules.append({"protocol": "tcp", "from_port": port, "to_port": port,
                      "source": source})
        print(f"  Added: port {port} from {source}")


# --------------------------------------------------------------- Security Groups


def _group_label(group):
    """Names a group and the network it belongs to.

    The network is part of the identity, not decoration. Two groups with the
    same name in different networks are ordinary, and the one that matters is
    the one sitting alongside the machine.
    """
    return (f"{group['GroupName']:<24} {group['GroupId']:<22} "
            f"in {group.get('VpcId', 'unknown network')}")


def security_group_menu(ec2):
    print("\n--- Security Groups ---")
    print("1. Create")
    print("2. Scan and fix")
    print("3. Delete one")
    print("4. Purge all managed groups")
    choice = input("\nSelect action (1-4): ").strip()

    if choice == "1":
        vpc_id = _choose_network(ec2, "this group")
        if not vpc_id:
            return

        name = input("\nGroup name [test-sg]: ").strip() or "test-sg"
        rules = _ask_for_rules(ec2, vpc_id)
        if not rules:
            print("No rules given. The group will allow nothing inbound.")

        warnings = check_firewall_rules(rules)
        if warnings:
            _report(warnings)
            if input("\nCreate anyway? (y/N): ").strip().lower() != "y":
                print("Stopped. Nothing was created.")
                return

        ok, res, problems = create_security_group(
            ec2, name, "Managed by provisioner", vpc_id, rules
        )
        if not ok:
            print(f"Error: {res}")
            return

        print(f"Created: {res}")
        for p in problems:
            print(f"  [!] {p}")

    elif choice == "2":
        groups = list_security_groups(ec2, only_ours=True)
        if not groups:
            print("No managed security groups found.")
            return
        sg = _choose(groups, _group_label, "Select group to scan")
        if not sg:
            return

        # Via the registry so the CLI and the API scan identically. Without
        # this the two interfaces would drift and only one would be tested.
        resource = registry.SECURITY_GROUP
        warnings = resource.check(resource.read(ec2, sg["GroupId"]))
        _report(warnings)
        _offer_fixes(warnings, lambda gid, w: fix_sg(ec2, gid, w), sg["GroupId"])

    elif choice == "3":
        groups = list_security_groups(ec2, only_ours=True)
        if not groups:
            print("No managed security groups found.")
            return
        sg = _choose(groups, _group_label, "Select group to delete")
        if sg:
            ok, msg = delete_security_group(ec2, sg["GroupId"])
            print(msg)

    elif choice == "4":
        if input("Delete ALL managed security groups? (y/N): ").strip().lower() == "y":
            for sg_id, ok, msg in cleanup_all_managed_groups(ec2):
                print(f"[{sg_id}] -> {msg}")


# ------------------------------------------------------------------- S3 Buckets


def bucket_menu(s3):
    print("\n--- S3 Buckets ---")
    print("1. Create (secure by default)")
    print("2. Create (deliberately weak, for the demo)")
    print("3. Scan and fix")
    print("4. Delete one")
    print("5. Purge all managed buckets")
    choice = input("\nSelect action (1-5): ").strip()

    if choice in ("1", "2"):
        secure = choice == "1"
        suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
        default_name = f"scp-test-{suffix}"
        name = input(f"Bucket name [{default_name}]: ").strip() or default_name

        if not secure:
            print("\nThis bucket will be created with no encryption, no versioning,")
            print("and no public access block. That is the point of this option.")
            if input("Continue? (y/N): ").strip().lower() != "y":
                return

        ok, res, problems = create_bucket(
            s3, name, region=REGION, secure_by_default=secure
        )
        if not ok:
            print(f"Error: {res}")
            return

        print(f"Created: {res}")
        for p in problems:
            print(f"  [!] {p}")

        _report(check_bucket_settings(read_bucket_for_scanning(s3, res)))

    elif choice == "3":
        buckets = list_buckets(s3, only_ours=True)
        if not buckets:
            print("No managed buckets found.")
            return
        b = _choose(buckets, lambda x: x["Name"], "Select bucket to scan")
        if not b:
            return
        warnings = check_bucket_settings(read_bucket_for_scanning(s3, b["Name"]))
        _report(warnings)
        _offer_fixes(warnings, lambda name, w: fix_bucket(s3, name, w), b["Name"])

        if fixable(warnings):
            print("\nRe-reading the bucket to confirm what actually changed:")
            _report(check_bucket_settings(read_bucket_for_scanning(s3, b["Name"])))

    elif choice == "4":
        buckets = list_buckets(s3, only_ours=True)
        if not buckets:
            print("No managed buckets found.")
            return
        b = _choose(buckets, lambda x: x["Name"], "Select bucket to delete")
        if not b:
            return
        force = input("Delete any files inside too? (y/N): ").strip().lower() == "y"
        ok, msg = delete_bucket(s3, b["Name"], force=force)
        print(msg)

    elif choice == "5":
        print("This deletes every bucket this tool created.")
        if input("Are you sure? (y/N): ").strip().lower() != "y":
            return
        force = input("Delete any files inside them too? (y/N): ").strip().lower() == "y"
        results = cleanup_all_managed_buckets(s3, force=force)
        if not results:
            print("Nothing to clean up.")
        for name, ok, msg in results:
            print(f"[{name}] -> {msg}")


# ------------------------------------------------------------------------- Entry


def key_pair_menu(ec2):
    print("\n--- Key Pairs ---")
    print("1. Create a new key on this machine and register the public half")
    print("2. Register an existing public key")
    print("3. Scan")
    print("4. Delete one")
    print("5. Remove all managed key pairs")
    choice = input("\nSelect action (1-5): ").strip()

    resource = registry.KEY_PAIR

    if choice == "1":
        name = input("Key name: ").strip()
        if not name:
            print("A name is required.")
            return

        print("\nssh-keygen will create the pair on this machine.")
        print("The private key is written to your disk and never sent anywhere.")

        ok, result, private_path = key_pairs.generate_locally(name)
        if not ok:
            print(f"Error: {result}")
            return

        print(f"\nPrivate key: {private_path}")
        print("Keep it. AWS never has a copy, so nobody can recover it for you.")

        created, res, problems = resource.create(
            ec2, {"name": name, "public_key": result}
        )
        print(f"\nRegistered with AWS: {res}" if created else f"Error: {res}")
        for p in problems:
            print(f"  [!] {p}")

    elif choice == "2":
        name = input("Key name: ").strip()
        path = input("Path to the .pub file: ").strip()

        try:
            material = Path(path).expanduser().read_text()
        except OSError as e:
            print(f"Could not read that file: {e}")
            return

        created, res, problems = resource.create(
            ec2, {"name": name, "public_key": material}
        )
        print(f"Registered: {res}" if created else f"Error: {res}")
        for p in problems:
            print(f"  [!] {p}")

    elif choice == "3":
        keys = resource.list_all(ec2, only_ours=True)
        if not keys:
            print("No managed key pairs found.")
            return
        chosen = _choose(keys, lambda k: k["name"], "Select key to scan")
        if chosen:
            _report(resource.check(resource.read(ec2, chosen["id"])))

    elif choice == "4":
        keys = resource.list_all(ec2, only_ours=True)
        if not keys:
            print("No managed key pairs found.")
            return
        chosen = _choose(keys, lambda k: k["name"], "Select key to delete")
        if chosen:
            ok, msg = resource.delete(ec2, chosen["id"], {})
            print(msg)

    elif choice == "5":
        if input("Remove ALL managed key pairs? (y/N): ").strip().lower() == "y":
            for name, ok, msg in resource.cleanup(ec2, {}):
                print(f"[{name}] -> {msg}")


def instance_menu(ec2):
    print("\n--- Servers ---")
    print("1. Launch")
    print("2. Scan and fix")
    print("3. Terminate one")
    print("4. Terminate all managed servers")
    choice = input("\nSelect action (1-4): ").strip()

    resource = registry.INSTANCE

    if choice == "1":
        suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
        default_name = f"scp-{suffix}"
        name = input(f"Server name [{default_name}]: ").strip() or default_name

        # Network and subnet before anything else. Neither can be changed after
        # launch, and both constrain what follows: the firewall groups on offer
        # are the ones in this network, and whether a public address means
        # anything depends on the subnet's routing.
        vpc_id = _choose_network(ec2, "this server")
        if not vpc_id:
            return

        subnet = _choose_subnet(ec2, vpc_id)
        if not subnet:
            return

        # A key pair cannot be attached after launch, so it has to be chosen
        # now or not at all. Offering the list beats asking for a name the
        # user has to remember exactly.
        key_name = None
        keys = registry.KEY_PAIR.list_all(ec2, only_ours=False)
        if keys:
            print("\nAttach a key pair for SSH access?")
            print("[ ] none - use EC2 Instance Connect or Session Manager instead")
            for idx, k in enumerate(keys):
                print(f"[{idx}] {k['name']}")
            raw = input("\nSelect a key, or press enter for none: ").strip()
            if raw.isdigit() and int(raw) < len(keys):
                key_name = keys[int(raw)]["id"]
        else:
            print("\nNo key pairs exist yet, so this server will have none.")
            print("That is fine unless you need to log in over SSH.")

        # Without this the instance silently lands in the VPC's default
        # security group, which is not what anyone intends and is invisible
        # unless you go looking.
        group_ids = []
        groups = [g for g in registry.SECURITY_GROUP.list_all(ec2, only_ours=False)
                  if g.get("vpc_id") == vpc_id]
        if groups:
            print("\nWhich firewall rules should apply?")
            for idx, g in enumerate(groups):
                print(f"[{idx}] {g['name']} ({g['id']})")
            raw = input("\nSelect one or more, comma separated, "
                        "or press enter for none: ").strip()
            for part in raw.split(","):
                part = part.strip()
                if part.isdigit() and int(part) < len(groups):
                    group_ids.append(groups[int(part)]["id"])
        else:
            print("\nNo firewall groups exist in this network yet. A group")
            print("belongs to one network and cannot be borrowed from another,")
            print("so one would have to be created there first.")

        if not group_ids:
            print("\nNo group chosen, so this lands in the network's default")
            print("security group. That group usually allows nothing inbound,")
            print("so the machine will be unreachable. Often fine, but it is")
            print("worth knowing rather than discovering later.")

        public = input("\nGive it a public address? (y/N): ").strip().lower() == "y"
        if public and not subnet["reaches_internet"]:
            # An address assigned in a subnet with no route to a gateway is not
            # a smaller version of being on the internet, it is nothing at all:
            # nothing outside can reach it and it cannot reach out. Worth
            # saying now rather than after the machine is running and silent.
            print("\nThat subnet has no route to the internet, so the address")
            print("would go nowhere. Nothing outside could reach the machine")
            print("and the machine could not reach out. Machines here are")
            print("reached through a bastion in a public subnet instead.")
            public = input("Give it one anyway? (y/N): ").strip().lower() == "y"
        elif public:
            print("It will be reachable from the internet, and its firewall")
            print("rules will be the only thing in the way.")
        elif subnet["auto_assign_public_ip"]:
            print("\nThis subnet hands out public addresses to anything")
            print("launched into it. Saying no here overrides that, which is")
            print("why the tool always states the answer rather than leaving")
            print("it to the subnet.")

        spec = {"name": name, "region": REGION, "key_name": key_name,
                "security_group_ids": group_ids or None,
                "subnet_id": subnet["subnet_id"],
                "assign_public_ip": public}

        warnings = resource.check_spec(spec)
        if warnings:
            _report(warnings)
            if input("\nLaunch anyway? (y/N): ").strip().lower() != "y":
                print("Stopped. Nothing was launched.")
                return

        ok, res, problems = resource.create(ec2, spec)
        if not ok:
            print(f"Error: {res}")
            return

        print(f"\nLaunched: {res}")
        for p in problems:
            print(f"  [!] {p}")
        print("This is now costing money. Terminate it when you are done.")

        settings = resource.read(ec2, res)
        _describe_instance(settings["instance"])
        _report(resource.check(settings))

        if not settings["instance"].get("private_ip"):
            print("\nAddresses are assigned as the machine starts. Scan it")
            print("again in a moment to see them.")

    elif choice == "2":
        servers = resource.list_all(ec2, only_ours=True)
        if not servers:
            print("No managed servers found.")
            return
        chosen = _choose(servers, lambda s: f"{s['name']} ({s['id']})",
                         "Select server to scan")
        if not chosen:
            return

        settings = resource.read(ec2, chosen["id"])
        _describe_instance(settings["instance"])

        warnings = resource.check(settings)
        _report(warnings)
        _offer_fixes(warnings, lambda sid, w: resource.fix(ec2, sid, w, {}),
                     chosen["id"])

    elif choice == "3":
        servers = resource.list_all(ec2, only_ours=True)
        if not servers:
            print("No managed servers found.")
            return
        chosen = _choose(servers, lambda s: f"{s['name']} ({s['id']})",
                         "Select server to terminate")
        if chosen:
            ok, msg = resource.delete(ec2, chosen["id"], {})
            print(msg)

    elif choice == "4":
        print("This terminates every server this tool launched. Permanent.")
        if input("Are you sure? (y/N): ").strip().lower() == "y":
            results = resource.cleanup(ec2, {})
            if not results:
                print("Nothing running.")
            for sid, ok, msg in results:
                print(f"[{sid}] -> {msg}")


def _cascade_delete_network(ec2, vpc_id, name):
    """Shows everything that would be destroyed, then asks properly.

    A yes/no prompt is not enough here. This is the only operation in the tool
    that destroys things the user did not name, and the answer to "are you
    sure" is reflexively yes. Printing the inventory first, and requiring the
    network's own ID typed back, makes the confirmation cost more attention
    than the mistake would.
    """
    plan = vpcs.plan_deletion(ec2, vpc_id)
    foreign = vpcs.not_ours(plan, ec2, vpc_id)

    servers = [item for item in plan if item[0] == "server"]

    print(f"\nDeleting {name} would destroy {len(plan)} things, in this order:")
    for kind, item_id, label in plan:
        marker = "  !" if (kind, item_id, label) in foreign else "   "
        print(f"{marker} {kind:<17} {item_id:<22} {label}")

    if foreign:
        print(f"\n  ! marks {len(foreign)} thing(s) this tool did not create.")
        print("    Something or someone else may be relying on them.")

    if servers:
        print(f"\n  {len(servers)} running machine(s) will be terminated.")
        print("    Their disks are destroyed with them. This cannot be undone.")

    print("\nThis is permanent.")
    typed = input(f"Type the network's ID ({vpc_id}) to confirm, "
                  "or anything else to stop: ").strip()

    if typed != vpc_id:
        print("Stopped. Nothing was deleted.")
        return

    print("\nDeleting. Terminating machines takes a minute or so.")
    ok, message = vpcs.delete_vpc(ec2, vpc_id, force=True)
    print(f"\n{message}")


def network_menu(ec2):
    print("\n--- Networks ---")
    print("1. Create")
    print("2. Scan")
    print("3. Delete an empty one")
    print("4. Delete one and everything inside it")
    choice = input("\nSelect action (1-4): ").strip()

    resource = registry.VPC

    if choice == "1":
        suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
        default_name = f"scp-{suffix}"
        name = input(f"Network name [{default_name}]: ").strip() or default_name

        print("\nThis creates one public and one private subnet.")
        print("The private one has no route to the internet at all, which is")
        print("what makes it private. Machines there cannot fetch updates.")

        ok, res, problems = resource.create(ec2, {"name": name, "region": REGION})
        if not ok:
            print(f"\nError: {res}")
            return

        print(f"\nCreated: {res}")
        for p in problems:
            print(f"  [!] {p}")

        settings = resource.read(ec2, res)
        print("\n--- Subnets ---")
        for subnet in settings["subnets"]:
            reach = ("reaches the internet" if subnet["reaches_internet"]
                     else "no route out")
            print(f"  {subnet['name']:<24} {subnet['subnet_id']:<24} "
                  f"{subnet['cidr']:<16} {reach}")

        _report(resource.check(settings))

    elif choice == "2":
        networks = resource.list_all(ec2, only_ours=False)
        if not networks:
            print("No networks found.")
            return
        chosen = _choose(networks, lambda n: f"{n['name']} ({n['id']})",
                         "Select network to scan")
        if not chosen:
            return

        settings = resource.read(ec2, chosen["id"])
        print("\n--- Subnets ---")
        for subnet in settings["subnets"]:
            reach = ("reaches the internet" if subnet["reaches_internet"]
                     else "no route out")
            print(f"  {subnet['name']:<24} {subnet['subnet_id']:<24} "
                  f"{subnet['cidr']:<16} {reach}")

        _report(resource.check(settings))

    elif choice == "3":
        networks = resource.list_all(ec2, only_ours=True)
        if not networks:
            print("No managed networks found.")
            return
        chosen = _choose(networks, lambda n: f"{n['name']} ({n['id']})",
                         "Select network to delete")
        if not chosen:
            return

        ok, message = resource.delete(ec2, chosen["id"], {})
        print(f"\n{message}")
        if not ok:
            print("\nUse option 4 if you want to remove those as well.")

    elif choice == "4":
        networks = resource.list_all(ec2, only_ours=True)
        if not networks:
            print("No managed networks found.")
            return
        chosen = _choose(networks, lambda n: f"{n['name']} ({n['id']})",
                         "Select network to delete entirely")
        if chosen:
            _cascade_delete_network(ec2, chosen["id"], chosen["name"])


def blueprint_menu(ec2):
    print("\n--- Blueprints ---")
    print("A blueprint builds several resources at once, arranged so the")
    print("result is correct. Creating each piece properly and still ending")
    print("up with something insecure is easy; the safety is in how they fit")
    print("together, not in any one of them.")
    print("\n1. Bastion host and a private machine behind it")
    choice = input("\nSelect (1), or press enter to go back: ").strip()

    if choice != "1":
        return

    print("\nThis builds:")
    print("  a network with a public and a private subnet")
    print("  two key pairs, generated here, public halves sent to AWS")
    print("  two firewall groups, the private one trusting only the bastion")
    print("  two machines, one reachable from your address, one from neither")

    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    default_name = f"scp-{suffix}"
    name = input(f"\nName prefix [{default_name}]: ").strip() or default_name

    print("\nThe two machines are t3.micro and cost money while they run.")
    with_instances = input(
        "Include them? (Y/n, no leaves everything else free): "
    ).strip().lower() != "n"

    print()
    ok, created, problems = bastion.build(
        ec2, name, region=REGION, with_instances=with_instances
    )

    if problems:
        print("\nWorth knowing:")
        for p in problems:
            print(f"  [!] {p}")

    if not ok:
        print("\nThe build did not finish.")
        if created.get("order"):
            print("These were created before it stopped:")
            for kind, identifier in created["order"]:
                print(f"  {kind:<18} {identifier}")
            print("\nNothing was rolled back. Half-built infrastructure that")
            print("is reported is easier to deal with than half-built")
            print("infrastructure that was silently destroyed.")
            for line in bastion.teardown_instructions(created):
                print(f"  {line}")
        return

    print("\nBuilt.")

    if not with_instances:
        print("\nNo machines were launched, so nothing is costing anything.")
        print("Launch them later with 4 Servers, choosing the subnets and")
        print("groups this created.")
        return

    print("\nWaiting for addresses to be assigned...")
    time.sleep(8)

    details = bastion.connection_details(ec2, created)
    print()
    for line in bastion.connection_instructions(details):
        print(f"  {line}")

    print("\n  Once you are on the private machine, try this:")
    print("      curl -i http://169.254.169.254/latest/meta-data/instance-id")
    print("  It returns 401. That command reads the machine's own AWS")
    print("  credentials over an unauthenticated request, and it works on an")
    print("  instance launched with AWS defaults. It fails here because this")
    print("  tool requires a session token first. CIS 5.7.")

    print()
    for line in bastion.teardown_instructions(created):
        print(f"  {line}")


def _describe_account(settings):
    """Prints what the account's access setup looks like.

    Worth printing separately from the findings because most of it is not a
    finding. "Twelve users, a password policy, root has a second login step"
    is the shape of the account, and someone reading a clean scan should be
    able to see that the scan actually looked at something.
    """
    print("\n--- Account ---")
    print(f"  account:        {settings.get('account_id')}")
    if settings.get("account_alias"):
        print(f"  also known as:  {settings.get('account_alias')}")
    print(f"  region checked: {settings.get('region')}")
    print(f"  users:          {settings.get('user_count')}")

    root_mfa = settings.get("root_mfa_enabled")
    print(f"  root login:     {'password plus a second step' if root_mfa else 'password only'}")
    print(f"  root keys:      {settings.get('root_access_keys')}")

    policy = settings.get("password_policy")
    if policy:
        print(f"  password rules: at least {policy.get('minimum_length')} "
              f"characters, last {policy.get('passwords_remembered') or 0} "
              "remembered")
    else:
        print("  password rules: none set, so AWS defaults apply")

    skipped = settings.get("checks_skipped")
    if skipped:
        print(f"\n  {len(skipped)} check(s) could not run: {', '.join(skipped)}")


def account_menu(iam):
    """Auditing the account itself. There is nothing here to create.

    A one-item menu rather than the five every other resource has, and that is
    the point being made: this is the only thing in the tool that reports
    without offering to change anything.
    """
    print("\n--- Account Access ---")
    print("This audits how people and programs get into this account.")
    print("Nothing here is created, changed or deleted - every finding is")
    print("about a credential, and getting one of those wrong locks somebody")
    print("out with no way back.\n")

    resource = registry.IAM

    accounts = resource.list_all(iam, only_ours=False)
    if not accounts:
        print("Could not work out which account these credentials belong to.")
        return

    account_id = accounts[0]["id"]
    print(f"Reading {accounts[0]['name']}...")
    print("The credential report is built on request, so this can take a few")
    print("seconds.")

    settings = resource.read(iam, account_id)
    if settings is None:
        print("No such account.")
        return

    _describe_account(resource.describe(settings))
    _report(resource.check(settings))
    print("\nNothing here is fixed automatically. Each finding says what to")
    print("change and where.")


def snapshot_menu(ec2):
    """Auditing disk backups. There is nothing here to create.

    The sweep runs before the per-backup scan because it answers the urgent
    question in a single call - is anything readable by the whole world right
    now - and the fuller scan costs two calls for every backup in the account.
    Waiting for the slow answer before giving the fast one would be the wrong
    way round for the one finding here that is an emergency.
    """
    print("\n--- Disk Backups ---")
    print("A backup is a complete, readable copy of a disk. Anyone who can")
    print("restore one can read everything that was on it, including files")
    print("deleted before it was taken. Nothing here is created or deleted;")
    print("a backup is somebody's last copy of something.\n")

    resource = registry.SNAPSHOT

    listed = resource.list_all(ec2, only_ours=False)
    if not listed:
        print("This account owns no disk backups in this region, so there is")
        print("nothing to audit. That is the good version of this answer.")
        return

    print(f"This account owns {len(listed)} in this region.")

    exposed = snapshots.publicly_restorable(ec2)
    if exposed:
        print(f"\n{len(exposed)} of them can be restored by anyone with an AWS")
        print("account. That is the worst finding this tool has. Details below.")
    else:
        print("None of them can be restored by the public.")

    print("\nReading each one. Two calls apiece, so this is not instant.")
    findings = []
    for row in listed:
        settings = resource.read(ec2, row["id"])
        # A backup deleted between the listing and this read is not an error.
        if settings is None:
            continue
        findings.extend(resource.check(settings))

    _report(findings)
    print("\nNothing here is fixed automatically. Each finding says what to")
    print("change and where.")


def alarm_menu(cloudwatch):
    """Alarms, which are the one thing here that fails by staying quiet.

    Everything else this tool builds is dangerous when it is doing something.
    An alarm is dangerous when it is doing nothing, and looks identical either
    way, so the scan is offered on every path through this menu rather than as
    a separate choice.
    """
    print("\n--- Alarms ---")
    print("1. Watch account spending")
    print("2. Watch a server's CPU")
    print("3. Scan an existing alarm")
    print("4. Delete one")
    print("5. Remove all alarms this tool made")
    choice = input("\nSelect action (1-5): ").strip()

    resource = registry.ALARM

    if choice in ("1", "2"):
        billing = choice == "1"
        name = input("Alarm name: ").strip()
        if not name:
            print("A name is required.")
            return

        raw = input("Tell me when it goes above "
                    f"{'$' if billing else ''}: ").strip()
        try:
            threshold = float(raw)
        except ValueError:
            print("That is not a number.")
            return

        email = input("Email to alert (blank for none): ").strip()
        if not email:
            print("\n  Without an address this alarm has nowhere to send a")
            print("  message. It will turn red and tell nobody. Continuing.")

        spec = {
            "name": name,
            "namespace": alarms.BILLING_NAMESPACE if billing
            else alarms.CPU_NAMESPACE,
            "metric_name": alarms.BILLING_METRIC if billing
            else alarms.CPU_METRIC,
            "threshold": threshold,
            "region": REGION,
            "notify": True,
            "email": email or None,
        }

        # Same pre-flight the API runs, so the CLI and the page refuse the
        # same things. A spending alarm in the wrong region is caught here
        # before anything is created.
        warnings = resource.check_spec(spec)
        if warnings:
            _report(warnings)
            if input("\nCreate it anyway? (y/N): ").strip().lower() != "y":
                print("Nothing was created.")
                return

        ok, result, problems = resource.create(cloudwatch, spec)
        print(f"\nCreated {result}" if ok else f"\nRefused: {result}")
        for p in problems:
            print(f"  [!] {p}")

        if ok:
            _report(resource.check(resource.read(cloudwatch, result)))

    elif choice == "3":
        found = resource.list_all(cloudwatch, only_ours=False)
        if not found:
            print("No alarms exist in this region. Nothing is being watched.")
            return
        chosen = _choose(found, lambda a: a["name"], "Select alarm to scan")
        if chosen:
            _report(resource.check(resource.read(cloudwatch, chosen["id"])))

    elif choice == "4":
        found = resource.list_all(cloudwatch, only_ours=True)
        if not found:
            print("No alarms made by this tool.")
            return
        chosen = _choose(found, lambda a: a["name"], "Select alarm to delete")
        if chosen:
            ok, msg = resource.delete(cloudwatch, chosen["id"], {})
            print(msg)

    elif choice == "5":
        if input("Remove ALL alarms this tool made? (y/N): ").strip().lower() == "y":
            for name, ok, msg in resource.cleanup(cloudwatch, {}):
                print(f"[{name}] -> {msg}")


# --------------------------------------------------------------- Azure storage


# The characters Azure will accept in each type's name, since they differ and
# both are stricter than anything AWS asks for. A storage account is lowercase
# letters and digits only; a vault also allows hyphens but must start with a
# letter. Only used to generate the offered default, which is the one name a
# person did not choose and so the one that must not be rejected.
_AZURE_NAME_SEEDS = {
    "azure-storage": lambda suffix: f"scp{suffix}",
    "azure-keyvault": lambda suffix: f"scp-{suffix}",
}


def azure_menu(resource, client):
    """Any Azure resource type, driven entirely through the registry.

    One menu rather than one per type, unlike the AWS half above. That is not
    inconsistency for its own sake: the AWS menus each ask for something
    genuinely different - a network to place a group in, an instance size, a
    metric and a threshold - while every Azure type here takes the same four
    answers, a name, a resource group, a location and whether to build it
    safely. Writing this once means the next Azure type needs a registry entry
    and no menu at all.

    What the deliberately-weak option is about to build is printed by running
    check_spec and showing the findings, rather than by a hardcoded sentence
    per type. Two reasons: a sentence goes stale the moment a rule is added,
    and showing the actual findings is the thing this tool exists to do. It is
    also exactly what POST /resources/{type} does before it provisions.

    The client is passed in like every other menu even though Azure's
    get_client ignores the region it is given. Azure carries a location on each
    resource rather than on the connection, so there is nothing regional for
    main() to decide - but one menu taking its client from somewhere else would
    be a difference to remember for no benefit.
    """
    label = resource.label
    print(f"\n--- {label}s ---")
    print("1. Create (secure by default)")
    print("2. Create (deliberately weak, for the demo)")
    print("3. Scan")
    print("4. Delete one")
    print(f"5. Remove all {label.lower()}s this tool made")
    choice = input("\nSelect action (1-5): ").strip()

    if choice in ("1", "2"):
        secure = choice == "1"

        suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
        seed = _AZURE_NAME_SEEDS.get(resource.key, lambda s: f"scp-{s}")
        default_name = seed(suffix)
        name = input(f"{resource.id_label} [{default_name}]: ").strip() or default_name

        group = input("Resource group: ").strip()
        if not group:
            print("Azure puts every resource in a resource group, and there is no")
            print("default worth inventing. It will be created if it does not")
            print("already exist, but it has to be named.")
            return

        location = input("Location [eastus]: ").strip() or "eastus"

        spec = {
            "name": name,
            "resource_group": group,
            "region": location,
            "secure_by_default": secure,
        }

        # What this would be, before it is anything. The same scan the API runs
        # before it provisions, and the reason the weak option needs no
        # hardcoded description of what makes it weak.
        planned = resource.check_spec(spec)
        if planned:
            print("\nBefore building it, this is what it would be:")
            _report(planned)

        if not secure or worst_level(planned) == CRITICAL:
            if input("\nBuild it anyway? (y/N): ").strip().lower() != "y":
                return

        ok, res, problems = resource.create(client, spec)
        if not ok:
            print(f"Error: {res}")
            return

        print(f"Created: {res}")
        for p in problems:
            print(f"  [!] {p}")

        # Read back rather than trusting the request. A create can succeed and
        # still not take a setting, and reporting the form would be reporting
        # an intention.
        _report(resource.check(resource.read(client, res)))

    elif choice == "3":
        found = resource.list_all(client, only_ours=False)
        if not found:
            print(f"No {label.lower()}s in this subscription.")
            return
        chosen = _choose(found, lambda a: a["name"], f"Select one to scan")
        if not chosen:
            return

        settings = resource.read(client, chosen["id"])
        # Deleted between the listing and this read is not an error.
        if settings is None:
            print("That one is no longer there.")
            return

        _report(resource.check(settings))
        print("\nNothing in the Azure half is fixed automatically yet; each")
        print("finding says what to change and where.")

    elif choice == "4":
        found = resource.list_all(client, only_ours=True)
        if not found:
            print(f"No {label.lower()}s this tool made.")
            return
        chosen = _choose(found, lambda a: a["name"], "Select one to delete")
        if not chosen:
            return

        # The refusal text lives in az/, next to the call that would do it, so
        # this asks first and lets the module say why it matters afterwards if
        # the answer is no.
        refused, why = resource.delete(client, chosen["id"], {"force": False})
        if not refused:
            print(f"\n{why}")

        typed = input(f"\nType the name to confirm ({chosen['name']}): ").strip()
        if typed != chosen["name"]:
            print("That did not match. Nothing was deleted.")
            return

        ok, msg = resource.delete(client, chosen["id"], {"force": True})
        print(msg)

    elif choice == "5":
        found = resource.list_all(client, only_ours=True)
        if not found:
            print("Nothing to clean up.")
            return

        print(f"\nThis deletes {len(found)} {label.lower()}(s) carrying this")
        print("tool's tag, and everything inside them. The tag records which")
        print("tool made them, not which person - on a shared subscription this")
        print("reaches a colleague's work as readily as your own.")
        for item in found:
            print(f"  - {item['name']}")

        if input("\nType DELETE to go ahead: ").strip() != "DELETE":
            print("Nothing was deleted.")
            return

        for resource_id, ok, msg in resource.cleanup(client, {"force": True}):
            print(f"[{resource_id.split('/')[-1]}] -> {msg}")


# ------------------------------------------------------------------------- Entry


def main():
    print("=== Secure Cloud Provisioner ===")
    print("1. Security Groups (network)")
    print("2. S3 Buckets (storage)")
    print("3. Key Pairs (access)")
    print("4. Servers (compute) - these cost money")
    print("5. Networks (the VPC everything else sits in)")
    print("6. Blueprints - build a whole architecture at once")
    print("7. Account access - audit only, changes nothing")
    print("8. Disk backups - audit only, changes nothing")
    print("9. Alarms - tell me when spending or load goes up")
    print("10. Azure storage accounts")
    print("11. Azure key vaults - these hold the keys other things depend on")
    resource = input("\nSelect resource type (1-11): ").strip()

    try:
        if resource == "1":
            security_group_menu(ec2_client(REGION))
        elif resource == "2":
            bucket_menu(s3_client(REGION))
        elif resource == "3":
            key_pair_menu(ec2_client(REGION))
        elif resource == "4":
            instance_menu(ec2_client(REGION))
        elif resource == "5":
            network_menu(ec2_client(REGION))
        elif resource == "6":
            blueprint_menu(ec2_client(REGION))
        elif resource == "7":
            account_menu(registry.IAM.get_client(REGION))
        elif resource == "8":
            snapshot_menu(registry.SNAPSHOT.get_client(REGION))
        elif resource == "9":
            alarm_menu(registry.ALARM.get_client(REGION))
        elif resource == "10":
            azure_menu(registry.AZURE_STORAGE,
                       registry.AZURE_STORAGE.get_client(REGION))
        elif resource == "11":
            azure_menu(registry.AZURE_KEYVAULT,
                       registry.AZURE_KEYVAULT.get_client(REGION))
        else:
            print("Not a valid selection.")
    except AzureNotConfigured as e:
        # Reached before the menu prints, because the client is built first.
        # Deliberately not an ImportError or a traceback: the two ways to be
        # unconfigured have two different fixes and the message carries whichever
        # one applies.
        print(f"\nStopped: {e}")
    except PermissionDenied as e:
        print(f"\nStopped: the login this tool is using is missing {e.permission}.")
        print("Add that permission to the tool's IAM policy and run this again.")
        print("The full list this tool needs is in docs/iam-setup.md.")
    except KeyboardInterrupt:
        print("\nCancelled.")


if __name__ == "__main__":
    main()
