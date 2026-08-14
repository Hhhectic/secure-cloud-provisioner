"""Azure virtual machines: the counterpart of `aws/instances.py`.

The fifth Azure type and the only one that spends money, which shapes every
decision in this file.

**Sizes are an allowlist, not a warning.** `ALLOWED_VM_SIZES` is the whole set
this tool can build, and anything outside it is refused outright rather than
warned about - the same guardrail `aws/instances.py` states and for the same
reason recorded in CLAUDE.md: a confirmation prompt does not survive a typo,
and a refusal does. The difference in cost between the smallest of these and
the largest machine Azure will sell is about four orders of magnitude per hour.

**Passwords are refused, not discouraged.** `deploy_azure_vm` in
`archive/streamlit-gui/` supports password authentication by reading
`AZURE_VM_ADMIN_PASSWORD` from the environment. This does not, and the refusal
is deliberate rather than an omission: this project's position on secrets is
already written down in *Key pairs are import-only* - `create_key_pair` is
never called because it returns private key material in a response body, and
`frontend/keygen.js` generates in the browser so the secret is made where it
already lives. Accepting a password here would put a credential that logs into
a running machine into a request body, an API log and whatever is between. The
public half of a key pair is not a secret and is all this needs.

**Creating a machine creates five things.** Azure has no single call: a machine
needs a network, a subnet, a security group, optionally a public address, and a
network card joining them. `create_vm` builds what is missing and says what it
built. Nothing rolls back, which is this project's stated position - a partial
failure reports exactly what exists, because silently destroying half-built
infrastructure is worse when a piece of it might already be doing something.

Every SDK import happens inside a function, so importing this module costs
nothing on a machine with only the AWS half installed.
"""

from az import names, nsg as az_nsg, vnet as az_vnet
from az.common import (AzureNotConfigured, AzureRefused, _import,
                       credential, denied,
                       ensure_resource_group, is_managed, managed_tags,
                       network_client, not_allowed_to_look, plain,
                       resource_group_of, subscription_id,
                       why_azure_refused)

# Small and cheap. Anything absent from this set is refused outright. Widen it
# deliberately if you genuinely need to, and read the hourly price before you
# do - the smallest of these is about $0.01/hour and the sizes people reach for
# by habit are two hundred times that.
#
# Three families, and the reason there are three is a lesson from a real
# subscription rather than a wish to be thorough.
#
# The classic B-series was the whole list, on the grounds that it is the cheap
# burstable one and is what the AWS half's t3.micro corresponds to. Against a
# real subscription every one of them came back
# `NotAvailableForSubscription` - in eastus, and in the eight other regions
# checked. Not a capacity blip and not a quota problem: the quota was four
# cores and unused. Azure simply does not offer the older B-series to some
# subscriptions at all, and an allowlist containing only sizes the caller
# cannot use is a guardrail that refuses everything.
#
# So the list now spans generations. Bsv2 is the current burstable family and
# is what a subscription without the classic one usually has. The 1 and 2 vCPU
# v7 general-purpose and compute sizes are the fallback where neither
# burstable family is offered - dearer per hour than a B1s and still small.
# Nothing here exceeds 2 vCPU, which is what keeps the guardrail meaningful:
# the refusal exists so that a typo cannot spend a hundred times more, not so
# that only one family may be used.
ALLOWED_VM_SIZES = {
    # Classic burstable. Cheapest when a subscription is offered them.
    "Standard_B1ls",
    "Standard_B1s",
    "Standard_B1ms",
    "Standard_B2s",
    # Burstable v2, the current generation of the same idea.
    "Standard_B2ts_v2",
    "Standard_B2ls_v2",
    "Standard_B2s_v2",
    "Standard_B2als_v2",
    "Standard_B2as_v2",
    # Smallest general-purpose and compute sizes, for subscriptions offered
    # neither burstable family. One and two vCPU only.
    "Standard_F1als_v7",
    "Standard_F1as_v7",
    "Standard_F2als_v7",
    "Standard_D2als_v7",
    "Standard_D2ls_v7",
}

DEFAULT_VM_SIZE = "Standard_B1s"


def offered_sizes(client, location):
    """Which allowlisted sizes this subscription can start here, and what
    each one is.

    Azure restricts sizes per subscription as well as per region, and reports
    the two the same way. `resource_skus.list` is the only place the answer
    exists before a create is attempted - a size can be perfectly real, in a
    region that has it, and still be refused for this subscription with
    `SkuNotAvailable`, which is what happened on the first live run.

    Returns [{"name", "vcpus", "memory_gb"}], sorted by name and empty if
    nothing in the allowlist is offered. Never raises: this is called both to
    build a menu and to improve a refusal, and a refusal that fails while
    explaining itself is worse than the plain one.

    The capabilities come back on the same call that answers the availability
    question, so carrying them costs nothing. They are worth carrying because
    the names do not say what they are: `Standard_F1as_v7` and
    `Standard_F1als_v7` differ by one letter and by twice the memory, and
    nobody picks correctly between those from the name alone.
    """
    try:
        found = {}
        for sku in client.resource_skus.list(
                filter=f"location eq '{location}'"):
            if sku.resource_type != "virtualMachines":
                continue
            if sku.name not in ALLOWED_VM_SIZES:
                continue
            # Any restriction at all means this subscription cannot start it
            # here, whatever the reason code says.
            if sku.restrictions:
                continue
            # getattr, because "never raises" here swallows an AttributeError
            # into "no sizes offered" - which is exactly what happened when
            # this first read sku.capabilities directly and the test stub had
            # no such field. A blanket except turns a typo into a silent
            # empty menu.
            caps = {c.name: c.value
                    for c in (getattr(sku, "capabilities", None) or [])}
            found[sku.name] = {
                "name": sku.name,
                "vcpus": _as_number(caps.get("vCPUs")),
                "memory_gb": _as_number(caps.get("MemoryGB")),
            }
        return [found[k] for k in sorted(found)]
    except Exception:
        return []


def _as_number(value):
    """A capability as a number, or None. Azure sends them all as strings."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return int(number) if number == int(number) else number


def available_sizes(client, location):
    """The names alone, for callers that only need the list.

    Kept as its own function rather than folded into `offered_sizes` because
    three callers want exactly this and rewriting them to index a dict would
    be churn for nothing.
    """
    return [size["name"] for size in offered_sizes(client, location)]


def first_available_size(client, location, preferred=None):
    """One size this subscription can start here, or None.

    Used by the smoke test so that a live run works on a subscription that is
    offered any of the allowlist rather than only on one offered the classic
    B-series. Prefers the cheapest thing available, which is the order the
    allowlist is written in rather than an alphabetical one.
    """
    offered = set(available_sizes(client, location))
    if not offered:
        return None

    for size in [preferred] + PREFERENCE_ORDER:
        if size and size in offered:
            return size

    return sorted(offered)[0]


# Cheapest first, as far as that can be stated without a price list in the
# repository going stale. Burstable before fixed, smaller before larger.
PREFERENCE_ORDER = [
    "Standard_B1ls", "Standard_B1s", "Standard_B1ms", "Standard_B2s",
    "Standard_B2ts_v2", "Standard_B2ls_v2", "Standard_B2s_v2",
    "Standard_B2als_v2", "Standard_B2as_v2",
    "Standard_F1als_v7", "Standard_F1as_v7", "Standard_F2als_v7",
    "Standard_D2als_v7", "Standard_D2ls_v7",
]

# Ubuntu 22.04 LTS. Pinned to a publisher, offer and SKU rather than to a
# version, with "latest" as the version, so a machine built today gets today's
# patches. The alternative - pinning a version - means every machine this tool
# builds is progressively more out of date, which is a security decision
# disguised as a reproducibility one.
VM_IMAGE = {
    "publisher": "Canonical",
    "offer": "0001-com-ubuntu-server-jammy",
    "sku": "22_04-lts-gen2",
    "version": "latest",
}


class VMSizeNotAllowed(Exception):
    """A refusal rather than a warning. See ALLOWED_VM_SIZES."""


def get_client(region="us-east-1"):
    """Returns a compute client. The region is accepted and ignored.

    Azure carries the location on the resource rather than on the connection,
    so there is no regional endpoint to choose. The parameter exists because
    the registry hands every resource type a region.
    """
    ComputeManagementClient = _import("azure.mgmt.compute",
                                      "ComputeManagementClient")
    return ComputeManagementClient(credential(), subscription_id())


def list_vms(client, only_ours=False):
    """Every virtual machine in the subscription."""
    found = [
        {"id": v.id, "name": v.name,
         "resource_group": resource_group_of(v.id),
         "location": plain(getattr(v, "location", None)),
         "tags": getattr(v, "tags", None)}
        for v in client.virtual_machines.list_all()
    ]

    if only_ours:
        found = [v for v in found if is_managed(v["tags"])]

    return found


def _locate(client, name):
    """The resource group a named machine lives in. Returns (group, short)."""
    group = resource_group_of(name)
    short = name.split("/")[-1] if group else name

    if group:
        return group, short

    for candidate in list_vms(client):
        if candidate["name"] == short:
            return candidate["resource_group"], short

    return None, short


def _effective_rules(net, nic):
    """Every rule filtering this machine, from its card and from its subnet.

    Azure applies security groups at two places and either, neither or both may
    be present. Reading only one of them is how a machine behind an open subnet
    group looks filtered, so both are collected and handed to the scanner as
    one list - which is what `scanner/azure_nsg_effective.py` expects, and what
    lets a machine's exposure be decided by the same code that decides a
    group's.
    """
    rules = []
    seen_groups = []

    def collect(group_ref):
        group_id = getattr(group_ref, "id", None)
        if not group_id or group_id in seen_groups:
            return
        seen_groups.append(group_id)
        group_name = group_id.split("/")[-1]
        settings = az_nsg.read_nsg_for_scanning(net, group_id)
        if settings:
            rules.extend(settings.get("rules") or [])

    collect(getattr(nic, "network_security_group", None))

    for configuration in (getattr(nic, "ip_configurations", None) or []):
        subnet_ref = getattr(configuration, "subnet", None)
        subnet_id = getattr(subnet_ref, "id", None)
        if not subnet_id:
            continue
        # A subnet reference on a network card is an id and nothing else, so
        # the subnet has to be fetched to find out whether it carries a group.
        parts = subnet_id.split("/")
        try:
            group_name = parts[parts.index("resourceGroups") + 1]
            vnet_name = parts[parts.index("virtualNetworks") + 1]
            subnet_name = parts[-1]
        except (ValueError, IndexError):
            continue
        subnet = net.subnets.get(group_name, vnet_name, subnet_name)
        collect(getattr(subnet, "network_security_group", None))

    return rules, seen_groups


def read_vm_for_scanning(client, name):
    """One machine's settings, flattened for the scanner.

    Accepts a bare name or a full resource id. Returns None when there is no
    such machine, which the routes turn into a 404.

    Reads three resources beyond the machine itself - its network card, any
    public address on that card, and the security groups filtering it - because
    none of what makes an Azure machine exposed lives on the machine. Each is a
    separate call and a separate permission, so a failure is recorded in
    `unreadable` rather than read as "nothing found": the two look identical in
    a result and only one of them is safe to score clean.
    """
    group, short = _locate(client, name)
    if not group:
        return None

    try:
        found = client.virtual_machines.get(group, short, expand="instanceView")
    except Exception as e:
        # Refusal before absence, because Azure says both in the same words
        # and a handler knowing only 404 re-raises the first as a crash.
        if denied(e):
            raise not_allowed_to_look(group, "virtual machines") from e
        if getattr(e, "status_code", None) == 404:
            return None
        raise

    os_profile = getattr(found, "os_profile", None)
    linux = getattr(os_profile, "linux_configuration", None)
    storage = getattr(found, "storage_profile", None)
    os_disk = getattr(storage, "os_disk", None)
    security = getattr(found, "security_profile", None)

    settings = {
        "vm_name": found.name,
        "resource_id": found.id,
        "resource_group": group,
        "location": plain(getattr(found, "location", None)),
        "vm_size": plain(getattr(getattr(found, "hardware_profile", None),
                                 "vm_size", None)),
        "admin_username": getattr(os_profile, "admin_username", None),
        # Azure models this the other way up, as "disable password
        # authentication". Kept in the tool's own direction so the scanner is
        # not reading a double negative, which is where this kind of check goes
        # wrong.
        "password_authentication_disabled": getattr(
            linux, "disable_password_authentication", None),
        "os_disk_encrypted": True if os_disk is not None else None,
        "encryption_at_host": getattr(security, "encryption_at_host", None),
        "power_state": _power_state(found),
        "public_ip": None,
        "effective_rules": [],
        "security_groups": [],
    }

    unreadable = {}
    net = network_client()

    try:
        nic_id = None
        profile = getattr(found, "network_profile", None)
        for interface in (getattr(profile, "network_interfaces", None) or []):
            nic_id = interface.id
            if getattr(interface, "primary", None):
                break

        if not nic_id:
            unreadable["public_ip"] = "this machine has no network card"
            unreadable["effective_rules"] = "this machine has no network card"
        else:
            nic_group = resource_group_of(nic_id)
            nic = net.network_interfaces.get(nic_group, nic_id.split("/")[-1])

            for configuration in (getattr(nic, "ip_configurations", None) or []):
                address = getattr(configuration, "public_ip_address", None)
                if getattr(address, "id", None):
                    public = net.public_ip_addresses.get(
                        resource_group_of(address.id),
                        address.id.split("/")[-1])
                    settings["public_ip"] = getattr(public, "ip_address", None) \
                        or "allocated, no address yet"
                    break

            rules, groups = _effective_rules(net, nic)
            settings["effective_rules"] = rules
            settings["security_groups"] = groups
    except Exception as e:
        unreadable["effective_rules"] = (
            f"the login could not read this machine's network "
            f"({type(e).__name__})"
        )

    if settings["password_authentication_disabled"] is None:
        # A Windows machine has no linux_configuration at all, and this tool
        # only builds Linux. Saying so beats scoring it either way.
        unreadable["password_authentication_disabled"] = (
            "this machine has no Linux configuration, so how it authenticates "
            "was not readable here"
        )

    settings["unreadable"] = unreadable
    return settings


def _power_state(machine):
    """Running, stopped, deallocated - or None when the view was not asked for.

    Comes from the instance view rather than from the machine's own properties,
    because a machine's provisioning state says it was created successfully and
    says nothing about whether it is currently on. A deallocated machine costs
    nothing but its disk; a stopped one still costs, which is a distinction
    worth being able to make.
    """
    view = getattr(machine, "instance_view", None)
    for status in (getattr(view, "statuses", None) or []):
        code = str(getattr(status, "code", "") or "")
        if code.startswith("PowerState/"):
            return code.split("/", 1)[1]
    return None


def describe_vm(settings):
    """What the machine is, rather than what is wrong with it."""
    if not settings:
        return None
    return {
        "vm_name": settings.get("vm_name"),
        "resource_group": settings.get("resource_group"),
        "location": settings.get("location"),
        "vm_size": settings.get("vm_size"),
        "power_state": settings.get("power_state"),
        "public_ip": settings.get("public_ip"),
        "admin_username": settings.get("admin_username"),
        "security_groups": [g.split("/")[-1]
                            for g in settings.get("security_groups") or []],
        "checks_skipped": sorted(settings.get("unreadable") or {}),
    }


def create_vm(client, name, resource_group, location="eastus",
              vm_size=None, admin_username="azureuser", ssh_public_key=None,
              vnet_name=None, subnet_name="default", nsg_name=None,
              assign_public_ip=False, open_ports=None, allowed_source=None,
              encryption_at_host=False):
    """Creates one Linux virtual machine and what it needs. Returns
    (ok, id_or_error, problems).

    Builds, in order: the resource group, a virtual network, a security group,
    optionally a public address, a network card, and the machine. Anything
    named that already exists is reused rather than rebuilt, so pointing this
    at an existing network is how a second machine joins the first one's.

    `problems` carries every resource this created besides the machine, because
    deleting the machine does not delete them and somebody who ran this once to
    try it should not have to discover that from a bill.

    **Only the public half of a key is accepted, and it is required unless the
    machine is unreachable.** See the module docstring.
    """
    problems = []
    vm_size = vm_size or DEFAULT_VM_SIZE
    open_ports = [str(p) for p in (open_ports or [])]
    source = allowed_source or "*"

    legal, why_not = names.check("azure-vm", name)
    if not legal:
        return False, why_not, problems

    legal, why_not = names.check("resource-group", resource_group)
    if not legal:
        return False, why_not, problems

    if vm_size not in ALLOWED_VM_SIZES:
        allowed = ", ".join(sorted(ALLOWED_VM_SIZES))
        return False, (
            f"'{vm_size}' is not a size this tool will create. It builds only "
            f"{allowed}, which are the cheap burstable ones. This is a refusal "
            "rather than a warning because the difference between the smallest "
            "of these and a machine somebody picks by habit is about a hundred "
            "times the hourly cost, and a typo should not be able to spend it."
        ), problems

    if not ssh_public_key:
        return False, (
            "A public SSH key is required. This tool never accepts a password "
            "for a machine it builds: a password logs in, so putting one in a "
            "request body puts it in the logs and in everything between here "
            "and Azure. Generate a key with `ssh-keygen`, or in the browser on "
            "the page, and send the public half - which is not a secret."
        ), problems

    if not str(ssh_public_key).strip().startswith(("ssh-", "ecdsa-")):
        return False, (
            "That does not look like a public SSH key. It should be one line "
            "beginning ssh-ed25519, ssh-rsa or ecdsa-. If it begins with "
            "'-----BEGIN', it is the private half and must never be sent "
            "anywhere."
        ), problems

    # Asked before anything is built, which is the whole point of asking.
    #
    # ALLOWED_VM_SIZES is this tool's list; what *this subscription* will
    # actually start is a different question, and only `resource_skus` answers
    # it. Without this check a size Azure declines - which is every burstable
    # size on this subscription - gets as far as building a virtual network, a
    # security group and a network card before failing, and those are left
    # behind. With `assign_public_ip` it strands a static address that bills.
    #
    # This check was written, reverted, and put back. The revert was made on a
    # measurement that turned out to be wrong: `resource_skus.list` was timed
    # at over three minutes and recorded as such, which would have made every
    # machine create wait on it. Re-measured on a quiet subscription it is
    # five to eight seconds for 1,490 SKUs - the slow reading was taken
    # straight after a burst of creates and deletes and was almost certainly
    # Azure throttling with SDK backoff. Six seconds on a create that already
    # takes a minute, to stop three resources being stranded, is a trade worth
    # making.
    #
    # An empty answer is still not a refusal. `offered_sizes` never raises and
    # returns nothing when it cannot ask, and a subscription this tool cannot
    # interrogate should still be allowed to try - Azure's own verdict is the
    # backstop, as it was before.
    offered = available_sizes(client, location)
    if offered and vm_size not in offered:
        return False, (
            f"Azure will not start {vm_size} in {location} for this "
            f"subscription. It is on this tool's allowlist, but Azure declines "
            f"to offer some machine families to some subscriptions regardless "
            f"of quota or capacity, and reports that in the language of "
            f"capacity. Sizes it will start here: {', '.join(offered)}. "
            f"Nothing was created."
        ), problems

    # The resource group is checked before a second client is built, because
    # it is the cheapest thing that can stop this and the one most likely to.
    # Building the network client first meant a caller who named a group they
    # cannot see paid for a client they never used.
    try:
        created, note = ensure_resource_group(resource_group, location)
    except AzureRefused as e:
        return False, str(e), problems

    if created:
        problems.append(note)

    net = network_client()

    # ---- The network --------------------------------------------------------
    vnet_name = vnet_name or f"{name}-vnet"
    existing = az_vnet.read_vnet_for_scanning(net, vnet_name)
    if existing is None:
        made, result, vnet_problems = az_vnet.create_vnet(
            net, vnet_name, resource_group, location=location,
            subnets=[{"name": subnet_name,
                      "address_prefix": az_vnet.DEFAULT_SUBNET}])
        if not made:
            return False, f"Could not create the network: {result}", problems
        problems.append(
            f"Virtual network '{vnet_name}' was created for this machine and "
            "is not removed when the machine is deleted."
        )
        subnet_id = _subnet_id(net, resource_group, vnet_name, subnet_name)
    else:
        subnet_id = _subnet_id(net, existing["resource_group"], vnet_name,
                               subnet_name)
        if not subnet_id:
            return False, (
                f"Virtual network '{vnet_name}' exists but has no subnet "
                f"called '{subnet_name}'."
            ), problems

    # ---- The firewall -------------------------------------------------------
    nsg_name = nsg_name or f"{name}-nsg"
    rules = [{
        "name": f"allow-{port}",
        "direction": "Inbound",
        "access": "Allow",
        "protocol": "Tcp",
        "source_address_prefix": source,
        "destination_port_range": port,
    } for port in open_ports]

    if az_nsg.read_nsg_for_scanning(net, nsg_name) is None:
        made, nsg_id, nsg_problems = az_nsg.create_nsg(
            net, nsg_name, resource_group, location=location, rules=rules)
        if not made:
            return False, f"Could not create the security group: {nsg_id}", problems
        problems.append(
            f"Network security group '{nsg_name}' was created for this machine "
            "and is not removed when the machine is deleted."
        )
    else:
        nsg_id = None
        for found in az_nsg.list_nsgs(net):
            if found["name"] == nsg_name:
                nsg_id = found["id"]
                break
        problems.append(
            f"Network security group '{nsg_name}' already existed and was "
            "reused as it is. The ports asked for here were not added to it - "
            "scan it to see what it actually allows."
        )

    # ---- A public address, only if asked for --------------------------------
    #
    # Stated rather than defaulted, for the reason CLAUDE.md records under "An
    # absent setting is not a safe setting": the AWS half implemented
    # assign_public_ip=False as not mentioning it, and the subnet's own default
    # decided instead.
    public_ip_id = None
    if assign_public_ip:
        public = net.public_ip_addresses.begin_create_or_update(
            resource_group, f"{name}-ip",
            {"location": location,
             "tags": managed_tags(),
             "sku": {"name": "Standard"},
             "properties": {"publicIPAllocationMethod": "Static",
                            "publicIPAddressVersion": "IPv4"}}).result()
        public_ip_id = public.id
        problems.append(
            f"Public address '{name}-ip' was created and is not removed when "
            "the machine is deleted. A static address that belongs to nothing "
            "still costs."
        )

    # ---- The network card ---------------------------------------------------
    ip_configuration = {
        "name": f"{name}-ipcfg",
        "properties": {"subnet": {"id": subnet_id}},
    }
    if public_ip_id:
        ip_configuration["properties"]["publicIPAddress"] = {"id": public_ip_id}

    nic_body = {
        "location": location,
        "tags": managed_tags(),
        "properties": {"ipConfigurations": [ip_configuration]},
    }
    if nsg_id:
        nic_body["properties"]["networkSecurityGroup"] = {"id": nsg_id}

    nic = net.network_interfaces.begin_create_or_update(
        resource_group, f"{name}-nic", nic_body).result()
    problems.append(
        f"Network card '{name}-nic' was created for this machine."
    )

    # ---- The machine --------------------------------------------------------
    body = {
        "location": location,
        "tags": managed_tags(),
        "properties": {
            "hardwareProfile": {"vmSize": vm_size},
            "storageProfile": {
                "imageReference": VM_IMAGE,
                "osDisk": {
                    "createOption": "FromImage",
                    "managedDisk": {"storageAccountType": "StandardSSD_LRS"},
                    # So that deleting the machine does not leave its disk
                    # behind billing. Azure's default is to keep it.
                    "deleteOption": "Delete",
                },
            },
            "osProfile": {
                "computerName": name,
                "adminUsername": admin_username,
                "linuxConfiguration": {
                    # Stated explicitly, not left to the platform.
                    "disablePasswordAuthentication": True,
                    "ssh": {"publicKeys": [{
                        "path": f"/home/{admin_username}/.ssh/authorized_keys",
                        "keyData": str(ssh_public_key).strip(),
                    }]},
                },
            },
            "networkProfile": {
                "networkInterfaces": [{"id": nic.id,
                                       "properties": {"primary": True}}],
            },
        },
    }

    if encryption_at_host:
        body["properties"]["securityProfile"] = {"encryptionAtHost": True}

    # The machine is the last thing built and the most likely to be refused,
    # and by the time it is attempted four other resources exist. Letting the
    # exception out loses `problems`, which is the only record of them - the
    # caller gets a traceback and a subscription quietly holding a network, a
    # security group, a card and possibly a billable address it never hears
    # about. "Nothing rolls back. Partial failures report exactly what exists"
    # is this project's stated position and it is only kept if the report
    # survives the failure.
    try:
        made = client.virtual_machines.begin_create_or_update(
            resource_group, name, body).result()
    except Exception as e:
        return False, _why_the_machine_was_refused(
            e, resource_group, client=client, location=location), problems

    return True, made.id, problems


def _why_the_machine_was_refused(error, resource_group, client=None,
                                 location=None):
    """Turns an SDK exception into a sentence somebody can act on.

    Azure reports the conditions that actually stop this in a form that names
    the fix without looking like it does. Three of them were met on real runs
    against one subscription, in order, each only visible once the one before
    it was cleared: a subscription that had never created a machine, under a
    service principal that could not fix that itself, and then a size that
    subscription is not offered anywhere.
    """
    detail = str(error)

    if "SkuNotAvailable" in detail or "Capacity Restrictions" in detail:
        offered = available_sizes(client, location) if client and location else []
        if offered:
            return (
                f"Azure will not start that size in {location} for this "
                f"subscription. Sizes from this tool's allowlist that it will "
                f"start there: {', '.join(offered)}. Pass one of those as "
                "vm_size."
            )
        return (
            f"Azure will not start that size in {location} for this "
            "subscription, and none of the other sizes this tool allows are "
            f"offered in {location} either. This is a restriction on the "
            "subscription rather than on the region - Azure declines to offer "
            "some machine families to some subscriptions regardless of quota, "
            "and reports it the same way it reports a region being full. Try "
            "another location, or ask Azure support to enable a size there. "
            f"Azure said: {detail[:200]}"
        )

    if "MissingSubscriptionRegistration" in detail:
        return (
            "This subscription has never been used to create a virtual "
            "machine, so Azure has not switched the Microsoft.Compute service "
            "on for it. That is a one-time setting on the subscription and it "
            "is free. An owner can do it in the portal under Subscriptions -> "
            "Resource providers -> Microsoft.Compute -> Register, or with "
            "`az provider register --namespace Microsoft.Compute`. Registering "
            "takes a couple of minutes; nothing else here needs it, which is "
            "why storage, vaults, networks and security groups all worked. "
            "This tool cannot do it for you unless its service principal holds "
            "Contributor on the subscription rather than on one resource "
            "group."
        )

    if "AuthorizationFailed" in detail or "does not have authorization" in detail:
        action = "the action it needs"
        marker = "perform action '"
        if marker in detail:
            action = "'" + detail.split(marker, 1)[1].split("'", 1)[0] + "'"
        return (
            f"The service principal is not allowed to {action}. Azure grants "
            f"reads and writes separately, so listing machines can work while "
            f"creating one does not. Grant Contributor on '{resource_group}'."
        )

    if "QuotaExceeded" in detail or "OperationNotAllowed" in detail:
        return (
            "Azure refused on quota. A new subscription often has no compute "
            "quota in a region until asked for some, and free accounts have "
            "very little. The message from Azure was: " + detail[:300]
        )

    return f"Azure refused to create the machine: {detail[:400]}"


def _subnet_id(net, resource_group, vnet_name, subnet_name):
    """The id of one subnet, or None."""
    try:
        return net.subnets.get(resource_group, vnet_name, subnet_name).id
    except Exception:
        return None


def delete_vm(client, name, force=False):
    """Deletes one machine. Returns (ok, message).

    Refuses without force. Deletes the machine and its operating system disk,
    which was created with deleteOption Delete for exactly this reason, and
    does not delete the network card, the public address, the security group or
    the network - because this tool may not have made them, and a delete that
    reaches resources it did not create is how somebody's network disappears
    because a machine that briefly used it was removed.

    Says so plainly rather than reporting success and leaving somebody to find
    four billable leftovers later.
    """
    group, short = _locate(client, name)

    if not force:
        return False, (
            f"Not deleted. '{short}' may be doing something, and a machine "
            "that looks idle from here can be the one thing somebody depends "
            "on. Ask for it explicitly, with the machine's id repeated back."
        )

    if not group:
        return False, f"No virtual machine named '{short}' in this subscription."

    try:
        client.virtual_machines.begin_delete(group, short).result()
    except Exception as e:            # HttpResponseError, imported lazily
        return False, why_azure_refused(e, f"delete '{short}'")

    return True, (
        f"Deleted virtual machine '{short}' and its operating system disk. Its "
        f"network card ('{short}-nic'), any public address, its security group "
        "and its virtual network are still there - this tool did not "
        "necessarily create them and does not remove what it may not own. A "
        "static public address with nothing attached still costs; the rest do "
        "not."
    )


def cleanup_all_managed_vms(client, force=False):
    """Deletes every machine carrying this tool's tag. Returns [(id, ok, msg)].

    Bounded by the tag and not by who ran it. On a shared subscription this
    reaches a colleague's machine as readily as your own, which is the same
    hazard CLAUDE.md records for the AWS cleanup and for the other Azure ones -
    and matters most here, because this is the type that might be running
    something.
    """
    return [
        (found["id"],) + delete_vm(client, found["id"], force=force)
        for found in list_vms(client, only_ours=True)
    ]


def plan_deletion(client, name):
    """What a delete would take with it, and what it would leave.

    The only preview here that is mostly about what *survives*, because that is
    the surprising half: four resources stay and one of them can carry a
    charge.
    """
    settings = read_vm_for_scanning(client, name)
    if settings is None:
        return None

    short = settings.get("vm_name")
    left = [f"{short}-nic", f"{short}-vnet", f"{short}-nsg"]
    if settings.get("public_ip"):
        left.append(f"{short}-ip")

    return {
        "items": [{"id": short, "type": "virtual machine"},
                  {"id": "operating system disk", "type": "managed disk"}],
        "destroys": {"virtual machines": 1, "managed disks": 1},
        "message": (
            "Deleting this destroys the machine and its operating system disk. "
            f"These are left behind and are not removed: {', '.join(left)}. A "
            "static public address with nothing attached still costs."
        ),
    }


def apply_fix(client, name, warning):
    """Not offered, and every reason is that the fix is somewhere else.

    Every finding this type reports is about a resource that is not the
    machine. An open administration port is a rule on a security group, which
    `az/nsg.py` can now fix. A public address is a separate resource, and
    removing it disconnects whatever is using it. Password authentication
    cannot be changed on a running machine at all - Azure sets it at creation.

    A fix that reaches from a machine into its firewall would also make one
    resource type quietly rewrite another, which is the coupling the registry
    exists to avoid. Scan the security group and fix it there, where the
    finding names the rule.
    """
    return False, (
        "Findings on a machine are fixed on the resources around it, not on "
        "the machine. An open port is a rule on its security group - scan that "
        "group and fix it there, where the change is visible next to the other "
        "rules it has to be judged against. Password authentication is set when "
        "a machine is created and cannot be changed afterwards."
    )
