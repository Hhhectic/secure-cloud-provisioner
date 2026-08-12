"""Azure virtual networks: the network everything else sits in.

The counterpart of `aws/vpcs.py`, and the fourth Azure type. It exists for the
reason the AWS one does - a machine's placement decides more about its exposure
than any setting on it, and neither the network nor the subnet can be changed
after creation - and because an Azure virtual machine cannot be built without
one.

Every SDK import happens inside `az/common.py`, inside a function, so importing
this module costs nothing on a machine with only the AWS half installed.

**A network's delete is the one that reaches other things.** Azure refuses to
delete a network while anything is still in it, which is a safer failure than
the AWS equivalent - `aws/vpcs.py` had to learn to wait for interfaces to clear
and to forgive "already gone" codes on the way. That refusal is left to Azure
rather than pre-empted here: the error names what is still attached, which is
more use than anything this module could say before trying.
"""

from az import names
from az.common import (AzureNotConfigured, AzureRefused, denied,
                       ensure_resource_group, is_managed, managed_tags,
                       network_client, not_allowed_to_look, plain,
                       resource_group_of)


def get_client(region="us-east-1"):
    """Returns a network client. The region is accepted and ignored.

    Virtual networks and security groups come off the same Azure client, so
    this is `az/nsg.py`'s function under another name. Both exist because the
    registry hands each type its own `get_client` and a type sharing another
    type's would be a coupling nobody reading the registry would expect.
    """
    return network_client(region)


def list_vnets(client, only_ours=False):
    """Every virtual network in the subscription."""
    found = [
        {"id": v.id, "name": v.name,
         "resource_group": resource_group_of(v.id),
         "location": v.location,
         "tags": getattr(v, "tags", None)}
        for v in client.virtual_networks.list_all()
    ]

    if only_ours:
        found = [v for v in found if is_managed(v["tags"])]

    return found


def _locate(client, name):
    """The resource group a named network lives in. Returns (group, short)."""
    group = resource_group_of(name)
    short = name.split("/")[-1] if group else name

    if group:
        return group, short

    for candidate in list_vnets(client):
        if candidate["name"] == short:
            return candidate["resource_group"], short

    return None, short


def read_vnet_for_scanning(client, name):
    """One network's settings, flattened for the scanner.

    Accepts a bare name or a full resource id. Returns None when there is no
    such network, which the routes turn into a 404.

    The subnets are read for whether each has a security group attached, not
    for what that group allows. Which is a deliberate line: `az/nsg.py` already
    judges a group's rules, and following the reference from here would report
    the same finding twice under two resource ids, in a tool whose whole
    argument for one warning shape is that a finding is counted once.
    """
    group, short = _locate(client, name)
    if not group:
        return None

    try:
        found = client.virtual_networks.get(group, short)
    except Exception as e:
        # Refusal before absence, the same order _name_is_taken already uses
        # below: "not allowed" is not "not there".
        if denied(e):
            raise not_allowed_to_look(group, "virtual networks") from e
        # Matching the status code rather than catching ResourceNotFoundError,
        # which lives behind an import this module does not make at scope.
        if getattr(e, "status_code", None) == 404:
            return None
        raise

    address_space = getattr(found, "address_space", None)

    settings = {
        "vnet_name": found.name,
        "resource_id": found.id,
        "resource_group": group,
        "location": plain(getattr(found, "location", None)),
        "address_prefixes": list(
            getattr(address_space, "address_prefixes", None) or []),
        # Absent means off. Azure only populates the DDoS block once somebody
        # attaches a paid plan, so None here is the ordinary case and means the
        # basic tier - a documented default rather than a gap in the read, the
        # same reasoning `az/storage.py` applies to public_network_access.
        "ddos_protection_enabled": bool(
            getattr(found, "enable_ddos_protection", None)),
        "peerings": [p.name for p in (getattr(found, "virtual_network_peerings",
                                              None) or [])],
        "subnets": [],
    }

    unreadable = {}
    try:
        settings["subnets"] = [
            {
                "name": s.name,
                "address_prefix": plain(getattr(s, "address_prefix", None)),
                # The id of the attached group, or None. The scanner only asks
                # whether there is one.
                "network_security_group": getattr(
                    getattr(s, "network_security_group", None), "id", None),
            }
            for s in (getattr(found, "subnets", None) or [])
        ]
    except Exception as e:
        unreadable["subnets"] = (
            f"the login could not read this network's subnets "
            f"({type(e).__name__})"
        )

    settings["unreadable"] = unreadable
    return settings


def describe_vnet(settings):
    """What the network is, rather than what is wrong with it."""
    if not settings:
        return None
    return {
        "vnet_name": settings.get("vnet_name"),
        "resource_group": settings.get("resource_group"),
        "location": settings.get("location"),
        "address_prefixes": settings.get("address_prefixes") or [],
        "subnet_count": len(settings.get("subnets") or []),
        "subnets": [s.get("name") for s in settings.get("subnets") or []],
        "peerings": settings.get("peerings") or [],
        "checks_skipped": sorted(settings.get("unreadable") or {}),
    }


# What a network gets when the caller does not say. A private range, and a /16
# split into one /24 - big enough for anything this tool builds and small
# enough not to collide with the ranges people commonly already use.
DEFAULT_ADDRESS_SPACE = "10.20.0.0/16"
DEFAULT_SUBNET = "10.20.1.0/24"


def _name_is_taken(client, name, resource_group):
    """Whether a network of this name already exists. Returns (taken, why).

    Scoped to the resource group, which is where Azure enforces uniqueness for
    a virtual network. The same guard `az/nsg.py` makes, and for the identical
    reason: `begin_create_or_update` on a name you already own replaces the
    network's whole configuration - including its subnet list - and reports
    success. Deleting somebody's subnets is worse than refusing to build.
    """
    try:
        client.virtual_networks.get(resource_group, name)
    except Exception as e:
        # 403 here is the same fact ensure_resource_group records: a resource
        # group this login cannot see answers every read inside it with a
        # refusal, and "not allowed" is not "not there". Checked before 404,
        # because only one of the two is an answer to the question asked.
        if denied(e):
            raise not_allowed_to_look(resource_group, "virtual networks") from e
        if getattr(e, "status_code", None) == 404:
            return False, None
        raise

    return True, (
        f"A virtual network called '{name}' already exists in "
        f"'{resource_group}'. Creating it again would replace its address "
        "space and its entire subnet list with what was submitted here, and "
        "Azure would report that as success - so this refuses instead."
    )


def create_vnet(client, name, resource_group, location="eastus",
                address_prefixes=None, subnets=None):
    """Creates one virtual network. Returns (ok, id_or_error, problems).

    `subnets` is a list of {"name", "address_prefix"}. One is created when none
    is given, because a network with no subnets holds nothing and Azure gives
    no default - and a caller who wanted an empty network can pass an empty
    list explicitly, which is the difference between a default and an
    assumption.

    No security group is attached to any subnet. There is nothing sensible to
    attach: the group would have to exist first, and inventing one here would
    be this module deciding what somebody's firewall says. `check_vnet_spec`
    reports that absence before the network is built, so it is a stated
    consequence rather than a silent one.
    """
    problems = []

    legal, why_not = names.check("azure-vnet", name)
    if not legal:
        return False, why_not, problems

    legal, why_not = names.check("resource-group", resource_group)
    if not legal:
        return False, why_not, problems

    prefixes = list(address_prefixes or [DEFAULT_ADDRESS_SPACE])

    if subnets is None:
        subnets = [{"name": "default", "address_prefix": DEFAULT_SUBNET}]
        problems.append(
            f"No subnets were given, so one called 'default' was created at "
            f"{DEFAULT_SUBNET}. Nothing can be placed in a network without "
            "one."
        )

    # Both of these read inside the resource group, so both answer a name the
    # login cannot see with a refusal rather than with "no". One catch, because
    # to the caller they are one question: can this be built here.
    try:
        taken, why_not = _name_is_taken(client, name, resource_group)
        if taken:
            return False, why_not, problems

        created, note = ensure_resource_group(resource_group, location)
    except AzureRefused as e:
        return False, str(e), problems
    if created:
        problems.append(note)

    # camelCase, because this dict is the request body rather than a model.
    # See az/common.plain for what the other spelling costs.
    body = {
        "location": location,
        "tags": managed_tags(),
        "properties": {
            "addressSpace": {"addressPrefixes": prefixes},
            "subnets": [
                {"name": s.get("name"),
                 "properties": {"addressPrefix": s.get("address_prefix")}}
                for s in subnets
            ],
        },
    }

    made = client.virtual_networks.begin_create_or_update(
        resource_group, name, body).result()

    problems.append(
        f"'{name}' filters nothing yet. None of its subnets has a security "
        "group attached, so anything placed in them is reachable on every port "
        "from anything that can route to the subnet. Create a network security "
        "group and attach it."
    )

    return True, made.id, problems


def delete_vnet(client, name, force=False):
    """Deletes one virtual network. Returns (ok, message).

    Refuses without force like every other Azure delete here. Azure itself then
    refuses if anything is still in the network, and that second refusal is
    left in place rather than worked around: its message names what is still
    attached, which is more use than a generic failure and is exactly what
    `aws/vpcs.py` had to reconstruct by hand for the AWS side.
    """
    group, short = _locate(client, name)

    if not force:
        return False, (
            f"Not deleted. Removing '{short}' removes the network every "
            "machine and subnet in it sits on. Azure refuses while anything is "
            "still there, so this cannot silently destroy a running system - "
            "but it can destroy an empty network somebody is about to use. Ask "
            "for it explicitly, with the network's id repeated back."
        )

    if not group:
        return False, f"No virtual network named '{short}' in this subscription."

    client.virtual_networks.begin_delete(group, short).result()
    return True, f"Deleted virtual network '{short}'."


def cleanup_all_managed_vnets(client, force=False):
    """Deletes every network carrying this tool's tag. Returns [(id, ok, msg)]."""
    return [
        (found["id"],) + delete_vnet(client, found["id"], force=force)
        for found in list_vnets(client, only_ours=True)
    ]


def plan_deletion(client, name):
    """What a delete would take with it, as the route's preview shape.

    Lists the subnets, because they are what goes and because Azure's own
    refusal depends on whether anything is inside them. Unlike a storage
    account, whose forced delete destroys data and can therefore have no honest
    preview, deleting a network destroys only the network - and only if it is
    already empty.
    """
    settings = read_vnet_for_scanning(client, name)
    if settings is None:
        return None

    subnets = settings.get("subnets") or []
    return {
        "items": [{"id": s.get("name"), "type": "subnet"} for s in subnets],
        "destroys": {"subnets": len(subnets)},
        "message": (
            f"Deleting this network deletes its {len(subnets)} subnet(s). "
            "Azure refuses while any machine, database or private endpoint is "
            "still in one of them, and names what is in the way."
        ),
    }


def apply_fix(client, name, warning):
    """Not offered, and the reason is that the fix is another resource.

    The finding this type reports is a subnet with no security group attached.
    Fixing it means attaching one - which means choosing one, and the choice
    decides what the subnet allows. There is no safe default: an empty group
    denies everything inbound and would cut off whatever is already running
    there, and a permissive one would be this tool writing somebody's firewall
    and calling it a fix.

    `POST /fix` carries a rule id and nothing else, deliberately, so there is
    nowhere for the caller to say which group to attach. Create the group with
    `POST /resources/azure-nsg`, which this tool now does, and attach it.
    """
    return False, (
        "A subnet with no security group is fixed by attaching one, and which "
        "group to attach decides what the subnet allows - so there is no safe "
        "answer this tool can pick for you. Create one with the network "
        "security group type and attach it to the subnet."
    )
