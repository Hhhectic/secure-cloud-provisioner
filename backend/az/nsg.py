"""Azure network security groups: the firewall, read for scanning.

The direct counterpart of `aws/security_groups.py`, and arranged the same way
on purpose: list, read into a flat shape the scanner understands, and nothing
else. Every SDK import happens inside `az/common.py`, inside a function, so
importing this module costs nothing on a machine with only the AWS half
installed.

Read-only for now. Azure provisioning exists on `group/main` in `azure_crud.py`
and is deliberately not wired in here: the point of this first pass is to prove
that a second cloud fits the warning contract and the registry, and a create
path that nobody has run against a real subscription would be a claim rather
than a feature.
"""

from az.common import AzureNotConfigured, network_client, resource_group_of


def get_client(region="us-east-1"):
    """Returns a network client. The region is accepted and ignored.

    Every resource type in the registry is handed a region because AWS needs
    one. Azure carries the location on the resource instead, so this signature
    exists to keep the routes free of any knowledge about which cloud they are
    speaking to.
    """
    return network_client(region)


def _rule_for_scanning(rule):
    """One security rule, flattened to what the scanner reads.

    Azure offers both `destination_port_range` and `destination_port_ranges`,
    and a rule uses one or the other. Collapsing them here means the rules do
    not have to know that, and a rule that used the plural form would
    otherwise be read as having no ports at all - silence on the one thing
    this scanner exists to find.
    """
    ranges = getattr(rule, "destination_port_ranges", None) or []
    single = getattr(rule, "destination_port_range", None)
    if single:
        ranges = list(ranges) + [single]

    sources = getattr(rule, "source_address_prefixes", None) or []
    source = getattr(rule, "source_address_prefix", None)
    if source:
        sources = list(sources) + [source]

    return {
        "name": getattr(rule, "name", None),
        "direction": getattr(rule, "direction", None),
        "access": getattr(rule, "access", None),
        "protocol": getattr(rule, "protocol", None),
        "priority": getattr(rule, "priority", None),
        "destination_port_ranges": [str(r) for r in ranges],
        "source_address_prefixes": [str(s) for s in sources],
    }


def _expand(rule):
    """One flattened rule per (source, port range) pair.

    A single Azure rule can name several sources and several port ranges, and
    it permits every combination. The scanner asks about one source and one
    range at a time, so the combinations are made explicit here rather than
    each rule having to loop.
    """
    out = []
    for source in rule["source_address_prefixes"] or [None]:
        for ports in rule["destination_port_ranges"] or [None]:
            out.append({
                "name": rule["name"],
                "direction": rule["direction"],
                "access": rule["access"],
                "protocol": rule["protocol"],
                "priority": rule["priority"],
                "source_address_prefix": source,
                "destination_port_range": ports,
            })
    return out


def list_nsgs(client, only_ours=False):
    """Every network security group in the subscription.

    only_ours is accepted and ignored: nothing here creates groups, so there is
    no tag to filter on. Saying so is better than quietly returning everything
    under a name that promises otherwise.
    """
    return [
        {"id": g.id, "name": g.name,
         "resource_group": resource_group_of(g.id),
         "location": g.location}
        for g in client.network_security_groups.list_all()
    ]


def read_nsg_for_scanning(client, name):
    """One group's rules, flattened for the scanner.

    Accepts either the bare name or the full Azure resource id, because the
    registry's identifier is a single string and both are things a person
    might paste. Returns None when there is no such group, which the routes
    turn into a 404 - the same contract every AWS reader here follows.
    """
    group = resource_group_of(name)
    short = name.split("/")[-1] if group else name

    if not group:
        # Only a name was given, so the group it lives in has to be found.
        for candidate in list_nsgs(client):
            if candidate["name"] == short:
                group = candidate["resource_group"]
                break
        if not group:
            return None

    try:
        found = client.network_security_groups.get(group, short)
    except Exception as e:
        # The SDK raises ResourceNotFoundError, which lives behind an import
        # this module deliberately does not make. Matching on the status code
        # keeps the lazy-import property.
        if getattr(e, "status_code", None) == 404:
            return None
        raise

    rules = []
    for rule in list(found.security_rules or []) + list(
            found.default_security_rules or []):
        rules.extend(_expand(_rule_for_scanning(rule)))

    attached = []
    attached += [i.id for i in (found.network_interfaces or [])]
    attached += [s.id for s in (found.subnets or [])]

    return {
        "nsg_name": found.name,
        "resource_id": found.id,
        "resource_group": group,
        "location": found.location,
        "rules": rules,
        "attached_to": attached,
    }


def describe_nsg(settings):
    """What the group is, rather than what is wrong with it."""
    if not settings:
        return None
    return {
        "nsg_name": settings.get("nsg_name"),
        "resource_group": settings.get("resource_group"),
        "location": settings.get("location"),
        "rule_count": len(settings.get("rules") or []),
        "attached_to": settings.get("attached_to") or [],
    }


def apply_fix(client, name, warning):
    """Azure firewall findings are reported, not fixed.

    The AWS side can narrow a rule to the caller's own address because it knows
    what that address is and the rule is one object it can rewrite. An Azure
    rule carries a priority that decides which of several overlapping rules
    wins, so changing one in isolation can be undone by another the tool never
    looked at. Until this reads the whole ordered set and can say what the
    result would be, offering a button would be offering a guess.
    """
    return False, (
        "Azure firewall findings are reported rather than fixed. Rules here "
        "are evaluated in priority order, so narrowing one without reading the "
        "rest can be silently undone by another. Change it in the portal or "
        "in your deployment templates, where the whole set is visible."
    )
