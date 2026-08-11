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

from az import names
from az.common import (AzureNotConfigured, ensure_resource_group, is_managed,
                       managed_tags, network_client, plain, resource_group_of)


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

    # plain() on every field the scanner reads. Direction, access and protocol
    # come back as SDK enums, which are str subclasses that compare equal to
    # their value and render as their qualified name - so the scanner's
    # str(...).lower() turned "Inbound" into "securityruledirection.inbound"
    # and skipped every rule of every real group. See az/common.plain.
    return {
        "name": plain(getattr(rule, "name", None)),
        "direction": plain(getattr(rule, "direction", None)),
        "access": plain(getattr(rule, "access", None)),
        "protocol": plain(getattr(rule, "protocol", None)),
        "priority": getattr(rule, "priority", None),
        "destination_port_ranges": [str(plain(r)) for r in ranges],
        "source_address_prefixes": [str(plain(s)) for s in sources],
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

    only_ours now means something. It used to be accepted and ignored, because
    nothing here created groups and so no group carried this tool's tag; that
    stopped being true when `create_nsg` arrived, and a filter that silently
    returns everything is worse on a type this tool can now destroy than on one
    it could only read.
    """
    found = [
        {"id": g.id, "name": g.name,
         "resource_group": resource_group_of(g.id),
         "location": g.location,
         "tags": getattr(g, "tags", None)}
        for g in client.network_security_groups.list_all()
    ]

    if only_ours:
        found = [g for g in found if is_managed(g["tags"])]

    return found


def _locate(client, name):
    """The resource group a named group lives in. Returns (group, short_name).

    Accepts a bare name or a full resource id, like every other reader here.
    Returns (None, short) when there is no such group, which callers turn into
    a 404 or a refusal.
    """
    group = resource_group_of(name)
    short = name.split("/")[-1] if group else name

    if group:
        return group, short

    for candidate in list_nsgs(client):
        if candidate["name"] == short:
            return candidate["resource_group"], short

    return None, short


def read_nsg_for_scanning(client, name):
    """One group's rules, flattened for the scanner.

    Accepts either the bare name or the full Azure resource id, because the
    registry's identifier is a single string and both are things a person
    might paste. Returns None when there is no such group, which the routes
    turn into a 404 - the same contract every AWS reader here follows.
    """
    group, short = _locate(client, name)
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


# The lowest priority Azure accepts, and the band this tool writes in.
#
# 100 upwards, ten apart. The gap is the point: a rule inserted later to sit
# in front of an existing one needs somewhere to go, and consecutive
# priorities leave nowhere without renumbering the whole set. Azure reserves
# 65000 and above for its own three defaults per direction.
FIRST_PRIORITY = 100
PRIORITY_STEP = 10
MAX_PRIORITY = 4096


def _priorities_for(rules):
    """A priority per rule, in the order given. Returns (priorities, error).

    Assigned here rather than accepted from the caller, and that is the whole
    reason creating a group is now possible at all. A caller supplying
    priorities can supply two rules with the same one - which Azure rejects -
    or an ordering whose effect is not the one the list reads as, which Azure
    accepts and nobody notices. The list order is the precedence, which is the
    only arrangement where what somebody typed and what Azure does are the same
    thing.

    A caller who has genuinely thought about priorities can still say so: an
    explicit priority on a rule is kept. Mixing the two is refused rather than
    resolved, because "these three are automatic and this one is 400" has an
    answer only if somebody decides what it is, and guessing produces exactly
    the silent misordering this function exists to prevent.
    """
    given = [r for r in rules if r.get("priority") is not None]

    if given and len(given) != len(rules):
        return None, (
            "Some rules name a priority and some do not. Priority decides "
            "which of two overlapping rules wins, so a set that is half "
            "ordered by hand and half ordered by this tool has no ordering "
            "anybody stated. Give a priority for every rule, or for none and "
            "let the list order decide."
        )

    if given:
        seen = {}
        for rule in rules:
            priority = rule["priority"]
            try:
                priority = int(priority)
            except (TypeError, ValueError):
                return None, (
                    f"'{rule.get('name')}' has a priority of {priority!r}, "
                    f"which is not a number. Azure wants {FIRST_PRIORITY} to "
                    f"{MAX_PRIORITY}."
                )
            if not FIRST_PRIORITY <= priority <= MAX_PRIORITY:
                return None, (
                    f"'{rule.get('name')}' has priority {priority}. Azure "
                    f"accepts {FIRST_PRIORITY} to {MAX_PRIORITY} for rules "
                    "somebody wrote; everything above is reserved for its own "
                    "defaults."
                )
            key = (str(rule.get("direction", "Inbound")).lower(), priority)
            if key in seen:
                return None, (
                    f"'{rule.get('name')}' and '{seen[key]}' both have "
                    f"priority {priority} in the same direction. Azure "
                    "requires them to be unique, because two rules at the "
                    "same priority have no defined winner."
                )
            seen[key] = rule.get("name")
        return [int(r["priority"]) for r in rules], None

    highest = FIRST_PRIORITY + PRIORITY_STEP * (len(rules) - 1)
    if rules and highest > MAX_PRIORITY:
        return None, (
            f"{len(rules)} rules do not fit between {FIRST_PRIORITY} and "
            f"{MAX_PRIORITY} at {PRIORITY_STEP} apart. Give priorities "
            "explicitly if you need this many."
        )

    return [FIRST_PRIORITY + PRIORITY_STEP * i for i in range(len(rules))], None


def _rule_body(rule, priority):
    """One rule as the request body wants it.

    camelCase, because this dict is serialized as written rather than mapped
    from a model - the same lesson `az/keyvault.py` paid for. Every field is
    stated including the ones whose Azure default is already what is wanted,
    for the reason `assign_public_ip` taught the AWS half: an absent setting is
    not a safe setting, it is the platform's setting.
    """
    return {
        "name": rule.get("name"),
        "properties": {
            "protocol": rule.get("protocol", "Tcp"),
            "sourcePortRange": rule.get("source_port_range", "*"),
            "destinationPortRange": rule.get("destination_port_range", "*"),
            "sourceAddressPrefix": rule.get("source_address_prefix", "*"),
            "destinationAddressPrefix": rule.get(
                "destination_address_prefix", "*"),
            "access": rule.get("access", "Allow"),
            "direction": rule.get("direction", "Inbound"),
            "priority": priority,
        },
    }


def create_nsg(client, name, resource_group, location="eastus", rules=None):
    """Creates one network security group. Returns (ok, id_or_error, problems).

    The last Azure capability that lived only in the root app, and the thing
    keeping it alive. `azure_crud.create_network_security_group` is the version
    this replaces; three things are different and each one is a hazard that
    version has:

    **It refuses a name that already exists.** `begin_create_or_update` on a
    group you already own *replaces its entire rule list* with whatever was
    sent, silently, and reports success. The root app does exactly this, so
    creating a group with a name somebody else used deletes their firewall.
    `_name_is_taken` asks first - the same guard `az/storage.py` states for
    accounts, and the reason given there applies far more sharply here.

    **Priorities are assigned from the list order.** The root app numbers rules
    `100 + index` regardless of what the caller asked for, so a caller who
    supplied priorities gets different ones and never hears about it. See
    `_priorities_for`.

    **There is no `secure_by_default` switch, and that is not an omission.**
    Storage accounts and vaults have one because their safety is a handful of
    booleans with a right answer. A security group's safety *is* its rule list;
    there is no second setting to harden and no safe default that is also
    useful, since the safe default is no rules at all. The pre-creation
    judgement still happens, in the place it happens for every other type:
    `POST /resources/azure-nsg` runs `check_nsg_spec` and refuses on anything
    critical unless `accept_risk` is set. What the form said before creation is
    what the scanner says after it, which is the contract that matters, and
    here it is kept by both reading the same rules rather than by both reading
    the same switch.
    """
    problems = []
    rules = list(rules or [])

    legal, why_not = names.check("azure-nsg", name)
    if not legal:
        return False, why_not, problems

    legal, why_not = names.check("resource-group", resource_group)
    if not legal:
        return False, why_not, problems

    priorities, error = _priorities_for(rules)
    if error:
        return False, error, problems

    taken, why_not = _name_is_taken(client, name, resource_group)
    if taken:
        return False, why_not, problems

    created, note = ensure_resource_group(resource_group, location)
    if created:
        problems.append(note)

    body = {
        "location": location,
        "tags": managed_tags(),
        "properties": {
            "securityRules": [_rule_body(rule, priority)
                              for rule, priority in zip(rules, priorities)],
        },
    }

    made = client.network_security_groups.begin_create_or_update(
        resource_group, name, body).result()

    if not rules:
        problems.append(
            f"'{name}' was created with no rules of its own. Azure's own final "
            "rule denies all inbound traffic from outside, so this group "
            "currently allows nothing in - which is safe, and is probably not "
            "what you want yet."
        )

    return True, made.id, problems


def _name_is_taken(client, name, resource_group):
    """Whether a group of this name already exists. Returns (taken, why).

    Scoped to the resource group, because that is where Azure enforces
    uniqueness for a network security group - unlike a storage account or a
    vault, whose names are global to all of Azure. Two groups called `web` in
    two resource groups are two different groups and both are legal.
    """
    try:
        client.network_security_groups.get(resource_group, name)
    except Exception as e:
        if getattr(e, "status_code", None) == 404:
            return False, None
        raise

    return True, (
        f"A network security group called '{name}' already exists in "
        f"'{resource_group}'. Creating it again would replace its entire rule "
        "list with the one submitted here, and Azure would report that as "
        "success - so this refuses instead. Scan it to see what it currently "
        "allows, or choose another name."
    )


def delete_nsg(client, name, force=False):
    """Deletes one group. Returns (ok, message).

    Refuses without force, like every other Azure delete here, and for a reason
    specific to this type: a group still attached to a machine or a subnet
    cannot be deleted at all, and one that *can* be deleted is one nothing is
    relying on for its firewall. The dangerous case is the third - a group
    attached to something that is about to stop being protected by it.
    """
    group, short = _locate(client, name)

    if not force:
        return False, (
            f"Not deleted. Removing '{short}' takes away the firewall rules "
            "protecting whatever it is attached to, and Azure will not warn "
            "the machines behind it. Ask for it explicitly, with the group's "
            "id repeated back."
        )

    if not group:
        return False, (
            f"No network security group named '{short}' in this subscription."
        )

    client.network_security_groups.begin_delete(group, short).result()
    return True, f"Deleted network security group '{short}'."


def cleanup_all_managed_nsgs(client, force=False):
    """Deletes every group carrying this tool's tag. Returns [(id, ok, msg)].

    Bounded by the tag and not by who ran it, exactly as the storage and vault
    cleanups are.
    """
    return [
        (found["id"],) + delete_nsg(client, found["id"], force=force)
        for found in list_nsgs(client, only_ours=True)
    ]


def plan_deletion(client, name):
    """What a delete would take with it. Returns the route's preview shape.

    This type has one where storage and vaults do not, and the difference is
    that a group's blast radius is *outside* it: deleting a storage account
    destroys what is inside the account, which is why no preview can be honest
    about it, while deleting a security group destroys nothing and exposes
    everything attached to it. That list is knowable, and it is exactly what
    somebody about to press the button needs.
    """
    settings = read_nsg_for_scanning(client, name)
    if settings is None:
        return None

    attached = settings.get("attached_to") or []
    return {
        "items": [{"id": a, "type": "protected by this group"} for a in attached],
        "destroys": {"network interfaces or subnets left unprotected":
                     len(attached)},
        "message": (
            f"Deleting this group destroys nothing, and removes the firewall "
            f"from {len(attached)} thing(s) that are using it. They keep "
            "running; they stop being filtered."
            if attached else
            "This group is attached to nothing, so deleting it changes what "
            "no traffic reaches."
        ),
    }


def apply_fix(client, name, warning):
    """Narrows one rule so it no longer opens a door to the whole internet.

    The reason this used to refuse was real and is now answered: an Azure rule
    carries a priority deciding which of several overlapping rules wins, so
    changing one in isolation could be undone by another the tool never looked
    at. `scanner/azure_nsg_effective.py` reads the whole ordered set, which is
    what makes a change here something that can be judged rather than guessed.

    **What it does is set the rule's access to Deny, not delete it.** Three
    options were available and this is the least destructive of them. Deleting
    the rule loses what somebody wrote. Narrowing the source needs an address
    the finding does not carry - `POST /fix` takes a rule id and nothing else,
    deliberately, so that the API is not a remote "change this firewall to
    whatever I say" endpoint. Flipping access leaves the rule, its name, its
    ports and its priority exactly where they were, so what was intended is
    still legible and re-opening it is one field in the portal.

    The effect is checked before it is applied: if the rule is already shadowed
    it is not touched, because the fix would change nothing and reporting
    success would be a lie.
    """
    group, short = _locate(client, name)
    if not group:
        return False, (
            f"No network security group named '{short}' in this subscription."
        )

    rule_name = (warning or {}).get("rule", {}).get("rule_name")
    if not rule_name:
        return False, (
            "That finding does not name a rule, so there is nothing to narrow. "
            "Findings about the group as a whole are not fixable here."
        )

    try:
        found = client.network_security_groups.get(group, short)
    except Exception as e:
        if getattr(e, "status_code", None) == 404:
            return False, f"No network security group named '{short}'."
        raise

    target = None
    for rule in found.security_rules or []:
        if rule.name == rule_name:
            target = rule
            break

    if target is None:
        return False, (
            f"'{short}' has no rule called '{rule_name}' any more. It may have "
            "been changed since this finding was produced; scan it again."
        )

    if str(plain(getattr(target, "access", "")) or "").lower() == "deny":
        return False, (
            f"'{rule_name}' already denies. Nothing was changed."
        )

    client.security_rules.begin_create_or_update(
        group, short, rule_name,
        {"properties": {
            "protocol": plain(target.protocol),
            "sourcePortRange": plain(target.source_port_range) or "*",
            "destinationPortRange": plain(target.destination_port_range) or "*",
            "sourceAddressPrefix": plain(target.source_address_prefix) or "*",
            "destinationAddressPrefix": plain(
                target.destination_address_prefix) or "*",
            "access": "Deny",
            "direction": plain(target.direction),
            "priority": target.priority,
        }}).result()

    return True, (
        f"'{rule_name}' on '{short}' now denies instead of allowing. The rule "
        "is otherwise untouched - same ports, same priority, same name - so "
        "what it was for is still readable and re-opening it to particular "
        "addresses is one field. Anything currently connected through it will "
        "stop."
    )
