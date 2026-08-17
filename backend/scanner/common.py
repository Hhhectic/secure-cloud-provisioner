"""Shared warning contract for all resource scanners.

Every scanner in this package returns the same warning shape regardless of what
cloud resource it inspects. This is the boundary that keeps the rule logic
portable: a firewall rule and a storage bucket have nothing in common, but a
warning about either looks identical to the caller.

No cloud SDK imports belong in this file, or in anything that imports it.
"""

import ipaddress

from scanner.controls import control as _control

CRITICAL = "critical"
WARNING = "warning"
INFO = "info"

_ORDER = {CRITICAL: 0, WARNING: 1, INFO: 2}

# What Azure writes instead of a range. AWS has no equivalent; a security group
# source is always a CIDR or another group.
EVERYONE_TAGS = {"*", "any", "internet"}

# How much public address space stops being an allowlist and starts being a
# region of the internet.
#
# Both clouds decided this by string equality against "0.0.0.0/0" and "::/0"
# until now, and that is exactly the shape of check somebody puts a backdoor
# around: `0.0.0.0/1` and `128.0.0.0/1` are two rules covering every address
# there is, and both were silent, on both clouds. So were `0.0.0.0/4` and
# `::/1`. Azure was worse than silent - its evaluator answered DenyByDefault
# about a port it would in fact have allowed from two billion hosts.
#
# A /16 is 65,536 addresses. A real allowlist is an office, a VPN endpoint or
# one machine, which is a /24 or smaller in practice; nothing legitimately
# permits SSH from sixty-five thousand arbitrary public hosts, and anything
# larger is not a list of chosen machines. Somebody who genuinely means it can
# acknowledge the finding - that mechanism exists precisely so this file does
# not have to guess at intent.
#
# IPv6 is set at /32 because the scales do not correspond: a site is given a
# /48 and an internet provider a /32, so /32 is "an entire provider" and /48 is
# "one organisation".
BROAD_PREFIX_V4 = 16
BROAD_PREFIX_V6 = 32


def open_to_strangers(source):
    """Whether a rule's source lets in hosts nobody chose. (open, description).

    `description` is the phrase the scanners put in a finding, and is None when
    open is False.

    Private, reserved, loopback, carrier-grade-NAT and documentation ranges are
    never open however large: 10.0.0.0/8 is sixteen million addresses and not
    one of them is a stranger. Python's `is_global` draws that line and draws
    it in one place, which is better than this module keeping its own list of
    what RFC1918 says.

    Anything that will not parse is not open. That keeps the property
    azure_nsg_effective states for itself - it can never manufacture an Allow
    the cloud would not make - and it is what leaves `sg:sg-1234` and any Azure
    service tag this does not know to the callers that handle them.
    """
    text = str(source or "").strip()
    if not text:
        return False, None

    if text.lower() in EVERYONE_TAGS:
        return True, "the entire internet"

    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return False, None

    if not network.is_global:
        return False, None

    limit = BROAD_PREFIX_V6 if network.version == 6 else BROAD_PREFIX_V4
    if network.prefixlen > limit:
        return False, None

    if network.prefixlen == 0:
        return True, ("the entire internet (over IPv6)" if network.version == 6
                      else "the entire internet")

    # Named rather than called "the internet", because it is not, and a person
    # checking this against their own firewall needs to recognise what they
    # wrote. The count is what makes the point: nobody reads /12 as a million.
    return True, f"{network.with_prefixlen} — {network.num_addresses:,} addresses"


def warning(level, message, rule=None, fix=None, resource_id=None, control=None):
    """Constructs a standard warning payload.

    Args:
        level: One of CRITICAL, WARNING, INFO.
        message: Plain-language explanation aimed at a non-expert.
        rule: The underlying resource detail this warning points at. For a
            firewall this is one ingress rule; for a bucket it is the settings
            snapshot. Must carry a "rule_id" key for the warning to be fixable.
        fix: Optional {"action": str, "label": str} describing a remediation
            the tool can perform on the user's behalf.
        resource_id: The security group ID or bucket name this belongs to.
        control: Symbolic name from scanner.controls, where the finding maps to
            a published recommendation. Left None where it does not; an empty
            citation is better than a fabricated one.
    """
    found = _control(control) if control else None

    return {
        "level": level,
        "message": message,
        "rule_id": (rule or {}).get("rule_id"),
        "resource_id": resource_id or (rule or {}).get("resource_id"),
        "rule": rule,
        "fix": fix,
        "control": found.to_dict() if found else None,
    }


def summarize(warnings):
    """Aggregates warning totals by severity level.

    "acknowledged" counts findings somebody has decided to live with. It sits
    alongside the severities rather than being subtracted from them: an
    acknowledged critical is still a critical, and a tally that quietly
    excluded it would be the thing scanner/acknowledged.py exists to avoid.

    "accepted" is the same total broken down by severity, and exists because
    the flat one could not be rendered without ambiguity. "2 critical, 2
    warning, 3 accepted" reads as seven findings, and does not say which three
    were accepted - so a reader cannot tell whether anything is outstanding
    without opening the type. Both are kept: the flat count is what the detail
    panel's fourth tally shows, and the breakdown is what lets a summary say
    which severities are spoken for.
    """
    counts = {CRITICAL: 0, WARNING: 0, INFO: 0, "acknowledged": 0,
              "accepted": {CRITICAL: 0, WARNING: 0, INFO: 0}}
    for w in warnings:
        level = w["level"]
        counts[level] = counts.get(level, 0) + 1
        if w.get("acknowledged"):
            counts["acknowledged"] += 1
            counts["accepted"][level] = counts["accepted"].get(level, 0) + 1
    return counts


def fixable(warnings):
    """Filters warnings that carry enough metadata to act on."""
    return [w for w in warnings if w.get("fix") and w.get("rule_id")]


def worst_level(warnings):
    """Returns the highest severity present, or None for a clean result."""
    if not warnings:
        return None
    return min((w["level"] for w in warnings), key=lambda lv: _ORDER.get(lv, 99))


def cited(warnings):
    """Filters warnings that map to a published control."""
    return [w for w in warnings if w.get("control")]


def print_warnings(warnings):
    """Prints formatted warning messages to standard output."""
    icons = {CRITICAL: "[!]", WARNING: "[~]", INFO: "[i]"}
    if not warnings:
        print("[ok] No known problems found.")
        return
    for w in warnings:
        print(icons.get(w["level"], "[?]"), w["message"])
        if w.get("control"):
            c = w["control"]
            print(f"      {c['framework']} v{c['version']} §{c['id']} "
                  f"(Level {c['level']})")
        if w.get("fix") and w.get("rule_id"):
            print("      -> can fix:", w["fix"]["label"], f"({w['rule_id']})")
        elif w.get("fix"):
            # No rule_id means this does not exist yet: settings typed into a
            # form, scanned before anything was created. Offering to fix it
            # would be offering to repair something that has not been built,
            # and the earlier version printed the label followed by "(None)".
            # The remedy at this stage is to go back and change the answer.
            print("      -> change this before creating it, or accept it "
                  "knowingly")
