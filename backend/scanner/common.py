"""Shared warning contract for all resource scanners.

Every scanner in this package returns the same warning shape regardless of what
cloud resource it inspects. This is the boundary that keeps the rule logic
portable: a firewall rule and a storage bucket have nothing in common, but a
warning about either looks identical to the caller.

No cloud SDK imports belong in this file, or in anything that imports it.
"""

from scanner.controls import control as _control

CRITICAL = "critical"
WARNING = "warning"
INFO = "info"

_ORDER = {CRITICAL: 0, WARNING: 1, INFO: 2}


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
    """Aggregates warning totals by severity level."""
    counts = {CRITICAL: 0, WARNING: 0, INFO: 0}
    for w in warnings:
        counts[w["level"]] = counts.get(w["level"], 0) + 1
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
