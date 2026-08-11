"""Security rules for evaluating Azure network security groups.

Contains pure Python evaluation logic with no external cloud dependencies.

This is the first rule set here that is not about AWS, and it exists to settle a
claim `scanner/common.py` has made since the first commit: that its warning
shape is provider-agnostic. That was an assertion with no evidence behind it
while every scanner in this package read the same one cloud. It is now a
statement this file either supports or refutes, and nothing in
`scanner/common.py` had to change to accommodate it.

Ported from `azure_scanner.check_nsg_ssh_rule` on `group/main`, which was
correct and returned a different shape: a dictionary of title, severity,
description, impact and remediation, aimed at being rendered on its own. The
rewrite is not a criticism of it. Two scanners returning two shapes is fine
until something has to count both, and `api/app.py` counts.

The judgement is deliberately identical to the AWS firewall rules next door. A
port open to the whole internet is the same fact whoever is hosting it, and if
this file disagreed with `scanner/rules.py` about what that means, one of them
would be wrong.
"""

from scanner import azure_nsg_effective as effective
from scanner.common import (
    CRITICAL,
    WARNING,
    INFO,
    warning as _warning,
    summarize,
    fixable,
    cited,
    worst_level,
    print_warnings,
)

# What Azure writes where AWS writes 0.0.0.0/0. "*" and "Internet" are Azure's
# own service tags; the CIDR appears when somebody has typed it by hand.
OPEN_TO_EVERYONE = {"*", "0.0.0.0/0", "internet", "::/0"}

# The ports this reports on, and what they are for. Deliberately the same list
# and the same words as the AWS side: a reader who has seen one finding should
# not have to learn a second vocabulary for the other cloud.
ADMIN_PORTS = {
    "22": "SSH, the remote login door for Linux servers",
    "3389": "RDP, the remote desktop door for Windows servers",
}


def _target(nsg_name, setting, rule_name=None):
    suffix = f"{rule_name}:{setting}" if rule_name else setting
    return {
        "rule_id": f"{nsg_name}:{suffix}",
        "resource_id": nsg_name,
        "setting": setting,
        "rule_name": rule_name,
    }


def _is_open_to_everyone(source):
    return str(source or "").strip().lower() in OPEN_TO_EVERYONE


def _ports_covered(destination_port_range):
    """Which administration ports a rule's destination range lets through.

    Azure writes a single port, a range like "1000-2000", or "*" for all of
    them. A range is expanded only far enough to answer the question being
    asked, because the question is never "how many ports" but "is one of these
    two among them".
    """
    text = str(destination_port_range or "").strip()

    if text == "*":
        return list(ADMIN_PORTS)

    if "-" in text:
        try:
            low, high = (int(part) for part in text.split("-", 1))
        except ValueError:
            return []
        return [port for port in ADMIN_PORTS if low <= int(port) <= high]

    return [port for port in ADMIN_PORTS if port == text]


def check_nsg(settings):
    """Evaluates one network security group and returns detected risks.

    Expects the shape produced by az.nsg.read_nsg_for_scanning():
        {
          "nsg_name": str,
          "resource_group": str,
          "location": str,
          "rules": [{"name", "direction", "access", "protocol",
                     "source_address_prefix", "destination_port_range",
                     "priority"}],
          "attached_to": [str],
        }
    """
    if not settings:
        return []

    name = settings.get("nsg_name", "this security group")
    rules = settings.get("rules") or []
    warnings = []

    for index, rule in enumerate(rules):
        rule_name = rule.get("name") or f"rule {index + 1}"

        if str(rule.get("direction", "")).lower() != "inbound":
            continue
        if str(rule.get("access", "")).lower() != "allow":
            continue
        if not _is_open_to_everyone(rule.get("source_address_prefix")):
            continue

        for port in _ports_covered(rule.get("destination_port_range")):
            # An Allow sitting behind a Deny at a lower priority never applies,
            # and calling it an exposure is how a scanner teaches people to
            # skim past it. Azure decides by priority, lowest first, and stops
            # at the first match - so the whole ordered set has to be read
            # before any one rule can be judged. That sentence was the reason
            # this file was per-rule and the reason az/nsg.py was read-only;
            # scanner/azure_nsg_effective.py is where it is now answered.
            blocker = effective.shadowed_by(rules, rule, port)
            if blocker:
                warnings.append(_warning(
                    INFO,
                    f"'{rule_name}' on '{name}' would open port {port} "
                    f"({ADMIN_PORTS[port]}) to the entire internet, but it "
                    f"never takes effect: '{blocker.get('name')}' denies the "
                    f"same traffic at priority {blocker.get('priority')}, and "
                    "Azure stops at the first rule that matches. This is worth "
                    "knowing rather than acting on - the rule is one priority "
                    "change away from being live.",
                    _target(name, f"shadowed_open_{port}", rule_name),
                ))
                continue

            warnings.append(_warning(
                CRITICAL,
                f"Port {port} ({ADMIN_PORTS[port]}) is reachable from the "
                f"entire internet on '{name}', through the rule "
                f"'{rule_name}'. Anyone can try to log in. Limit this to the "
                "addresses that genuinely need it.",
                _target(name, f"open_{port}", rule_name),
                # Sets the rule to Deny rather than narrowing it, because
                # narrowing needs an address this finding does not carry and
                # `POST /fix` deliberately accepts nothing from the caller.
                # See az/nsg.apply_fix.
                fix={
                    "action": "deny_rule",
                    "label": f"Close port {port} by denying this rule",
                },
            ))

        # A rule opening everything is worth saying separately. The loop above
        # reports the two doors it knows the names of; this is the fact that
        # every other door is open too, which is a different sentence.
        if str(rule.get("destination_port_range", "")).strip() == "*":
            # Judged on port 22 as the representative: a rule covering every
            # port is shadowed for "everything" only if it is shadowed for the
            # doors that matter, and a Deny narrower than the Allow leaves the
            # rest of the range open.
            if not effective.shadowed_by(rules, rule, "22"):
                warnings.append(_warning(
                    CRITICAL,
                    f"'{rule_name}' on '{name}' allows the entire internet to "
                    "reach every port, not only the well-known ones. Anything "
                    "listening on this machine is reachable, including things "
                    "nobody meant to expose and things installed later.",
                    _target(name, "open_all_ports", rule_name),
                    fix={
                        "action": "deny_rule",
                        "label": "Close every port by denying this rule",
                    },
                ))

    # ---- Whether the group is doing anything at all --------------------------
    if not settings.get("attached_to"):
        warnings.append(_warning(
            INFO,
            f"'{name}' is not attached to any network or machine, so none of "
            "its rules apply to anything. An unused security group is not "
            "dangerous, but it is one somebody may attach later while trusting "
            "rules nobody has looked at since.",
            _target(name, "unused"),
        ))

    return warnings


def check_nsg_spec(spec):
    """Scans rules typed into a form, before the group exists.

    Same judgement, no rule names from Azure yet, and therefore no fix: the
    remedy for a bad rule in a form is to change the form.
    """
    if not spec:
        return []

    return check_nsg({
        "nsg_name": spec.get("name") or "this security group",
        # azure_rules, not rules: the AWS field carries a different shape and
        # a form submitting one is not describing the other.
        "rules": spec.get("azure_rules") or [],
        # Nothing can be attached to a group that does not exist, and saying
        # so before creation would be reporting the obvious.
        "attached_to": ["pending"],
    })
