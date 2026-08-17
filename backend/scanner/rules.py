"""Security rules engine for evaluating firewall settings.

Contains pure Python evaluation logic with no external AWS dependencies.
"""

import ipaddress

from scanner.common import (
    CRITICAL,
    WARNING,
    INFO,
    warning as _warning,
    summarize,
    fixable,
    worst_level,
    print_warnings,
    open_to_strangers,
)

OPEN_TO_WORLD_V4 = "0.0.0.0/0"
OPEN_TO_WORLD_V6 = "::/0"

# Kept because the create form offers these two as menu entries and the
# registry imports them for it. Judging a rule no longer goes through this set
# - see common.open_to_strangers - because a set of two literals is a check
# somebody can write their way around.
OPEN_SOURCES = {OPEN_TO_WORLD_V4, OPEN_TO_WORLD_V6}


def _is_ipv6(source):
    """Whether a source is written as an IPv6 range, for the CIS citation.

    The two administration-port controls are numbered separately for v4 and v6,
    so this decides which one a finding cites rather than whether there is a
    finding at all.
    """
    try:
        return ipaddress.ip_network(str(source).strip(), strict=False).version == 6
    except ValueError:
        return False

RISKY_PORTS = {
    22: "SSH, the remote login door for Linux servers",
    3389: "Remote Desktop, the remote login door for Windows servers",
    3306: "a MySQL database",
    5432: "a PostgreSQL database",
    27017: "a MongoDB database",
    6379: "a Redis data store",
    9200: "an Elasticsearch search engine",
    5900: "VNC, a remote screen-sharing service",
}


def _admin_port_control(is_ipv6):
    """CIS splits the remote-administration-port control by address family."""
    return "SG_ADMIN_PORTS_V6" if is_ipv6 else "SG_ADMIN_PORTS_V4"


ADMIN_PORTS = {22, 3389}


def _check_outbound(rule, reach):
    """Evaluates one outbound rule.

    Unrestricted outbound is the AWS default on every new security group, so
    flagging it as a problem would put a warning on essentially every group in
    existence and train people to ignore the tool. It is reported as context
    instead: it matters for what an attacker can send outward once inside, and
    no published benchmark here requires restricting it.
    """
    wide, _ = open_to_strangers(rule.get("source"))
    if not wide:
        return None

    if rule.get("protocol") == "-1":
        return _warning(
            INFO,
            f"Anything on this machine can reach {reach} on any port. This is "
            "the default for a new security group, not something that was "
            "switched on. It matters if something hostile gets in: it is the "
            "path data would leave by. Restricting it takes real planning, so "
            "treat this as context rather than a fault.",
            rule,
        )

    return None


def check_firewall_rules(rules):
    """Evaluates rules list and returns detected security risks."""
    warnings = []

    for rule in rules:
        source = rule.get("source", "")
        protocol = rule.get("protocol", "tcp")
        start = rule.get("from_port")
        end = rule.get("to_port")
        # Not string equality against "0.0.0.0/0" any more. See
        # common.open_to_strangers: two rules saying 0.0.0.0/1 and 128.0.0.0/1
        # cover every address on the internet and this reported nothing at all
        # about either of them.
        is_public, reach = open_to_strangers(source)
        is_ipv6 = _is_ipv6(source)

        if rule.get("direction") == "outbound":
            outbound = _check_outbound(rule, reach)
            if outbound:
                warnings.append(outbound)
            continue

        if not is_public:
            # A rule sourced from another security group, on a port people
            # expect to see flagged. Everything else non-public passes in
            # silence, which is right: there is nothing to say about port 443
            # from a private range.
            #
            # This one gets said out loud because its absence is confusing. An
            # auditor looking for "who can reach SSH here" needs to see that
            # the answer is "whatever is in that group" rather than an empty
            # result they have to interpret. It is also the correct pattern,
            # and a tool that only ever reports faults teaches people that
            # silence is the best outcome available.
            if (source.startswith("sg:")
                    and start is not None and end is not None
                    and any(start <= p <= end for p in ADMIN_PORTS)):
                group = source[3:]
                port = next(p for p in ADMIN_PORTS if start <= p <= end)
                warnings.append(_warning(
                    INFO,
                    f"Port {port} is reachable only from the security group "
                    f"{group}, not from any address. This is the stronger "
                    "arrangement: it keeps working if that machine's address "
                    "changes, and nothing else can gain entry by arriving from "
                    "the right address. Whatever is in that group can reach "
                    "this port, so that group is worth checking too.",
                    rule,
                ))
            continue

        if protocol == "-1":
            warnings.append(_warning(
                CRITICAL,
                f"This opens every port to {reach}. Anyone anywhere can reach "
                "any service on this machine.",
                rule,
                fix={"action": "remove", "label": "Remove this rule"},
                control=_admin_port_control(is_ipv6),
            ))
            continue

        if start is not None and end is not None and (end - start) > 100:
            covers_admin = any(start <= p <= end for p in ADMIN_PORTS)
            warnings.append(_warning(
                CRITICAL,
                f"Ports {start} through {end} are open to {reach}. "
                "That is a very wide opening.",
                rule,
                fix={"action": "remove", "label": "Remove this rule"},
                control=_admin_port_control(is_ipv6) if covers_admin else None,
            ))
            continue

        matched_risky = False
        for port, description in RISKY_PORTS.items():
            if start is not None and end is not None and start <= port <= end:
                matched_risky = True
                warnings.append(_warning(
                    CRITICAL,
                    f"Port {port} ({description}) is reachable from {reach}. "
                    "Anyone can try to log in. Limit this to your own address.",
                    rule,
                    fix={
                        "action": "narrow_to_my_ip",
                        "label": "Limit this to my current IP address",
                    },
                    # Only 22 and 3389 are the remote administration ports the
                    # benchmark names. The databases below are just as bad to
                    # expose, but citing CIS for them would be a fabrication.
                    control=(_admin_port_control(is_ipv6)
                             if port in ADMIN_PORTS else None),
                ))

        if matched_risky:
            continue

        if start == 80 and end == 80:
            warnings.append(_warning(
                INFO,
                "Port 80 carries unencrypted web traffic. Open to everyone is "
                "normal for a public site, but use port 443 for anything with a login.",
                rule,
            ))
        elif start == 443 and end == 443:
            continue
        else:
            # A rule can arrive with no ports on it - an ICMP rule, or one the
            # reader could not flatten. "Port None is open to the entire
            # internet" is what that used to render as, which reads as a bug
            # rather than as a finding and tells nobody anything.
            opening = (f"Port {start}" if start is not None
                       else "This rule names no port range, so everything it "
                            "covers")
            warnings.append(_warning(
                WARNING,
                f"{opening} is open to {reach}. Confirm this service is meant "
                "to be public.",
                rule,
                fix={
                    "action": "narrow_to_my_ip",
                    "label": "Limit this to my current IP address",
                },
            ))

    return warnings


def check_default_group(group, rules):
    """Flags a VPC's default security group that still carries rules. CIS 5.5.

    The default group matters more than its obscurity suggests: anything
    launched without a group named explicitly lands in it. So a rule left here
    applies to resources nobody deliberately put here, which is the opposite of
    how people assume security groups work.

    The remedy is to strip its rules, not to delete it. AWS will not allow the
    default group to be deleted, which is why check_group_usage skips it.
    """
    if not group.get("is_default"):
        return []

    inbound = [r for r in rules if r.get("direction") != "outbound"]
    outbound = [r for r in rules if r.get("direction") == "outbound"]

    if not inbound and not outbound:
        return []

    group_id = group.get("group_id")
    parts = []
    if inbound:
        parts.append(f"{len(inbound)} inbound")
    if outbound:
        parts.append(f"{len(outbound)} outbound")

    return [_warning(
        WARNING,
        f"The default security group for this network still has "
        f"{' and '.join(parts)} rule(s) on it. Anything launched without a "
        "security group chosen for it lands here automatically, so these rules "
        "will apply to resources nobody meant to put here. Best practice is to "
        "strip it to nothing and use named groups instead. It cannot be "
        "deleted, only emptied.",
        {"rule_id": f"{group_id}:default_group_rules", "resource_id": group_id},
        control="DEFAULT_SG_RESTRICTS_ALL",
    )]


def check_group_usage(group):
    """Flags a security group that nothing is attached to.

    Expects {"group_id", "group_name", "in_use": bool, "is_default": bool}.

    An unattached group is not itself reachable, so this is not urgent. It
    matters because dead configuration is where stale wide-open rules survive
    unnoticed: nobody audits a group they believe is unused, and nobody notices
    when it is attached to something months later.

    The default group of a VPC is skipped. It cannot be deleted, so reporting
    it as unused would be a permanent warning with no available action;
    check_default_group covers what can actually be done about it.
    """
    if group.get("is_default") or group.get("in_use", True):
        return []

    group_id = group.get("group_id")
    name = group.get("group_name") or group_id

    return [_warning(
        INFO,
        f"Nothing is using the security group '{name}'. Rules in an unused "
        "group do not protect or expose anything today, but they are easy to "
        "forget and they apply the moment something is attached. Delete it if "
        "it is finished with.",
        {"rule_id": f"{group_id}:unused", "resource_id": group_id},
        control="UNUSED_SECURITY_GROUPS",
    )]
