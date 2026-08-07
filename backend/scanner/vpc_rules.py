"""Security rules for evaluating VPC network layout.

Contains pure Python evaluation logic with no external AWS dependencies.

The central idea here is that a subnet's name is not evidence. A subnet called
"private" that has a route to an internet gateway is a public subnet with a
misleading label, and the label is worse than no label: it is what someone
reads when deciding where to put a database. Every rule below judges the
routing, and uses the name only to notice when the two disagree.
"""

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

PRIVATE_NAMES = ("private", "internal", "backend", "data", "db")


def _target(vpc_id, setting, subnet_id=None):
    suffix = f"{subnet_id}:{setting}" if subnet_id else setting
    return {
        "rule_id": f"{vpc_id}:{suffix}",
        "resource_id": vpc_id,
        "setting": setting,
    }


def _looks_private(subnet):
    """Whether this subnet is described as private, by tag or by name."""
    if subnet.get("declared_role") == "private":
        return True
    name = (subnet.get("name") or "").lower()
    return any(word in name for word in PRIVATE_NAMES)


def check_vpc(settings):
    """Evaluates one VPC's layout and returns detected risks.

    Expects the shape produced by aws.vpcs.read_vpc_for_scanning().
    """
    if not settings:
        return []

    vpc_id = settings.get("vpc_id", "unknown")
    name = settings.get("name") or vpc_id
    warnings = []

    # ---- Flow logs. CIS 3.7 --------------------------------------------------
    #
    # Detect only. Turning flow logs on requires choosing somewhere to send
    # them and a role permitting the write, and both are decisions with
    # ongoing storage cost attached. A fix button that silently created a log
    # destination would be spending money on the user's behalf.
    if not settings.get("flow_logs_enabled"):
        warnings.append(_warning(
            WARNING,
            f"No record is kept of network traffic in {name}. If something "
            "goes wrong here, there will be nothing to look at afterwards: no "
            "way to tell what connected to what, or when, or whether anything "
            "left. Turning this on means choosing somewhere to store the logs "
            "and accepting the storage cost, so this tool reports it rather "
            "than deciding for you.",
            _target(vpc_id, "flow_logs"),
            control="VPC_FLOW_LOGS",
        ))

    subnets = settings.get("subnets") or []

    if not subnets:
        warnings.append(_warning(
            INFO,
            f"{name} has no subnets, so nothing can be placed in it yet.",
            _target(vpc_id, "no_subnets"),
        ))
        return warnings

    # ---- The label versus the routing ----------------------------------------
    for subnet in subnets:
        subnet_id = subnet.get("subnet_id")
        subnet_name = subnet.get("name") or subnet_id
        reaches = subnet.get("reaches_internet")

        if _looks_private(subnet) and reaches:
            warnings.append(_warning(
                CRITICAL,
                f"'{subnet_name}' is described as private but has a route to "
                "the internet. Anything placed here believing it is isolated "
                "is not: give a machine in this subnet a public address, by "
                "accident or on purpose, and it is immediately reachable from "
                "anywhere. A misleading name is worse than none, because it is "
                "what someone reads when deciding where to put a database.",
                _target(vpc_id, "private_subnet_reaches_internet", subnet_id),
            ))

        if subnet.get("auto_assign_public_ip"):
            level = CRITICAL if _looks_private(subnet) else WARNING
            warnings.append(_warning(
                level,
                f"Machines launched into '{subnet_name}' are given a public "
                "address automatically unless whoever launches them says "
                "otherwise. Anyone who does not know to say otherwise gets a "
                "machine on the open internet without choosing to.",
                _target(vpc_id, "auto_assign_public_ip", subnet_id),
            ))

        if subnet.get("using_main_route_table") and not reaches:
            warnings.append(_warning(
                INFO,
                f"'{subnet_name}' has no route table of its own and is using "
                "the network's default one. It has no way out today, but the "
                "default table is shared: a route added to it later for some "
                "other subnet's benefit would quietly give this one a way out "
                "too. A route table of its own would prevent that.",
                _target(vpc_id, "shares_main_route_table", subnet_id),
            ))

    # ---- Whether there is any private space at all ---------------------------
    if subnets and all(s.get("reaches_internet") for s in subnets):
        warnings.append(_warning(
            INFO,
            f"Every subnet in {name} can reach the internet, so there is "
            "nowhere in this network to put something that should not. That "
            "is fine for a network of public web servers and wrong for almost "
            "anything holding data.",
            _target(vpc_id, "no_private_subnet"),
        ))

    # ---- The default VPC -----------------------------------------------------
    if settings.get("is_default"):
        warnings.append(_warning(
            INFO,
            "This is the default network AWS creates in every region. Its "
            "subnets all reach the internet and hand out public addresses "
            "automatically, which makes it convenient and a poor place for "
            "anything that matters. It cannot be improved much; the answer is "
            "to build a network deliberately instead.",
            _target(vpc_id, "default_vpc"),
        ))

    return warnings
