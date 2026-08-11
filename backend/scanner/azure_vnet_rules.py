"""Security rules for evaluating Azure virtual networks.

Pure evaluation logic, no cloud calls, like every other module in this package.

The counterpart of `scanner/rules.py`'s VPC judgement, and the newest of the
Azure rule sets. What a virtual network gets judged on is narrower than what a
storage account does, and deliberately so: a network is not dangerous by
itself, it is dangerous by what it fails to put in the way. So the findings
here are about absence rather than about a setting somebody turned on.

**The finding that matters is a subnet with no security group.** Azure applies
network security groups at two places, the subnet and the network interface,
and if neither has one then nothing is filtered - every port on every machine
in that subnet is reachable from everything that can route to it. That is not
the same as being reachable from the internet, which is why this is a warning
rather than critical: a machine with no public address is still behind the
network's own boundary. But it is the condition under which one mistake
elsewhere - a public IP added later, a peering, a gateway - becomes total
rather than partial, and it is invisible in the portal unless somebody clicks
into each subnet in turn.

Nothing here carries a CIS citation, for the reason recorded in CLAUDE.md: CIS
AWS Foundations is an AWS benchmark, and the Azure one is a separate document
nobody on this project has read.
"""

from scanner.common import CRITICAL, WARNING, INFO, warning as _warning


def _target(vnet_name, setting, subnet=None):
    suffix = f"{subnet}:{setting}" if subnet else setting
    return {
        "rule_id": f"{vnet_name}:{suffix}",
        "resource_id": vnet_name,
        "setting": setting,
        "subnet_name": subnet,
    }


# Subnets Azure reserves for its own appliances. A gateway subnet is not
# allowed to carry a network security group at all - attaching one breaks the
# gateway - so reporting its absence would be reporting a rule Azure enforces
# against us.
RESERVED_SUBNETS = {
    "GatewaySubnet",
    "AzureFirewallSubnet",
    "AzureFirewallManagementSubnet",
    "AzureBastionSubnet",
    "RouteServerSubnet",
}


def check_vnet(settings):
    """Evaluates one virtual network and returns detected risks.

    Expects the shape produced by az.vnet.read_vnet_for_scanning():
        {
          "vnet_name": str,
          "resource_group": str,
          "location": str,
          "address_prefixes": [str],
          "subnets": [{"name", "address_prefix", "network_security_group",
                       "private_endpoint_network_policies"}],
          "ddos_protection_enabled": bool | None,
          "peerings": [str],
          "unreadable": {setting: why},
        }
    """
    if not settings:
        return []

    name = settings.get("vnet_name", "this virtual network")
    unreadable = settings.get("unreadable") or {}
    warnings = []

    # A skipped check is a finding, not a silence. Reported first, exactly as
    # scanner/iam_rules.py does, because a partial scan that looks clean is the
    # one way this tool can actively mislead.
    for setting, why in sorted(unreadable.items()):
        warnings.append(_warning(
            WARNING,
            f"Could not check {setting} on '{name}': {why}. This part of the "
            "audit did not run, so treat it as unanswered rather than as "
            "passed.",
            _target(name, f"unreadable_{setting}"),
        ))

    # ---- Subnets with nothing filtering them ---------------------------------
    if "subnets" not in unreadable:
        for subnet in settings.get("subnets") or []:
            subnet_name = subnet.get("name") or "an unnamed subnet"

            if subnet_name in RESERVED_SUBNETS:
                continue

            if not subnet.get("network_security_group"):
                warnings.append(_warning(
                    WARNING,
                    f"The subnet '{subnet_name}' in '{name}' has no security "
                    "group attached, so nothing filters traffic to the "
                    "machines in it at the network layer. Every port each of "
                    "them is listening on is reachable from anything that can "
                    "route to the subnet. A machine here is protected only by "
                    "a security group attached to its own network card, if it "
                    "has one, and by its own firewall - neither of which is "
                    "visible from the network's page.",
                    _target(name, "subnet_without_firewall", subnet_name),
                ))

    # ---- Distributed denial of service protection ----------------------------
    #
    # An informational note and not a warning, because the standard tier is a
    # real monthly charge and the basic protection every Azure network gets is
    # not nothing. Saying "turn this on" as a warning would be recommending a
    # bill this tool cannot see the budget for - the same restraint
    # scanner/alarm_rules.py shows about the eleventh alarm.
    if settings.get("ddos_protection_enabled") is False:
        warnings.append(_warning(
            INFO,
            f"'{name}' relies on the basic denial-of-service protection every "
            "Azure network gets, rather than the paid standard tier. That is "
            "the ordinary choice and is not a fault. The paid tier adds "
            "protection tuned to your own traffic and costs a fixed monthly "
            "amount whether or not anything attacks you.",
            _target(name, "no_ddos_protection"),
        ))

    # ---- What else this network is joined to ---------------------------------
    #
    # Not a fault, and reported because a peering is the single thing most
    # likely to make the finding above matter more than it looks: an unfiltered
    # subnet reachable from one other network is reachable from everything that
    # network is joined to.
    peerings = settings.get("peerings") or []
    if peerings:
        warnings.append(_warning(
            INFO,
            f"'{name}' is joined to {len(peerings)} other network(s): "
            f"{', '.join(peerings)}. Traffic can pass between them, so a "
            "subnet here with nothing filtering it is reachable from there "
            "too. This is worth knowing rather than fixing.",
            _target(name, "peered"),
        ))

    return warnings


def check_vnet_spec(spec):
    """Scans a virtual network form, before the network exists.

    The same judgement, over the subnets somebody has typed. `az/vnet.py`
    attaches no security group to a subnet it creates - there is nothing
    sensible to attach, since the group would have to exist first - so this
    fires on every subnet in a new network, which is correct and is the point:
    the form should say that the network it is about to build filters nothing
    until something is attached to it.
    """
    if not spec:
        return []

    return check_vnet({
        "vnet_name": spec.get("name") or "this virtual network",
        "address_prefixes": spec.get("address_prefixes") or [],
        "subnets": spec.get("subnets") or [],
        # Absent from a form, and false is what Azure gives a new network
        # unless somebody attaches a paid plan to it.
        "ddos_protection_enabled": False,
        "peerings": [],
        "unreadable": {},
    })
