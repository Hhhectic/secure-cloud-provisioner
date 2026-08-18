"""Whether anyone would be told that the subscription changed underneath them.

The Azure counterpart of scanner/alarm_rules.py, and the reasoning carries over
without modification: **an alarm fails by being quiet.** Every other rule set
here judges a resource that is dangerous while it is doing something. These
judge an absence, and an absence looks identical in the console whether nobody
has touched your firewalls or nobody is watching them.

Nothing here carries a citation. CIS AWS Foundations plainly does not reach
Azure, and the CIS Microsoft Azure Foundations Benchmark is a separate document
nobody on this project has read - inventing section numbers from it would be
the fabricated citation scanner/controls.py exists to warn about. These checks
come from Prowler's monitor block, which is not a published benchmark and is
not cited as one either.
"""

from scanner.common import WARNING, INFO, warning as _warning

# The operations worth being told about, and what each one means in words
# somebody who does not write ARM can act on.
#
# Chosen for the same property: each is a change that a person makes rarely and
# an intruder makes early. Creating a network security group rule is how an
# attacker opens a door; deleting one is how they remove the evidence that a
# door was ever shut. Policy assignments are how the rules about what may be
# built get switched off.
#
# Deliberately short. Prowler watches a longer list and the extra entries are
# mostly the delete half of pairs already here; a scanner that reports thirteen
# missing alerts on a subscription with none teaches people to close the panel.
WATCHED = {
    "microsoft.network/networksecuritygroups/write":
        "a firewall rule set being created or changed",
    "microsoft.network/networksecuritygroups/delete":
        "a firewall being deleted",
    "microsoft.authorization/policyassignments/write":
        "the rules about what may be built being changed",
    "microsoft.authorization/policyassignments/delete":
        "the rules about what may be built being removed",
    "microsoft.keyvault/vaults/write":
        "a key vault being created or reconfigured",
}


def _target(subscription, setting):
    return {
        "rule_id": f"{subscription}:{setting}",
        "resource_id": subscription,
        "setting": setting,
    }


def check_monitoring(settings):
    """Evaluates whether the subscription reports its own security changes."""
    if not settings:
        return []

    subscription = settings.get("subscription", "this subscription")
    alerts = settings.get("alerts") or []
    warnings = []

    # An alert that exists and is switched off is worse than one that was never
    # written, because it appears in every listing and satisfies every glance.
    # Reported before the missing ones for that reason.
    for alert in alerts:
        name = alert.get("name") or "an unnamed alert"

        if not alert.get("enabled"):
            warnings.append(_warning(
                WARNING,
                f"The activity log alert '{name}' exists but is switched off. "
                "It appears in the portal's list exactly like a working one "
                "and fires at nothing, which is the most misleading state "
                "available here: somebody has already decided this was worth "
                "watching, and nobody will be told when it happens.",
                _target(subscription, f"alert_disabled_{name}"),
            ))
            continue

        if not alert.get("has_action"):
            warnings.append(_warning(
                WARNING,
                f"The activity log alert '{name}' is on but has no action "
                "group, so nothing happens when it fires. The event is "
                "recorded in a log somebody would have to already be reading "
                "to find, which is the situation the alert was written to "
                "avoid. Attach an action group with an email or a webhook.",
                _target(subscription, f"alert_unreachable_{name}"),
            ))

    # What is not watched at all.
    #
    # Only alerts that are both enabled and reachable count as cover. An alert
    # that is switched off does not watch anything, and one that reaches nobody
    # watches without telling - counting either would let the two findings
    # above cancel out this one, so a subscription could report "everything is
    # watched" on the strength of alerts that cannot speak.
    covered = set()
    for alert in alerts:
        if alert.get("enabled") and alert.get("has_action"):
            covered.update(alert.get("operations") or [])

    missing = [text for op, text in WATCHED.items() if op not in covered]

    if missing and not alerts:
        # Nothing at all, which is one sentence rather than five.
        warnings.append(_warning(
            WARNING,
            "This subscription has no activity log alerts, so nothing tells "
            "anybody when its security settings change. Firewalls can be "
            "opened, policy can be switched off and vaults reconfigured, and "
            "the first anyone knows is when they go looking. Azure keeps the "
            "activity log either way; an alert is what makes somebody read it.",
            _target(subscription, "no_activity_log_alerts"),
        ))
    elif missing:
        listed = "; ".join(missing)
        warnings.append(_warning(
            INFO,
            f"Some security-relevant changes are watched here and these are "
            f"not: {listed}. Alerts already exist, so this is a gap in a "
            "working arrangement rather than an absence of one - which is "
            "usually a shorter conversation.",
            _target(subscription, "unwatched_operations"),
        ))

    return warnings


def check_monitoring_spec(spec):
    """Nothing to check before creating: this type is audited, never made."""
    return []
