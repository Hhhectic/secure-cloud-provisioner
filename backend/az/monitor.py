"""Whether the subscription would tell anyone that something changed.

Every other Azure type here reads one resource and judges it. This reads the
*subscription* and judges its configuration, which is why it is registered as a
type whose single resource is the subscription itself: `ResourceType` has one
shape, the routes take an id as one path segment, and the subscription id is a
perfectly good one. Inventing a second shape for account-wide findings would
have meant teaching every route and the page about a second kind of resource,
to serve one type.

The reasoning transfers exactly from `scanner/alarm_rules.py`, and so does the
sentence that justifies it: **an alarm fails by being quiet.** Everything else
this tool reports is dangerous while it is doing something. A missing activity
log alert is dangerous while nothing happens at all, and the console shows the
same empty page whether nobody has attacked you or nobody is watching.

What this does not cover, and why
---------------------------------
Prowler's monitor block is thirteen checks and roughly a third of them are
about *diagnostic settings* - whether the activity log is exported somewhere it
will outlive the ninety days Azure keeps it. Those are not here, and not by
choice: `azure-mgmt-monitor` 7.0.0 ships no diagnostic-settings operation group
at all. Reading them needs a different API version or a raw ARM call, and
guessing at one would be worse than the gap. Stated rather than worked around,
the way the three Azure vault constraints are.

Defender is a deliberate no rather than a gap. Its three checks ask whether
paid Microsoft products are licensed, and "you have not bought Defender" is a
purchasing decision, not a configuration mistake.
"""

from az.common import (AzureRefused, denied, not_allowed_to_look, plain,
                       credential, subscription_id, why_azure_refused)


def get_client(region=None):
    """The monitor management client. SDK imported here, never at module scope.

    `api/registry.py` imports every provider module at startup, so an import
    up top would make azure-mgmt-monitor a hard requirement of starting the
    AWS half - the objection this whole package is arranged around. region is
    accepted and ignored: activity log alerts are a subscription-wide
    resource with a global scope, and the signature has to match every other
    get_client in the registry.
    """
    from azure.mgmt.monitor import MonitorManagementClient

    return MonitorManagementClient(credential(), subscription_id())


def _operations_watched_by(alert):
    """The operation names one alert fires on.

    An activity log alert's condition is a list of leaf conditions, each an
    (anyOf-able) field/equals pair. Only `operationName` matters here; the
    others narrow by category, level or resource and are how somebody scopes
    an alert rather than what it watches for.

    `plain` is called on every value because the SDK's enums are str
    subclasses that render through str() as 'ClassName.MEMBER' since Python
    3.11 - the trap that made a security group opening every port scan clean.
    """
    condition = getattr(alert, "condition", None)
    leaves = list(getattr(condition, "all_of", None) or [])

    found = set()
    for leaf in leaves:
        field = (plain(getattr(leaf, "field", None)) or "").lower()
        if field != "operationname":
            # anyOf holds alternatives for one field, and an alert written
            # that way watches several operations through one leaf.
            for alt in (getattr(leaf, "any_of", None) or []):
                if (plain(getattr(alt, "field", None)) or "").lower() == "operationname":
                    value = plain(getattr(alt, "equals", None))
                    if value:
                        found.add(value.lower())
            continue
        value = plain(getattr(leaf, "equals", None))
        if value:
            found.add(value.lower())

    return sorted(found)


def _has_action(alert):
    """Whether anything is on the other end of this alert.

    An alert with no action group is the Azure spelling of an alarm with no
    SNS topic: it fires, it is recorded, and it reaches nobody.
    """
    actions = getattr(alert, "actions", None)
    groups = list(getattr(actions, "action_groups", None) or [])
    return bool(groups)


def read_subscription_for_scanning(client, resource_id=None):
    """Every activity log alert in the subscription, shaped for the scanner.

    resource_id is accepted because the routes pass one, and is checked rather
    than ignored: asking about a subscription other than the one these
    credentials reach would otherwise be answered with this one's posture,
    which is the mistake `read_account_for_scanning` already guards in the AWS
    half.

    A refused read raises AzureRefused rather than returning None. This is the
    seventh place that distinction has had to be made - Azure answers "you hold
    no role here" and "there is nothing here" in nearly the same words, and a
    read that only handles the second turns a missing role into either a crash
    or a clean bill of health.
    """
    mine = subscription_id()
    if resource_id and resource_id != mine:
        return None

    try:
        found = list(client.activity_log_alerts.list_by_subscription_id())
    except Exception as error:  # noqa: BLE001 - narrowed immediately below
        if denied(error):
            raise AzureRefused(
                not_allowed_to_look(None, "the subscription's activity log alerts")
            ) from error
        raise AzureRefused(
            why_azure_refused(error, "reading activity log alerts")
        ) from error

    alerts = []
    for alert in found:
        alerts.append({
            "name": plain(getattr(alert, "name", None)),
            # Azure defaults `enabled` to true when the field is absent, and an
            # alert that exists but is switched off is the quietest failure
            # here: it is present in every listing and fires at nothing.
            "enabled": getattr(alert, "enabled", True) is not False,
            "operations": _operations_watched_by(alert),
            "has_action": _has_action(alert),
        })

    return {"subscription": mine, "alerts": alerts}


def describe_subscription(settings):
    """What the subscription is, as opposed to what is wrong with it."""
    if not settings:
        return None

    alerts = settings.get("alerts") or []
    return {
        "subscription": settings.get("subscription"),
        "alert_count": len(alerts),
        "enabled_count": sum(1 for a in alerts if a.get("enabled")),
    }


def list_subscriptions(client, only_ours=False):
    """One row, because there is one subscription these credentials reach.

    only_ours is accepted and ignored for the same reason the IAM type ignores
    it: a subscription is not something this tool made, and a filter offering
    to narrow one row to zero would be a control that does nothing.
    """
    return [{"id": subscription_id(), "name": subscription_id()}]
