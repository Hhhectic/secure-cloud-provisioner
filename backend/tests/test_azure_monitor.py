"""The first type here whose resource is the account rather than a thing in it.

`azure-monitor` reads the subscription and judges whether anybody would be told
that its security settings changed. The reasoning is scanner/alarm_rules.py's,
transferred: an alarm fails by being quiet, and quiet looks identical to safe.

These are rule tests over dicts plus a stub client, so nothing here touches a
subscription. The stub deliberately models two things the real SDK does and a
naive fake would not - enums that lie to str(), and `enabled` being absent
rather than False - because a stub written to match the code cannot disagree
with it, which is the lesson _StubVaultClient cost this project once already.
"""

import ast
from enum import Enum
from pathlib import Path

import pytest

from api import registry
from scanner.azure_monitor_rules import WATCHED, check_monitoring
from scanner.common import WARNING, INFO, worst_level

SUBSCRIPTION = "74baf379-b419-4e16-a50b-98bc450901c9"
NSG_WRITE = "Microsoft.Network/networkSecurityGroups/write"


class _SdkEnum(str, Enum):
    """Reproduces the trap: a str subclass whose str() is not its value.

    Since Python 3.11 `str(X.MEMBER)` on a `class X(str, Enum)` renders as
    'X.MEMBER', not the value - while == and isinstance(str) both still say
    what you expect. That is what made a security group opening every port to
    the internet scan completely clean.
    """
    OPERATION_NAME = "operationName"


def test_the_stub_enum_really_does_reproduce_the_trap():
    """Without this the tests below could pass for a new reason if a future
    Python made str() return the value again."""
    assert _SdkEnum.OPERATION_NAME == "operationName"
    assert isinstance(_SdkEnum.OPERATION_NAME, str)
    assert str(_SdkEnum.OPERATION_NAME) != "operationName"


class _Leaf:
    def __init__(self, field, equals, any_of=None):
        self.field = field
        self.equals = equals
        self.any_of = any_of


class _Condition:
    def __init__(self, leaves):
        self.all_of = leaves


class _Actions:
    def __init__(self, groups):
        self.action_groups = groups


class _Alert:
    def __init__(self, name, operations=(), enabled=True, groups=("ag",),
                 field=_SdkEnum.OPERATION_NAME):
        self.name = name
        self.condition = _Condition([_Leaf(field, op) for op in operations])
        self.actions = _Actions(list(groups))
        if enabled is not None:
            self.enabled = enabled


class _Client:
    def __init__(self, alerts):
        outer = self

        class _Alerts:
            def list_by_subscription_id(self):
                return list(outer._alerts)

        self._alerts = alerts
        self.activity_log_alerts = _Alerts()


# ------------------------------------------------------------------- Reading


def _read(alerts, monkeypatch):
    from az import monitor
    monkeypatch.setattr(monitor, "subscription_id", lambda: SUBSCRIPTION)
    return monitor.read_subscription_for_scanning(_Client(alerts))


def test_an_alerts_operations_survive_the_enum(monkeypatch):
    """The whole reason az/common.plain exists, applied at this boundary too."""
    settings = _read([_Alert("nsg-watch", [NSG_WRITE])], monkeypatch)

    assert settings["alerts"][0]["operations"] == [NSG_WRITE.lower()]


def test_an_alert_with_no_enabled_field_is_treated_as_on(monkeypatch):
    """Azure omits `enabled` when it is true. Reading absence as False would
    report every working alert as switched off."""
    settings = _read([_Alert("nsg", [NSG_WRITE], enabled=None)], monkeypatch)

    assert settings["alerts"][0]["enabled"] is True


def test_asking_about_another_subscription_is_not_answered_with_this_one(
        monkeypatch):
    from az import monitor
    monkeypatch.setattr(monitor, "subscription_id", lambda: SUBSCRIPTION)

    assert monitor.read_subscription_for_scanning(
        _Client([]), "some-other") is None


def test_a_refused_read_is_a_refusal_rather_than_an_empty_list(monkeypatch):
    """The seventh time this distinction has had to be made here.

    An empty alert list and "you hold no role on this subscription" produce the
    same screen, and one of them is a clean bill of health nobody earned.
    """
    from az import monitor
    from az.common import AzureRefused

    class _Refusing:
        class activity_log_alerts:
            @staticmethod
            def list_by_subscription_id():
                raise PermissionError("Forbidden")

    monkeypatch.setattr(monitor, "subscription_id", lambda: SUBSCRIPTION)
    monkeypatch.setattr(monitor, "denied", lambda e: True)

    with pytest.raises(AzureRefused):
        monitor.read_subscription_for_scanning(_Refusing())


# --------------------------------------------------------------------- Rules


def _settings(alerts):
    return {"subscription": SUBSCRIPTION, "alerts": alerts}


def _settings_of(warnings):
    return {w["rule"]["setting"] for w in warnings}


def test_a_subscription_with_no_alerts_says_so_once():
    """One sentence rather than one per unwatched operation. Five findings on a
    subscription that has none teaches people to close the panel."""
    warnings = check_monitoring(_settings([]))

    assert len(warnings) == 1
    assert warnings[0]["level"] == WARNING
    assert "no_activity_log_alerts" in warnings[0]["rule_id"]


def test_a_disabled_alert_is_worse_than_a_missing_one():
    """It appears in every listing exactly like a working one."""
    warnings = check_monitoring(_settings([
        {"name": "nsg", "enabled": False, "operations": [NSG_WRITE.lower()],
         "has_action": True}]))

    disabled = [w for w in warnings if "alert_disabled" in w["rule_id"]]
    assert disabled and disabled[0]["level"] == WARNING


def test_an_alert_reaching_nobody_is_reported():
    """The Azure spelling of an alarm with no SNS topic."""
    warnings = check_monitoring(_settings([
        {"name": "nsg", "enabled": True, "operations": [NSG_WRITE.lower()],
         "has_action": False}]))

    assert any("alert_unreachable" in w["rule_id"] for w in warnings)


def test_an_alert_that_cannot_speak_does_not_count_as_cover():
    """The one that would have let the findings cancel each other out.

    If a disabled or unreachable alert counted towards cover, a subscription
    could report "everything is watched" on the strength of alerts that fire at
    nobody - the two findings above quietly buying off the third.
    """
    for alert in ({"name": "a", "enabled": False, "has_action": True},
                  {"name": "a", "enabled": True, "has_action": False}):
        alert["operations"] = list(WATCHED)
        assert "unwatched_operations" in _settings_of(
            check_monitoring(_settings([alert]))), alert


def test_watching_everything_leaves_only_silence():
    warnings = check_monitoring(_settings([
        {"name": "all", "enabled": True, "has_action": True,
         "operations": list(WATCHED)}]))

    assert warnings == []


def test_a_partial_gap_is_a_note_rather_than_a_warning():
    """Alerts already exist, so this is a gap in a working arrangement."""
    covered = list(WATCHED)[:2]
    warnings = check_monitoring(_settings([
        {"name": "some", "enabled": True, "has_action": True,
         "operations": covered}]))

    gap = [w for w in warnings if "unwatched_operations" in w["rule_id"]]
    assert gap and gap[0]["level"] == INFO
    assert worst_level(warnings) == INFO


def test_no_finding_here_carries_a_citation():
    """CIS AWS Foundations does not reach Azure, and nobody here has read the
    CIS Azure benchmark. An invented section number is the fabrication
    scanner/controls.py warns about."""
    warnings = check_monitoring(_settings([]))
    warnings += check_monitoring(_settings([
        {"name": "x", "enabled": False, "operations": [], "has_action": False}]))

    assert all(w["control"] is None for w in warnings)


# -------------------------------------------------------------- Registration


def test_the_type_is_registered_as_an_audited_azure_type():
    known = registry.get("azure-monitor")

    assert known.provider == "azure"
    assert known.read_only is True


def test_the_subscription_is_its_own_resource_id(monkeypatch):
    """The design decision, asserted.

    The routes take an id as one path segment and a subscription id is one,
    which is why an account-wide finding needed no new ResourceType shape and
    no route change.
    """
    from az import monitor
    monkeypatch.setattr(monitor, "subscription_id", lambda: SUBSCRIPTION)

    rows = registry.get("azure-monitor").list_all(None, False)

    assert rows == [{"id": SUBSCRIPTION, "name": SUBSCRIPTION}]
    assert "/" not in rows[0]["id"]


def test_the_sdk_is_imported_inside_a_function_not_at_module_scope():
    """The property every az/ module here has to hold.

    api/registry.py imports every provider module at startup, so a module-level
    import would make azure-mgmt-monitor a hard requirement of starting the AWS
    half. Read from the source rather than inferred from the suite passing,
    exactly as test_azure_provider.py does for the other five.
    """
    source = Path(__file__).resolve().parent.parent / "az" / "monitor.py"
    tree = ast.parse(source.read_text())

    for node in tree.body:
        names = [a.name for a in getattr(node, "names", [])]
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            assert not any(n.startswith("azure") for n in names), (
                "an azure import at module scope makes the SDK a hard "
                "requirement of starting the AWS half")
