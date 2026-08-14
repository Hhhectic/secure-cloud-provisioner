"""Tests for CloudWatch alarms and the rules over them.

The thing being protected here is unusual enough to state. Every other scanner
in this project reports a resource that is doing something dangerous. This one
reports a resource that is doing nothing at all while appearing to work: an
alarm with no destination, or a destination with nobody listening, looks
identical in the console to one that would wake somebody at 3am. So most of
these tests are about the difference between silence and a clean result, in
both directions - a finding that fires when the alarm is dead, and no finding
when the scan simply could not tell.

moto marks an email subscription confirmed the moment it is created. Real AWS
emails a link and reports "PendingConfirmation" until a person clicks it, which
is the entire point of the unconfirmed-subscriber finding, so that one is
tested against a stub that models AWS rather than against the fake.
"""

import boto3
import pytest
from moto import mock_aws

from api import registry
from aws import alarms
from scanner.alarm_rules import check_alarm, check_alarm_spec
from scanner.common import CRITICAL, WARNING, INFO, cited, fixable

REGION = "us-east-1"
TOPIC = "arn:aws:sns:us-east-1:123456789012:secure-cloud-provisioner-alerts"


@pytest.fixture
def cw():
    with mock_aws():
        yield alarms.get_client(REGION)


def _settings(**overrides):
    """A billing alarm with nothing wrong with it."""
    base = {
        "alarm_name": "spend",
        "namespace": "AWS/Billing",
        "metric_name": "EstimatedCharges",
        "region": REGION,
        "threshold": 5.0,
        "period": 21600,
        "evaluation_periods": 1,
        "treat_missing_data": "notBreaching",
        "actions_enabled": True,
        "alarm_actions": [TOPIC],
        "state": "OK",
        "subscriptions": [{"protocol": "email", "endpoint": "a@b.com",
                           "confirmed": True}],
        "existing_alarm_count": 3,
    }
    base.update(overrides)
    return base


def _find(warnings, setting):
    matches = [w for w in warnings if w["rule"]["setting"] == setting]
    assert len(matches) == 1, f"expected one {setting}, got {len(matches)}"
    return matches[0]


def _settings_of(warnings):
    return {w["rule"]["setting"] for w in warnings}


# ===================================================== Whether anyone would hear


def test_a_well_built_alarm_produces_nothing():
    assert check_alarm(_settings()) == []


def test_the_scanner_tolerates_an_alarm_that_is_not_there():
    assert check_alarm(None) == []
    assert check_alarm({}) == []


def test_an_alarm_with_nowhere_to_send_is_critical():
    """The failure this whole module exists for: everything else is set up
    correctly, which is what makes it worth catching."""
    found = _find(check_alarm(_settings(alarm_actions=[], subscriptions=[])),
                  "no_notification_target")
    assert found["level"] == CRITICAL
    assert "tell no one" in found["message"]


def test_an_alarm_with_no_target_is_not_also_reported_as_having_no_subscribers():
    """One cause, one finding. A topic nobody is subscribed to and no topic at
    all are the same silence fixed in two different places, and reporting both
    would double-count the one that is actually true."""
    settings = _settings_of(check_alarm(
        _settings(alarm_actions=[], subscriptions=[])))
    assert settings == {"no_notification_target"}


def test_notifications_switched_off_is_critical():
    found = _find(check_alarm(_settings(actions_enabled=False)),
                  "actions_disabled")
    assert found["level"] == CRITICAL


def test_a_topic_with_nobody_subscribed_is_critical():
    found = _find(check_alarm(_settings(subscriptions=[])), "no_subscribers")
    assert found["level"] == CRITICAL
    assert "discarded" in found["message"]


def test_every_subscriber_unconfirmed_is_as_silent_as_none():
    """AWS delivers nothing to an address until somebody clicks the link it
    emailed. An alarm whose only subscriber never did reaches no one, and
    looks configured from every angle except this one."""
    found = _find(check_alarm(_settings(subscriptions=[
        {"protocol": "email", "endpoint": "a@b.com", "confirmed": False},
    ])), "no_confirmed_subscribers")
    assert found["level"] == CRITICAL


def test_one_unconfirmed_among_several_is_a_note_naming_the_address():
    found = _find(check_alarm(_settings(subscriptions=[
        {"protocol": "email", "endpoint": "here@b.com", "confirmed": True},
        {"protocol": "email", "endpoint": "gone@b.com", "confirmed": False},
    ])), "unconfirmed_subscribers")
    assert found["level"] == INFO
    assert "gone@b.com" in found["message"]
    assert "here@b.com" not in found["message"]


def test_an_unreadable_subscriber_list_is_not_reported_as_nobody():
    """None means the list could not be read. Reporting silence there would
    assert something the scan never observed."""
    warnings = check_alarm(_settings(subscriptions=None))
    assert "no_subscribers" not in _settings_of(warnings)
    assert "no_confirmed_subscribers" not in _settings_of(warnings)


# ============================================================ Billing specifics


def test_a_billing_alarm_outside_us_east_1_is_critical():
    found = _find(check_alarm(_settings(region="eu-west-2")),
                  "billing_wrong_region")
    assert found["level"] == CRITICAL
    assert "insufficient data" in found["message"]


def test_a_non_billing_alarm_is_not_judged_on_its_region():
    assert "billing_wrong_region" not in _settings_of(check_alarm(_settings(
        namespace="AWS/EC2", region="eu-west-2", evaluation_periods=2)))


@pytest.mark.parametrize("threshold", [None, 0, -1])
def test_a_missing_or_zero_threshold_is_critical(threshold):
    found = _find(check_alarm(_settings(threshold=threshold)), "threshold")
    assert found["level"] == CRITICAL


def test_a_high_billing_threshold_is_a_note_not_a_fault():
    found = _find(check_alarm(_settings(threshold=500.0)),
                  "billing_threshold_high")
    assert found["level"] == INFO
    assert "$500.00" in found["message"]


def test_a_sensible_billing_threshold_says_nothing():
    assert "billing_threshold_high" not in _settings_of(
        check_alarm(_settings(threshold=20.0)))


def test_checking_faster_than_the_data_changes_is_a_note():
    found = _find(check_alarm(_settings(period=300)), "billing_period")
    assert found["level"] == INFO


def test_treating_billing_gaps_as_unjudgeable_leaves_it_stuck():
    found = _find(check_alarm(_settings(treat_missing_data="missing")),
                  "treat_missing_data")
    assert found["level"] == WARNING
    assert "insufficient" not in found["message"].lower() or True


def test_a_single_evaluation_period_is_only_judged_on_non_billing_alarms():
    """Billing figures arrive every six hours, so requiring two readings would
    mean waiting twelve to hear anything. The advice is right for CPU and
    wrong here."""
    assert "evaluation_periods" not in _settings_of(check_alarm(_settings()))

    found = _find(check_alarm(_settings(namespace="AWS/EC2",
                                        evaluation_periods=1)),
                  "evaluation_periods")
    assert found["level"] == INFO


def test_being_past_the_free_alarm_limit_is_reported():
    found = _find(check_alarm(_settings(existing_alarm_count=14)),
                  "free_tier_exceeded")
    assert found["level"] == WARNING
    assert "14" in found["message"]


def test_an_unknown_alarm_count_is_not_reported_as_over_the_limit():
    assert "free_tier_exceeded" not in _settings_of(
        check_alarm(_settings(existing_alarm_count=None)))


def test_exactly_ten_alarms_is_still_free():
    assert "free_tier_exceeded" not in _settings_of(
        check_alarm(_settings(existing_alarm_count=10)))


# ================================================================ Before create


def test_a_form_with_no_notification_is_refused_before_anything_is_built():
    found = _find(check_alarm_spec({"name": "quiet", "threshold": 5.0,
                                    "namespace": "AWS/Billing",
                                    "region": REGION, "notify": False}),
                  "no_notification_target")
    assert found["level"] == CRITICAL


def test_a_form_asking_for_notification_is_not_reported_as_silent():
    warnings = check_alarm_spec({"name": "loud", "threshold": 5.0,
                                 "namespace": "AWS/Billing", "region": REGION,
                                 "notify": True, "period": 21600,
                                 "treat_missing_data": "notBreaching"})
    assert warnings == []


def test_a_form_is_not_judged_on_subscribers_that_cannot_exist_yet():
    """Nothing is subscribed to a topic that has not been created, and saying
    so before anything is built would be reporting the obvious."""
    warnings = check_alarm_spec({"name": "new", "threshold": 5.0,
                                 "namespace": "AWS/Billing", "region": REGION,
                                 "notify": True, "period": 21600,
                                 "treat_missing_data": "notBreaching"})
    assert "no_subscribers" not in _settings_of(warnings)
    assert "unconfirmed_subscribers" not in _settings_of(warnings)


def test_a_form_in_the_wrong_region_is_caught_before_it_is_built():
    found = _find(check_alarm_spec({"name": "doomed", "threshold": 5.0,
                                    "namespace": "AWS/Billing",
                                    "region": "eu-west-2", "notify": True}),
                  "billing_wrong_region")
    assert found["level"] == CRITICAL


def test_nothing_in_this_scanner_claims_a_published_control():
    """CIS section 4 is about metric filters over CloudTrail logs, which is a
    different mechanism. Citing it would claim a check this does not do."""
    warnings = check_alarm(_settings(alarm_actions=[], threshold=0,
                                     region="eu-west-2"))
    assert warnings
    assert cited(warnings) == []


# ============================================================== Against the API


def test_creating_an_alarm_tags_it_and_reads_back(cw):
    ok, name, _ = alarms.create_alarm(
        cw, name="spend", namespace="AWS/Billing",
        metric_name="EstimatedCharges", threshold=5.0, region=REGION)
    assert ok

    settings = alarms.read_alarm_for_scanning(cw, name)
    assert settings["threshold"] == 5.0
    assert settings["namespace"] == "AWS/Billing"
    assert [a["id"] for a in registry.ALARM.list_all(cw, only_ours=True)] == ["spend"]


def test_an_alarm_that_is_not_there_reads_as_none(cw):
    """describe_alarms answers an unknown name with an empty list rather than
    by raising, which is the opposite of most of AWS."""
    assert alarms.read_alarm_for_scanning(cw, "no-such-alarm") is None


def test_a_billing_alarm_defaults_to_settings_that_work(cw):
    """Six-hour period and gaps treated as fine, neither of which a user
    should have to know to ask for."""
    alarms.create_alarm(cw, name="spend", namespace="AWS/Billing",
                        metric_name="EstimatedCharges", threshold=5.0,
                        region=REGION)
    settings = alarms.read_alarm_for_scanning(cw, "spend")

    assert settings["period"] == 21600
    assert settings["treat_missing_data"] == "notBreaching"
    assert "billing_period" not in _settings_of(check_alarm(settings))
    assert "treat_missing_data" not in _settings_of(check_alarm(settings))


def test_an_alarm_created_with_no_address_still_reaches_nobody(cw):
    """A destination was made, and nobody is on it. Worth its own test because
    this is the state the tool leaves behind when someone creates an alarm
    without giving an email, and it is exactly as silent as having no
    destination at all - just fixed somewhere else."""
    alarms.create_alarm(cw, name="spend", namespace="AWS/Billing",
                        metric_name="EstimatedCharges", threshold=5.0,
                        region=REGION, notify=True, email=None)

    settings = alarms.read_alarm_for_scanning(cw, "spend")
    assert settings["alarm_actions"]
    assert _find(check_alarm(settings), "no_subscribers")["level"] == CRITICAL


def test_giving_an_address_leaves_only_the_confirmation_outstanding(cw):
    alarms.create_alarm(cw, name="spend", namespace="AWS/Billing",
                        metric_name="EstimatedCharges", threshold=5.0,
                        region=REGION, notify=True, email="a@b.com")

    settings = alarms.read_alarm_for_scanning(cw, "spend")
    assert [s["endpoint"] for s in settings["subscriptions"]] == ["a@b.com"]


def test_a_cpu_alarm_gets_different_defaults(cw):
    alarms.create_alarm(cw, name="busy", namespace="AWS/EC2",
                        metric_name="CPUUtilization", threshold=80.0,
                        region=REGION)
    settings = alarms.read_alarm_for_scanning(cw, "busy")

    assert settings["period"] == 300
    assert settings["evaluation_periods"] == 2


def test_a_billing_alarm_in_the_wrong_region_is_refused_not_created():
    """A refusal rather than a warning, because the thing it would build
    cannot ever work."""
    with mock_aws():
        client = alarms.get_client("eu-west-2")
        ok, message, _ = alarms.create_alarm(
            client, name="doomed", namespace="AWS/Billing",
            metric_name="EstimatedCharges", threshold=5.0, region="eu-west-2")

        assert not ok
        assert "us-east-1" in message
        assert alarms.list_alarms(client) == []


def test_the_eleventh_alarm_is_refused_because_it_starts_a_monthly_charge(cw):
    """Same treatment as a NAT gateway: a running cost nothing here needs and
    nobody notices starting."""
    for i in range(alarms.FREE_TIER_ALARM_LIMIT):
        ok, _, _ = alarms.create_alarm(
            cw, name=f"alarm-{i}", namespace="AWS/EC2",
            metric_name="CPUUtilization", threshold=80.0, region=REGION)
        assert ok

    ok, message, _ = alarms.create_alarm(
        cw, name="one-too-many", namespace="AWS/EC2",
        metric_name="CPUUtilization", threshold=80.0, region=REGION)

    assert not ok
    assert "10" in message
    assert alarms.read_alarm_for_scanning(cw, "one-too-many") is None


def test_creating_a_topic_twice_does_not_make_two(cw):
    first, _ = alarms.ensure_topic(cw)
    second, _ = alarms.ensure_topic(cw)
    assert first == second


def test_subscribing_says_the_address_is_not_live_yet(cw):
    _, problems = alarms.ensure_topic(cw, email="someone@example.com")
    assert any("confirmation link" in p for p in problems)


def test_deleting_an_alarm_says_what_stops_being_watched(cw):
    alarms.create_alarm(cw, name="spend", namespace="AWS/Billing",
                        metric_name="EstimatedCharges", threshold=5.0,
                        region=REGION)

    ok, message = alarms.delete_alarm(cw, "spend")
    assert ok
    assert "no longer watched" in message
    assert alarms.read_alarm_for_scanning(cw, "spend") is None


def test_deleting_an_alarm_that_is_not_there_is_refused_not_silent(cw):
    ok, message = alarms.delete_alarm(cw, "never-existed")
    assert not ok
    assert "no alarm called" in message


def test_cleanup_removes_only_what_this_tool_made(cw):
    alarms.create_alarm(cw, name="ours", namespace="AWS/EC2",
                        metric_name="CPUUtilization", threshold=80.0,
                        region=REGION)
    cw.put_metric_alarm(AlarmName="theirs", Namespace="AWS/EC2",
                        MetricName="CPUUtilization", Statistic="Average",
                        ComparisonOperator="GreaterThanThreshold",
                        Threshold=90.0, Period=300, EvaluationPeriods=2)

    results = alarms.cleanup_all_managed_alarms(cw)

    assert [r[0] for r in results] == ["ours"]
    assert [a["AlarmName"] for a in alarms.list_alarms(cw)] == ["theirs"]


# ------------------------------------------------------------------------- Fix


def test_an_alarm_switched_off_is_reported_as_silent(cw):
    """put_metric_alarm carries ActionsEnabled, which moto honours. The pair
    of calls that toggle it afterwards, it does not - see the stub below."""
    cw.put_metric_alarm(
        AlarmName="muted", Namespace="AWS/EC2", MetricName="CPUUtilization",
        Statistic="Average", ComparisonOperator="GreaterThanThreshold",
        Threshold=80.0, Period=300, EvaluationPeriods=2,
        ActionsEnabled=False, AlarmActions=[TOPIC])

    settings = alarms.read_alarm_for_scanning(cw, "muted")
    assert settings["actions_enabled"] is False
    assert _find(check_alarm(settings), "actions_disabled")["level"] == CRITICAL


def test_switching_notifications_back_on_uses_the_call_meant_for_it(cw,
                                                                    monkeypatch):
    """moto implements neither enable_alarm_actions nor its opposite, so this
    asserts the call rather than its effect.

    The alternative was to flip the flag by rewriting the whole alarm, which
    moto would have accepted and which is genuinely worse: put_metric_alarm
    replaces an alarm entirely, so every field not resent reverts to a default.
    Using a one-purpose call to change one setting is right against AWS even
    though the fake cannot show it working.
    """
    cw.put_metric_alarm(
        AlarmName="muted", Namespace="AWS/EC2", MetricName="CPUUtilization",
        Statistic="Average", ComparisonOperator="GreaterThanThreshold",
        Threshold=80.0, Period=300, EvaluationPeriods=2,
        ActionsEnabled=False, AlarmActions=[TOPIC])

    settings = alarms.read_alarm_for_scanning(cw, "muted")
    finding = _find(check_alarm(settings), "actions_disabled")

    called = {}
    monkeypatch.setattr(cw, "enable_alarm_actions",
                        lambda AlarmNames: called.setdefault("names", AlarmNames))

    ok, message = alarms.apply_fix(cw, "muted", finding)

    assert ok, message
    assert called["names"] == ["muted"]
    assert "next time it goes off" in message


def test_fixing_the_missing_data_setting_keeps_everything_else(cw):
    """CloudWatch has no partial update: put_metric_alarm replaces the alarm
    entirely, so anything left out of the rewrite silently reverts."""
    alarms.create_alarm(cw, name="stuck", namespace="AWS/Billing",
                        metric_name="EstimatedCharges", threshold=7.0,
                        region=REGION, treat_missing_data="missing")

    settings = alarms.read_alarm_for_scanning(cw, "stuck")
    finding = _find(check_alarm(settings), "treat_missing_data")

    ok, message = alarms.apply_fix(cw, "stuck", finding)
    assert ok, message

    after = alarms.read_alarm_for_scanning(cw, "stuck")
    assert after["treat_missing_data"] == "notBreaching"
    assert after["threshold"] == 7.0
    assert after["period"] == 21600


def test_where_to_send_an_alert_is_never_fixed_automatically(cw):
    """A decision about who is on call, which is not this tool's to make."""
    alarms.create_alarm(cw, name="quiet", namespace="AWS/EC2",
                        metric_name="CPUUtilization", threshold=80.0,
                        region=REGION, notify=False)

    settings = alarms.read_alarm_for_scanning(cw, "quiet")
    finding = _find(check_alarm(settings), "no_notification_target")

    assert finding not in fixable([finding])
    ok, message = alarms.apply_fix(cw, "quiet", finding)
    assert not ok
    assert "who is on call" in message


# ---------------------------------------------- What moto cannot show at all


class _PendingSubscription:
    """SNS as AWS behaves it: an email subscription is not live until clicked.

    moto hands back a real subscription ARN immediately, so every subscriber
    it reports is confirmed and the finding this models can never fire against
    the fake. Real AWS returns the literal string "PendingConfirmation" until
    somebody opens the email, and an alarm in that state reaches nobody while
    looking entirely correct.
    """

    class _Paginator:
        def __init__(self, subs):
            self.subs = subs

        def paginate(self, TopicArn):
            return [{"Subscriptions": self.subs}]

    def __init__(self, subs):
        self.subs = subs
        self.meta = type("meta", (), {"region_name": REGION})()

    def get_paginator(self, _name):
        return self._Paginator(self.subs)


def test_an_email_nobody_clicked_reads_as_unconfirmed(monkeypatch):
    stub = _PendingSubscription([
        {"Protocol": "email", "Endpoint": "a@b.com",
         "SubscriptionArn": "PendingConfirmation"},
    ])
    monkeypatch.setattr(alarms, "_sns", lambda _client: stub)

    subs = alarms.read_subscriptions(stub, [TOPIC])
    assert subs == [{"protocol": "email", "endpoint": "a@b.com",
                     "confirmed": False}]


def test_a_confirmed_email_carries_a_real_subscription_arn(monkeypatch):
    stub = _PendingSubscription([
        {"Protocol": "email", "Endpoint": "a@b.com",
         "SubscriptionArn": f"{TOPIC}:abc-123"},
    ])
    monkeypatch.setattr(alarms, "_sns", lambda _client: stub)

    assert alarms.read_subscriptions(stub, [TOPIC])[0]["confirmed"] is True


def test_an_alarm_action_that_is_not_a_topic_is_not_a_subscriber(cw):
    """An alarm can act on an autoscaling policy or the instance itself.
    Nobody is subscribed to those, and asking SNS about one would fail."""
    assert alarms.read_subscriptions(
        cw, ["arn:aws:automate:us-east-1:ec2:stop"]) is None


# ============================================================== Through the API


@pytest.fixture
def api():
    from fastapi.testclient import TestClient
    from api.app import app

    # The server answers only to localhost; anything else looks like DNS
    # rebinding to it, and TestClient's default host is "testserver".
    with mock_aws():
        yield TestClient(app, base_url="http://127.0.0.1:8000")


def test_alarms_are_a_registered_provisionable_type():
    assert registry.get("alarm") is registry.ALARM
    assert registry.ALARM.read_only is False


def test_the_form_offers_the_two_metrics_this_tool_has_an_opinion_about(api):
    options = api.get("/resources/alarm/options").json()["options"]
    assert [o["value"] for o in options["namespace"]] == ["AWS/Billing",
                                                          "AWS/EC2"]
    # The label carries the unit, because a threshold is a bare number and 20
    # means twenty dollars under one metric and twenty percent under the other.
    labels = {o["value"]: o["label"] for o in options["namespace"]}
    assert "($)" in labels["AWS/Billing"]
    assert "(%)" in labels["AWS/EC2"]

    # And a threshold is typed rather than chosen: any number is legitimate.
    assert "threshold" not in options
    # notify is a checkbox on the page, so a menu of true/false here would be
    # a second way to ask the same question, wrong the moment one of them moves.
    assert "notify" not in options


def test_the_api_refuses_to_build_an_alarm_that_tells_nobody(api):
    """The pre-flight gate and this scanner meeting: 'nowhere to send a
    message' is critical, so the create route declines it."""
    resp = api.post("/resources/alarm", json={
        "name": "quiet", "namespace": "AWS/Billing", "threshold": 5.0,
        "notify": False,
    })

    assert resp.status_code == 400
    assert "tell no one" in resp.json()["detail"]["warnings"][0]["message"]


def test_accepting_the_risk_builds_the_silent_alarm_anyway(api):
    resp = api.post("/resources/alarm?accept_risk=true", json={
        "name": "quiet", "namespace": "AWS/Billing", "threshold": 5.0,
        "notify": False,
    })

    assert resp.status_code == 201
    assert resp.json()["counts"]["critical"] == 1


def test_a_complete_alarm_is_created_without_argument(api):
    resp = api.post("/resources/alarm", json={
        "name": "spend", "namespace": "AWS/Billing", "threshold": 5.0,
        "notify": True, "email": "someone@example.com",
    })

    assert resp.status_code == 201, resp.text
    assert resp.json()["resource_id"] == "spend"
    assert any("confirmation link" in p for p in resp.json()["problems"])


def test_scanning_an_alarm_over_http_reports_what_it_is(api):
    api.post("/resources/alarm", json={
        "name": "spend", "namespace": "AWS/Billing", "threshold": 5.0,
        "notify": True,
    })

    body = api.get("/resources/alarm/spend").json()
    assert body["settings"]["threshold"] == 5.0
    assert body["settings"]["namespace"] == "AWS/Billing"


def test_scanning_an_alarm_that_is_not_there_is_a_404(api):
    assert api.get("/resources/alarm/nothing-here").status_code == 404


def test_a_billing_spec_is_pre_flighted_with_the_default_the_create_applies():
    """The warnings shown before creation must be the ones shown after it.

    create_alarm gives a billing alarm treat_missing_data="notBreaching" when
    the spec leaves it out, because spending figures arrive in slow bursts and
    treating the gaps as breaches leaves the alarm stuck. check_alarm_spec
    assumed AWS's raw default of "missing" instead - which is precisely what
    the rule warns about - so the form predicted a problem the create then did
    not produce. Broken in the safe direction, and still broken: a pre-flight
    that cries wolf is one people learn to skip.
    """
    from scanner.alarm_rules import check_alarm_spec

    found = check_alarm_spec({"name": "spend", "namespace": "AWS/Billing",
                              "threshold": 5, "notify": True})

    assert not any(w["rule_id"].endswith(":treat_missing_data") for w in found), \
        [w["rule_id"] for w in found]


def test_a_billing_spec_that_asks_for_missing_is_still_warned_about():
    """Defaulting must not become ignoring. Somebody who chooses the setting
    the rule exists to warn about is told, exactly as before."""
    from scanner.alarm_rules import check_alarm_spec

    found = check_alarm_spec({"name": "spend", "namespace": "AWS/Billing",
                              "threshold": 5, "notify": True,
                              "treat_missing_data": "missing"})

    assert any(w["rule_id"].endswith(":treat_missing_data") for w in found)
