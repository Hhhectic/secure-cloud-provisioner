"""Security rules for evaluating CloudWatch alarms.

Contains pure Python evaluation logic with no external AWS dependencies.

Grown from check_alarm_config in scripts/cloudwatch_harness.py, which was
written to mirror check_firewall_rules and already had the right shape: plain
settings in, plain warnings out, no boto3. What it did not have was this
project's warning contract, so the findings could not be counted, cited or
rendered alongside every other kind. They can now.

The failure this file exists to catch is specific and worth naming. Every
finding below describes an alarm that *looks* configured - it appears in the
console, it has a threshold, it has a name someone chose - and cannot ever
tell anyone anything. A firewall with a bad rule is visibly wrong the moment
you read it. A dead alarm is invisibly wrong until the day you needed it, and
its whole purpose was to be the thing you did not have to watch.

No published benchmark covers these. CIS section 4 is about monitoring, but it
asks for metric filters over CloudTrail logs - who signed in as root, who
changed an IAM policy - which is a different mechanism from an alarm on a
metric AWS publishes by itself. Citing it here would claim a compliance check
this does not perform, so everything below is deliberately uncited.
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

# Billing metrics are published only to us-east-1, whatever region the spending
# happens in. An alarm on them built anywhere else receives no data, ever.
BILLING_NAMESPACE = "AWS/Billing"
BILLING_REGION = "us-east-1"

# Estimated charges refresh roughly every six hours.
BILLING_PERIOD = 21600

# Ten alarms are free forever. The eleventh starts a monthly bill.
FREE_TIER_ALARM_LIMIT = 10

# Above this, a billing alarm on a student project is telling you something you
# already found out from the bill.
HIGH_BILLING_THRESHOLD = 50


def _target(alarm_name, setting):
    return {
        "rule_id": f"{alarm_name}:{setting}",
        "resource_id": alarm_name,
        "setting": setting,
    }


def check_alarm(settings):
    """Evaluates one alarm and returns detected risks.

    Expects the shape produced by aws.alarms.read_alarm_for_scanning():
        {
          "alarm_name": str,
          "namespace": str,
          "metric_name": str,
          "region": str,
          "threshold": float | None,
          "period": int | None,
          "evaluation_periods": int,
          "treat_missing_data": str,
          "actions_enabled": bool,
          "alarm_actions": [str],
          "state": str,
          "subscriptions": [{"protocol", "endpoint", "confirmed"}] | None,
          "existing_alarm_count": int | None,
        }
    """
    if not settings:
        return []

    name = settings.get("alarm_name", "this alarm")
    namespace = settings.get("namespace") or ""
    is_billing = namespace == BILLING_NAMESPACE
    warnings = []

    warnings.extend(_check_it_can_speak(settings, name))

    # ---- The wrong region for the metric ------------------------------------
    region = settings.get("region")
    if is_billing and region and region != BILLING_REGION:
        warnings.append(_warning(
            CRITICAL,
            f"'{name}' watches your spending, but it was built in {region} and "
            f"AWS only publishes spending figures to {BILLING_REGION}. No "
            "figure ever reaches it, so it cannot go off no matter how large "
            "the bill gets. It will sit showing 'insufficient data' forever, "
            "which is easy to read as 'nothing is wrong'.",
            _target(name, "billing_wrong_region"),
        ))

    # ---- A threshold that means nothing --------------------------------------
    threshold = settings.get("threshold")
    if threshold is None or threshold <= 0:
        warnings.append(_warning(
            CRITICAL,
            f"'{name}' has no usable limit set, so it is either going off "
            "constantly or it can never go off at all. Either way it is not "
            "telling you anything about the thing it is supposed to watch.",
            _target(name, "threshold"),
        ))
    elif is_billing and threshold > HIGH_BILLING_THRESHOLD:
        warnings.append(_warning(
            INFO,
            f"'{name}' does not complain until the bill passes "
            f"${threshold:,.2f}. For a project meant to stay inside the free "
            "tier that is a long way past the point you wanted to know about. "
            "A few dollars is a more useful place to hear about it.",
            _target(name, "billing_threshold_high"),
        ))

    # ---- Settings that make it slow or jumpy ---------------------------------
    period = settings.get("period")
    if is_billing and period is not None and period < BILLING_PERIOD:
        warnings.append(_warning(
            INFO,
            f"'{name}' checks more often than the figure it watches changes. "
            "Spending estimates update about every six hours, so asking more "
            "frequently does not find out any sooner.",
            _target(name, "billing_period"),
        ))

    if is_billing and settings.get("treat_missing_data") == "missing":
        warnings.append(_warning(
            WARNING,
            f"'{name}' treats a gap in the data as a problem it cannot judge. "
            "Spending figures arrive in slow bursts with gaps between them, so "
            "this alarm will spend most of its life stuck saying it does not "
            "have enough information rather than watching. Treating a gap as "
            "'nothing is wrong' is the usual choice here.",
            _target(name, "treat_missing_data"),
        ))

    if not is_billing and settings.get("evaluation_periods", 1) == 1:
        warnings.append(_warning(
            INFO,
            f"'{name}' goes off on a single reading. One brief spike - a "
            "backup running, somebody compiling something - is enough to set "
            "it off, and an alarm that cries wolf gets muted, which is the "
            "same as not having it. Requiring two readings in a row is calmer.",
            _target(name, "evaluation_periods"),
        ))

    # ---- Cost ----------------------------------------------------------------
    existing = settings.get("existing_alarm_count")
    if existing is not None and existing > FREE_TIER_ALARM_LIMIT:
        warnings.append(_warning(
            WARNING,
            f"This account has {existing} alarms and the first "
            f"{FREE_TIER_ALARM_LIMIT} are the free ones. The rest are billed "
            "every month for as long as they exist, whether or not they ever "
            "go off. Delete the ones nobody reads.",
            _target(name, "free_tier_exceeded"),
        ))

    return warnings


def _check_it_can_speak(settings, name):
    """Whether anyone would hear this alarm. The point of the whole file.

    Three ways to be silent, and they need saying separately because they are
    fixed in three different places: no destination at all, a destination with
    nobody subscribed, and a subscriber who never clicked the confirmation
    link in the email AWS sent them.
    """
    warnings = []
    actions = settings.get("alarm_actions") or []

    if not actions:
        return [_warning(
            CRITICAL,
            f"'{name}' has nowhere to send a message. When the thing it "
            "watches goes wrong it will turn red on a page nobody has open "
            "and tell no one. Everything else about it is set up correctly, "
            "which is what makes this worth catching: it looks like "
            "monitoring and it is decoration.",
            _target(name, "no_notification_target"),
        )]

    if not settings.get("actions_enabled", True):
        warnings.append(_warning(
            CRITICAL,
            f"'{name}' has somewhere to send a message and has been switched "
            "off. It still changes colour and still notifies nobody. This is "
            "usually left over from someone silencing a noisy alarm and not "
            "turning it back on.",
            _target(name, "actions_disabled"),
        ))

    # None means the subscriber list could not be read, which is not the same
    # as an empty one. Reporting silence here would be asserting something the
    # scan never observed.
    subscriptions = settings.get("subscriptions")
    if subscriptions is None:
        return warnings

    if not subscriptions:
        warnings.append(_warning(
            CRITICAL,
            f"'{name}' sends its message to a mailing list with nobody on it. "
            "The message is delivered and then discarded. Subscribe an "
            "address that a person actually reads.",
            _target(name, "no_subscribers"),
        ))
        return warnings

    unconfirmed = [s for s in subscriptions if not s.get("confirmed")]
    if len(unconfirmed) == len(subscriptions):
        warnings.append(_warning(
            CRITICAL,
            f"Nobody subscribed to '{name}' has confirmed their address. AWS "
            "emails a link when an address is added and delivers nothing until "
            "someone clicks it, so this alarm currently reaches no one. Check "
            "the inbox, including the spam folder.",
            _target(name, "no_confirmed_subscribers"),
        ))
    elif unconfirmed:
        addresses = ", ".join(s.get("endpoint", "an address")
                              for s in unconfirmed)
        warnings.append(_warning(
            INFO,
            f"'{name}' reaches someone, but {addresses} never clicked the "
            "confirmation link AWS sent, so that address is being skipped. If "
            "it belongs to whoever is meant to be on call, this alarm is not "
            "reaching them.",
            _target(name, "unconfirmed_subscribers"),
        ))

    return warnings


def check_alarm_spec(spec):
    """Scans an alarm the form describes but has not created yet.

    The subscriber list is deliberately absent rather than empty: nothing is
    subscribed to a topic that does not exist, and reporting that as a finding
    before anything is built would be reporting the obvious. Whether the
    address gets confirmed is knowable only afterwards, and the live scan says
    so then.
    """
    if not spec:
        return []

    return check_alarm({
        "alarm_name": spec.get("name") or "this alarm",
        "namespace": spec.get("namespace") or "",
        "region": spec.get("region"),
        "threshold": spec.get("threshold"),
        "period": spec.get("period"),
        "evaluation_periods": spec.get("evaluation_periods", 1),
        # The same defaults aws/alarms.py:create_alarm applies when the spec
        # leaves these out, rather than AWS's raw ones.
        #
        # This is the contract _bucket_check_spec states: the warnings shown
        # before creation are the warnings shown after it. It was broken here
        # in the safe direction, which is still broken - a billing alarm with
        # no treat_missing_data was pre-flighted as "missing", which is exactly
        # what the rule below warns about, and then created as "notBreaching",
        # which is not. The form warned that the alarm would spend its life
        # unable to judge, and then built one that could. A pre-flight that
        # predicts a problem the create does not produce is a pre-flight
        # people learn to skip.
        "treat_missing_data": spec.get("treat_missing_data")
            or ("notBreaching"
                if (spec.get("namespace") or "") == BILLING_NAMESPACE
                else "missing"),
        # A form that names somewhere to send the message counts as having a
        # destination; whether anyone is listening cannot be known yet.
        "alarm_actions": ["pending"] if spec.get("notify") else [],
        "actions_enabled": True,
        "subscriptions": None,
        "existing_alarm_count": None,
    })
