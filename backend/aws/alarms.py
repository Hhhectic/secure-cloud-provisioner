"""CloudWatch alarms, and the SNS topic they shout into.

An alarm is three separate things that have to agree, and AWS will happily let
you build any one of them wrong: a metric that exists, a threshold on it, and a
destination for the message. Get the third wrong and you have monitoring that
looks complete in the console and reaches nobody. That is the failure this
module is arranged around, which is why the topic is read alongside the alarm
rather than left to the caller - the scanner cannot judge whether an alarm can
speak without knowing who is subscribed to what it speaks into.

Two refusals live here rather than in the rules, because a rule reports and
this has to decline.

A billing alarm outside us-east-1 cannot work. AWS publishes estimated charges
to that region only, so the alarm receives no data anywhere else and sits
showing INSUFFICIENT_DATA forever. The scanner reports one that already exists;
this refuses to add another, because building it would be building something
known-dead.

The eleventh alarm costs money every month, for as long as it exists, whether
or not it ever fires. That is the same shape as the NAT gateway refusal in
vpcs.py: a running charge that nothing here needs and that nobody notices
starting. A confirmation prompt does not survive a typo; a refusal does.
"""

import boto3
from botocore.exceptions import ClientError

from scanner.alarm_rules import (
    BILLING_NAMESPACE,
    BILLING_REGION,
    BILLING_PERIOD,
    FREE_TIER_ALARM_LIMIT,
)

MANAGED_TAG_KEY = "ManagedBy"
MANAGED_TAG_VALUE = "secure-cloud-provisioner"

DEFAULT_TOPIC_NAME = "secure-cloud-provisioner-alerts"

# What the two alarms this tool knows how to build actually watch. Anything
# else is a metric name typed by hand, which is allowed; these are the two
# worth making a menu out of.
BILLING_METRIC = "EstimatedCharges"
CPU_NAMESPACE = "AWS/EC2"
CPU_METRIC = "CPUUtilization"

_NOT_FOUND = {"ResourceNotFound", "ResourceNotFoundException",
              "ValidationError", "InvalidParameterValue"}


def get_client(region="us-east-1"):
    """Initializes and returns a CloudWatch client."""
    return boto3.client("cloudwatch", region_name=region)


def _sns(cloudwatch):
    """An SNS client in the same region as the alarm.

    A topic in another region can be notified, but nothing here builds one, and
    an alarm quietly wired to a topic somewhere else is exactly the kind of
    arrangement that is impossible to reason about later.
    """
    return boto3.client("sns", region_name=cloudwatch.meta.region_name)


# ------------------------------------------------------------------------ Read


def list_alarms(cloudwatch, only_ours=False):
    """Returns alarms, optionally only the ones this tool created."""
    paginator = cloudwatch.get_paginator("describe_alarms")
    found = []

    for page in paginator.paginate(AlarmTypes=["MetricAlarm"]):
        for alarm in page.get("MetricAlarms", []):
            if only_ours and not _is_ours(cloudwatch, alarm):
                continue
            found.append(alarm)

    return found


def _is_ours(cloudwatch, alarm):
    """Whether this tool created the alarm, by tag.

    Alarms carry tags but describe_alarms does not return them, so this is one
    extra call per alarm. That is why only_ours is a filter here rather than
    something every list pays for.
    """
    try:
        tags = cloudwatch.list_tags_for_resource(
            ResourceARN=alarm["AlarmArn"])["Tags"]
    except ClientError:
        return False
    return any(t["Key"] == MANAGED_TAG_KEY and t["Value"] == MANAGED_TAG_VALUE
               for t in tags)


def count_alarms(cloudwatch):
    """How many metric alarms exist in this region.

    Used both to report the free-tier finding and to refuse the alarm that
    would start charging for it.
    """
    total = 0
    for page in cloudwatch.get_paginator("describe_alarms").paginate(
            AlarmTypes=["MetricAlarm"]):
        total += len(page.get("MetricAlarms", []))
    return total


def read_subscriptions(cloudwatch, topic_arns):
    """Who would actually receive a message sent to these topics.

    Returns None if nothing could be read, which the scanner treats as "not
    checked" rather than "nobody is subscribed". The difference matters: one
    is a finding about the alarm, the other is a gap in the audit.

    A subscription whose ARN is the literal string "PendingConfirmation" is one
    where AWS emailed a link and nobody has clicked it. Those addresses receive
    nothing, so an alarm with only pending subscribers is as silent as one with
    no subscribers at all - and looks configured from every angle except this
    one.
    """
    if not topic_arns:
        return []

    sns = _sns(cloudwatch)
    subscriptions = []
    read_anything = False

    for arn in topic_arns:
        # An alarm action can be something other than a topic - an autoscaling
        # policy, an EC2 action. Those are not things anyone is subscribed to.
        if not arn.startswith("arn:aws:sns:"):
            continue
        try:
            paginator = sns.get_paginator("list_subscriptions_by_topic")
            for page in paginator.paginate(TopicArn=arn):
                read_anything = True
                for sub in page.get("Subscriptions", []):
                    subscriptions.append({
                        "protocol": sub.get("Protocol"),
                        "endpoint": sub.get("Endpoint"),
                        "confirmed":
                            sub.get("SubscriptionArn") != "PendingConfirmation",
                    })
        except ClientError:
            continue

    return subscriptions if read_anything else None


def read_alarm_for_scanning(cloudwatch, alarm_name):
    """Retrieves one alarm's settings formatted for scanner processing.

    Returns None when there is no such alarm. describe_alarms answers an
    unknown name with an empty list rather than by raising, which is the
    opposite of most of AWS and easy to mistake for a successful read of
    nothing.
    """
    try:
        found = cloudwatch.describe_alarms(
            AlarmNames=[alarm_name], AlarmTypes=["MetricAlarm"]
        )["MetricAlarms"]
    except ClientError as e:
        if e.response["Error"]["Code"] in _NOT_FOUND:
            return None
        raise

    if not found:
        return None

    return _to_scanner_shape(cloudwatch, found[0],
                             existing_alarm_count=count_alarms(cloudwatch))


def _to_scanner_shape(cloudwatch, alarm, existing_alarm_count=None):
    actions = alarm.get("AlarmActions") or []

    return {
        "alarm_name": alarm["AlarmName"],
        "alarm_arn": alarm.get("AlarmArn"),
        "namespace": alarm.get("Namespace"),
        "metric_name": alarm.get("MetricName"),
        "region": cloudwatch.meta.region_name,
        "threshold": alarm.get("Threshold"),
        "period": alarm.get("Period"),
        "evaluation_periods": alarm.get("EvaluationPeriods", 1),
        "treat_missing_data": alarm.get("TreatMissingData", "missing"),
        "actions_enabled": alarm.get("ActionsEnabled", True),
        "alarm_actions": actions,
        "state": alarm.get("StateValue"),
        "description": alarm.get("AlarmDescription"),
        "subscriptions": read_subscriptions(cloudwatch, actions),
        "existing_alarm_count": existing_alarm_count,
    }


def billing_metrics_available(cloudwatch):
    """Whether AWS has ever published a spending figure for this account.

    'Receive Billing Alerts' is a console toggle with no API behind it, so the
    only reliable probe is asking whether the metric exists at all. The three
    failures are kept apart because they are fixed in three different places:
    a billing preference, an IAM policy, and everything else.

    Returns 'ready', 'not_enabled', 'denied' or 'error'.
    """
    try:
        found = cloudwatch.list_metrics(
            Namespace=BILLING_NAMESPACE, MetricName=BILLING_METRIC)["Metrics"]
        return "ready" if found else "not_enabled"
    except ClientError as e:
        if e.response["Error"]["Code"] in ("AccessDenied",
                                           "AccessDeniedException",
                                           "AuthorizationError"):
            return "denied"
        return "error"


# ---------------------------------------------------------------------- Create


def ensure_topic(cloudwatch, name=DEFAULT_TOPIC_NAME, email=None):
    """Finds or creates the topic an alarm notifies, and subscribes an address.

    Returns (topic_arn, problems). CreateTopic is idempotent - the same name
    returns the same ARN rather than a second topic - so this is safe to call
    on every create.

    Subscribing cannot complete here. AWS sends a confirmation email and the
    address receives nothing until somebody opens it and clicks the link, which
    is a person's job and not this process's. That is reported as a problem
    rather than hidden, because an alarm whose only subscriber never confirmed
    is silent and looks fine.
    """
    problems = []
    sns = _sns(cloudwatch)

    try:
        topic_arn = sns.create_topic(
            Name=name,
            Tags=[{"Key": MANAGED_TAG_KEY, "Value": MANAGED_TAG_VALUE}],
        )["TopicArn"]
    except ClientError as e:
        return None, [f"Could not create somewhere to send the alert: "
                      f"{e.response['Error']['Message']}"]

    if not email:
        return topic_arn, problems

    already = read_subscriptions(cloudwatch, [topic_arn]) or []
    if any(s.get("endpoint") == email for s in already):
        return topic_arn, problems

    try:
        sns.subscribe(TopicArn=topic_arn, Protocol="email", Endpoint=email)
        problems.append(
            f"AWS has emailed {email} a confirmation link. Until somebody "
            "clicks it that address receives nothing, so this alarm cannot "
            "reach anyone yet. Check the spam folder."
        )
    except ClientError as e:
        problems.append(f"Could not subscribe {email}: "
                        f"{e.response['Error']['Message']}")

    return topic_arn, problems


def create_alarm(cloudwatch, name, namespace, metric_name, threshold,
                 region=None, period=None, evaluation_periods=2,
                 treat_missing_data=None, comparison="GreaterThanThreshold",
                 statistic=None, dimensions=None, notify=True, email=None,
                 description=None):
    """Creates one metric alarm. Returns (ok, name_or_error, problems).

    Refuses two things outright rather than reporting them afterwards; see the
    module docstring for why each is a refusal and not a warning.
    """
    problems = []
    region = region or cloudwatch.meta.region_name
    is_billing = namespace == BILLING_NAMESPACE

    # ---- Refusal: a billing alarm anywhere else cannot receive data ---------
    if is_billing and region != BILLING_REGION:
        return False, (
            f"A spending alarm has to live in {BILLING_REGION}, and this one "
            f"was asked for in {region}. AWS publishes spending figures to "
            f"{BILLING_REGION} only, so an alarm built here would receive "
            "nothing and could never go off. Nothing was created. Switch the "
            f"region to {BILLING_REGION} and try again."
        ), []

    # ---- Refusal: the eleventh alarm starts a monthly charge ----------------
    existing = count_alarms(cloudwatch)
    if existing >= FREE_TIER_ALARM_LIMIT:
        return False, (
            f"This account already has {existing} alarms and the first "
            f"{FREE_TIER_ALARM_LIMIT} are the free ones. Creating another "
            "would start a charge every month for as long as it exists, "
            "whether or not it ever goes off. Nothing was created. Delete an "
            "alarm nobody reads and try again."
        ), []

    if is_billing:
        status = billing_metrics_available(cloudwatch)
        if status == "not_enabled":
            problems.append(
                "This account has never published a spending figure, because "
                "'Receive Billing Alerts' is off. It is a one-time switch in "
                "the Billing console with no API behind it. The alarm is "
                "created and will sit saying it has no data until somebody "
                "turns that on."
            )
        elif status == "denied":
            problems.append(
                "Could not tell whether spending figures are published: this "
                "login is not allowed to list metrics. That is a permissions "
                "problem rather than a billing one."
            )

    topic_arn = None
    if notify:
        topic_arn, topic_problems = ensure_topic(cloudwatch, email=email)
        problems.extend(topic_problems)

    # Defaults that make each kind of alarm work rather than merely exist. A
    # billing alarm asked to check faster than the figure changes is not
    # wrong, just pointless, and treating its gaps as breaches leaves it stuck.
    if period is None:
        period = BILLING_PERIOD if is_billing else 300
    if treat_missing_data is None:
        treat_missing_data = "notBreaching" if is_billing else "missing"
    if statistic is None:
        statistic = "Maximum" if is_billing else "Average"

    if dimensions is None and is_billing:
        dimensions = [{"Name": "Currency", "Value": "USD"}]

    kwargs = {
        "AlarmName": name,
        "Namespace": namespace,
        "MetricName": metric_name,
        "Statistic": statistic,
        "ComparisonOperator": comparison,
        "Threshold": float(threshold),
        "Period": period,
        "EvaluationPeriods": evaluation_periods,
        "TreatMissingData": treat_missing_data,
        "ActionsEnabled": True,
        "AlarmDescription": description or
                            "Created by secure-cloud-provisioner",
        "Tags": [
            {"Key": MANAGED_TAG_KEY, "Value": MANAGED_TAG_VALUE},
            {"Key": "Environment", "Value": "test"},
        ],
    }
    if dimensions:
        kwargs["Dimensions"] = dimensions
    if topic_arn:
        kwargs["AlarmActions"] = [topic_arn]

    try:
        cloudwatch.put_metric_alarm(**kwargs)
    except ClientError as e:
        return False, e.response["Error"]["Message"], problems

    return True, name, problems


# ---------------------------------------------------------------------- Delete


def delete_alarm(cloudwatch, alarm_name):
    """Removes one alarm.

    Deleting an alarm is not destructive in the way deleting a bucket is -
    nothing is lost but the watching. It is still worth saying what stops,
    because the thing an alarm protects against is silent until it happens.
    """
    if read_alarm_for_scanning(cloudwatch, alarm_name) is None:
        return False, f"There is no alarm called '{alarm_name}'."

    try:
        cloudwatch.delete_alarms(AlarmNames=[alarm_name])
    except ClientError as e:
        return False, e.response["Error"]["Message"]

    return True, (
        f"Deleted {alarm_name}. Whatever it was watching is no longer watched; "
        "nothing else changed."
    )


def cleanup_all_managed_alarms(cloudwatch):
    """Removes every alarm this tool created."""
    results = []
    for alarm in list_alarms(cloudwatch, only_ours=True):
        ok, message = delete_alarm(cloudwatch, alarm["AlarmName"])
        results.append((alarm["AlarmName"], ok, message))
    return results


# ------------------------------------------------------------------------- Fix


def apply_fix(cloudwatch, alarm_name, warning):
    """Repairs the alarm settings that can be corrected in place.

    Only the settings whose right value is not a judgement call are offered.
    Where a message should go is a decision about who is on call; a threshold
    is a decision about how much money is acceptable. Neither is this tool's to
    make, so both are reported and left alone.
    """
    setting = (warning.get("rule") or {}).get("setting")

    current = read_alarm_for_scanning(cloudwatch, alarm_name)
    if current is None:
        return False, f"There is no alarm called '{alarm_name}'."

    if setting == "actions_disabled":
        try:
            cloudwatch.enable_alarm_actions(AlarmNames=[alarm_name])
        except ClientError as e:
            return False, e.response["Error"]["Message"]
        return True, (
            f"Switched notifications back on for {alarm_name}. It will send a "
            "message the next time it goes off."
        )

    if setting == "treat_missing_data":
        ok, result, _ = _rebuild_with(cloudwatch, current,
                                      TreatMissingData="notBreaching")
        if not ok:
            return False, result
        return True, (
            f"{alarm_name} now treats a gap in the spending data as 'nothing "
            "is wrong' rather than as something it cannot judge, so it will "
            "watch instead of sitting in insufficient data."
        )

    if setting == "evaluation_periods":
        ok, result, _ = _rebuild_with(cloudwatch, current, EvaluationPeriods=2)
        if not ok:
            return False, result
        return True, (
            f"{alarm_name} now needs two readings in a row before it goes off, "
            "so a single brief spike will not set it going."
        )

    return False, (
        "That one cannot be fixed automatically. Where an alert should go, and "
        "what limit is worth being told about, are decisions about who is on "
        "call and how much money is acceptable. This tool will not guess "
        "either."
    )


def _rebuild_with(cloudwatch, current, **changes):
    """Rewrites one alarm with some settings changed.

    CloudWatch has no partial update: put_metric_alarm replaces the alarm
    entirely, and anything left out reverts to a default. So every setting is
    read back and resent, and only the named ones differ.
    """
    kwargs = {
        "AlarmName": current["alarm_name"],
        "Namespace": current["namespace"],
        "MetricName": current["metric_name"],
        "ComparisonOperator": "GreaterThanThreshold",
        "Threshold": current["threshold"],
        "Period": current["period"],
        "EvaluationPeriods": current["evaluation_periods"],
        "TreatMissingData": current["treat_missing_data"],
        "ActionsEnabled": current["actions_enabled"],
        "AlarmDescription": current.get("description") or "",
        "Statistic": "Maximum"
        if current["namespace"] == BILLING_NAMESPACE else "Average",
    }
    if current.get("alarm_actions"):
        kwargs["AlarmActions"] = current["alarm_actions"]
    if current["namespace"] == BILLING_NAMESPACE:
        kwargs["Dimensions"] = [{"Name": "Currency", "Value": "USD"}]

    kwargs.update(changes)

    try:
        cloudwatch.put_metric_alarm(**kwargs)
    except ClientError as e:
        return False, e.response["Error"]["Message"], []
    return True, current["alarm_name"], []
