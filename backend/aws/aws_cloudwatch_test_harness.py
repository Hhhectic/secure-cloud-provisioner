"""
AWS CloudWatch Test Harness  —  KAN-12

Mirrors the structure of aws_ec2_test_harness.ipynb, in order:
  1. Confirm credentials work
  2. Find the prerequisites (billing metrics + something to monitor)
  3. Check alarm settings for problems BEFORE creating anything
  4. Permission probe (creates nothing)
  5. Really create an SNS topic + alarms, read them back
  6. Read live metrics and describe health in plain language
  7. Delete everything

MONEY WARNING: everything here is inside the always-free tier.
  * 10 alarms free, forever. This creates at most 2.
  * 1,000 SNS email notifications free per month.
  * Basic EC2 metrics (5-minute) and the AWS/Billing metric are free.
  * No compute is launched.

CREDENTIALS: same as the EC2 notebook. In Colab, use the key icon and add
  AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION. Never paste keys
  into a cell.

PERMISSIONS the login needs:
  sts:GetCallerIdentity
  cloudwatch:DescribeAlarms, PutMetricAlarm, DeleteAlarms,
             ListMetrics, GetMetricStatistics
  sns:CreateTopic, Subscribe, ListSubscriptionsByTopic, DeleteTopic, GetTopicAttributes
  ec2:DescribeInstances          (only to find an instance to monitor)

ONE-TIME CONSOLE STEP: billing metrics are not published until someone
  enables Billing -> Billing Preferences -> "Receive Billing Alerts".
  There is no API for that toggle. Step 2 detects it and tells you.
"""

# ============================================================
# 1. Install and connect
# ============================================================
# !pip install -q boto3

import datetime as dt

import boto3
from botocore.exceptions import ClientError

# Billing metrics are published ONLY to us-east-1, no matter where your
# resources live. This is the single most common reason a billing alarm
# silently never fires.
BILLING_REGION = "us-east-1"
BILLING_NAMESPACE = "AWS/Billing"
BILLING_PERIOD = 21_600  # 6 hours; estimated charges refresh no faster

ALARM_PREFIX = "provisioning-tool-test-"
TOPIC_NAME = "provisioning-tool-test-alerts"

# Change this to an address you can actually open. AWS sends a confirmation
# link and delivers nothing until you click it.
ALERT_EMAIL = "huorichard2@gmail.com"

try:
    from google.colab import userdata

    ACCESS_KEY = userdata.get("AWS_ACCESS_KEY_ID").strip()
    SECRET_KEY = userdata.get("AWS_SECRET_ACCESS_KEY").strip()
    REGION = userdata.get("AWS_REGION").strip() or "us-east-1"
    session = boto3.Session(
        aws_access_key_id=ACCESS_KEY,
        aws_secret_access_key=SECRET_KEY,
        region_name=REGION,
    )
    print("Using Colab secrets.")
except ImportError:
    # Running locally: boto3 reads ~/.aws/credentials on its own.
    REGION = "us-east-1"
    session = boto3.Session(region_name=REGION)
    print("Not in Colab. Using local AWS config.")

sts = session.client("sts")
ec2 = session.client("ec2")
cw = session.client("cloudwatch", region_name=REGION)
# Separate pinned client for anything billing-related.
cw_billing = session.client("cloudwatch", region_name=BILLING_REGION)
sns = session.client("sns", region_name=REGION)
print("Region:", REGION)


# Who am I? Fails fast if the keys are wrong or expired.
ACCOUNT_ID = None
try:
    me = sts.get_caller_identity()
    ACCOUNT_ID = me["Account"]
    print("Account:", ACCOUNT_ID)
    print("Identity:", me["Arn"])
except ClientError as e:
    print("Credentials not working:", e.response["Error"]["Message"])


# ============================================================
# 2. Find the prerequisites
# ============================================================
# Two things an alarm needs: a metric that actually exists, and somewhere
# to send the notification.

def billing_metrics_available(client):
    """The 'Receive Billing Alerts' preference has no API. The only reliable
    probe is asking whether the metric has ever been published.

    Returns one of: 'ready', 'not_enabled', 'denied', 'error'. These are three
    different problems in three different consoles, so do not collapse them
    into one boolean -- that sends people hunting in the wrong place.
    """
    try:
        resp = client.list_metrics(
            Namespace=BILLING_NAMESPACE, MetricName="EstimatedCharges"
        )
        return "ready" if resp["Metrics"] else "not_enabled"
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("AccessDenied", "AccessDeniedException", "AuthorizationError"):
            return "denied"
        print("Could not list billing metrics:", e.response["Error"]["Message"])
        return "error"


BILLING_STATUS = billing_metrics_available(cw_billing)
BILLING_READY = BILLING_STATUS == "ready"

if BILLING_STATUS == "ready":
    print("Billing metrics: available.")
elif BILLING_STATUS == "not_enabled":
    print(
        "Billing metrics: NOT published yet.\n"
        "  Open the Billing console -> Billing Preferences -> enable\n"
        "  'Receive Billing Alerts'. One-time, console only, free.\n"
        "  The billing alarm will be skipped until then."
    )
elif BILLING_STATUS == "denied":
    print(
        "Billing metrics: cannot tell -- this login lacks cloudwatch:ListMetrics.\n"
        "  This is an IAM problem, not the billing preference. Fix the policy\n"
        "  before assuming the toggle is off."
    )
else:
    print("Billing metrics: unknown state, see the error above.")


def find_running_instance(client):
    """Returns an instance id to monitor, or None. Purely optional --
    the CPU alarm is skipped if you have nothing running."""
    try:
        resp = client.describe_instances(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
        )
    except ClientError as e:
        print("Could not list instances:", e.response["Error"]["Message"])
        return None

    for reservation in resp["Reservations"]:
        for inst in reservation["Instances"]:
            return inst["InstanceId"]
    return None


INSTANCE_ID = find_running_instance(ec2)
print("Instance to monitor:", INSTANCE_ID or "none running (CPU alarm will be skipped)")


# ============================================================
# 3. The alarm checker
# ============================================================
# Same idea as check_firewall_rules in the EC2 notebook: this is the heart
# of the project, so it stays completely separate from the AWS code. Plain
# settings in, plain warnings out. No boto3 anywhere in it, which means you
# can test it without an AWS account and reuse the shape for Azure later.

FREE_TIER_ALARM_LIMIT = 10


def check_alarm_config(spec, existing_alarm_count=0):
    """spec: dict shaped like the kwargs for put_metric_alarm, plus an
    optional 'Region' key. Returns a list of {level, message} in plain
    language."""
    warnings = []

    namespace = spec.get("Namespace", "")
    region = spec.get("Region", "")
    actions = spec.get("AlarmActions", [])
    threshold = spec.get("Threshold")
    period = spec.get("Period")
    eval_periods = spec.get("EvaluationPeriods", 1)
    missing = spec.get("TreatMissingData", "missing")
    is_billing = namespace == BILLING_NAMESPACE

    if not actions:
        warnings.append({
            "level": "critical",
            "message": "This alarm has nowhere to send a notification. "
                       "It will turn red in the console and tell nobody.",
        })

    if is_billing and region and region != BILLING_REGION:
        warnings.append({
            "level": "critical",
            "message": f"Billing metrics only exist in {BILLING_REGION}. "
                       f"An alarm built in {region} will never receive data "
                       "and will never fire.",
        })

    if threshold is None or threshold <= 0:
        warnings.append({
            "level": "critical",
            "message": "The threshold is zero or missing, so this alarm is "
                       "either always firing or meaningless.",
        })
    elif is_billing and threshold > 50:
        warnings.append({
            "level": "info",
            "message": f"A ${threshold:.2f} threshold is high for a free-tier "
                       "project. You would be well past the free tier before "
                       "hearing anything.",
        })

    if is_billing and period is not None and period < BILLING_PERIOD:
        warnings.append({
            "level": "info",
            "message": "Estimated charges only update about every 6 hours, so "
                       "a shorter period does not make this alarm faster.",
        })

    if is_billing and missing == "missing":
        warnings.append({
            "level": "info",
            "message": "Billing data arrives in slow bursts. Treating gaps as "
                       "'missing' leaves this alarm stuck in INSUFFICIENT_DATA. "
                       "'notBreaching' is the usual choice.",
        })

    if not is_billing and eval_periods == 1:
        warnings.append({
            "level": "info",
            "message": "One evaluation period means a single brief spike sets "
                       "this off. Two or more is calmer.",
        })

    if existing_alarm_count >= FREE_TIER_ALARM_LIMIT:
        warnings.append({
            "level": "critical",
            "message": f"This account already has {existing_alarm_count} alarms. "
                       f"Past {FREE_TIER_ALARM_LIMIT} you start paying per alarm "
                       "per month.",
        })

    if not warnings:
        warnings.append({"level": "ok", "message": "No known problems found in these settings."})

    return warnings


def print_warnings(warnings):
    icons = {"critical": "[!]", "info": "[i]", "ok": "[ok]"}
    for w in warnings:
        print(icons.get(w["level"], "[?]"), w["message"])


# Try it with no AWS involved at all.
print("--- Billing alarm built in the wrong region ---")
print_warnings(check_alarm_config({
    "Namespace": BILLING_NAMESPACE, "Region": "us-west-2",
    "Threshold": 5.0, "Period": 21600, "AlarmActions": ["arn:aws:sns:..."],
    "TreatMissingData": "notBreaching",
}))

print("\n--- Alarm with no notification target ---")
print_warnings(check_alarm_config({
    "Namespace": "AWS/EC2", "Region": "us-east-1",
    "Threshold": 80.0, "Period": 300, "EvaluationPeriods": 2,
    "AlarmActions": [],
}))

print("\n--- A sensible billing alarm ---")
print_warnings(check_alarm_config({
    "Namespace": BILLING_NAMESPACE, "Region": BILLING_REGION,
    "Threshold": 5.0, "Period": 21600, "EvaluationPeriods": 1,
    "AlarmActions": ["arn:aws:sns:us-east-1:123456789012:topic"],
    "TreatMissingData": "notBreaching",
}))


# ============================================================
# 4. Permission probe
# ============================================================
# HONEST LIMITATION: unlike EC2, the CloudWatch and SNS APIs have no DryRun
# parameter. There is no way to ask "would this be allowed?" without either
# doing it or reading something adjacent.
#
# What we do instead: call a harmless read in the same service. If the read
# is denied, the write certainly is. If the read succeeds, the write is
# LIKELY allowed but not guaranteed -- a policy can grant DescribeAlarms and
# deny PutMetricAlarm. Weaker than the EC2 dry run. Say so out loud.

def probe(call, label, **kwargs):
    """Returns (ok, message). Performs a read. Creates nothing."""
    try:
        call(**kwargs)
        return True, f"{label} read succeeded, so writes are probably allowed."
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("AccessDenied", "AccessDeniedException", "AuthorizationError"):
            return False, f"Not allowed. This login is missing {label} permission."
        return False, f"{code}: {e.response['Error']['Message']}"


ok, msg = probe(cw.describe_alarms, "cloudwatch", MaxRecords=1)
print("Can reach CloudWatch?", ok, "->", msg)

ok_sns, msg_sns = probe(sns.list_topics, "sns")
print("Can reach SNS?", ok_sns, "->", msg_sns)

# Count what already exists, so the free-tier check in step 3 is real.
try:
    EXISTING_ALARMS = len(cw.describe_alarms()["MetricAlarms"])
except ClientError:
    EXISTING_ALARMS = 0
print("Alarms already in this region:", EXISTING_ALARMS)


# ============================================================
# 5. Create for real
# ============================================================
# The order matters: check first, then create. That is the entire premise
# of the tool.

TOPIC_ARN = None
CREATED_ALARMS = []

# --- the notification channel ---
# CreateTopic is idempotent: the same name returns the same ARN.
try:
    TOPIC_ARN = sns.create_topic(Name=TOPIC_NAME)["TopicArn"]
    print("Topic ready:", TOPIC_ARN)

    subs = sns.list_subscriptions_by_topic(TopicArn=TOPIC_ARN)["Subscriptions"]
    if any(s["Endpoint"] == ALERT_EMAIL for s in subs):
        print("Email already subscribed.")
    else:
        sns.subscribe(TopicArn=TOPIC_ARN, Protocol="email", Endpoint=ALERT_EMAIL)
        print(f"Confirmation email sent to {ALERT_EMAIL}. Click the link or "
              "alarms deliver nothing.")

    pending = [s for s in sns.list_subscriptions_by_topic(TopicArn=TOPIC_ARN)["Subscriptions"]
               if s["SubscriptionArn"] == "PendingConfirmation"]
    if pending:
        print(f"WARNING: {len(pending)} subscription(s) still unconfirmed.")
except ClientError as e:
    print("Could not set up notifications:", e.response["Error"]["Message"])


# --- billing alarm ---
billing_spec = {
    "AlarmName": f"{ALARM_PREFIX}billing-over-5usd",
    "AlarmDescription": "Month-to-date AWS charges went over $5. Check for "
                        "resources left running after testing.",
    "Namespace": BILLING_NAMESPACE,
    "MetricName": "EstimatedCharges",
    "Dimensions": [{"Name": "Currency", "Value": "USD"}],
    "Statistic": "Maximum",
    "Period": BILLING_PERIOD,
    "EvaluationPeriods": 1,
    "Threshold": 5.0,
    "ComparisonOperator": "GreaterThanThreshold",
    "TreatMissingData": "notBreaching",
    "ActionsEnabled": True,
    "AlarmActions": [TOPIC_ARN] if TOPIC_ARN else [],
}

print("\n--- Checking the billing alarm before creating it ---")
warnings = check_alarm_config({**billing_spec, "Region": BILLING_REGION}, EXISTING_ALARMS)
print_warnings(warnings)

has_critical = any(w["level"] == "critical" for w in warnings)
user_accepted_risk = False  # In the real tool this is the checkbox the user ticks.

if has_critical and not user_accepted_risk:
    print("Stopped. Fix the settings above or confirm you accept the risk.")
elif not BILLING_READY:
    print("Skipped: billing metrics are not published for this account yet.")
else:
    try:
        # Region is our own key for the checker, not an AWS parameter.
        cw_billing.put_metric_alarm(**billing_spec)
        CREATED_ALARMS.append((BILLING_REGION, billing_spec["AlarmName"]))
        print("Created:", billing_spec["AlarmName"])
    except ClientError as e:
        print("Failed:", e.response["Error"]["Message"])


# --- CPU alarm ---
if INSTANCE_ID:
    cpu_spec = {
        "AlarmName": f"{ALARM_PREFIX}cpu-{INSTANCE_ID}",
        "AlarmDescription": f"CPU above 80% on {INSTANCE_ID}",
        "Namespace": "AWS/EC2",
        "MetricName": "CPUUtilization",
        "Dimensions": [{"Name": "InstanceId", "Value": INSTANCE_ID}],
        "Statistic": "Average",
        "Period": 300,          # 5 min = free basic monitoring
        "EvaluationPeriods": 2,  # sustained, not a single spike
        "Threshold": 80.0,
        "ComparisonOperator": "GreaterThanThreshold",
        "TreatMissingData": "missing",
        "ActionsEnabled": True,
        "AlarmActions": [TOPIC_ARN] if TOPIC_ARN else [],
    }

    print("\n--- Checking the CPU alarm before creating it ---")
    cpu_warnings = check_alarm_config({**cpu_spec, "Region": REGION}, EXISTING_ALARMS)
    print_warnings(cpu_warnings)

    if any(w["level"] == "critical" for w in cpu_warnings) and not user_accepted_risk:
        print("Stopped.")
    else:
        try:
            cw.put_metric_alarm(**cpu_spec)
            CREATED_ALARMS.append((REGION, cpu_spec["AlarmName"]))
            print("Created:", cpu_spec["AlarmName"])
        except ClientError as e:
            print("Failed:", e.response["Error"]["Message"])
else:
    print("\nNo running instance, so no CPU alarm.")


# --- read it back from AWS and re-check what is actually live ---
print("\nWhat is actually live right now:")
for region, name in CREATED_ALARMS:
    client = cw_billing if region == BILLING_REGION else cw
    try:
        found = client.describe_alarms(AlarmNames=[name])["MetricAlarms"]
        if not found:
            print(f"  {name}: not found after creation (unexpected).")
            continue
        live = found[0]
        print(f"  {live['AlarmName']} | state: {live['StateValue']} | "
              f"region: {region}")
        if live["StateValue"] == "INSUFFICIENT_DATA":
            print("    (normal for a new alarm; it needs datapoints first)")
        print_warnings(check_alarm_config({
            "Namespace": live["Namespace"],
            "Region": region,
            "Threshold": live.get("Threshold"),
            "Period": live.get("Period"),
            "EvaluationPeriods": live.get("EvaluationPeriods", 1),
            "TreatMissingData": live.get("TreatMissingData", "missing"),
            "AlarmActions": live.get("AlarmActions", []),
        }))
    except ClientError as e:
        print("  Could not read back:", e.response["Error"]["Message"])


# ============================================================
# 6. Read live metrics in plain language
# ============================================================
# This is the "plain-language resource health stats" half of KAN-12.
# get_metric_statistics is a free read. It creates nothing.

def describe_instance_health(client, instance_id, hours=3):
    end = dt.datetime.now(dt.timezone.utc)
    start = end - dt.timedelta(hours=hours)
    try:
        resp = client.get_metric_statistics(
            Namespace="AWS/EC2",
            MetricName="CPUUtilization",
            Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
            StartTime=start,
            EndTime=end,
            Period=300,
            Statistics=["Average", "Maximum"],
        )
    except ClientError as e:
        return f"Could not read metrics: {e.response['Error']['Message']}"

    points = resp["Datapoints"]
    if not points:
        return (f"{instance_id} has reported no CPU data in the last {hours} hours. "
                "It may have just launched (metrics take about 5 minutes to appear), "
                "or it may be stopped.")

    avg = sum(p["Average"] for p in points) / len(points)
    peak = max(p["Maximum"] for p in points)

    if avg < 5:
        verdict = "essentially idle. If you are not using it, stop it to save money."
    elif avg < 40:
        verdict = "working normally with plenty of headroom."
    elif avg < 75:
        verdict = "working fairly hard but keeping up."
    else:
        verdict = "running hot. It may be undersized for this workload."

    return (f"{instance_id} averaged {avg:.1f}% CPU over the last {hours} hours "
            f"(peak {peak:.1f}%). It is {verdict}")


if INSTANCE_ID:
    print("\n" + describe_instance_health(cw, INSTANCE_ID))


# ============================================================
# 7. Clean up
# ============================================================
# Run this every time. Alarms under the free 10 cost nothing, but the habit
# is what stops a forgotten alarm from quietly counting against the limit.

for region, name in CREATED_ALARMS:
    client = cw_billing if region == BILLING_REGION else cw
    try:
        client.delete_alarms(AlarmNames=[name])
        print("Deleted alarm", name)
    except ClientError as e:
        print("Could not delete", name, ":", e.response["Error"]["Message"])
CREATED_ALARMS = []

if TOPIC_ARN:
    try:
        sns.delete_topic(TopicArn=TOPIC_ARN)
        print("Deleted topic", TOPIC_ARN)
        TOPIC_ARN = None
    except ClientError as e:
        print("Could not delete topic:", e.response["Error"]["Message"])
else:
    print("Nothing to delete.")