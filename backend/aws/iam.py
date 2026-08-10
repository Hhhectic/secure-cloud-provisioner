"""The account's IAM configuration, read and never written.

This module is the first one here that audits rather than provisions, and the
asymmetry is deliberate. Everything else in aws/ can create the thing it
inspects; there is no sensible "create an IAM posture" operation, and the
plausible write operations - delete an access key, detach a policy, remove a
login profile - are the ones most likely to lock a real person out of a real
account. So there is no create, no delete and no cleanup; the permissions this
module needs are reads and nothing else (docs/iam-policy-account-audit.json),
and the tool's inline policy denies every IAM write outright.

Two things about reading IAM are different from reading a bucket or a group.

The credential report is generated asynchronously. Asking for it starts a job
and the answer is not ready yet; every other reader here gets its answer from
the call it made. fetch_credential_report polls, which is the same
eventual-consistency shape as waiting for an instance to appear, wearing
different clothes.

Several checks depend on AWS-managed policies existing under a fixed ARN. When
that lookup fails the honest answer is "not checked", not "compliant". Those
land in "unreadable" alongside the permission failures, for the same reason S3
records settings it was not allowed to read: a scan that silently downgrades an
unanswered question to a pass is worse than one that admits the gap.
"""

import csv
import io
import json
import time
from datetime import datetime, timezone
from urllib.parse import unquote

import boto3
from botocore.exceptions import BotoCoreError, ClientError

# Raised by this module too, so one HTTP handler turns a missing permission into
# a 403 for every resource type. The name says bucket only because that is
# where it was first needed; the meaning - "not allowed to look, which is not
# the same as nothing being there" - is what IAM needs as well.
from aws.s3_buckets import PermissionDenied

# The row the credential report uses for the account's root user. It is not an
# IAM user and does not appear in ListUsers, so this row is the only place most
# of what CIS asks about root can be read.
ROOT_ROW = "<root_account>"

# Placeholders the credential report uses instead of a timestamp. They mean
# different things - never used, does not apply, AWS does not track it - but
# none of them is a date, and treating any of them as one is how a report
# column becomes a fabricated finding.
NOT_A_DATE = {"N/A", "not_supported", "no_information", ""}

# CIS thresholds, in days. Named because the numbers are the control.
UNUSED_CREDENTIAL_DAYS = 45      # 1.11
KEY_ROTATION_DAYS = 90           # 1.13
RECENT_ROOT_USE_DAYS = 30        # 1.6

MINIMUM_PASSWORD_LENGTH = 14     # 1.7
MINIMUM_PASSWORDS_REMEMBERED = 24  # 1.8

SUPPORT_POLICY_ARN = "arn:aws:iam::aws:policy/AWSSupportAccess"
CLOUDSHELL_POLICY_ARN = "arn:aws:iam::aws:policy/AWSCloudShellFullAccess"

CREDENTIAL_REPORT_TIMEOUT = 30
CREDENTIAL_REPORT_POLL = 2

# Codes meaning the report is being built rather than refused.
_REPORT_PENDING = {"ReportNotPresent", "ReportInProgress", "ReportExpired"}

_DENIED = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
           "NotAuthorized"}


# Where the caller's chosen region is remembered.
#
# IAM is a global service, so boto3 resolves whatever region it is given to the
# pseudo-region "aws-global" and the original choice cannot be read back off the
# client - meta.region_name and meta.config.region_name both say "aws-global".
# That is correct for IAM and useless for the other two services this audit
# needs: Access Analyzer is genuinely regional, and building either it or STS
# for "aws-global" fails to resolve an endpoint at all. Nothing in the registry's
# read(client, resource_id) contract carries a region, so it rides on the client.
REGION_ATTRIBUTE = "_provisioner_region"


def get_client(region="us-east-1"):
    """Initializes and returns an IAM client that remembers its region."""
    client = boto3.client("iam", region_name=region)
    setattr(client, REGION_ATTRIBUTE, region)
    return client


def client_region(iam):
    """The region this client was built for.

    Falls back to boto3's own view for a client built elsewhere - the tests
    construct plain clients, and so would anyone using this module directly.
    """
    return getattr(iam, REGION_ATTRIBUTE, None) or iam.meta.region_name


def _denied(e, permission):
    """Converts an access-denied ClientError into PermissionDenied, else re-raises."""
    if e.response["Error"]["Code"] in _DENIED:
        raise PermissionDenied(permission, e.response["Error"]["Message"]) from e
    raise


# --------------------------------------------------------------- Parsing helpers


def _flag(value):
    """The credential report writes booleans as the strings 'true' and 'false'."""
    return (value or "").strip().lower() == "true"


def _moment(value):
    """Parses a credential report timestamp, or None if the column holds no date.

    The report uses four different placeholders where a date would go, and none
    of them parses. Returning None for all four is right: every caller wants to
    know how long ago something happened, and "it never did" is not a duration.
    """
    text = (value or "").strip()
    if text in NOT_A_DATE:
        return None
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    # Rows written without an offset are UTC; comparing an aware datetime with
    # a naive one raises rather than returning a wrong answer, so normalise.
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _days_since(moment, now):
    """Whole days between moment and now, or None if there is no moment."""
    if moment is None:
        return None
    return max(0, (now - moment).days)


def _as_list(value):
    """Policy documents write a single item either bare or in a list."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _as_document(value):
    """Returns a policy document as a dict.

    botocore decodes IAM policy documents for most calls, so this is usually
    already a dict. It is not guaranteed to be - the wire format is
    URL-encoded JSON - and a str arriving where a dict was assumed fails inside
    the rule rather than here, which is a long way from the cause.
    """
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            return json.loads(unquote(value))
        except (ValueError, TypeError):
            return {}
    return {}


def grants_full_admin(document):
    """Whether a policy document allows every action on every resource.

    This is CIS 1.15's test and nothing more: an Allow of Action "*" on
    Resource "*". A statement carrying a Condition is not counted, because it
    is not unconditional administrative access, and NotAction is not counted
    either. Both could be written to be equivalent to full admin, and deciding
    that in general means evaluating IAM's policy language, which is a
    different program. Reporting the shape CIS names, and only that, keeps the
    citation honest.
    """
    statements = _as_list(_as_document(document).get("Statement"))

    for statement in statements:
        if not isinstance(statement, dict):
            continue
        if statement.get("Effect") != "Allow" or statement.get("Condition"):
            continue
        if "*" in _as_list(statement.get("Action")) \
                and "*" in _as_list(statement.get("Resource")):
            return True

    return False


# Wildcards that let a holder read the account's whole identity configuration.
# Not an exhaustive list of read actions: a policy naming twenty of them
# individually is somebody who thought about it, and one saying iam:List* is
# somebody who did not.
IAM_ENUMERATION_WILDCARDS = ("iam:*", "iam:get*", "iam:list*")


def grants_account_wide_iam_read(document):
    """Whether a policy lets its holder read every identity in the account.

    Deliberately not the same question as full admin, and reported separately.
    Somebody who can list every user, role and policy, and read the documents
    attached to them, can find the way up without changing anything: this is
    the first thing an attacker does with a credential and the last thing that
    leaves a trace, because it is all reads.

    Full admin is excluded rather than counted twice - CIS 1.15 already says
    that, and saying it again under a second heading would inflate the count
    without adding a fact.
    """
    for statement in _as_list(_as_document(document).get("Statement")):
        if not isinstance(statement, dict):
            continue
        if statement.get("Effect") != "Allow" or statement.get("Condition"):
            continue
        if "*" not in _as_list(statement.get("Resource")):
            continue

        actions = [str(a).lower() for a in _as_list(statement.get("Action"))]
        if "*" in actions:
            continue
        if any(a in IAM_ENUMERATION_WILDCARDS for a in actions):
            return True

    return False


# ------------------------------------------------------------ Credential report


def fetch_credential_report(iam, timeout=CREDENTIAL_REPORT_TIMEOUT,
                            poll=CREDENTIAL_REPORT_POLL, sleep=time.sleep,
                            clock=time.monotonic):
    """Returns the credential report as CSV text, or None if it never arrived.

    AWS builds this report asynchronously. GenerateCredentialReport starts the
    job and returns immediately; GetCredentialReport raises until it finishes.
    The generate call is safe to repeat - AWS reuses a report less than four
    hours old rather than rebuilding it - so the loop asks for the answer and
    only nudges the job along when told it is not ready.

    Returns None on timeout rather than raising. A report that is slow is a
    gap in the audit, and the scanner is built to report gaps; an exception
    here would abandon the fifteen findings that do not depend on it.

    sleep and clock are injected together. The elapsed time is measured rather
    than counted in poll intervals, because the calls themselves take time and
    a slow one would otherwise never count against the budget; that only leaves
    the timeout testable if the clock a test controls is the clock this reads.
    """
    deadline = clock() + timeout

    try:
        iam.generate_credential_report()
    except ClientError as e:
        _denied(e, "iam:GenerateCredentialReport")

    while True:
        try:
            return iam.get_credential_report()["Content"].decode("utf-8")
        except ClientError as e:
            if e.response["Error"]["Code"] not in _REPORT_PENDING:
                _denied(e, "iam:GetCredentialReport")
            if clock() + poll > deadline:
                return None
            sleep(poll)
            try:
                iam.generate_credential_report()
            except ClientError as retry_error:
                _denied(retry_error, "iam:GenerateCredentialReport")


def parse_credential_report(text, now=None):
    """Turns credential report CSV into {user_name: facts}.

    Every date column becomes an age in days, because no rule here cares when
    something happened, only how long ago. The root account keeps its
    "<root_account>" key so callers can pick it out.
    """
    now = now or datetime.now(timezone.utc)
    rows = {}

    for row in csv.DictReader(io.StringIO(text or "")):
        name = row.get("user")
        if not name:
            continue

        keys = []
        for slot in ("1", "2"):
            keys.append({
                "slot": int(slot),
                "active": _flag(row.get(f"access_key_{slot}_active")),
                "age_days": _days_since(
                    _moment(row.get(f"access_key_{slot}_last_rotated")), now),
                "last_used_days": _days_since(
                    _moment(row.get(f"access_key_{slot}_last_used_date")), now),
            })

        rows[name] = {
            "user_name": name,
            "arn": row.get("arn"),
            "created_days": _days_since(
                _moment(row.get("user_creation_time")), now),
            "password_enabled": _flag(row.get("password_enabled")),
            "password_last_used_days": _days_since(
                _moment(row.get("password_last_used")), now),
            "mfa_enabled": _flag(row.get("mfa_active")),
            "access_keys": keys,
        }

    return rows


# ------------------------------------------------------------------ Account-wide


def read_account_summary(iam):
    """Root credential facts from GetAccountSummary.

    Preferred over the credential report's root row for the two questions both
    can answer. This is a direct statement of current state, where the report
    is a snapshot that may be up to four hours old, and it is the only source
    available in an account whose report has not been generated yet.
    """
    try:
        summary = iam.get_account_summary()["SummaryMap"]
    except ClientError as e:
        _denied(e, "iam:GetAccountSummary")

    return {
        "root_access_keys": summary.get("AccountAccessKeysPresent", 0),
        "root_mfa_enabled": bool(summary.get("AccountMFAEnabled", 0)),
        "mfa_devices_in_use": summary.get("MFADevicesInUse", 0),
        "users": summary.get("Users", 0),
    }


def read_password_policy(iam):
    """Returns the account password policy, or None if none is set.

    NoSuchEntity here means no policy exists, which is a finding rather than a
    failure to read: an account with no password policy accepts AWS's defaults,
    which are below what CIS asks for.
    """
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            return None
        _denied(e, "iam:GetAccountPasswordPolicy")

    return {
        "minimum_length": policy.get("MinimumPasswordLength"),
        "passwords_remembered": policy.get("PasswordReusePrevention"),
        "max_age_days": policy.get("MaxPasswordAge"),
        "users_can_change": policy.get("AllowUsersToChangePassword", False),
    }


def root_uses_hardware_mfa(iam):
    """Whether root's MFA device is hardware, or None if it cannot be told.

    AWS offers no direct answer. What it offers is the list of *virtual* MFA
    devices, so root having MFA enabled while owning no virtual device is the
    evidence that the device is hardware. That inference only holds when root
    MFA is known to be on, which is why this returns None rather than False for
    an account with no root MFA at all - there is no device to classify, and
    CIS 1.4 already reports that.
    """
    try:
        devices = iam.list_virtual_mfa_devices()["VirtualMFADevices"]
    except ClientError as e:
        _denied(e, "iam:ListVirtualMFADevices")

    for device in devices:
        user = device.get("User") or {}
        # Root's ARN ends in ":root" and carries no user path.
        if (user.get("Arn") or "").endswith(":root"):
            return False

    return True


def read_analyzers(iam_region):
    """How many Access Analyzer analyzers exist in one region.

    CIS 1.19 asks for one in every region. This checks the region the tool is
    pointed at, and the finding says so rather than implying it swept all of
    them: an account-wide claim from a one-region read would be a stronger
    statement than the evidence supports.
    """
    client = boto3.client("accessanalyzer", region_name=iam_region)
    try:
        return len(client.list_analyzers(type="ACCOUNT")["analyzers"])
    except ClientError as e:
        _denied(e, "access-analyzer:ListAnalyzers")


def read_expired_certificates(iam, now=None):
    """Server certificates in IAM whose expiry has passed."""
    now = now or datetime.now(timezone.utc)
    try:
        listed = iam.list_server_certificates()["ServerCertificateMetadataList"]
    except ClientError as e:
        _denied(e, "iam:ListServerCertificates")

    expired = []
    for cert in listed:
        expires = cert.get("Expiration")
        if expires and expires < now:
            expired.append({
                "name": cert.get("ServerCertificateName"),
                "expired_days": _days_since(expires, now),
            })
    return expired


def policy_is_attached_to_anyone(iam, policy_arn):
    """Whether any user, group or role has this managed policy attached.

    NoSuchEntity is not False. It means the lookup failed to find a policy that
    exists in every real AWS account, so the caller records the check as
    unperformed instead of reporting a pass it did not earn.
    """
    try:
        entities = iam.list_entities_for_policy(PolicyArn=policy_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            return None
        _denied(e, "iam:ListEntitiesForPolicy")

    return bool(entities.get("PolicyUsers")
                or entities.get("PolicyGroups")
                or entities.get("PolicyRoles"))


def read_admin_policies(iam):
    """Attached policies that grant full administrative access.

    Only attached policies are examined. An unattached policy grants nobody
    anything, and CIS 1.15 asks what is attached rather than what exists.
    """
    try:
        pages = iam.get_paginator("list_policies").paginate(
            Scope="All", OnlyAttached=True)
        policies = [p for page in pages for p in page.get("Policies", [])]
    except ClientError as e:
        _denied(e, "iam:ListPolicies")

    admin = []
    for policy in policies:
        try:
            version = iam.get_policy_version(
                PolicyArn=policy["Arn"],
                VersionId=policy["DefaultVersionId"],
            )["PolicyVersion"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                continue
            _denied(e, "iam:GetPolicyVersion")

        if grants_full_admin(version.get("Document")):
            admin.append({
                "name": policy.get("PolicyName"),
                "arn": policy.get("Arn"),
                "attached_count": policy.get("AttachmentCount", 0),
            })

    return admin


def read_enumeration_policies(iam):
    """Attached policies that let their holder read every identity here.

    A second pass over the same policies rather than one loop producing both,
    so read_admin_policies keeps the shape its callers expect. The cost is a
    handful of extra GetPolicyVersion calls on an account's attached policies,
    which is a second at most and is paid once per audit.
    """
    try:
        pages = iam.get_paginator("list_policies").paginate(
            Scope="All", OnlyAttached=True)
        policies = [p for page in pages for p in page.get("Policies", [])]
    except ClientError as e:
        _denied(e, "iam:ListPolicies")

    enumerating = []
    for policy in policies:
        try:
            version = iam.get_policy_version(
                PolicyArn=policy["Arn"],
                VersionId=policy["DefaultVersionId"],
            )["PolicyVersion"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                continue
            _denied(e, "iam:GetPolicyVersion")

        if grants_account_wide_iam_read(version.get("Document")):
            enumerating.append({
                "name": policy.get("PolicyName"),
                "arn": policy.get("Arn"),
                "attached_count": policy.get("AttachmentCount", 0),
            })

    return enumerating


# ------------------------------------------------------------------------ Users


def read_users(iam):
    """Every IAM user, with how their permissions reach them.

    The credential report answers the credential questions. This answers the
    one it cannot: whether permissions arrive through a group or are pinned
    directly to the user, which is CIS 1.14.
    """
    try:
        pages = iam.get_paginator("list_users").paginate()
        listed = [u for page in pages for u in page.get("Users", [])]
    except ClientError as e:
        _denied(e, "iam:ListUsers")

    users = []
    for user in listed:
        name = user["UserName"]
        try:
            attached = iam.list_attached_user_policies(
                UserName=name)["AttachedPolicies"]
            inline = iam.list_user_policies(UserName=name)["PolicyNames"]
            groups = iam.list_groups_for_user(UserName=name)["Groups"]
        except ClientError as e:
            _denied(e, "iam:ListAttachedUserPolicies")

        users.append({
            "user_name": name,
            "arn": user.get("Arn"),
            "attached_policies": [p["PolicyName"] for p in attached],
            "inline_policies": list(inline),
            "group_count": len(groups),
        })

    return users


# ---------------------------------------------------------------- The whole read


def account_id(iam):
    """The account this tool is pointed at."""
    sts = boto3.client("sts", region_name=client_region(iam))
    try:
        return sts.get_caller_identity()["Account"]
    except ClientError as e:
        _denied(e, "sts:GetCallerIdentity")


def account_alias(iam):
    """The account's friendly name, or None. Cosmetic, so failure is not fatal."""
    try:
        aliases = iam.list_account_aliases()["AccountAliases"]
    except (ClientError, BotoCoreError):
        return None
    return aliases[0] if aliases else None


def read_account_for_scanning(iam, resource_id=None, now=None,
                              credential_report_timeout=CREDENTIAL_REPORT_TIMEOUT,
                              sleep=time.sleep):
    """Reads the account's IAM posture, formatted for scanner processing.

    Returns None when resource_id names an account this login is not in, which
    is this module's version of "no such resource": every other reader here
    returns None for a thing that is not there, and the routes turn that into a
    404 rather than a scan of whatever account the credentials happen to reach.

    Each read is attempted independently and a failure is recorded in
    "unreadable" rather than aborting the rest. An account where the login can
    see users but not the password policy still produces fourteen real findings,
    and the one it cannot check says so.
    """
    now = now or datetime.now(timezone.utc)
    this_account = account_id(iam)

    if resource_id and resource_id != this_account:
        return None

    settings = {
        "account_id": this_account,
        "account_alias": account_alias(iam),
        "region": client_region(iam),
    }
    unreadable = {}

    def attempt(name, permission, reader):
        try:
            settings[name] = reader()
        except PermissionDenied as e:
            settings[name] = None
            unreadable[name] = e.permission
        except (ClientError, BotoCoreError):
            # Everything reachable here is a read this tool was allowed to make
            # and AWS still would not answer - a service not available in the
            # region, a throttle, a transport failure. Same consequence as a
            # missing permission: the question went unanswered, and the scan
            # says so instead of scoring it as a pass.
            settings[name] = None
            unreadable[name] = permission

    attempt("summary", "iam:GetAccountSummary", lambda: read_account_summary(iam))
    attempt("password_policy", "iam:GetAccountPasswordPolicy",
            lambda: read_password_policy(iam))
    attempt("users", "iam:ListUsers", lambda: read_users(iam))
    attempt("admin_policies", "iam:ListPolicies", lambda: read_admin_policies(iam))
    attempt("enumeration_policies", "iam:ListPolicies",
            lambda: read_enumeration_policies(iam))
    attempt("expired_certificates", "iam:ListServerCertificates",
            lambda: read_expired_certificates(iam, now=now))
    attempt("analyzer_count", "access-analyzer:ListAnalyzers",
            lambda: read_analyzers(client_region(iam)))
    attempt("support_role_exists", "iam:ListEntitiesForPolicy",
            lambda: policy_is_attached_to_anyone(iam, SUPPORT_POLICY_ARN))
    attempt("cloudshell_full_access", "iam:ListEntitiesForPolicy",
            lambda: policy_is_attached_to_anyone(iam, CLOUDSHELL_POLICY_ARN))

    # Hardware MFA is only meaningful once root MFA is known to be on, and the
    # inference behind it needs the virtual device list, so it is read here
    # rather than alongside the summary it depends on.
    summary = settings.get("summary") or {}
    if summary.get("root_mfa_enabled"):
        attempt("root_hardware_mfa", "iam:ListVirtualMFADevices",
                lambda: root_uses_hardware_mfa(iam))
    else:
        settings["root_hardware_mfa"] = None

    attempt("credential_report", "iam:GetCredentialReport",
            lambda: fetch_credential_report(
                iam, timeout=credential_report_timeout, sleep=sleep))

    report = settings.pop("credential_report", None)
    if report is None and "credential_report" not in unreadable:
        # Asked for, permitted, and still not ready inside the timeout.
        unreadable["credential_report"] = "iam:GetCredentialReport"

    credentials = parse_credential_report(report, now=now) if report else {}
    settings["root_report"] = credentials.pop(ROOT_ROW, None)
    settings["credentials"] = credentials

    # The two views of a user are joined here rather than in the scanner, which
    # has no way to fetch either and no business knowing they came from
    # different calls.
    for user in settings.get("users") or []:
        user.update(credentials.get(user["user_name"], {}))

    settings["unreadable"] = unreadable
    return settings


def describe_account(settings):
    """What the account's IAM looks like, as opposed to what is wrong with it.

    Deliberately not the whole read. The user list carries key ages and last-use
    dates gathered so the rules could judge them, and handing that back as a
    description would restate every finding in a second shape.
    """
    if not settings:
        return None

    summary = settings.get("summary") or {}
    policy = settings.get("password_policy")

    return {
        "account_id": settings.get("account_id"),
        "account_alias": settings.get("account_alias"),
        "region": settings.get("region"),
        "user_count": len(settings.get("users") or []),
        "root_mfa_enabled": summary.get("root_mfa_enabled"),
        "root_access_keys": summary.get("root_access_keys"),
        "password_policy": policy,
        "checks_skipped": sorted(settings.get("unreadable") or {}),
    }


# ------------------------------------------------------------------------- Fix


def apply_fix(iam, resource_id, warning):
    """IAM findings are never fixed automatically.

    Every remediation in this section is a credential change: delete a key,
    detach a policy, remove a password, enable MFA on a device only its owner
    holds. Each one can lock a person or a running service out of the account,
    and unlike a bucket setting there is no undo - a deleted access key cannot
    be recreated with the same value.

    The account this runs against is also the one holding the tool's own
    credentials. A fix button here could plausibly remove the permission it
    needs to report what it just did.
    """
    return False, (
        "IAM findings are reported, not fixed. Every change here is to "
        "someone's credentials, and getting one wrong locks a person or a "
        "running service out of the account with no way back. Each finding "
        "says what to change and where."
    )
