"""Tests for the account access audit and the rules over it.

Split three ways, and the split matters.

The reader tests run against moto, and moto's IAM is further from AWS than its
EC2 is. It has no root account row in the credential report, no AWS-managed
policies, and no Access Analyzer at all. So anything that depends on how AWS
behaves is tested against an explicit stub that models the behaviour being
relied on, rather than against a fake that happens to agree.

The rule tests take dicts and touch no cloud at all, which is the point of
keeping scanner/ free of boto3: every finding below is reachable without an
account, including the ones that need a 400-day-old access key.

The citation tests guard the one thing in this feature that cannot be found by
running it. Section 1 was renumbered in CIS v5.0.0, most of these IDs are one
away from their v3.0.0 value, and a wrong-but-plausible number is exactly the
error that survives review.
"""

import json
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from api import registry
from aws import iam
from aws.s3_buckets import PermissionDenied
from scanner import controls
from scanner.common import CRITICAL, WARNING, INFO, cited, fixable, worst_level
from scanner.iam_rules import check_account

REGION = "us-east-1"
ACCOUNT = "123456789012"
NOW = datetime(2026, 8, 7, 12, 0, tzinfo=timezone.utc)

FULL_ADMIN = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}


@pytest.fixture
def iam_client():
    with mock_aws():
        yield iam.get_client(REGION)


# --------------------------------------------------------------- Test helpers


def _settings(**overrides):
    """An account with nothing wrong with it, for one thing to be broken in."""
    base = {
        "account_id": ACCOUNT,
        "account_alias": "example",
        "region": REGION,
        "summary": {"root_access_keys": 0, "root_mfa_enabled": True},
        "root_hardware_mfa": True,
        "root_report": {},
        "password_policy": {
            "minimum_length": 14,
            "passwords_remembered": 24,
            # An account with nothing wrong with it has an expiry set. Without
            # this the helper produced a password_never_expires note in every
            # test that used it - the note firing correctly, against a default
            # that claimed to be well run and was missing one.
            "max_age_days": 90,
        },
        "users": [],
        "credentials": {},
        "admin_policies": [],
        "expired_certificates": [],
        "analyzer_count": 1,
        "support_role_exists": True,
        "cloudshell_full_access": False,
        "unreadable": {},
    }
    base.update(overrides)
    return base


def _user(name="alice", **overrides):
    base = {
        "user_name": name,
        "arn": f"arn:aws:iam::{ACCOUNT}:user/{name}",
        "created_days": 10,
        "password_enabled": False,
        "password_last_used_days": None,
        "mfa_enabled": True,
        "access_keys": [],
        "attached_policies": [],
        "inline_policies": [],
        "group_count": 1,
    }
    base.update(overrides)
    return base


def _key(slot=1, active=True, age_days=10, last_used_days=1):
    return {"slot": slot, "active": active, "age_days": age_days,
            "last_used_days": last_used_days}


def _find(warnings, setting):
    """The one finding whose rule_id ends in this setting."""
    matches = [w for w in warnings if w["rule_id"].endswith(f":{setting}")]
    assert len(matches) == 1, f"expected one {setting}, got {len(matches)}"
    return matches[0]


def _settings_of(warnings):
    return {w["rule"]["setting"] for w in warnings}


# =========================================================== Reading the account


def test_the_client_remembers_the_region_boto3_throws_away():
    """IAM is global, so boto3 resolves any region to "aws-global" and the
    caller's choice cannot be read back. Access Analyzer and STS are not
    global, and neither has an endpoint in a pseudo-region."""
    with mock_aws():
        client = iam.get_client("eu-west-2")
        assert client.meta.region_name == "aws-global"
        assert iam.client_region(client) == "eu-west-2"


def test_a_client_built_elsewhere_still_reports_a_region():
    with mock_aws():
        assert iam.client_region(boto3.client("iam", region_name=REGION))


def test_asking_about_another_account_returns_none_rather_than_this_one(iam_client):
    """The reader's version of "no such resource". Scanning whichever account
    the credentials happen to reach, when asked about a different one, would
    answer a question nobody posed."""
    assert iam.read_account_for_scanning(iam_client, "999999999999") is None


def test_asking_about_this_account_by_id_works(iam_client):
    settings = iam.read_account_for_scanning(iam_client, ACCOUNT)
    assert settings["account_id"] == ACCOUNT


def test_no_resource_id_means_whichever_account_the_login_is_in(iam_client):
    assert iam.read_account_for_scanning(iam_client)["account_id"] == ACCOUNT


def test_a_check_that_could_not_run_is_recorded_not_skipped_silently(iam_client):
    """moto has no Access Analyzer, which makes it a working example of the
    case this has to handle: the question went unanswered."""
    settings = iam.read_account_for_scanning(iam_client)
    assert settings["unreadable"]["analyzer_count"] == "access-analyzer:ListAnalyzers"
    assert settings["analyzer_count"] is None


def test_one_unreadable_check_does_not_abandon_the_others(iam_client):
    iam_client.create_user(UserName="alice")
    settings = iam.read_account_for_scanning(iam_client)

    assert "analyzer_count" in settings["unreadable"]
    assert [u["user_name"] for u in settings["users"]] == ["alice"]
    assert settings["summary"]["root_mfa_enabled"] is False


def test_no_password_policy_reads_as_none_rather_than_unreadable(iam_client):
    """NoSuchEntity here means no policy is set, which is a finding. Recording
    it as a failed read would replace a real finding with a shrug."""
    settings = iam.read_account_for_scanning(iam_client)
    assert settings["password_policy"] is None
    assert "password_policy" not in settings["unreadable"]


def test_a_password_policy_is_read_back(iam_client):
    iam_client.update_account_password_policy(
        MinimumPasswordLength=16, PasswordReusePrevention=24)
    policy = iam.read_password_policy(iam_client)
    assert policy["minimum_length"] == 16
    assert policy["passwords_remembered"] == 24


def test_users_carry_how_their_permissions_reach_them(iam_client):
    iam_client.create_user(UserName="alice")
    iam_client.create_group(GroupName="engineers")
    iam_client.add_user_to_group(GroupName="engineers", UserName="alice")
    iam_client.put_user_policy(UserName="alice", PolicyName="pinned",
                               PolicyDocument=json.dumps(FULL_ADMIN))

    alice = iam.read_users(iam_client)[0]
    assert alice["group_count"] == 1
    assert alice["inline_policies"] == ["pinned"]


def test_the_two_views_of_a_user_are_joined_before_the_scanner_sees_them(iam_client):
    """The credential report knows about keys and passwords; ListUsers knows
    about policies and groups. A rule cannot fetch either, so they arrive as
    one user."""
    iam_client.create_user(UserName="alice")
    iam_client.create_access_key(UserName="alice")

    settings = iam.read_account_for_scanning(iam_client)
    alice = settings["users"][0]

    assert alice["group_count"] == 0            # from ListUsers
    assert any(k["active"] for k in alice["access_keys"])  # from the report


def test_only_attached_policies_are_examined_for_full_admin(iam_client):
    """An unattached policy grants nobody anything, and CIS 1.15 asks what is
    attached rather than what exists."""
    created = iam_client.create_policy(
        PolicyName="godmode", PolicyDocument=json.dumps(FULL_ADMIN))["Policy"]

    assert iam.read_admin_policies(iam_client) == []

    iam_client.create_user(UserName="alice")
    iam_client.attach_user_policy(UserName="alice", PolicyArn=created["Arn"])

    found = iam.read_admin_policies(iam_client)
    assert [p["name"] for p in found] == ["godmode"]


def test_a_narrow_attached_policy_is_not_reported_as_admin(iam_client):
    narrow = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
    created = iam_client.create_policy(
        PolicyName="reader", PolicyDocument=json.dumps(narrow))["Policy"]
    iam_client.create_user(UserName="alice")
    iam_client.attach_user_policy(UserName="alice", PolicyArn=created["Arn"])

    assert iam.read_admin_policies(iam_client) == []


def test_the_audit_never_creates_deletes_or_cleans_up():
    for operation in (registry.IAM.create, registry.IAM.delete,
                      registry.IAM.cleanup):
        with pytest.raises(NotImplementedError):
            operation(None, None)


def test_fixing_an_iam_finding_is_refused_with_a_reason(iam_client):
    ok, message = registry.IAM.fix(iam_client, ACCOUNT, {}, {})
    assert not ok
    assert "reported, not fixed" in message


# ------------------------------------------------- Recognising full admin access


def test_full_admin_is_recognised_from_a_decoded_document():
    assert iam.grants_full_admin(FULL_ADMIN)


def test_full_admin_is_recognised_from_the_url_encoded_wire_format():
    """botocore decodes policy documents for most calls, but the wire format is
    URL-encoded JSON and a str arriving where a dict was assumed would fail
    inside the rule, a long way from the cause."""
    assert iam.grants_full_admin(quote(json.dumps(FULL_ADMIN)))


def test_a_single_statement_written_bare_rather_than_in_a_list_is_read():
    assert iam.grants_full_admin(
        {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}})


def test_a_conditional_allow_is_not_unconditional_admin():
    """Deciding whether a condition is toothless means evaluating IAM's policy
    language. CIS 1.15 names one shape and this reports that shape only."""
    assert not iam.grants_full_admin({"Statement": [{
        "Effect": "Allow", "Action": "*", "Resource": "*",
        "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
    }]})


def test_a_deny_of_everything_is_not_admin():
    assert not iam.grants_full_admin(
        {"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]})


def test_a_wildcard_action_on_one_resource_is_not_full_admin():
    assert not iam.grants_full_admin({"Statement": [
        {"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::one"}]})


def test_unparseable_policy_material_is_not_reported_as_admin():
    for junk in (None, "", "not json", 42, {"Statement": ["a string"]}):
        assert not iam.grants_full_admin(junk)


# ------------------------------------------------- The asynchronous credential report


class _ReportStub:
    """An IAM client that models the credential report the way AWS does it.

    moto answers GetCredentialReport immediately, so the polling this needs
    would never run against it and the timeout would never be reached. AWS
    starts a job and raises until it finishes, which is the behaviour being
    relied on, so it is stated here rather than assumed.
    """

    def __init__(self, ready_after, content="user\nalice\n"):
        self.ready_after = ready_after
        self.content = content
        self.gets = 0
        self.generates = 0

    def generate_credential_report(self):
        self.generates += 1
        return {"State": "STARTED"}

    def get_credential_report(self):
        self.gets += 1
        if self.gets <= self.ready_after:
            raise ClientError(
                {"Error": {"Code": "ReportInProgress", "Message": "building"}},
                "GetCredentialReport")
        return {"Content": self.content.encode()}


class _FakeClock:
    """A clock that only moves when the code under test sleeps.

    The timeout is measured against a clock rather than counted in poll
    intervals, so a test whose sleep does nothing would never reach the
    deadline and would poll until the stub relented. Driving both from here
    exercises the real timeout without spending real seconds.
    """

    def __init__(self):
        self.elapsed = 0.0
        self.slept = []

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.elapsed += seconds

    def __call__(self):
        return self.elapsed


def test_the_credential_report_is_waited_for_rather_than_given_up_on():
    stub = _ReportStub(ready_after=2)
    clock = _FakeClock()

    text = iam.fetch_credential_report(stub, timeout=30, poll=1,
                                       sleep=clock.sleep, clock=clock)

    assert text == "user\nalice\n"
    assert stub.gets == 3
    assert clock.slept == [1, 1]


def test_asking_again_nudges_the_job_along_rather_than_only_waiting():
    """The generate call is safe to repeat - AWS reuses a report under four
    hours old - and an account that has never generated one needs the nudge."""
    stub = _ReportStub(ready_after=2)
    clock = _FakeClock()

    iam.fetch_credential_report(stub, timeout=30, poll=1,
                                sleep=clock.sleep, clock=clock)

    assert stub.generates == 3


def test_a_report_that_never_arrives_returns_none_instead_of_raising():
    """Fifteen findings do not depend on the report. An exception here would
    throw all of them away to say one thing was slow."""
    stub = _ReportStub(ready_after=999)
    clock = _FakeClock()

    assert iam.fetch_credential_report(stub, timeout=3, poll=1,
                                       sleep=clock.sleep, clock=clock) is None
    assert clock.elapsed <= 3


def test_a_report_that_never_arrives_is_recorded_as_an_unread_check(monkeypatch,
                                                                    iam_client):
    monkeypatch.setattr(iam, "fetch_credential_report",
                        lambda *a, **k: None)
    settings = iam.read_account_for_scanning(iam_client)
    assert settings["unreadable"]["credential_report"] == "iam:GetCredentialReport"


def test_being_refused_the_report_is_a_permission_problem_not_a_slow_one():
    class Denied:
        def generate_credential_report(self):
            raise ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "no"}},
                "GenerateCredentialReport")

    with pytest.raises(PermissionDenied):
        iam.fetch_credential_report(Denied())


# ------------------------------------------------------ Parsing the report itself


def _report_csv(rows):
    columns = ["user", "arn", "user_creation_time", "password_enabled",
               "password_last_used", "mfa_active",
               "access_key_1_active", "access_key_1_last_rotated",
               "access_key_1_last_used_date",
               "access_key_2_active", "access_key_2_last_rotated",
               "access_key_2_last_used_date"]
    lines = [",".join(columns)]
    for row in rows:
        lines.append(",".join(str(row.get(c, "N/A")) for c in columns))
    return "\n".join(lines)


def test_dates_become_ages_because_no_rule_cares_when_only_how_long_ago():
    text = _report_csv([{
        "user": "alice",
        "user_creation_time": (NOW - timedelta(days=500)).isoformat(),
        "password_enabled": "true",
        "password_last_used": (NOW - timedelta(days=60)).isoformat(),
        "mfa_active": "false",
        "access_key_1_active": "true",
        "access_key_1_last_rotated": (NOW - timedelta(days=400)).isoformat(),
        "access_key_1_last_used_date": (NOW - timedelta(days=2)).isoformat(),
    }])

    alice = iam.parse_credential_report(text, now=NOW)["alice"]

    assert alice["created_days"] == 500
    assert alice["password_last_used_days"] == 60
    assert alice["mfa_enabled"] is False
    assert alice["access_keys"][0]["age_days"] == 400
    assert alice["access_keys"][0]["last_used_days"] == 2


@pytest.mark.parametrize("placeholder",
                         ["N/A", "not_supported", "no_information", ""])
def test_the_four_things_the_report_writes_instead_of_a_date_are_not_dates(
        placeholder):
    """They mean different things - never used, does not apply, not tracked -
    and none of them is a duration. Treating one as a date is how a report
    column becomes a fabricated finding."""
    text = _report_csv([{"user": "alice", "password_last_used": placeholder}])
    assert iam.parse_credential_report(text, now=NOW)["alice"][
        "password_last_used_days"] is None


def test_a_timestamp_without_an_offset_is_read_as_utc():
    """Comparing an aware datetime with a naive one raises rather than
    returning a wrong answer, so the whole scan would fail on one column."""
    text = _report_csv([{"user": "alice",
                         "password_last_used": "2026-08-05T12:00:00"}])
    assert iam.parse_credential_report(text, now=NOW)["alice"][
        "password_last_used_days"] == 2


def test_the_root_row_is_kept_separate_from_the_users(iam_client):
    text = _report_csv([
        {"user": iam.ROOT_ROW, "password_last_used": (
            NOW - timedelta(days=3)).isoformat()},
        {"user": "alice"},
    ])
    parsed = iam.parse_credential_report(text, now=NOW)
    assert iam.ROOT_ROW in parsed and "alice" in parsed


def test_an_empty_report_parses_to_nothing_rather_than_raising():
    assert iam.parse_credential_report("") == {}
    assert iam.parse_credential_report(None) == {}


# ----------------------------------------------------- Hardware MFA on the root user


class _MFAStub:
    def __init__(self, devices):
        self.devices = devices

    def list_virtual_mfa_devices(self):
        return {"VirtualMFADevices": self.devices}


def test_root_owning_a_virtual_device_means_the_second_step_is_not_hardware():
    stub = _MFAStub([{"User": {"Arn": f"arn:aws:iam::{ACCOUNT}:root"}}])
    assert iam.root_uses_hardware_mfa(stub) is False


def test_root_owning_no_virtual_device_means_the_device_is_hardware():
    """AWS offers no direct answer, so the absence of a virtual device is the
    only evidence available. It only holds where root MFA is known to be on,
    which is why the caller asks this question second."""
    stub = _MFAStub([{"User": {"Arn": f"arn:aws:iam::{ACCOUNT}:user/alice"}}])
    assert iam.root_uses_hardware_mfa(stub) is True


def test_hardware_mfa_is_not_asked_about_when_root_has_no_second_step(iam_client):
    settings = iam.read_account_for_scanning(iam_client)
    assert settings["summary"]["root_mfa_enabled"] is False
    assert settings["root_hardware_mfa"] is None


# ------------------------------------------------------------- Expired certificates


class _CertStub:
    def __init__(self, certs):
        self.certs = certs

    def list_server_certificates(self):
        return {"ServerCertificateMetadataList": self.certs}


def test_only_certificates_past_their_expiry_are_reported():
    stub = _CertStub([
        {"ServerCertificateName": "old", "Expiration": NOW - timedelta(days=30)},
        {"ServerCertificateName": "current", "Expiration": NOW + timedelta(days=30)},
    ])
    expired = iam.read_expired_certificates(stub, now=NOW)
    assert [c["name"] for c in expired] == ["old"]
    assert expired[0]["expired_days"] == 30


# ---------------------------------------------- Managed policies that must exist


class _EntitiesStub:
    def __init__(self, response=None, error_code=None):
        self.response = response or {}
        self.error_code = error_code

    def list_entities_for_policy(self, PolicyArn):
        if self.error_code:
            raise ClientError(
                {"Error": {"Code": self.error_code, "Message": "x"}},
                "ListEntitiesForPolicy")
        return self.response


def test_a_managed_policy_nobody_holds_reads_as_false():
    stub = _EntitiesStub({"PolicyUsers": [], "PolicyGroups": [], "PolicyRoles": []})
    assert iam.policy_is_attached_to_anyone(stub, iam.SUPPORT_POLICY_ARN) is False


def test_a_managed_policy_held_by_a_role_reads_as_true():
    stub = _EntitiesStub({"PolicyRoles": [{"RoleName": "support"}]})
    assert iam.policy_is_attached_to_anyone(stub, iam.SUPPORT_POLICY_ARN) is True


def test_a_policy_that_should_exist_and_does_not_is_unknown_rather_than_absent():
    """AWSSupportAccess exists in every real account. Not finding it means the
    lookup failed, and answering False would report a clean result the scan
    never earned."""
    stub = _EntitiesStub(error_code="NoSuchEntity")
    assert iam.policy_is_attached_to_anyone(stub, iam.SUPPORT_POLICY_ARN) is None


def test_an_unknown_support_role_state_produces_no_finding_either_way():
    warnings = check_account(_settings(support_role_exists=None))
    assert "support_role" not in _settings_of(warnings)


# ================================================================ The rules


def test_the_scanner_tolerates_an_account_that_is_not_there():
    assert check_account(None) == []
    assert check_account({}) == []


def test_a_well_run_account_produces_nothing():
    assert check_account(_settings()) == []


def test_nothing_in_this_section_is_offered_as_an_automatic_fix():
    """Every remediation here is a credential change with no undo, and the
    account being audited is the one holding this tool's own credentials."""
    warnings = check_account(_settings(
        summary={"root_access_keys": 2, "root_mfa_enabled": False},
        password_policy=None,
        users=[_user(password_enabled=True, mfa_enabled=False,
                     access_keys=[_key(age_days=400)])],
        admin_policies=[{"name": "godmode", "attached_count": 3}],
        analyzer_count=0,
    ))
    assert warnings
    assert fixable(warnings) == []


# ---- Root ------------------------------------------------------------------


def test_a_root_access_key_is_critical_and_cites_1_3():
    found = _find(check_account(_settings(
        summary={"root_access_keys": 1, "root_mfa_enabled": True})),
        "root_access_key")
    assert found["level"] == CRITICAL
    assert found["control"]["id"] == "1.3"


def test_root_without_a_second_login_step_is_critical_and_cites_1_4():
    found = _find(check_account(_settings(
        summary={"root_access_keys": 0, "root_mfa_enabled": False})),
        "root_mfa")
    assert found["level"] == CRITICAL
    assert found["control"]["id"] == "1.4"


def test_a_phone_app_rather_than_a_physical_device_is_a_note_citing_1_5():
    """The difference between good and slightly better. Saying it in the same
    tone as "root has no protection at all" would flatten both."""
    found = _find(check_account(_settings(root_hardware_mfa=False)),
                  "root_hardware_mfa")
    assert found["level"] == INFO
    assert found["control"]["id"] == "1.5"


def test_an_unknown_hardware_mfa_state_says_nothing():
    assert "root_hardware_mfa" not in _settings_of(
        check_account(_settings(root_hardware_mfa=None)))


def test_root_used_recently_cites_1_6():
    found = _find(check_account(_settings(
        root_report={"password_last_used_days": 3, "access_keys": []})),
        "root_recently_used")
    assert found["level"] == WARNING
    assert found["control"]["id"] == "1.6"


def test_root_used_long_ago_is_not_reported():
    assert "root_recently_used" not in _settings_of(check_account(_settings(
        root_report={"password_last_used_days": 400, "access_keys": []})))


def test_a_root_access_key_used_recently_counts_as_root_being_used():
    warnings = check_account(_settings(root_report={
        "password_last_used_days": None,
        "access_keys": [{"slot": 1, "active": True, "last_used_days": 2}],
    }))
    assert "root_recently_used" in _settings_of(warnings)


def test_a_root_row_the_report_did_not_include_says_nothing_about_use():
    """moto's credential report has no root row, and neither does a report
    that has not finished generating."""
    assert "root_recently_used" not in _settings_of(check_account(_settings()))


# ---- Password policy -------------------------------------------------------


def test_no_password_policy_at_all_is_reported_once_citing_1_7():
    warnings = check_account(_settings(password_policy=None))
    found = _find(warnings, "no_password_policy")
    assert found["control"]["id"] == "1.7"
    # Not also reported as a short-length and a reuse finding: one cause,
    # one finding.
    assert "password_length" not in _settings_of(warnings)
    assert "password_reuse" not in _settings_of(warnings)


def test_a_short_minimum_password_length_cites_1_7():
    found = _find(check_account(_settings(password_policy={
        "minimum_length": 8, "passwords_remembered": 24})), "password_length")
    assert found["control"]["id"] == "1.7"


def test_exactly_fourteen_characters_passes():
    assert "password_length" not in _settings_of(check_account(_settings(
        password_policy={"minimum_length": 14, "passwords_remembered": 24})))


def test_allowing_an_old_password_back_cites_1_8():
    found = _find(check_account(_settings(password_policy={
        "minimum_length": 14, "passwords_remembered": None})), "password_reuse")
    assert found["control"]["id"] == "1.8"


def test_an_unreadable_password_policy_is_not_reported_as_a_missing_one():
    """Silence would imply the policy is fine; a normal finding would assert
    something the scan never observed."""
    warnings = check_account(_settings(
        password_policy=None,
        unreadable={"password_policy": "iam:GetAccountPasswordPolicy"}))
    assert "no_password_policy" not in _settings_of(warnings)
    assert _find(warnings, "unreadable_password_policy")["level"] == WARNING


# ---- Users -----------------------------------------------------------------


def test_a_console_login_without_a_second_step_is_critical_and_cites_1_9():
    found = _find(check_account(_settings(users=[
        _user(password_enabled=True, mfa_enabled=False)])), "user_mfa")
    assert found["level"] == CRITICAL
    assert found["control"]["id"] == "1.9"
    assert "alice" in found["message"]


def test_a_user_with_no_console_password_is_not_asked_about_mfa():
    assert "user_mfa" not in _settings_of(check_account(_settings(
        users=[_user(password_enabled=False, mfa_enabled=False)])))


def test_a_per_person_finding_names_the_person_in_the_rule():
    """An access key being 400 days old is useless without a name attached."""
    found = _find(check_account(_settings(users=[
        _user("bob", password_enabled=True, mfa_enabled=False)])), "user_mfa")
    assert found["rule"]["user"] == "bob"
    assert found["resource_id"] == ACCOUNT


def test_two_users_with_the_same_problem_are_two_findings():
    warnings = check_account(_settings(users=[
        _user("alice", password_enabled=True, mfa_enabled=False),
        _user("bob", password_enabled=True, mfa_enabled=False),
    ]))
    assert len({w["rule_id"] for w in warnings}) == 2


def test_a_password_never_used_in_45_days_cites_1_11():
    found = _find(check_account(_settings(users=[_user(
        password_enabled=True, password_last_used_days=None,
        created_days=100)])), "password_never_used")
    assert found["control"]["id"] == "1.11"


def test_a_new_login_not_yet_used_is_not_reported():
    """Someone who joined on Monday has not failed a control by Wednesday."""
    assert "password_never_used" not in _settings_of(check_account(_settings(
        users=[_user(password_enabled=True, password_last_used_days=None,
                     created_days=3)])))


def test_a_login_unused_for_45_days_cites_1_11():
    found = _find(check_account(_settings(users=[_user(
        password_enabled=True, password_last_used_days=100)])),
        "password_unused")
    assert found["control"]["id"] == "1.11"


def test_an_access_key_unused_for_45_days_cites_1_11():
    found = _find(check_account(_settings(users=[_user(
        access_keys=[_key(age_days=200, last_used_days=100)])])),
        "key_unused_1")
    assert found["control"]["id"] == "1.11"


def test_an_access_key_never_used_at_all_says_so_rather_than_giving_a_date():
    found = _find(check_account(_settings(users=[_user(
        access_keys=[_key(age_days=200, last_used_days=None)])])),
        "key_never_used_1")
    assert "never been used" in found["message"]


def test_an_inactive_key_is_not_judged():
    """A disabled key cannot be used, so its age is not a finding."""
    assert check_account(_settings(users=[_user(
        access_keys=[_key(active=False, age_days=900,
                          last_used_days=900)])])) == []


def test_two_active_keys_cites_1_12():
    found = _find(check_account(_settings(users=[_user(
        access_keys=[_key(slot=1), _key(slot=2)])])), "multiple_access_keys")
    assert found["control"]["id"] == "1.12"


def test_one_active_and_one_disabled_key_is_not_two_keys():
    assert "multiple_access_keys" not in _settings_of(check_account(_settings(
        users=[_user(access_keys=[_key(slot=1), _key(slot=2, active=False)])])))


def test_a_key_older_than_90_days_cites_1_13():
    found = _find(check_account(_settings(users=[_user(
        access_keys=[_key(age_days=400)])])), "key_age_1")
    assert found["control"]["id"] == "1.13"
    assert "400 days ago" in found["message"]


def test_a_key_inside_90_days_is_not_reported():
    assert "key_age_1" not in _settings_of(check_account(_settings(
        users=[_user(access_keys=[_key(age_days=30)])])))


def test_each_key_slot_is_reported_separately():
    warnings = check_account(_settings(users=[_user(
        access_keys=[_key(slot=1, age_days=400), _key(slot=2, age_days=500)])]))
    assert {"key_age_1", "key_age_2"} <= _settings_of(warnings)


def test_permissions_pinned_to_a_person_cite_1_14():
    found = _find(check_account(_settings(users=[_user(
        attached_policies=["ReadOnly"])])), "direct_permissions")
    assert found["control"]["id"] == "1.14"
    assert found["level"] == INFO


def test_an_inline_policy_counts_as_a_direct_grant():
    assert "direct_permissions" in _settings_of(check_account(_settings(
        users=[_user(inline_policies=["pinned"])])))


def test_unrestricted_access_pinned_to_a_person_is_more_than_a_note():
    """Same control, different severity. "You have permissions directly" and
    "you have every permission there is, directly" are not the same news."""
    found = _find(check_account(_settings(
        users=[_user(attached_policies=["godmode"])],
        admin_policies=[{"name": "godmode", "attached_count": 1}],
    )), "direct_permissions")
    assert found["level"] == WARNING
    assert "unrestricted access" in found["message"]


def test_permissions_through_a_group_only_say_nothing():
    assert check_account(_settings(users=[_user(group_count=2)])) == []


# ---- Account-wide ----------------------------------------------------------


def test_a_policy_granting_everything_cites_1_15():
    found = _find(check_account(_settings(admin_policies=[
        {"name": "godmode", "attached_count": 3}])), "full_admin_policy_godmode")
    assert found["control"]["id"] == "1.15"
    assert "3 identities" in found["message"]


def test_one_holder_of_an_admin_policy_reads_as_singular():
    found = _find(check_account(_settings(admin_policies=[
        {"name": "godmode", "attached_count": 1}])), "full_admin_policy_godmode")
    assert "1 identity has it" in found["message"]


def test_nobody_able_to_raise_a_support_case_cites_1_16():
    found = _find(check_account(_settings(support_role_exists=False)),
                  "support_role")
    assert found["control"]["id"] == "1.16"
    assert found["level"] == INFO


def test_an_expired_certificate_cites_1_18():
    found = _find(check_account(_settings(expired_certificates=[
        {"name": "old", "expired_days": 30}])), "expired_certificate_old")
    assert found["control"]["id"] == "1.18"


def test_no_access_analyzer_cites_1_19_and_admits_it_checked_one_region():
    """CIS asks for one in every region. A one-region read cannot support an
    account-wide claim, so the finding says which region it looked at."""
    found = _find(check_account(_settings(analyzer_count=0)), "access_analyzer")
    assert found["control"]["id"] == "1.19"
    assert REGION in found["message"]
    assert "one region" in found["message"]


def test_an_unreadable_analyzer_count_is_not_reported_as_zero():
    warnings = check_account(_settings(
        analyzer_count=None,
        unreadable={"analyzer_count": "access-analyzer:ListAnalyzers"}))
    assert "access_analyzer" not in _settings_of(warnings)


def test_the_browser_shell_being_widely_granted_cites_1_21():
    found = _find(check_account(_settings(cloudshell_full_access=True)),
                  "cloudshell_full_access")
    assert found["control"]["id"] == "1.21"


# ---- Checks that did not run -----------------------------------------------


def test_every_unread_check_is_reported_as_a_gap_in_plain_language():
    warnings = check_account(_settings(
        unreadable={"users": "iam:ListUsers"}, users=None))
    found = _find(warnings, "unreadable_users")
    assert found["level"] == WARNING
    assert "iam:ListUsers" in found["message"]
    assert "how they get their permissions" in found["message"]


def test_the_gaps_are_reported_before_the_findings():
    """The person reading needs to know the scan was partial before the
    absence of findings below reassures them."""
    warnings = check_account(_settings(
        summary={"root_access_keys": 1, "root_mfa_enabled": False},
        unreadable={"users": "iam:ListUsers"}))
    assert warnings[0]["rule"]["setting"] == "unreadable_users"


# ================================================== Citation and registration


SECTION_ONE = {
    "ROOT_ACCESS_KEY": "1.3",
    "ROOT_MFA": "1.4",
    "ROOT_HARDWARE_MFA": "1.5",
    "ROOT_DAILY_USE": "1.6",
    "PASSWORD_LENGTH": "1.7",
    "PASSWORD_REUSE": "1.8",
    "USER_MFA": "1.9",
    "UNUSED_CREDENTIALS": "1.11",
    "ONE_ACTIVE_KEY": "1.12",
    "KEY_ROTATION": "1.13",
    "PERMISSIONS_VIA_GROUPS": "1.14",
    "NO_FULL_ADMIN_POLICY": "1.15",
    "SUPPORT_ROLE": "1.16",
    "EXPIRED_CERTIFICATES": "1.18",
    "ACCESS_ANALYZER": "1.19",
    "CLOUDSHELL_FULL_ACCESS": "1.21",
}


@pytest.mark.parametrize("name,expected", sorted(SECTION_ONE.items()))
def test_section_one_uses_the_v5_numbering_not_the_v3_numbering(name, expected):
    """Section 1 renumbered in v5.0.0 when "security questions" was dropped,
    and everything after it moved down by one. Most of these IDs are one away
    from a plausible wrong answer, which is the kind of error that survives
    review because nothing it produces looks broken."""
    assert controls.CONTROLS[name].id == expected


def test_the_benchmark_version_these_ids_were_read_against_has_not_moved():
    """If this fails, every ID above needs checking against the new document
    rather than assuming the numbering held. It did not last time."""
    assert controls.CIS_VERSION == "5.0.0"


# IAM findings that are deliberately uncited, and why each one is.
#
# This used to be empty, and the test below asserted every finding was cited on
# the grounds that CIS section 1 covers all of IAM. Two findings ported from
# Prowler broke that, and neither is a forgotten citation:
#
#   password_never_expires - CIS carried a password-expiry recommendation in
#     v1.2 and deliberately dropped it by v3.0.0, because forced rotation
#     produces predictable variations. Citing a control the benchmark removed
#     on purpose would be worse than citing none.
#   user_virtual_mfa - CIS 1.6 asks for hardware MFA on the root user only.
#     Stretching it to cover every user would claim a control for a population
#     it does not name.
#
# Named individually rather than allowing "some findings are uncited", so a
# citation that really was forgotten still fails this.
UNCITED_BY_DESIGN = {"password_never_expires", "user_virtual_mfa"}


def test_every_iam_finding_carries_a_citation():
    """Section 1 covers nearly all of IAM, so an uncited finding is a forgotten
    citation unless it is one of the two named above."""
    warnings = check_account(_settings(
        summary={"root_access_keys": 1, "root_mfa_enabled": False},
        root_hardware_mfa=False,
        root_report={"password_last_used_days": 1, "access_keys": []},
        password_policy={"minimum_length": 6, "passwords_remembered": 0},
        users=[_user(password_enabled=True, mfa_enabled=False,
                     password_last_used_days=100,
                     attached_policies=["godmode"],
                     access_keys=[_key(slot=1, age_days=400,
                                       last_used_days=100),
                                  _key(slot=2)])],
        admin_policies=[{"name": "godmode", "attached_count": 1}],
        expired_certificates=[{"name": "old", "expired_days": 5}],
        analyzer_count=0,
        support_role_exists=False,
        cloudshell_full_access=True,
    ))
    expected = [w for w in warnings
                if w["rule"]["setting"] not in UNCITED_BY_DESIGN]
    assert len(cited(warnings)) == len(expected), (
        "uncited: "
        + str(sorted(w["rule"]["setting"] for w in warnings
                     if not w.get("control")))
    )
    assert worst_level(warnings) == CRITICAL


def test_findings_about_unread_checks_are_the_one_uncited_kind():
    """A skipped check is not a control failure. Citing one against it would
    claim the benchmark was assessed when it was not."""
    warnings = check_account(_settings(unreadable={"users": "iam:ListUsers"}))
    assert cited(warnings) == []


def test_the_account_is_a_registered_resource_type():
    assert registry.get("iam") is registry.IAM


def test_the_account_is_registered_as_audit_only():
    assert registry.IAM.read_only is True


def test_the_account_is_not_registered_after_networks():
    """Cleanup walks the registry in order and networks have to be last. An
    audited type creates nothing, so it has no place in that ordering."""
    keys = list(registry.REGISTRY)
    assert keys.index("iam") < keys.index("network")


def test_there_is_no_form_that_creates_an_account_posture():
    assert registry.IAM.check_spec({"name": "anything"}) == []


def test_describing_the_account_does_not_restate_the_findings(iam_client):
    """The user list carries key ages and last-use dates gathered so the rules
    could judge them. Handing that back as a description would say the same
    thing twice in two shapes."""
    iam_client.create_user(UserName="alice")
    described = registry.IAM.describe(
        iam.read_account_for_scanning(iam_client))

    assert described["user_count"] == 1
    assert "users" not in described
    assert described["checks_skipped"] == ["analyzer_count"]


def test_describing_an_account_that_is_not_there_is_none():
    assert registry.IAM.describe(None) is None


# ============================================================= Over HTTP

# The routes already have tests against a stand-in read-only type, written
# before there was a real one. These use the registered IAM type instead,
# because the thing worth protecting now is that the actual audit reaches the
# actual routes without either being changed for the other.


@pytest.fixture
def api():
    from fastapi.testclient import TestClient
    from api.app import app

    with mock_aws():
        yield TestClient(app, base_url="http://127.0.0.1:8000")


def test_the_account_is_listed_as_one_row(api):
    body = api.get("/resources/iam").json()
    assert [r["id"] for r in body["resources"]] == [ACCOUNT]


def test_scanning_the_account_returns_what_it_is_and_what_is_wrong(api):
    body = api.get(f"/resources/iam/{ACCOUNT}").json()
    assert body["settings"]["account_id"] == ACCOUNT
    assert body["warnings"]
    assert body["fixable_count"] == 0


def test_scanning_a_different_account_is_a_404(api):
    assert api.get("/resources/iam/999999999999").status_code == 404


def test_the_account_cannot_be_created_deleted_or_cleaned_up(api):
    created = api.post("/resources/iam", json={"name": "x"})
    assert created.status_code == 405
    assert "audited by this tool" in created.json()["detail"]

    assert api.delete(f"/resources/iam/{ACCOUNT}").status_code == 405
    assert api.post("/resources/iam/cleanup").status_code == 405


def test_fixing_an_iam_finding_over_http_is_refused(api):
    """/fix re-derives the finding server-side, so a rule_id that is real still
    reaches apply_fix, and apply_fix is what refuses."""
    warnings = api.get(f"/resources/iam/{ACCOUNT}").json()["warnings"]
    rule_id = next(w["rule_id"] for w in warnings)

    refused = api.post(f"/resources/iam/{ACCOUNT}/fix",
                       json={"rule_id": rule_id})
    assert refused.status_code == 404
    assert "No fixable finding" in refused.json()["detail"]


# --------------------------------------------- Reading every identity


def test_a_policy_granting_broad_iam_read_is_recognised():
    """Found by deploying CloudGoat's iam_enum_basics against a real account.

    The scenario hands a user IAMReadOnlyAccess and this tool said nothing.
    Being able to list every user, role and policy is how somebody works out
    where the way up is, and it is all reads, so it leaves nothing behind.
    """
    for actions in (["iam:List*"], ["iam:Get*"], ["iam:*"],
                    ["s3:GetObject", "iam:List*"]):
        document = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": actions, "Resource": "*"}]}
        assert iam.grants_account_wide_iam_read(document), actions


def test_full_admin_is_not_also_counted_as_enumeration():
    """CIS 1.15 already says it. Saying it twice under a second heading
    inflates the count without adding a fact."""
    document = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "*", "Resource": "*"}]}

    assert iam.grants_full_admin(document)
    assert not iam.grants_account_wide_iam_read(document)


def test_a_policy_naming_its_iam_reads_individually_is_not_flagged():
    """The distinction the rule is drawing.

    A policy listing the reads it needs is somebody who thought about it, and
    this tool's own audit policy is exactly that shape. One saying iam:List* is
    somebody who did not.
    """
    document = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow",
        "Action": ["iam:GetAccountSummary", "iam:ListUsers",
                   "iam:GetCredentialReport", "iam:ListPolicies"],
        "Resource": "*",
    }]}
    assert not iam.grants_account_wide_iam_read(document)


def test_a_conditional_or_scoped_grant_is_not_flagged():
    conditional = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Action": "iam:List*", "Resource": "*",
        "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}]}
    assert not iam.grants_account_wide_iam_read(conditional)

    scoped = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Action": "iam:List*",
        "Resource": "arn:aws:iam::123456789012:user/one"}]}
    assert not iam.grants_account_wide_iam_read(scoped)


def test_the_finding_names_the_policy_and_carries_no_citation():
    """No published benchmark covers this, so it stands on being true."""
    found = _find(check_account(_settings(
        enumeration_policies=[{"name": "IAMReadOnlyAccess",
                               "attached_count": 2}],
    )), "enumeration_IAMReadOnlyAccess")

    assert found is not None
    assert found["level"] == WARNING
    assert "IAMReadOnlyAccess" in found["message"]
    assert "2 identities have it" in found["message"]
    assert found["control"] is None


# ------------------------------------------- Where a person could get to

# The other end of every CloudGoat chain. Roles were built first because the
# benchmark said "role to something"; re-running iam_privesc_by_ec2 afterwards
# showed the tool naming the AdministratorAccess role on a machine and saying
# nothing about the user who could put it there, because the escalation lived
# in that user's inline policy and nothing read it.


def _doc(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def _grant(actions, resource="*", **extra):
    s = {"Effect": "Allow", "Action": actions, "Resource": resource}
    s.update(extra)
    return s


def _user_with(*documents, source="inline", **overrides):
    return _user(policies=[
        {"name": f"p{i}", "source": source, "document": d}
        for i, d in enumerate(documents)], **overrides)


def test_a_user_who_can_pass_a_role_and_start_a_machine_is_named():
    """iam_privesc_by_ec2's actor, in the shape the scenario deploys it."""
    found = _find(check_account(_settings(users=[_user_with(
        _doc(_grant(["iam:PassRole", "ec2:RunInstances"])))])),
        "user_pass_role_to_compute")

    assert found["level"] == CRITICAL
    assert "start a machine" in found["message"]
    assert found["rule"]["user"] == "alice"


def test_a_user_who_can_attach_a_policy_is_named():
    found = _find(check_account(_settings(users=[_user_with(
        _doc(_grant("iam:AttachUserPolicy")))])),
        "user_escalation_attachuserpolicy")
    assert found["level"] == CRITICAL


def test_a_user_with_full_admin_is_named_and_cites_1_15():
    found = _find(check_account(_settings(users=[_user_with(
        _doc(_grant("*")))])), "user_full_admin")
    assert found["level"] == CRITICAL
    assert found["control"]["id"] == "1.15"


def test_full_admin_does_not_also_list_every_path_it_implies():
    warnings = [w for w in check_account(_settings(users=[_user_with(
        _doc(_grant("*")))])) if w["rule"]["setting"].startswith("user_")]
    assert {w["rule"]["setting"] for w in warnings} == {"user_full_admin"}


def test_an_escalation_inherited_through_a_group_still_counts():
    """Permissions arriving through a group are the recommended arrangement,
    so an escalation assembled there is if anything more likely than one
    pinned to a person."""
    user = _user(policies=[
        {"name": "engineers/launch", "source": "group",
         "document": _doc(_grant(["iam:PassRole", "ec2:RunInstances"]))}])
    assert "user_pass_role_to_compute" in _settings_of(
        check_account(_settings(users=[user])))


def test_an_escalation_split_between_a_group_and_an_inline_policy_counts():
    user = _user(policies=[
        {"name": "engineers/pass", "source": "group",
         "document": _doc(_grant("iam:PassRole"))},
        {"name": "own", "source": "inline",
         "document": _doc(_grant("ec2:RunInstances"))}])
    assert "user_pass_role_to_compute" in _settings_of(
        check_account(_settings(users=[user])))


def test_a_conditioned_grant_is_not_counted_for_users_either():
    assert "user_pass_role_to_compute" not in _settings_of(
        check_account(_settings(users=[_user_with(_doc(_grant(
            ["iam:PassRole", "ec2:RunInstances"],
            Condition={"StringEquals": {"aws:RequestedRegion": "eu-west-2"}})))])))


def test_a_user_whose_policy_could_not_be_read_is_not_scored_harmless():
    user = _user(policies=[{"name": "opaque", "source": "attached",
                            "document": None}])
    found = _find(check_account(_settings(users=[user])),
                  "unreadable_policies")
    assert found["level"] == WARNING
    assert "not counted as harmless" in found["message"]


def test_a_user_with_no_readable_policies_produces_no_escalation_findings():
    """The old behaviour, and the correct one when nothing can be read: this
    tool must not invent a finding from an absence."""
    assert not [w for w in check_account(_settings(users=[_user()]))
                if w["rule"]["setting"].startswith("user_escalation")]


def test_an_ordinary_user_policy_says_nothing():
    assert not [w for w in check_account(_settings(users=[_user_with(
        _doc(_grant("s3:GetObject", resource="arn:aws:s3:::one/*")))]))
        if w["rule"]["setting"].startswith("user_")]
