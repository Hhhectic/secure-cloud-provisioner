"""Tests for the S3 rules engine and bucket CRUD.

The rules tests touch no cloud at all. The CRUD tests run against moto, which
fakes AWS in memory: no account, no credentials, no bill, and fast enough to run
on every save.
"""

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from scanner.s3_rules import check_bucket_settings
from scanner.common import CRITICAL, WARNING, INFO, fixable, summarize
from aws import s3_buckets

REGION = "us-east-1"
BUCKET = "scp-unit-test-bucket"


# ------------------------------------------------------- Rules: no AWS involved


def _settings(**overrides):
    """A fully hardened bucket. Override single keys to introduce one flaw."""
    base = {
        "bucket": BUCKET,
        "public_access_block": dict(s3_buckets.ALL_BLOCKS_ON),
        "encryption": {"enabled": True, "algorithm": "aws:kms"},
        "versioning": {"enabled": True, "mfa_delete": True},
        "public_acl_grants": [],
        "policy_is_public": False,
        "policy_denies_http": True,
        "logging_enabled": True,
        "unreadable": {},
    }
    base.update(overrides)
    return base


def _ids(warnings):
    return {w["rule_id"] for w in warnings}


def test_hardened_bucket_is_clean():
    assert check_bucket_settings(_settings()) == []


def test_fresh_bucket_flags_all_three_defaults():
    """A bucket created with no settings at all: the demo starting state."""
    warnings = check_bucket_settings(_settings(
        public_access_block=None,
        encryption={"enabled": False, "algorithm": None},
        versioning={"enabled": False, "mfa_delete": False},
        logging_enabled=False,
    ))
    ids = _ids(warnings)
    assert f"{BUCKET}:public_access_block" in ids
    assert f"{BUCKET}:encryption" in ids
    assert f"{BUCKET}:versioning" in ids


def test_missing_public_access_block_is_critical():
    warnings = check_bucket_settings(_settings(public_access_block=None))
    assert len(warnings) == 1
    assert warnings[0]["level"] == CRITICAL
    assert warnings[0]["fix"]["action"] == "block_public_access"


def test_partial_public_access_block_is_still_critical():
    """Three switches on and one off is not three quarters safe."""
    partial = dict(s3_buckets.ALL_BLOCKS_ON)
    partial["BlockPublicPolicy"] = False
    warnings = check_bucket_settings(_settings(public_access_block=partial))
    assert len(warnings) == 1
    assert warnings[0]["level"] == CRITICAL
    assert "1 of the 4" in warnings[0]["message"]


def test_all_four_blocks_off_does_not_call_itself_partly_protected():
    """A live run produced "only partly protected... 4 of the 4 are off".

    All four off is the opposite of partly protected, and because AWS enables
    them on every new bucket it also means somebody turned them off on purpose.
    The message should say that rather than sounding reassuring.
    """
    all_off = {k: False for k in s3_buckets.ALL_BLOCKS_ON}
    w = check_bucket_settings(_settings(public_access_block=all_off))[0]

    assert w["level"] == CRITICAL
    assert "partly protected" not in w["message"]
    assert "deliberately" in w["message"]


def test_encryption_off_is_critical_and_fixable():
    warnings = check_bucket_settings(
        _settings(encryption={"enabled": False, "algorithm": None})
    )
    assert warnings[0]["level"] == CRITICAL
    assert warnings[0]["fix"]["action"] == "enable_encryption"


def test_aes256_is_informational_not_critical():
    """AES-256 is real encryption. Nudge toward KMS, do not cry wolf."""
    warnings = check_bucket_settings(
        _settings(encryption={"enabled": True, "algorithm": "AES256"})
    )
    assert len(warnings) == 1
    assert warnings[0]["level"] == INFO
    assert warnings[0]["fix"] is None


def test_versioning_off_is_a_warning_not_critical():
    warnings = check_bucket_settings(
        _settings(versioning={"enabled": False, "mfa_delete": False})
    )
    assert warnings[0]["level"] == WARNING
    assert warnings[0]["fix"]["action"] == "enable_versioning"


def test_live_public_grant_is_critical():
    warnings = check_bucket_settings(_settings(public_acl_grants=[
        {"uri": "http://acs.amazonaws.com/groups/global/AllUsers",
         "permission": "READ"},
    ]))
    assert warnings[0]["level"] == CRITICAL
    assert "right now" in warnings[0]["message"]


def test_public_policy_is_critical():
    warnings = check_bucket_settings(_settings(policy_is_public=True))
    assert warnings[0]["level"] == CRITICAL
    assert warnings[0]["rule_id"] == f"{BUCKET}:public_policy"


def test_logging_off_is_informational_only():
    warnings = check_bucket_settings(_settings(logging_enabled=False))
    assert len(warnings) == 1
    assert warnings[0]["level"] == INFO


# -------------------------------------------------- Degrading on a denied read


def test_unreadable_setting_is_reported_not_guessed():
    """A denied read must not be reported as the setting being absent.

    public_access_block=None normally means "never configured", which is a
    critical finding. When the read was denied, the same None means "no idea".
    Announcing a critical here would be asserting something never observed.
    """
    warnings = check_bucket_settings(_settings(
        public_access_block=None,
        unreadable={"public_access_block": "s3:GetBucketPublicAccessBlock"},
    ))
    assert len(warnings) == 1
    assert warnings[0]["level"] == WARNING
    assert "s3:GetBucketPublicAccessBlock" in warnings[0]["message"]
    assert warnings[0]["fix"] is None


def test_unreadable_settings_do_not_produce_a_clean_result():
    """Silence would read as a pass. Every skipped check has to be visible."""
    warnings = check_bucket_settings(_settings(
        public_access_block=None,
        encryption=None,
        versioning=None,
        unreadable={
            "public_access_block": "s3:GetBucketPublicAccessBlock",
            "encryption": "s3:GetEncryptionConfiguration",
            "versioning": "s3:GetBucketVersioning",
        },
    ))
    assert len(warnings) == 3
    assert all(w["level"] == WARNING for w in warnings)
    assert not fixable(warnings)


def test_readable_settings_still_checked_when_others_are_denied():
    """One denied permission must not silence the rest of the audit."""
    warnings = check_bucket_settings(_settings(
        public_access_block=None,
        encryption={"enabled": False, "algorithm": None},
        unreadable={"public_access_block": "s3:GetBucketPublicAccessBlock"},
    ))
    ids = _ids(warnings)
    assert f"{BUCKET}:unreadable_public_access_block" in ids
    assert f"{BUCKET}:encryption" in ids
    assert summarize(warnings)[CRITICAL] == 1


# ------------------------------------------- Contract shared with the SG scanner


def test_every_warning_carries_a_rule_id_and_resource_id():
    """Without both, the fix button has nothing to aim at."""
    warnings = check_bucket_settings(_settings(
        public_access_block=None,
        encryption={"enabled": False, "algorithm": None},
        versioning={"enabled": False, "mfa_delete": False},
        logging_enabled=False,
    ))
    assert warnings
    for w in warnings:
        assert w["rule_id"], w["message"]
        assert w["resource_id"] == BUCKET
        assert set(w) == {"level", "message", "rule_id", "resource_id", "rule",
                          "fix", "control"}


def test_fixable_filters_to_actionable_warnings_only():
    warnings = check_bucket_settings(_settings(
        encryption={"enabled": False, "algorithm": None},
        logging_enabled=False,
    ))
    actionable = fixable(warnings)
    assert len(warnings) == 2
    assert len(actionable) == 1
    assert actionable[0]["fix"]["action"] == "enable_encryption"


def test_messages_avoid_jargon():
    """The whole premise is that a non-expert can act on these."""
    warnings = check_bucket_settings(_settings(
        public_access_block=None,
        encryption={"enabled": False, "algorithm": None},
        versioning={"enabled": False, "mfa_delete": False},
    ))
    for w in warnings:
        lowered = w["message"].lower()
        for jargon in ("sse", "acl", "iam", "cidr", "arn", "principal"):
            assert jargon not in lowered.split(), f"jargon in: {w['message']}"
        assert w["message"][0].isupper()
        assert w["message"].rstrip().endswith(".")


# --------------------------------------------------------- CRUD against moto


@pytest.fixture
def s3():
    with mock_aws():
        yield boto3.client("s3", region_name=REGION)


def test_secure_by_default_bucket_scans_clean(s3):
    ok, name, problems = s3_buckets.create_bucket(s3, BUCKET, region=REGION)
    assert ok
    assert problems == []

    settings = s3_buckets.read_bucket_for_scanning(s3, name)
    criticals = [w for w in check_bucket_settings(settings) if w["level"] == CRITICAL]
    assert criticals == []


def test_create_reports_hardening_failures_instead_of_swallowing_them(s3):
    """A bucket can be created and still fail to harden. Both must be reported.

    This is the bug the first live run hit: create succeeded, the three
    hardening calls failed on a missing permission, and their return values were
    discarded, so the tool printed success over an unhardened bucket.
    """
    def refuse(*args, **kwargs):
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
            "PutBucketEncryption",
        )

    s3.put_bucket_encryption = refuse

    ok, name, problems = s3_buckets.create_bucket(s3, BUCKET, region=REGION)
    assert ok
    assert any("permission" in p for p in problems)


def test_creating_a_name_owned_by_another_account_fails_clearly(s3):
    def taken(*args, **kwargs):
        raise ClientError(
            {"Error": {"Code": "BucketAlreadyExists", "Message": "taken"}},
            "CreateBucket",
        )

    s3.create_bucket = taken
    ok, msg, _ = s3_buckets.create_bucket(s3, BUCKET, region=REGION)
    assert not ok
    assert "already taken by another AWS account" in msg


def test_weak_bucket_flags_then_fixes_clean(s3):
    """The demo path end to end: create weak, scan, fix, re-scan."""
    ok, name, _ = s3_buckets.create_bucket(
        s3, BUCKET, region=REGION, secure_by_default=False
    )
    assert ok

    before = check_bucket_settings(s3_buckets.read_bucket_for_scanning(s3, name))
    assert summarize(before)[CRITICAL] > 0

    for w in fixable(before):
        applied, msg = s3_buckets.apply_fix(s3, name, w)
        assert applied, msg

    after = check_bucket_settings(s3_buckets.read_bucket_for_scanning(s3, name))
    assert summarize(after)[CRITICAL] == 0
    assert summarize(after)[WARNING] == 0


def test_reads_survive_an_unconfigured_bucket(s3):
    """Unset settings raise on AWS. Each getter must report absence as a value."""
    s3.create_bucket(Bucket=BUCKET)

    assert s3_buckets.get_public_access_block(s3, BUCKET) is None
    assert s3_buckets.get_encryption(s3, BUCKET)["enabled"] is False
    assert s3_buckets.get_versioning(s3, BUCKET)["enabled"] is False
    assert s3_buckets.get_public_acl_grants(s3, BUCKET) == []
    assert s3_buckets.policy_is_public(s3, BUCKET) is False
    assert s3_buckets.logging_enabled(s3, BUCKET) is False


def test_denied_read_raises_permission_denied_not_client_error(s3):
    """The distinction the live run needed: denied is not the same as unset."""
    s3.create_bucket(Bucket=BUCKET)

    def refuse(*args, **kwargs):
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
            "GetPublicAccessBlock",
        )

    s3.get_public_access_block = refuse

    with pytest.raises(s3_buckets.PermissionDenied) as exc:
        s3_buckets.get_public_access_block(s3, BUCKET)
    assert exc.value.permission == "s3:GetBucketPublicAccessBlock"


def test_scan_degrades_rather_than_crashing_on_a_denied_read(s3):
    """One missing permission must not take down the whole scan."""
    s3.create_bucket(Bucket=BUCKET)

    def refuse(*args, **kwargs):
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
            "GetPublicAccessBlock",
        )

    s3.get_public_access_block = refuse

    settings = s3_buckets.read_bucket_for_scanning(s3, BUCKET)
    assert settings["unreadable"] == {
        "public_access_block": "s3:GetBucketPublicAccessBlock"
    }

    warnings = check_bucket_settings(settings)
    ids = _ids(warnings)
    assert f"{BUCKET}:unreadable_public_access_block" in ids
    assert f"{BUCKET}:encryption" in ids


def test_list_buckets_filters_on_the_managed_tag(s3):
    s3_buckets.create_bucket(s3, BUCKET, region=REGION)
    s3.create_bucket(Bucket="someone-elses-bucket")

    ours = [b["Name"] for b in s3_buckets.list_buckets(s3, only_ours=True)]
    everything = [b["Name"] for b in s3_buckets.list_buckets(s3)]

    assert ours == [BUCKET]
    assert "someone-elses-bucket" in everything


def test_cleanup_removes_only_managed_buckets(s3):
    s3_buckets.create_bucket(s3, BUCKET, region=REGION)
    s3.create_bucket(Bucket="someone-elses-bucket")

    results = s3_buckets.cleanup_all_managed_buckets(s3, force=True)
    assert [(name, ok) for name, ok, _ in results] == [(BUCKET, True)]

    remaining = [b["Name"] for b in s3_buckets.list_buckets(s3)]
    assert remaining == ["someone-elses-bucket"]


def test_delete_refuses_a_bucket_with_files_unless_forced(s3):
    # secure_by_default is off because the CIS 2.1.1 fix adds a policy denying
    # requests where aws:SecureTransport is false, and moto serves over plain
    # HTTP, so every subsequent call in-process is denied. Against real AWS
    # boto3 uses HTTPS and the policy never bites. This is a test-harness
    # artifact, not a product defect, but it does mean the teardown path can
    # only be exercised here on an unhardened bucket.
    s3_buckets.create_bucket(s3, BUCKET, region=REGION, secure_by_default=False)
    s3.put_object(Bucket=BUCKET, Key="notes.txt", Body=b"hello")

    ok, msg = s3_buckets.delete_bucket(s3, BUCKET)
    assert not ok
    assert "still has files" in msg

    ok, msg = s3_buckets.delete_bucket(s3, BUCKET, force=True)
    assert ok, msg


def test_force_delete_clears_versioned_objects(s3):
    """Versioning leaves delete markers a plain object delete would miss."""
    s3_buckets.create_bucket(s3, BUCKET, region=REGION, secure_by_default=False)
    s3.put_bucket_versioning(Bucket=BUCKET,
                             VersioningConfiguration={"Status": "Enabled"})
    s3.put_object(Bucket=BUCKET, Key="notes.txt", Body=b"v1")
    s3.put_object(Bucket=BUCKET, Key="notes.txt", Body=b"v2")
    s3.delete_object(Bucket=BUCKET, Key="notes.txt")

    ok, msg = s3_buckets.delete_bucket(s3, BUCKET, force=True)
    assert ok, msg
    assert BUCKET not in [b["Name"] for b in s3_buckets.list_buckets(s3)]


def test_creating_an_existing_bucket_is_not_an_error(s3):
    """Reruns should be safe, the same way the SG path reuses a duplicate."""
    ok, first, _ = s3_buckets.create_bucket(s3, BUCKET, region=REGION)
    ok_again, second, problems = s3_buckets.create_bucket(s3, BUCKET, region=REGION)

    assert ok and ok_again
    assert first == second == BUCKET
    assert any("already existed" in p for p in problems)
