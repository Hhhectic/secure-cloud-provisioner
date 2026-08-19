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


def test_every_bucket_setting_has_wording_for_when_it_cannot_be_read():
    """The label table is derived from the readers, not kept beside them.

    SETTING_LABELS.get(name, name) falls back to the raw key, so a missing
    entry is not an error - it is a sentence with an identifier in it, shown
    to somebody who does not know what other_accounts means. Two settings were
    in exactly that state, and one of them could not be reached at all until
    list_objects stopped raising, so nothing had ever printed it.
    """
    from scanner.s3_rules import SETTING_LABELS

    missing = set(s3_buckets._READERS) - set(SETTING_LABELS)
    assert not missing, f"no wording for {sorted(missing)}"


def test_contents_that_could_not_be_read_are_not_reported_as_an_empty_bucket():
    """A missing clause must not be read as "nothing in it".

    The scanner has always had this branch and nothing could reach it: the
    reader raised instead of recording, so `unreadable["objects"]` was never
    set by anything but a hand-written dict like this one.
    """
    warnings = check_bucket_settings(_settings(
        public_access_block=None,
        policy_is_public=True,
        objects=None,
        unreadable={"objects": "s3:ListBucket"},
    ))
    said = " ".join(w["message"] for w in warnings)
    assert "nothing in it" not in said
    assert "objects in it" not in said


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


class _ListingDenied:
    """A client that refuses ListBucket the way AWS refuses it.

    Everything else is the real moto client. Only list_objects_v2 is replaced,
    because the case being modelled is one permission missing rather than a
    broken account - which is also the shape of the real failure: a bucket
    owned by somebody else answers every read this way.
    """

    def __init__(self, real):
        self._real = real

    def __getattr__(self, name):
        return getattr(self._real, name)

    def list_objects_v2(self, **kwargs):
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
            "ListObjectsV2")


def test_a_refused_object_listing_is_recorded_rather_than_raised(s3):
    """The defect this test was written for answered 500 to a browser.

    read_bucket_for_scanning catches PermissionDenied per setting and files it
    under `unreadable`. list_objects raised botocore's ClientError instead,
    which that handler does not catch, so GET /resources/bucket/{name} on a
    bucket owned by another account crashed rather than reporting a gap in the
    audit. Found by driving the routes against a real account.
    """
    s3.create_bucket(Bucket=BUCKET)

    settings = s3_buckets.read_bucket_for_scanning(_ListingDenied(s3), BUCKET)

    assert settings is not None, "a readable bucket read as absent"
    assert settings["unreadable"].get("objects") == "s3:ListBucket"
    assert settings["objects"] is None

    # And the rest of the audit still happened. A refused listing must cost
    # the contents clause and nothing else.
    assert settings["encryption"] is not None
    assert settings["versioning"] is not None


def test_a_refused_listing_still_produces_a_scan(s3):
    """The whole point of `unreadable`: a partial audit beats no audit."""
    s3.create_bucket(Bucket=BUCKET)
    settings = s3_buckets.read_bucket_for_scanning(_ListingDenied(s3), BUCKET)

    warnings = check_bucket_settings(settings)

    said = " ".join(w["message"] for w in warnings)
    assert "nothing in it" not in said


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


def test_a_weak_bucket_is_unblocked_by_a_write_not_by_omission(s3):
    """secure_by_default=False must turn the four blocks off, not merely skip
    turning them on.

    Those were the same thing until April 2023, when AWS began applying all
    four blocks to every new bucket itself. After that, skipping the hardening
    returned a fully blocked bucket while the pre-create scan promised an
    exposure - the form said one thing and the account held another.

    moto does not apply that default either, which is why the old code looked
    correct here and the whole suite stayed green over it. Note what this
    asserts: not that the bucket *reads* as public, which it did before and
    after, but that the configuration was written. Only a write survives
    contact with real AWS.
    """
    ok, name, _ = s3_buckets.create_bucket(
        s3, BUCKET, region=REGION, secure_by_default=False)
    assert ok

    blocks = s3_buckets.get_public_access_block(s3, name)
    assert blocks is not None, "no block configuration was written at all"
    assert blocks == s3_buckets.ALL_BLOCKS_OFF


def test_asking_for_a_weak_bucket_does_not_weaken_an_existing_one(s3):
    """A name already in use has somebody's data behind it.

    create_bucket re-hardens a bucket that was already there, which is safe in
    the direction this tool usually travels. The inverse is not, so the weak
    path stops and says so rather than stripping protection off data it did not
    create.
    """
    ok, _, _ = s3_buckets.create_bucket(s3, BUCKET, region=REGION)
    assert ok

    ok, name, problems = s3_buckets.create_bucket(
        s3, BUCKET, region=REGION, secure_by_default=False)
    assert ok

    assert s3_buckets.get_public_access_block(s3, name) == s3_buckets.ALL_BLOCKS_ON
    # Not "already existed": create_bucket has always said that about a name it
    # found rather than made, so matching on it passes with or without the
    # refusal. The refusal is the only thing that says "does not weaken".
    assert any("does not weaken" in p for p in problems), problems


@pytest.mark.parametrize("secure", [True, False])
def test_the_preflight_predicts_the_blocks_the_create_writes(s3, secure):
    """What the form promises and what the create does must not drift apart.

    They live in different files, neither imports the other, and that is how
    they came to disagree about the single most important setting on the form:
    check_spec described an unprotected bucket that create_bucket had no way to
    produce.

    Only the public access block is compared. moto does not model the SSE-S3
    default AWS has applied since January 2023, so encryption genuinely differs
    between here and production and asserting on it would pin moto's behaviour
    rather than AWS's. That half is checked live, in scripts/smoke_test.py.

    Worth knowing what this test cannot do: it passed against the broken code
    too. moto models neither of the defaults AWS added in 2023, so offline the
    old prediction (no configuration) and the old result (no configuration)
    agreed, and the disagreement only existed against real AWS. This guards the
    two halves against drifting apart from here on; it is not what would have
    caught the original bug. That is
    test_a_weak_bucket_is_unblocked_by_a_write_not_by_omission, which asserts
    on the write rather than on the reading.
    """
    from api.registry import _bucket_check_spec

    name = BUCKET + ("-secure" if secure else "-weak")
    spec = {"name": name, "region": REGION, "secure_by_default": secure}

    predicted = {w["rule"]["setting"] for w in _bucket_check_spec(spec)}

    ok, created, _ = s3_buckets.create_bucket(
        s3, name, region=REGION, secure_by_default=secure)
    assert ok
    actual = {w["rule"]["setting"] for w in
              check_bucket_settings(s3_buckets.read_bucket_for_scanning(s3, created))}

    assert ("public_access_block" in predicted) == ("public_access_block" in actual), (
        f"preflight said public_access_block warning="
        f"{'public_access_block' in predicted}, the created bucket said "
        f"{'public_access_block' in actual}"
    )


# --------------------------------------------------- static website hosting


def test_a_new_bucket_serves_no_website(s3):
    """Off is reported as a value. AWS raises for a bucket that never had one."""
    s3.create_bucket(Bucket=BUCKET)

    site = s3_buckets.get_website(s3, BUCKET)

    assert site == {"enabled": False, "index": None, "error": None}


def test_hosting_switches_on_and_back_off(s3):
    ok, name, _ = s3_buckets.create_bucket(
        s3, BUCKET, region=REGION, secure_by_default=False)
    assert ok

    ok, message = s3_buckets.enable_website(s3, name)
    assert ok, message
    site = s3_buckets.get_website(s3, name)
    assert site["enabled"]
    assert site["index"] == "index.html"

    ok, message = s3_buckets.disable_website(s3, name)
    assert ok, message
    assert s3_buckets.get_website(s3, name)["enabled"] is False


def test_turning_hosting_off_twice_is_not_an_error(s3):
    """AWS accepts the delete on a bucket with no website, so this needs no
    exists-check and a double click is harmless."""
    s3.create_bucket(Bucket=BUCKET)

    assert s3_buckets.disable_website(s3, BUCKET)[0]
    assert s3_buckets.disable_website(s3, BUCKET)[0]


def test_turning_hosting_on_does_not_open_the_bucket(s3):
    """The switch configures hosting and stops there.

    Hosting and exposure are separate settings and this keeps them separate.
    A button labelled "serve a website" that also published every object would
    be the same shape of mistake as a create call that claimed to unblock a
    bucket without writing anything - a control asserting an outcome it did
    not produce.
    """
    ok, name, _ = s3_buckets.create_bucket(s3, BUCKET, region=REGION)
    assert ok
    before = s3_buckets.get_public_access_block(s3, name)

    ok, _ = s3_buckets.enable_website(s3, name)
    assert ok

    assert s3_buckets.get_public_access_block(s3, name) == before
    assert s3_buckets.get_public_access_block(s3, name) == s3_buckets.ALL_BLOCKS_ON
    assert s3_buckets.reachable_by_anyone(s3, name) == []


def test_turning_hosting_on_says_what_still_blocks_it(s3):
    """A hardened bucket has three separate reasons its site will not serve,
    and the message names them rather than reporting a bare success."""
    ok, name, _ = s3_buckets.create_bucket(s3, BUCKET, region=REGION)
    assert ok

    ok, message = s3_buckets.enable_website(s3, name)
    assert ok

    assert "Nothing is public" in message
    assert "403" in message
    # The one that is easy to miss: the website endpoint is http-only, so the
    # CIS 2.1.1 fix this tool applies by default denies every request to it.
    assert "http-only" in message


def test_a_bucket_can_be_created_already_hosting(s3):
    ok, name, problems = s3_buckets.create_bucket(
        s3, BUCKET, region=REGION, secure_by_default=False, website=True)
    assert ok

    assert s3_buckets.get_website(s3, name)["enabled"] is True
    # The outcome is reported rather than left to be discovered. Asking for a
    # site and getting one that serves nobody is the case worth a sentence.
    assert any("website hosting is on" in p for p in problems), problems


def test_creating_without_asking_for_a_website_leaves_hosting_off(s3):
    """The default, stated as a test because a create-time switch that
    defaulted on would grow an endpoint on every bucket this tool has made."""
    ok, name, problems = s3_buckets.create_bucket(s3, BUCKET, region=REGION)
    assert ok

    assert s3_buckets.get_website(s3, name)["enabled"] is False
    assert not any("website" in p.lower() for p in problems)


def test_a_secure_bucket_that_hosts_is_told_it_serves_nobody(s3):
    """Both boxes ticked is the combination that silently does not work.

    The endpoint is http-only and secure_by_default installs a policy denying
    exactly that, so the site refuses every visitor. Nothing prevents the
    combination - it is legitimate, and the second step is somebody's to take -
    but it is not allowed to look like it worked.
    """
    ok, name, problems = s3_buckets.create_bucket(
        s3, BUCKET, region=REGION, secure_by_default=True, website=True)
    assert ok

    said = " ".join(problems)
    assert "http-only" in said, problems
    assert "403" in said, problems


def test_website_endpoint_spells_both_region_forms():
    """Older regions take a dash, newer ones a dot. There is no rule, only a
    list, and getting it wrong yields a hostname that does not resolve."""
    assert s3_buckets.website_endpoint("b", "us-west-2") == (
        "http://b.s3-website-us-west-2.amazonaws.com")
    assert s3_buckets.website_endpoint("b", "eu-central-1") == (
        "http://b.s3-website.eu-central-1.amazonaws.com")


def test_the_page_and_the_backend_agree_on_which_regions_take_a_dash():
    """frontend/app.js keeps its own copy so it can show a bucket's address
    without a round trip. Two copies of a list nothing derives is exactly how
    the two drift, so the drift is asserted rather than hoped against."""
    from pathlib import Path
    import re

    page = (Path(__file__).resolve().parents[2]
            / "frontend" / "app.js").read_text(encoding="utf-8")
    block = re.search(r"WEBSITE_DASH_REGIONS = new Set\(\[(.*?)\]\)", page, re.S)
    assert block, "the page no longer declares WEBSITE_DASH_REGIONS"

    in_page = set(re.findall(r'"([a-z0-9-]+)"', block.group(1)))
    assert in_page == s3_buckets._WEBSITE_DASH_REGIONS


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
