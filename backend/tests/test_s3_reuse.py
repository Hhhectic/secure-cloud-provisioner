"""Tests for reusing a bucket name that already exists.

The behaviour under test is a us-east-1 quirk worth stating plainly: CreateBucket
is idempotent there. Recreating a bucket you already own returns success rather
than raising BucketAlreadyOwnedByYou, which is what every other region does. Code
that detects reuse by catching that exception therefore works everywhere except
the default region, which is the worst possible place for it to not work.
"""

import boto3
import pytest
from moto import mock_aws

from scanner.s3_rules import check_bucket_settings
from scanner.common import CRITICAL, summarize
from aws import s3_buckets

REGION = "us-east-1"
BUCKET = "scp-reuse-test-bucket"


@pytest.fixture
def s3():
    with mock_aws():
        yield boto3.client("s3", region_name=REGION)


def test_bucket_exists_is_false_before_and_true_after(s3):
    assert s3_buckets.bucket_exists(s3, BUCKET) is False
    s3.create_bucket(Bucket=BUCKET)
    assert s3_buckets.bucket_exists(s3, BUCKET) is True


def test_reuse_is_reported_despite_idempotent_create(s3):
    """The create call succeeds twice, so the tool must detect reuse itself."""
    _, _, first = s3_buckets.create_bucket(s3, BUCKET, region=REGION)
    _, _, second = s3_buckets.create_bucket(s3, BUCKET, region=REGION)

    assert first == []
    assert any("already existed" in p for p in second)


def test_reusing_an_existing_bucket_still_hardens_it(s3):
    """A weak bucket must not stay weak just because the name was taken.

    The earlier version returned as soon as it saw a duplicate, so pointing the
    tool at an existing unhardened bucket left it exactly as it found it.
    """
    s3.create_bucket(Bucket=BUCKET)

    before = check_bucket_settings(s3_buckets.read_bucket_for_scanning(s3, BUCKET))
    assert summarize(before)[CRITICAL] > 0

    ok, name, problems = s3_buckets.create_bucket(s3, BUCKET, region=REGION)
    assert ok
    assert any("already existed" in p for p in problems)

    after = check_bucket_settings(s3_buckets.read_bucket_for_scanning(s3, name))
    assert summarize(after)[CRITICAL] == 0


def test_reuse_still_applies_the_managed_tag(s3):
    """Otherwise a bucket made by hand stays invisible to cleanup forever."""
    s3.create_bucket(Bucket=BUCKET)
    assert s3_buckets.get_bucket_tags(s3, BUCKET) == {}

    s3_buckets.create_bucket(s3, BUCKET, region=REGION)

    tags = s3_buckets.get_bucket_tags(s3, BUCKET)
    assert tags[s3_buckets.MANAGED_TAG_KEY] == s3_buckets.MANAGED_TAG_VALUE
    assert BUCKET in [b["Name"] for b in s3_buckets.list_buckets(s3, only_ours=True)]


def _writable(s3, name, blocked=True):
    """A bucket this suite can actually put an object into.

    `secure_by_default` installs a policy denying any request where
    `aws:SecureTransport` is false, and **moto evaluates it** - against its own
    test client, which speaks plain HTTP. So a bucket created the secure way
    refuses every upload in the offline suite and accepts them perfectly
    against AWS, where boto3 has always used HTTPS.

    That is the reverse of moto's usual failure. The trap recorded elsewhere
    in this project is moto being *more* permissive than AWS; here it is
    stricter, by enforcing a condition that is never true in production. A
    test that took the refusal at face value would conclude uploads do not
    work.

    The smoke test uploads to a bucket created the normal way, which is where
    that claim can honestly be made.
    """
    ok, name_or_error, _ = s3_buckets.create_bucket(
        s3, name, region=REGION, secure_by_default=False)
    assert ok, name_or_error
    if blocked:
        # secure_by_default=False leaves no block configuration at all, which
        # reachable_by_anyone correctly reads as public. Put the blocks on
        # explicitly so these buckets differ from a secure one only in the
        # transport policy moto over-enforces.
        s3.put_public_access_block(
            Bucket=name,
            PublicAccessBlockConfiguration=s3_buckets.ALL_BLOCKS_ON)
    return name

# --------------------------------------------------- what is inside a bucket


def test_a_scan_can_see_how_much_is_in_a_bucket(s3):
    """The scanner could not previously look inside one, so a world-readable
    empty bucket and a world-readable bucket holding two hundred files were
    reported in identical words. They are not the same event: one is a
    misconfiguration and the other is an incident."""
    _writable(s3, "counted-bucket")
    for n in range(3):
        s3.put_object(Bucket="counted-bucket", Key=f"file-{n}.txt", Body=b"x")

    inside = s3_buckets.read_bucket_for_scanning(s3, "counted-bucket")["objects"]

    assert inside["count"] == 3
    assert inside["at_least"] is False
    assert sorted(inside["names"]) == ["file-0.txt", "file-1.txt", "file-2.txt"]


def test_an_empty_bucket_is_zero_rather_than_unknown(s3):
    s3_buckets.create_bucket(s3, "empty-bucket")
    inside = s3_buckets.read_bucket_for_scanning(s3, "empty-bucket")["objects"]
    assert inside["count"] == 0
    assert inside["names"] == []


def test_the_public_finding_says_how_much_is_behind_it(s3):
    """A clause, not a separate finding. How much is exposed belongs in the
    sentence about the exposure."""
    settings = {"bucket": "b", "policy_is_public": True, "unreadable": {},
                "objects": {"count": 12, "at_least": False, "bytes": 0,
                            "names": []}}
    found = [w for w in check_bucket_settings(settings)
             if w["rule"]["setting"] == "public_policy"]

    assert len(found) == 1
    assert "12 objects in it" in found[0]["message"]


def test_the_public_finding_stays_silent_when_the_contents_are_unreadable(s3):
    """A missing clause must not be read as "nothing in it". The unreadable
    list carries that separately, as it does for every other setting."""
    settings = {"bucket": "b", "policy_is_public": True,
                "unreadable": {"objects": "s3:ListBucket"},
                "objects": None}
    found = [w for w in check_bucket_settings(settings)
             if w["rule"]["setting"] == "public_policy"]

    assert "object" not in found[0]["message"]


# ----------------------------------------- uploading, and refusing to upload


def test_uploading_puts_the_objects_there(s3):
    _writable(s3, "upload-target")

    ok, message, written = s3_buckets.put_objects(
        s3, "upload-target", [("notes.txt", b"hello"), ("more.txt", b"there")])

    assert ok, message
    assert written == ["notes.txt", "more.txt"]
    inside = s3_buckets.read_bucket_for_scanning(s3, "upload-target")["objects"]
    assert inside["count"] == 2


def test_it_refuses_to_upload_into_a_bucket_the_world_can_read(s3):
    """The guard this whole feature is built around.

    Everything else in this tool is careful never to put data behind an
    exposure: make_vulnerable weakens a bucket and deliberately stops, and it
    publishes a snapshot only after proving the volume it came from was never
    written to. An upload button in the same interface that can turn Block
    Public Access off puts both halves one click apart, and the half that goes
    wrong is silent - a file lands somewhere readable and nothing says so.
    """
    _writable(s3, "open-bucket")
    s3.put_public_access_block(
        Bucket="open-bucket",
        PublicAccessBlockConfiguration=s3_buckets.ALL_BLOCKS_ON)
    # Closed, then opened, which is the sequence that matters.
    s3.delete_public_access_block(Bucket="open-bucket")

    ok, message, written = s3_buckets.put_objects(
        s3, "open-bucket", [("secret.txt", b"do not publish me")])

    assert not ok
    assert written == []
    assert "already open" in message
    # And nothing was written on the way to deciding that.
    inside = s3_buckets.read_bucket_for_scanning(s3, "open-bucket")["objects"]
    assert inside["count"] == 0


def test_the_check_is_made_against_the_bucket_now_not_when_it_was_created(s3):
    """A bucket created secure ten minutes ago may not be secure now, and the
    only reading that matters is the one taken against the state the object
    would actually land in."""
    _writable(s3, "was-secure")
    s3.put_public_access_block(
        Bucket="was-secure",
        PublicAccessBlockConfiguration=s3_buckets.ALL_BLOCKS_ON)
    assert s3_buckets.put_objects(s3, "was-secure", [("a.txt", b"1")])[0]

    s3.delete_public_access_block(Bucket="was-secure")

    ok, message, _ = s3_buckets.put_objects(s3, "was-secure", [("b.txt", b"2")])
    assert not ok
    assert "already open" in message


def test_a_setting_that_cannot_be_read_counts_as_public(s3, monkeypatch):
    """The one place in this module where an unanswered question is resolved
    against proceeding. The cost of being wrong runs one way only: a file
    nobody meant to publish, published."""
    _writable(s3, "cannot-tell")

    def refuse(*a, **k):
        raise s3_buckets.PermissionDenied("s3:GetBucketPolicyStatus")
    monkeypatch.setattr(s3_buckets, "policy_is_public", refuse)

    ok, message, _ = s3_buckets.put_objects(s3, "cannot-tell", [("a.txt", b"1")])
    assert not ok
    assert "could not be read" in message
