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
