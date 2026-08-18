"""Checks that ask every region, and say so honestly when they cannot.

Two findings here were account-wide questions answered in one place. CIS 1.19
asks for an Access Analyzer in *every* region and this asked the one the tool
was pointed at; `publicly_restorable` sees only its client's region, so an
account passing it had been shown to pass it once.

Both are the same shape, and so is the trap in both: a sweep that quietly
degrades into a single-region check reports "nothing wrong anywhere" on the
strength of one region. Every test below that matters is about that failure
rather than about the happy path.
"""

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from aws import iam, snapshots
from aws.common import enabled_regions
from scanner.iam_rules import check_account

REGION = "us-east-1"


@pytest.fixture
def aws():
    with mock_aws():
        yield


# ------------------------------------------------------------ Region listing


def test_the_region_list_comes_from_the_account_not_a_constant(aws):
    """A hardcoded list is wrong in both directions - stale as AWS opens
    regions, and naming ones this account never opted into."""
    found = enabled_regions(REGION)

    assert REGION in found
    assert len(found) > 5
    assert found == sorted(found)


def test_a_refused_region_list_raises_rather_than_shrinking_to_one(aws):
    """The decision belongs to the caller.

    Falling back to [region] here would let every sweep built on this claim it
    looked everywhere while looking in one place. Each caller catches this and
    records that it could not sweep.
    """
    def refuse(*a, **k):
        raise ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "no"}},
            "DescribeRegions")

    ec2 = boto3.client("ec2", region_name=REGION)
    ec2.describe_regions = refuse

    import aws.common as common
    original = common.client
    common.client = lambda service, region=None: ec2
    try:
        with pytest.raises(ClientError):
            enabled_regions(REGION)
    finally:
        common.client = original


# -------------------------------------------------------- Access Analyzer


def test_the_analyzer_sweep_reports_which_regions_it_reached(aws):
    """moto implements no Access Analyzer at all, so nothing answers and the
    whole check has to land in `unreadable` rather than as zero analyzers -
    which would read as "no analyzer anywhere", the reassuring wrong answer."""
    client = iam.get_client(REGION)
    settings = iam.read_account_for_scanning(client)

    assert settings["analyzer_coverage"] is None
    assert "analyzer_coverage" in settings["unreadable"]


def test_a_sweep_that_could_not_list_regions_says_one_region(aws):
    """The honesty case, driven through the rule.

    swept=False has to change the sentence. Without it, "no analyzer in the one
    region I could see" is reported in the words of "no analyzer in your
    account", and somebody acts on a claim nothing supports.
    """
    warnings = check_account({
        "account_id": "123456789012", "region": REGION, "unreadable": {},
        "analyzer_coverage": {"home": REGION, "checked": [REGION],
                              "without": [REGION], "swept": False},
    })
    message = next(w["message"] for w in warnings
                   if w["rule"]["setting"] == "access_analyzer")

    assert "one region rather than a sweep" in message
    assert "regions are not watching" not in message


def test_a_real_sweep_counts_regions_rather_than_hedging(aws):
    warnings = check_account({
        "account_id": "123456789012", "region": REGION, "unreadable": {},
        "analyzer_coverage": {
            "home": REGION, "checked": ["us-east-1", "eu-west-1", "ap-south-1"],
            "without": ["eu-west-1"], "swept": True},
    })
    message = next(w["message"] for w in warnings
                   if w["rule"]["setting"] == "access_analyzer")

    assert "1 of this account's 3 regions" in message
    assert "eu-west-1" in message
    assert "one region rather than a sweep" not in message


# ------------------------------------------------------------- Snapshots


def test_the_snapshot_sweep_visits_more_than_its_own_region(aws):
    found = snapshots.publicly_restorable_everywhere(REGION)

    assert found["swept"] is True
    assert REGION in found["checked"]
    assert len(found["checked"]) > 5, "a sweep of one region is not a sweep"
    assert found["found"] == [], "moto's account has no public snapshots"


def test_a_public_snapshot_is_found_in_a_region_nobody_is_watching(aws):
    """The whole point of the sweep. A snapshot shared with the world in a
    region nobody opens is the one that goes unnoticed; the region somebody
    works in daily is where a mistake gets spotted anyway."""
    far = "eu-west-1"
    ec2 = boto3.client("ec2", region_name=far)
    volume = ec2.create_volume(AvailabilityZone=f"{far}a", Size=1)
    snap = ec2.create_snapshot(VolumeId=volume["VolumeId"])["SnapshotId"]
    ec2.modify_snapshot_attribute(
        SnapshotId=snap, Attribute="createVolumePermission",
        OperationType="add", GroupNames=["all"])

    found = snapshots.publicly_restorable_everywhere(REGION)

    assert [s["region"] for s in found["found"]] == [far]
    assert found["found"][0]["id"] == snap


def test_the_snapshot_sweep_admits_when_it_could_not_sweep(aws, monkeypatch):
    """Same contract as the analyzer one. Reporting an empty `found` with
    swept=True after seeing a single region would be the clean bill of health
    this project spends `unreadable` on refusing to give."""
    def refuse(_region=None):
        raise ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "no"}},
            "DescribeRegions")

    monkeypatch.setattr(snapshots, "enabled_regions", refuse)
    found = snapshots.publicly_restorable_everywhere(REGION)

    assert found["swept"] is False
    assert found["checked"] == [REGION]
