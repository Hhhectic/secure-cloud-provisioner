"""Tests for snapshot reading and the rules over it.

Three of these exist because moto disagrees with AWS rather than because the
logic is subtle, and they are marked as such where they appear. moto ignores
both of the filters this module relies on and reports one error code where AWS
reports three, so the offline suite has to check what this code does with the
answer rather than trusting the fake to have filtered anything.
"""

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from api import registry
from aws import snapshots
from scripts import make_vulnerable
from aws.s3_buckets import PermissionDenied
from scanner.snapshot_rules import check_snapshot, check_snapshots
from scanner.common import CRITICAL, WARNING, summarize, fixable, cited

REGION = "us-east-1"


def _settings(**overrides):
    base = {
        "snapshot_id": "snap-0123456789abcdef0",
        "description": "nightly",
        "volume_id": "vol-0123456789abcdef0",
        "volume_size": 8,
        "encrypted": True,
        "state": "completed",
        "started": None,
        "owner_id": "123456789012",
        "public": False,
        "shared_with": [],
        "managed_by_us": False,
        "unreadable": {},
    }
    base.update(overrides)
    return base


@pytest.fixture
def ec2():
    with mock_aws():
        yield boto3.client("ec2", region_name=REGION)


def _snapshot(ec2, size=1, description="test", encrypted=False):
    volume = ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=size,
                               Encrypted=encrypted)
    return ec2.create_snapshot(VolumeId=volume["VolumeId"],
                               Description=description)["SnapshotId"]


def _make_public(ec2, snapshot_id):
    ec2.modify_snapshot_attribute(
        SnapshotId=snapshot_id,
        Attribute="createVolumePermission",
        OperationType="add",
        GroupNames=["all"],
    )


# ------------------------------------------------------------------- The rules


def test_a_snapshot_anyone_can_restore_is_critical():
    warnings = check_snapshot(_settings(public=True, encrypted=False))
    assert summarize(warnings)[CRITICAL] == 1

    critical = [w for w in warnings if w["level"] == CRITICAL][0]
    # The finding has to be actionable without leaving the page it is on.
    assert "modify-snapshot-attribute" in critical["message"]
    assert "snap-0123456789abcdef0" in critical["message"]


def test_a_private_encrypted_snapshot_produces_nothing():
    assert check_snapshot(_settings()) == []


def test_permissions_that_could_not_be_read_are_never_reported_as_private():
    """The one wrong answer here that reassures.

    A login without DescribeSnapshotAttribute cannot tell a private snapshot
    from a world-readable one. Reporting the safe half of that would be worse
    than reporting nothing, so "public" stays None and the gap is a finding.
    """
    warnings = check_snapshot(_settings(
        public=None,
        unreadable={"restore_permission": "ec2:DescribeSnapshotAttribute"},
    ))

    assert warnings
    assert summarize(warnings)[CRITICAL] == 0

    said = " ".join(w["message"] for w in warnings)
    assert "ec2:DescribeSnapshotAttribute" in said
    assert "unexamined" in said


def test_sharing_with_named_accounts_is_reported_without_crying_wolf():
    warnings = check_snapshot(_settings(shared_with=["210987654321"]))

    assert summarize(warnings)[CRITICAL] == 0
    assert summarize(warnings)[WARNING] == 1
    assert "210987654321" in warnings[0]["message"]


def test_a_long_share_list_is_summarised_rather_than_recited():
    accounts = [str(100000000000 + n) for n in range(9)]
    warnings = check_snapshot(_settings(shared_with=accounts))

    message = warnings[0]["message"]
    assert "9 other AWS accounts" in message
    assert "and 4 more" in message


def test_an_unencrypted_snapshot_explains_why_encryption_is_the_guard():
    """Encryption is reported in terms of the critical finding, not as boilerplate.

    AWS refuses to make an encrypted snapshot public at all, so this setting
    decides whether the worst case is reachable. A message that said only
    "encryption is off" would be true and would not explain why anyone should
    care about it here specifically.
    """
    warnings = check_snapshot(_settings(encrypted=False))

    assert summarize(warnings)[WARNING] == 1
    assert "will not let an encrypted backup be shared with everyone" in \
        warnings[0]["message"]


def test_no_snapshot_finding_offers_an_automatic_fix():
    warnings = check_snapshot(_settings(public=True, encrypted=False,
                                        shared_with=["210987654321"]))
    assert warnings
    assert fixable(warnings) == []


def test_nothing_here_claims_a_published_control():
    """Uncited on purpose. See the note at the foot of scanner/controls.py.

    CIS has no control over who may restore a snapshot, and the one usually
    quoted belongs to a standard this tool does not assess against.
    """
    warnings = check_snapshot(_settings(public=True, encrypted=False,
                                        shared_with=["210987654321"]))
    assert cited(warnings) == []


def test_every_finding_says_which_snapshot_it_came_from():
    warnings = check_snapshot(_settings(
        public=True,
        encrypted=False,
        shared_with=["210987654321"],
        unreadable={"restore_permission": "ec2:DescribeSnapshotAttribute"},
    ))

    assert len(warnings) == 4
    for w in warnings:
        assert w["resource_id"] == "snap-0123456789abcdef0", w


def test_a_scanner_tolerates_being_handed_nothing():
    """Every reader returns None for a resource that is not there."""
    assert check_snapshot(None) == []
    assert check_snapshots(None) == []


def test_several_snapshots_come_back_worst_first():
    warnings = check_snapshots([
        _settings(snapshot_id="snap-quiet"),
        _settings(snapshot_id="snap-loud", public=True, encrypted=False),
    ])

    assert warnings[0]["level"] == CRITICAL
    assert warnings[0]["resource_id"] == "snap-loud"


# -------------------------------------------------------------------- Reading


def test_a_snapshot_that_is_not_there_reads_back_as_none(ec2):
    assert snapshots.read_snapshot_for_scanning(
        ec2, "snap-00000000000000000") is None


def test_reading_reports_who_can_restore_it(ec2):
    snapshot_id = _snapshot(ec2)

    settings = snapshots.read_snapshot_for_scanning(ec2, snapshot_id)
    assert settings["public"] is False
    assert settings["shared_with"] == []
    assert settings["unreadable"] == {}

    _make_public(ec2, snapshot_id)

    settings = snapshots.read_snapshot_for_scanning(ec2, snapshot_id)
    assert settings["public"] is True
    assert summarize(check_snapshot(settings))[CRITICAL] == 1


def test_listing_leaves_out_snapshots_this_account_does_not_own(ec2):
    """moto ignores OwnerIds and answers with the AMI snapshots it seeds.

    Around twelve hundred of them, belonging to Amazon and to the Canonical and
    Red Hat accounts that publish public images. AWS honours the filter and
    moto does not, so the ownership check lives in list_snapshots rather than
    in the query - without it every rule about "our snapshots" would be
    answered from strangers' disks, offline, while looking correct.
    """
    mine = _snapshot(ec2)

    unfiltered = ec2.describe_snapshots(OwnerIds=["self"])["Snapshots"]
    assert len(unfiltered) > 100, "moto stopped seeding; this test is now moot"
    assert len({s["OwnerId"] for s in unfiltered}) > 1

    ours = snapshots.list_snapshots(ec2)
    assert [s["SnapshotId"] for s in ours] == [mine]


def test_the_sweep_confirms_each_candidate_rather_than_trusting_the_filter(ec2):
    """RestorableByUserIds is the other filter moto does not implement.

    It returns every snapshot regardless, so code that trusted the sweep would
    report a clean account's whole snapshot list as world-readable. Asking each
    candidate directly is what makes the answer right against both.
    """
    public_one = _snapshot(ec2, description="exposed")
    _snapshot(ec2, description="private")
    _make_public(ec2, public_one)

    swept = ec2.describe_snapshots(OwnerIds=["self"],
                                   RestorableByUserIds=["all"])["Snapshots"]
    assert len([s for s in swept if s["OwnerId"] == "123456789012"]) == 2

    found = snapshots.publicly_restorable(ec2)
    assert [s["SnapshotId"] for s in found] == [public_one]


def test_a_login_that_cannot_read_permissions_leaves_the_question_open():
    """Modelled with a stub, because moto grants everything.

    The permission failure has to arrive as an unanswered question rather than
    as a crash or a pass, and there is no way to provoke it against the fake.
    """
    class Stub:
        meta = type("meta", (), {"region_name": REGION})()

        def describe_snapshots(self, **kwargs):
            return {"Snapshots": [{
                "SnapshotId": "snap-0123456789abcdef0",
                "OwnerId": "123456789012",
                "VolumeSize": 8,
                "Encrypted": True,
                "State": "completed",
            }]}

        def describe_snapshot_attribute(self, **kwargs):
            raise ClientError(
                {"Error": {"Code": "UnauthorizedOperation",
                           "Message": "not authorized"}},
                "DescribeSnapshotAttribute",
            )

    settings = snapshots.read_snapshot_for_scanning(
        Stub(), "snap-0123456789abcdef0")

    assert settings["public"] is None
    assert settings["unreadable"] == {
        "restore_permission": "ec2:DescribeSnapshotAttribute"}
    assert summarize(check_snapshot(settings))[WARNING] == 1


@pytest.mark.parametrize("code", ["InvalidSnapshot.NotFound",
                                  "InvalidSnapshotID.Malformed",
                                  "InvalidParameterValue"])
def test_every_way_aws_says_no_such_snapshot_reads_back_as_none(code):
    """Three codes for one answer, and moto only ever produces the first.

    A well-formed ID that does not exist, an ID of the wrong length, and
    something that is not an ID at all. Handling only what the fake returns
    would turn two of the three into a 500 where a 404 belongs, and only ever
    against a real account.
    """
    class Stub:
        meta = type("meta", (), {"region_name": REGION})()

        def describe_snapshots(self, **kwargs):
            raise ClientError({"Error": {"Code": code, "Message": "no"}},
                              "DescribeSnapshots")

    assert snapshots.read_snapshot_for_scanning(Stub(), "whatever") is None


def test_a_refused_listing_says_which_permission_was_missing():
    """Not an empty list. An account with no snapshots and an account this
    login cannot look at are different answers, and only one of them is good
    news."""
    class Paginator:
        def paginate(self, **kwargs):
            raise ClientError(
                {"Error": {"Code": "UnauthorizedOperation", "Message": "no"}},
                "DescribeSnapshots")

    class Stub:
        meta = type("meta", (), {"region_name": REGION})()
        _scp_account_id = "123456789012"

        def get_paginator(self, name):
            return Paginator()

    with pytest.raises(PermissionDenied) as raised:
        snapshots.list_snapshots(Stub())

    assert raised.value.permission == "ec2:DescribeSnapshots"


# ------------------------------------------------------------------- Registry


def test_the_registry_offers_no_way_to_create_or_delete_a_snapshot():
    """Audited, not provisioned. The routes answer 405 rather than advertising
    an endpoint that could only ever refuse."""
    resource = registry.get("snapshot")

    assert resource.read_only
    for operation in (resource.create, resource.delete, resource.cleanup):
        with pytest.raises(NotImplementedError):
            operation(None, None)


# -------------------------------------------------- The demo script's guardrail


def _demo_volume_and_snapshot(ec2, size=1):
    volume = ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=size)
    snapshot = ec2.create_snapshot(VolumeId=volume["VolumeId"])
    return volume["VolumeId"], snapshot["SnapshotId"]


def test_a_blank_unattached_volume_is_safe_to_publish(ec2):
    volume, snapshot = _demo_volume_and_snapshot(ec2)

    ok, reason = make_vulnerable._safe_to_publish(ec2, volume, snapshot)
    assert ok, reason


def test_a_volume_something_has_been_attached_to_is_never_published(ec2):
    """The check that stands between a demo and a real incident.

    A volume that has been attached to a machine may hold anything. The demo
    only ever publishes a disk created seconds earlier and never used, and
    "never used" has to be verified rather than assumed - the script could be
    edited, or pointed at the wrong ID.
    """
    volume, snapshot = _demo_volume_and_snapshot(ec2)

    image = ec2.describe_images()["Images"][0]["ImageId"]
    instance = ec2.run_instances(ImageId=image, MinCount=1, MaxCount=1,
                                 InstanceType="t3.micro")["Instances"][0]
    ec2.attach_volume(VolumeId=volume, InstanceId=instance["InstanceId"],
                      Device="/dev/sdh")

    ok, reason = make_vulnerable._safe_to_publish(ec2, volume, snapshot)
    assert not ok
    assert "attached" in reason


def test_a_volume_of_the_wrong_size_is_never_published(ec2):
    """Not the disk this script made, so its contents are unknown."""
    volume, snapshot = _demo_volume_and_snapshot(ec2, size=8)

    ok, reason = make_vulnerable._safe_to_publish(ec2, volume, snapshot)
    assert not ok
    assert "not the disk this script made" in reason


def test_a_snapshot_of_some_other_volume_is_never_published(ec2):
    """Publishing is decided by the volume, so the pair has to match."""
    volume, _ = _demo_volume_and_snapshot(ec2)
    _, elsewhere = _demo_volume_and_snapshot(ec2)

    ok, reason = make_vulnerable._safe_to_publish(ec2, volume, elsewhere)
    assert not ok
    assert "did not come from this script's volume" in reason


def test_the_fix_route_declines_and_says_what_to_run_instead():
    ok, message = snapshots.apply_fix(None, "snap-0123456789abcdef0", {})
    assert not ok
    assert "by hand" in message
