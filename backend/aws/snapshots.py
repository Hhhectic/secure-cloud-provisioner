"""EBS snapshots, audited and never created.

A snapshot is a complete, readable copy of a disk. Not a summary of it and not
a backup in the sense of an archive that needs restoring somewhere special:
anyone who can restore it gets a volume they can attach and browse, including
the parts of the disk holding files that were deleted before it was taken,
because deleting a file removes the reference and leaves the contents.

That is why this module exists. A snapshot can be marked readable by every AWS
account in the world with one API call, the setting is not visible on the
snapshot list in the console, and nothing is logged when a stranger restores
one. Nobody discovers this by looking at their account; they discover it when
someone tells them. It is a real and recurring leak, and it is entirely
invisible until asked about directly.

Nothing here writes. Snapshots are audited rather than provisioned, for the
reason the registry gives: there is no sensible "create a snapshot posture"
operation, and a tool that offered to delete someone's disk backups on their
behalf would be dangerous in a way none of the rest of this is. The findings
say what to do; a person decides whether to do it.

Two things about reading snapshots differ from reading a bucket or a group.

Ownership has to be checked here rather than delegated to the API. The
OwnerIds filter is what AWS honours, but a snapshot belonging to somebody else
is not this account's leak to report even when it is genuinely public, and a
listing that mixed the two would attribute a stranger's mistake to the person
reading it.

Whether a snapshot is public lives on a separate attribute, not on the
snapshot. DescribeSnapshots never returns it, so a scan that only listed
snapshots would report confidently on the one property that matters without
ever having asked about it.
"""

import boto3
from botocore.exceptions import ClientError

from aws.s3_buckets import PermissionDenied

MANAGED_TAG_KEY = "ManagedBy"
MANAGED_TAG_VALUE = "secure-cloud-provisioner"

# AWS's name for "every AWS account in the world" in a createVolumePermission
# entry. A group of one value, and the only value it ever takes.
EVERYONE = "all"

# Codes that mean "this login is not allowed to look". EC2 answers
# UnauthorizedOperation where S3 answers AccessDenied, so the two modules
# cannot share a set even though they share the exception.
_DENIED = {"UnauthorizedOperation", "AccessDenied", "AccessDeniedException"}

# Codes that all mean "no snapshot by that name".
#
# moto answers InvalidSnapshot.NotFound to everything, including an ID that is
# not the right shape to be one. Real AWS distinguishes: a well-formed ID that
# does not exist is InvalidSnapshot.NotFound, a wrong-length one is
# InvalidSnapshotID.Malformed, and something that is not an ID at all is
# InvalidParameterValue. Catching only what the fake produces would return a
# 500 where a 404 belongs for two of the three, and only ever against AWS.
_NOT_FOUND = {
    "InvalidSnapshot.NotFound",
    "InvalidSnapshotID.Malformed",
    "InvalidParameterValue",
}

_ACCOUNT_ATTRIBUTE = "_scp_account_id"


def get_client(region="us-east-1"):
    """Initializes and returns an EC2 client."""
    return boto3.client("ec2", region_name=region)


def _denied(e, permission):
    """Converts an access-denied ClientError into PermissionDenied, else re-raises."""
    if e.response["Error"]["Code"] in _DENIED:
        raise PermissionDenied(permission, e.response["Error"]["Message"]) from e
    raise


def account_id(ec2):
    """The account this client belongs to, remembered on the client.

    Asked once rather than per listing. Unlike IAM, an EC2 client's region is
    the real one, so STS resolves normally and none of the pseudo-region
    trouble in aws/iam.py applies here.
    """
    cached = getattr(ec2, _ACCOUNT_ATTRIBUTE, None)
    if cached:
        return cached

    sts = boto3.client("sts", region_name=ec2.meta.region_name)
    try:
        found = sts.get_caller_identity()["Account"]
    except ClientError as e:
        _denied(e, "sts:GetCallerIdentity")

    setattr(ec2, _ACCOUNT_ATTRIBUTE, found)
    return found


# ------------------------------------------------------------------------ Read


def list_snapshots(ec2, only_ours=False):
    """Snapshots this account owns, newest first.

    The ownership check is done here as well as asked for in the query. AWS
    honours OwnerIds and moto ignores it completely, returning the twelve
    hundred public AMI snapshots it seeds itself - so the offline suite would
    otherwise be exercising a list of strangers' disks, and any rule about
    "how many of our snapshots are public" would be answered from them.
    """
    mine = account_id(ec2)

    filters = []
    if only_ours:
        filters.append({"Name": f"tag:{MANAGED_TAG_KEY}",
                        "Values": [MANAGED_TAG_VALUE]})

    found = []
    paginator = ec2.get_paginator("describe_snapshots")
    try:
        for page in paginator.paginate(OwnerIds=["self"], Filters=filters):
            found.extend(s for s in page.get("Snapshots", [])
                         if s.get("OwnerId") == mine)
    except ClientError as e:
        _denied(e, "ec2:DescribeSnapshots")

    # Two-part key so a snapshot with no start time sorts last instead of
    # raising: comparing a datetime against a fallback of 0 is a TypeError, and
    # it would only ever fire on whichever account first held such a snapshot.
    return sorted(found,
                  key=lambda s: (s.get("StartTime") is not None,
                                 s.get("StartTime")),
                  reverse=True)


def read_create_volume_permission(ec2, snapshot_id):
    """Who, other than this account, can restore this snapshot.

    Returns {"public": bool, "shared_with": [account id, ...]}.

    This is a separate call from describing the snapshot because it is a
    separate attribute in the API, and it is the whole point of the audit: a
    snapshot's own description says nothing about who can read it.
    """
    try:
        permissions = ec2.describe_snapshot_attribute(
            SnapshotId=snapshot_id,
            Attribute="createVolumePermission",
        )["CreateVolumePermissions"]
    except ClientError as e:
        _denied(e, "ec2:DescribeSnapshotAttribute")

    return {
        "public": any(p.get("Group") == EVERYONE for p in permissions),
        "shared_with": sorted(p["UserId"] for p in permissions
                              if p.get("UserId")),
    }


def publicly_restorable(ec2):
    """Every snapshot this account has made readable by anyone.

    One sweep call to find candidates, then one confirming read each. On a real
    account the sweep does the work and the confirmations cost nothing, because
    the answer is almost always an empty list.

    The confirmation is not redundant. RestorableByUserIds is a filter moto
    does not implement - it returns every snapshot it holds regardless - so
    trusting the sweep alone would report a clean account's entire snapshot
    list as public, offline, with no way to tell that from the real thing.
    Asking each candidate directly is right against both.
    """
    mine = account_id(ec2)

    candidates = []
    paginator = ec2.get_paginator("describe_snapshots")
    try:
        for page in paginator.paginate(OwnerIds=["self"],
                                       RestorableByUserIds=[EVERYONE]):
            candidates.extend(s for s in page.get("Snapshots", [])
                              if s.get("OwnerId") == mine)
    except ClientError as e:
        _denied(e, "ec2:DescribeSnapshots")

    confirmed = []
    for snapshot in candidates:
        if read_create_volume_permission(ec2, snapshot["SnapshotId"])["public"]:
            confirmed.append(snapshot)

    return confirmed


def read_snapshot_for_scanning(ec2, snapshot_id):
    """Retrieves one snapshot's settings formatted for scanner processing.

    Returns None when there is no such snapshot, so the routes can answer 404
    rather than letting an AWS exception surface as a 500.

    Who can restore it is recorded in "unreadable" when the login cannot ask,
    and "public" stays None rather than falling to False. A snapshot this tool
    was not allowed to ask about must not be reported as private: that is the
    one wrong answer here that reassures.
    """
    try:
        found = ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"]
    except ClientError as e:
        if e.response["Error"]["Code"] in _NOT_FOUND:
            return None
        _denied(e, "ec2:DescribeSnapshots")

    if not found:
        return None

    snapshot = found[0]
    tags = {t["Key"]: t["Value"] for t in snapshot.get("Tags", [])}

    settings = {
        "snapshot_id": snapshot["SnapshotId"],
        "description": snapshot.get("Description") or "",
        "volume_id": snapshot.get("VolumeId"),
        "volume_size": snapshot.get("VolumeSize"),
        "encrypted": snapshot.get("Encrypted", False),
        "state": snapshot.get("State"),
        "started": snapshot.get("StartTime"),
        "owner_id": snapshot.get("OwnerId"),
        "managed_by_us": tags.get(MANAGED_TAG_KEY) == MANAGED_TAG_VALUE,
    }

    unreadable = {}
    try:
        settings.update(read_create_volume_permission(ec2, snapshot_id))
    except PermissionDenied as e:
        settings["public"] = None
        settings["shared_with"] = []
        unreadable["restore_permission"] = e.permission

    settings["unreadable"] = unreadable
    return settings


# ------------------------------------------------------------------------- Fix


def apply_fix(ec2, snapshot_id, warning):
    """Snapshot findings are not fixed automatically.

    Making a public snapshot private is one call and this tool deliberately
    does not make it. The reason is not that the change is dangerous - it is
    the safe direction - but that this module holds no write permission at all,
    and a resource type that is audited in every other respect should not grow
    one write path that quietly makes it something else. The IAM policy does
    not grant ModifySnapshotAttribute either, so an attempt would fail on the
    permission rather than on this refusal.

    The finding says exactly what to run instead. A person who reads why a
    snapshot was public is less likely to make the next one public than a
    person who clicked a button.
    """
    return False, (
        "Snapshot findings have to be acted on by hand. The finding says which "
        "command makes this snapshot private again; this tool holds no "
        "permission to change a snapshot and does not ask for one."
    )
