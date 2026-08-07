"""Creates deliberately misconfigured resources so the scanner has something to find.

This exists because AWS has closed off most of the easy ways to create an
insecure resource. Since January 2023 every new bucket is encrypted, and since
April 2023 every new bucket has public access blocked, regardless of what the
creating API asks for. Both are good changes. They also mean "create a weak
bucket and watch the tool catch it" no longer works as a demonstration: the
platform hardens the bucket before the scanner ever sees it.

So the weakening happens deliberately, after creation, here.

What this script will and will not do
-------------------------------------
It turns off Block Public Access, which is what CIS 2.1.4 checks. It does not
attach a public bucket policy or a public ACL. That distinction is the whole
point: with the blocks off the bucket is *able* to be made public, which is a
real and reportable finding, but nothing in it is actually readable by anyone.
A script that genuinely published data to the internet would be one forgotten
teardown away from being a real incident, and no demonstration is worth that.

Security groups need no such care. AWS will happily open port 22 to the world,
which is exactly why the rule exists.

The public snapshot follows the bucket's rule, not the security group's
-----------------------------------------------------------------------
A snapshot is the one thing here that cannot be *nearly* published. There is
no equivalent of "the blocks are off but nothing is readable": either every
AWS account on earth can restore it or none can, and the finding only fires on
the first. So the exposure is made real and the data is removed instead.

The snapshot is taken from a volume created seconds earlier, one gibibyte,
never attached to anything, never formatted and never written to. It is a
blank device. Publishing it exposes zeros, and the finding it produces is
byte-for-byte the finding a genuinely leaked disk would produce, because the
condition being detected is the permission and not the contents.

Three things are checked before the permission is changed: that this run
created the volume, that nothing has ever been attached to it, and that it is
still the size it was made. Any of them failing stops the publish. That is a
guardrail rather than a comment, because the failure it prevents is publishing
somebody's actual disk.

It is off by default and needs --with-public-snapshot, and it needs write
permissions the tool itself deliberately does not hold. See
docs/iam-policy-demo.json.

Everything created here is tagged like any other resource this tool makes, so
the ordinary cleanup finds it:

    python scripts/make_vulnerable.py           # create the demo resources
    python scripts/make_vulnerable.py --with-public-snapshot
    python scripts/make_vulnerable.py --clean   # remove them again
"""

import argparse
import random
import string
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from botocore.exceptions import ClientError

from api import registry
from aws import s3_buckets
from aws import snapshots
from scanner.common import summarize, fixable, print_warnings

YELLOW, GREEN, DIM, RESET = "\033[33m", "\033[32m", "\033[2m", "\033[0m"
RED = "\033[31m"

# One gibibyte, the smallest EBS allows. Named because the number is part of
# the safety argument rather than a tuning choice: a blank volume this size
# costs pennies a month and holds nothing worth reading.
DEMO_VOLUME_SIZE = 1

DEMO_TAGS = [
    {"Key": snapshots.MANAGED_TAG_KEY, "Value": snapshots.MANAGED_TAG_VALUE},
    {"Key": "Environment", "Value": "test"},
    {"Key": "Name", "Value": "scp-demo-public-snapshot"},
]


def suffix():
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=6))


def make_exposed_security_group(region):
    """Opens SSH and RDP to the whole internet. CIS 5.3."""
    resource = registry.SECURITY_GROUP
    client = resource.get_client(region)

    ok, group_id, problems = resource.create(client, {
        "name": f"scp-demo-{suffix()}",
        "description": "DEMO ONLY - deliberately misconfigured. Safe to delete.",
        "rules": [
            {"protocol": "tcp", "from_port": 22, "to_port": 22,
             "source": "0.0.0.0/0"},
            {"protocol": "tcp", "from_port": 3389, "to_port": 3389,
             "source": "0.0.0.0/0"},
            {"protocol": "tcp", "from_port": 3306, "to_port": 3306,
             "source": "0.0.0.0/0"},
        ],
    })

    if not ok:
        print(f"  could not create the group: {group_id}")
        return None

    for p in problems:
        print(f"  {YELLOW}note{RESET} {p}")

    print(f"  created {group_id}")
    print(f"  {DIM}SSH, remote desktop and MySQL all open to the internet{RESET}")
    return group_id


def make_exposed_bucket(region):
    """Creates a bucket and then removes the protections AWS applied.

    Returns the bucket name, or None. See the module docstring for what is
    deliberately not done here.
    """
    resource = registry.BUCKET
    client = resource.get_client(region)
    name = f"scp-demo-{suffix()}"

    ok, created, problems = resource.create(client, {
        "name": name, "region": region, "secure_by_default": False,
    })

    if not ok:
        print(f"  could not create the bucket: {created}")
        return None

    for p in problems:
        print(f"  {YELLOW}note{RESET} {p}")

    # AWS switched these on by itself. Turn them back off so CIS 2.1.4 has
    # something to report. Every flag false is what an unprotected bucket
    # looked like before April 2023.
    try:
        client.put_public_access_block(
            Bucket=created,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )
        print(f"  created {created}")
        print(f"  {DIM}public access blocks switched off; no data is public{RESET}")
    except ClientError as e:
        print(f"  created {created} but could not weaken it: "
              f"{e.response['Error']['Message']}")

    return created


def _blank_volume(client, region):
    """Creates an empty volume and waits for it. Nothing ever writes to it."""
    zone = client.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]

    volume = client.create_volume(
        AvailabilityZone=zone,
        Size=DEMO_VOLUME_SIZE,
        VolumeType="gp3",
        # Unencrypted on purpose, twice over. AWS refuses to make an encrypted
        # snapshot public at all, so the critical finding is unreachable
        # without this - and it also lights up the encryption rule, which is
        # the finding that explains why.
        Encrypted=False,
        TagSpecifications=[{"ResourceType": "volume", "Tags": DEMO_TAGS}],
    )["VolumeId"]

    client.get_waiter("volume_available").wait(VolumeIds=[volume])
    return volume


def _safe_to_publish(client, volume_id, snapshot_id):
    """The three checks that stand between this script and a real incident.

    Returns (ok, reason). Every one of these is about the volume rather than
    the snapshot, because the snapshot is only as empty as the disk it came
    from, and the disk is the thing that could have had something on it.
    """
    try:
        volume = client.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]
    except ClientError as e:
        return False, f"could not re-read the volume: {e}"

    if volume.get("Attachments"):
        return False, ("the volume has been attached to something, so it may "
                       "hold real data")

    if volume.get("Size") != DEMO_VOLUME_SIZE:
        return False, (f"the volume is {volume.get('Size')} GiB, not "
                       f"{DEMO_VOLUME_SIZE}; this is not the disk this script "
                       "made")

    snapshot = snapshots.read_snapshot_for_scanning(client, snapshot_id)
    if snapshot is None or snapshot.get("volume_id") != volume_id:
        return False, "the snapshot did not come from this script's volume"

    return True, ""


def make_public_snapshot(region):
    """Publishes a snapshot of a blank volume. Returns the snapshot ID or None.

    See the module docstring for why this one is made genuinely public where
    the bucket is not.
    """
    client = registry.SNAPSHOT.get_client(region)

    try:
        volume = _blank_volume(client, region)
        print(f"  created blank volume {volume} "
              f"({DEMO_VOLUME_SIZE} GiB, never attached, never written to)")

        snapshot = client.create_snapshot(
            VolumeId=volume,
            Description="DEMO ONLY - snapshot of an empty volume. No data.",
            TagSpecifications=[{"ResourceType": "snapshot", "Tags": DEMO_TAGS}],
        )["SnapshotId"]

        print(f"  taking snapshot {snapshot}, this takes a moment...")
        client.get_waiter("snapshot_completed").wait(SnapshotIds=[snapshot])

    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("UnauthorizedOperation", "AccessDenied"):
            print(f"  {RED}refused: {code}{RESET}")
            print("  This needs write permissions the tool itself does not "
                  "hold.")
            print("  Attach docs/iam-policy-demo.json, run this, then detach "
                  "it.")
            return None
        print(f"  could not create the snapshot: {e.response['Error']['Message']}")
        return None

    ok, reason = _safe_to_publish(client, volume, snapshot)
    if not ok:
        print(f"  {RED}not publishing: {reason}{RESET}")
        print(f"  {DIM}the snapshot exists and is private. --clean removes "
              f"it.{RESET}")
        return snapshot

    try:
        client.modify_snapshot_attribute(
            SnapshotId=snapshot,
            Attribute="createVolumePermission",
            OperationType="add",
            GroupNames=["all"],
        )
    except ClientError as e:
        print(f"  created {snapshot} but could not publish it: "
              f"{e.response['Error']['Message']}")
        return snapshot

    print(f"  {YELLOW}published {snapshot} to every AWS account{RESET}")
    print(f"  {DIM}it holds no data; the finding is real, the exposure is "
          f"not{RESET}")
    return snapshot


def clean_demo_snapshots(region):
    """Removes the snapshot and its volume.

    Separate from clean() because snapshots are read_only in the registry -
    there is deliberately no cleanup callable for a type this tool audits, so
    the demo has to undo its own mess.
    """
    client = registry.SNAPSHOT.get_client(region)
    removed = 0

    for snapshot in snapshots.list_snapshots(client, only_ours=True):
        sid = snapshot["SnapshotId"]
        try:
            client.delete_snapshot(SnapshotId=sid)
            print(f"  {GREEN}removed{RESET} {sid}  {DIM}disk backup{RESET}")
            removed += 1
        except ClientError as e:
            print(f"  failed  {sid}  {DIM}{e.response['Error']['Message']}{RESET}")

    try:
        volumes = client.describe_volumes(Filters=[
            {"Name": f"tag:{snapshots.MANAGED_TAG_KEY}",
             "Values": [snapshots.MANAGED_TAG_VALUE]},
            {"Name": "status", "Values": ["available"]},
        ])["Volumes"]
    except ClientError as e:
        print(f"  could not list demo volumes: {e.response['Error']['Message']}")
        return

    for volume in volumes:
        vid = volume["VolumeId"]
        try:
            client.delete_volume(VolumeId=vid)
            print(f"  {GREEN}removed{RESET} {vid}  {DIM}blank volume{RESET}")
            removed += 1
        except ClientError as e:
            print(f"  failed  {vid}  {DIM}{e.response['Error']['Message']}{RESET}")

    if not removed:
        print("  no demo snapshots or volumes to remove")


def show_findings(resource, client, resource_id):
    warnings = resource.check(resource.read(client, resource_id))
    counts = summarize(warnings)

    print(f"\n  What the scanner sees on {resource_id}:")
    print_warnings(warnings)
    print(f"\n  {counts['critical']} critical, {counts['warning']} warning, "
          f"{counts['info']} informational, "
          f"{len(fixable(warnings))} fixable")


def clean(region):
    print("Removing everything this tool created\n")
    for resource in registry.REGISTRY.values():
        # An audited type made nothing, so it has nothing to remove and no
        # cleanup to call. Without this the sweep dies on the first one.
        if resource.read_only:
            continue

        client = resource.get_client(region)
        results = resource.cleanup(client, {"force": True})
        if not results:
            print(f"  no {resource.label.lower()}s to remove")
        for rid, ok, message in results:
            mark = f"{GREEN}removed{RESET}" if ok else "failed "
            print(f"  {mark} {rid}  {DIM}{message}{RESET}")

    # Always, regardless of which flags created things. A forgotten public
    # snapshot is the one leftover here that matters.
    clean_demo_snapshots(region)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--clean", action="store_true",
                        help="delete the demo resources instead of creating them")
    parser.add_argument("--with-public-snapshot", action="store_true",
                        help="also publish a snapshot of a blank volume to "
                             "every AWS account (holds no data; see the "
                             "module docstring)")
    args = parser.parse_args()

    if args.clean:
        clean(args.region)
        return 0

    print(f"{YELLOW}This creates real, deliberately misconfigured AWS "
          f"resources.{RESET}")
    print("Security groups with ports open to the internet, and a bucket with")
    print("its public access protections removed. No data is made public.")
    print(f"\nRun with --clean when you are finished. Region: {args.region}")

    if input("\nContinue? (y/N): ").strip().lower() != "y":
        print("Nothing created.")
        return 0

    # Asked separately from the question above, and after it. This is the only
    # thing here that is genuinely visible outside the account, and a person
    # who said yes to "open some ports" has not thereby said yes to this.
    if args.with_public_snapshot:
        print(f"\n{YELLOW}--with-public-snapshot is set.{RESET}")
        print("A snapshot of a blank, never-attached volume will be made")
        print("restorable by every AWS account in the world. It contains no")
        print("data. It is still a real public snapshot, and it stays public")
        print("until --clean removes it.")
        if input("\nPublish it? (y/N): ").strip().lower() != "y":
            args.with_public_snapshot = False
            print("Skipping the snapshot. Everything else still runs.")

    print("\nSecurity group\n" + "-" * 14)
    group_id = make_exposed_security_group(args.region)
    if group_id:
        show_findings(registry.SECURITY_GROUP,
                      registry.SECURITY_GROUP.get_client(args.region), group_id)

    print("\nBucket\n" + "-" * 6)
    bucket = make_exposed_bucket(args.region)
    if bucket:
        show_findings(registry.BUCKET,
                      registry.BUCKET.get_client(args.region), bucket)

    if args.with_public_snapshot:
        print("\nDisk backup\n" + "-" * 11)
        snapshot = make_public_snapshot(args.region)
        if snapshot:
            show_findings(registry.SNAPSHOT,
                          registry.SNAPSHOT.get_client(args.region), snapshot)

    print(f"\n{YELLOW}These are live. Run --clean when you are done.{RESET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
