"""End-to-end check against a real AWS account.

The pytest suite runs against moto, which fakes AWS in memory. That is the right
default: it is fast, free, needs no credentials, and it can simulate failures
that are hard to arrange for real. What it cannot do is tell you whether the
tool works.

moto has already disagreed with AWS twice in this project. It permits buckets
with no encryption, which AWS has not allowed since January 2023. And it
enforces the aws:SecureTransport condition over its own plain-HTTP endpoint,
which real boto3 never triggers because it speaks HTTPS. Both surfaced by
accident. This script is the deliberate version.

It also exercises the one thing moto structurally cannot check: whether the IAM
policy the tool is running under actually grants what the tool needs. Every
permission gap shows up here as a clear message naming the missing action.

Run it from the backend directory:

    python scripts/smoke_test.py            # create, scan, fix, verify, delete
    python scripts/smoke_test.py --keep     # leave the resources behind
    python scripts/smoke_test.py --region eu-west-2

This creates real resources. Security groups are free and empty buckets are
free, so the expected cost is nothing, but teardown runs in a finally block
either way. If the script is killed mid-run, `python main.py` has a purge option
for each resource type that finds anything left behind by its tag.
"""

import argparse
import json
import os
import random
import shutil
import string
import sys
import tempfile
import time
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, WaiterError

from api import registry
from aws import key_pairs as kp
from aws import instances as ec2i
from aws import snapshots
from aws import vpcs
from aws.s3_buckets import PermissionDenied
from scanner.common import (summarize, fixable, cited, print_warnings,
                            CRITICAL)

GREEN, RED, YELLOW, DIM, RESET = (
    "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"
)

results = {"passed": 0, "failed": 0, "notes": []}


def ok(message):
    results["passed"] += 1
    print(f"  {GREEN}pass{RESET}  {message}")


def fail(message):
    results["failed"] += 1
    print(f"  {RED}FAIL{RESET}  {message}")


def note(message):
    """Records something true but unexpected rather than treating it as failure.

    Divergence between moto and AWS is the main thing this script exists to
    surface, and most of it is not a defect in either. It needs to be visible
    without being alarming.
    """
    results["notes"].append(message)
    print(f"  {YELLOW}note{RESET}  {message}")


def check(condition, message):
    ok(message) if condition else fail(message)
    return condition


def heading(title):
    print(f"\n{title}\n{'-' * len(title)}")


def suffix():
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


# ------------------------------------------------------------------- Identity


def confirm_identity(region):
    heading("Credentials")
    try:
        who = boto3.client("sts", region_name=region).get_caller_identity()
    except NoCredentialsError:
        fail("No credentials found. Run `aws configure` first.")
        return None
    except ClientError as e:
        fail(f"Credentials rejected: {e.response['Error']['Message']}")
        return None

    print(f"  {DIM}account {who['Account']}{RESET}")
    print(f"  {DIM}{who['Arn']}{RESET}")
    ok("credentials work")
    return who


# ------------------------------------------------------------ Security groups


def smoke_security_group(region):
    heading("Security groups")

    resource = registry.SECURITY_GROUP
    client = resource.get_client(region)
    name = f"scp-smoke-{suffix()}"
    group_id = None

    try:
        spec = {
            "name": name,
            "description": "Created by the smoke test. Safe to delete.",
            "rules": [{"protocol": "tcp", "from_port": 22, "to_port": 22,
                       "source": "0.0.0.0/0"}],
        }

        print(f"  {DIM}group name: {name}{RESET}")

        created, group_id, problems = resource.create(client, spec)
        if not check(created, "created a group with SSH open to the world"):
            print(f"        {group_id}")
            return
        for p in problems:
            note(p)

        print(f"  {DIM}group id:   {group_id}{RESET}")

        # ---- Read it back and confirm the scanner sees the exposure ----------
        warnings = resource.check(resource.read(client, group_id))
        counts = summarize(warnings)

        check(counts[CRITICAL] >= 1,
              "scanner flagged the open SSH port as critical")

        ssh = next((w for w in warnings if w["rule_id"]
                    and w.get("rule", {}).get("from_port") == 22), None)
        if not check(ssh is not None, "the finding names the rule that caused it"):
            return

        print(f"  {DIM}offending rule id: {ssh['rule_id']}{RESET}")
        print(f"  {DIM}currently allows:  {ssh['rule']['source']}{RESET}")

        check(ssh["control"] and ssh["control"]["id"] == "5.3",
              "finding cites CIS 5.3")
        check(len(fixable(warnings)) >= 1, "the finding is marked fixable")

        # ---- Fix it, using the genuinely detected public IP ------------------
        fixed, message = resource.fix(client, group_id, ssh, {})
        if not check(fixed, "narrowed the rule to this machine's address"):
            print(f"        {message}")
            return
        print(f"        {DIM}{message}{RESET}")

        # ---- Confirm the fix actually landed ---------------------------------
        after = resource.check(resource.read(client, group_id))
        check(summarize(after)[CRITICAL] == 0,
              "re-scan shows the exposure is gone")

        rules = resource.read(client, group_id)["rules"]
        for r in rules:
            print(f"  {DIM}now: port {r['from_port']} allows "
                  f"{r['source']}  ({r['rule_id']}){RESET}")

        check(all(r["source"] != "0.0.0.0/0" for r in rules),
              "no rule still allows the whole internet")
        check(len(rules) == 1,
              "the rule was narrowed rather than deleted")

        unused = [w for w in after if w["rule_id"]
                  and w["rule_id"].endswith(":unused")]
        check(len(unused) == 1,
              "a group attached to nothing is reported as unused")

    except PermissionDenied as e:
        fail(f"missing IAM permission {e.permission}")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("UnauthorizedOperation", "AccessDenied"):
            fail(f"the IAM policy is missing something: {e.response['Error']['Message']}")
        else:
            fail(f"{code}: {e.response['Error']['Message']}")
    finally:
        if group_id and not KEEP:
            deleted, message = resource.delete(client, group_id, {})
            check(deleted, f"cleaned up {group_id}")
            if not deleted:
                print(f"        {message}")
        elif group_id:
            note(f"left {group_id} in place")


# ------------------------------------------------------------------- Buckets


def smoke_bucket(region):
    heading("Storage buckets")

    resource = registry.BUCKET
    client = resource.get_client(region)
    name = f"scp-smoke-{suffix()}"
    created_name = None

    try:
        created, created_name, problems = resource.create(
            client, {"name": name, "region": region, "secure_by_default": False}
        )
        if not check(created, "created a bucket with no hardening applied"):
            print(f"        {created_name}")
            created_name = None
            return
        for p in problems:
            note(p)

        print(f"  {DIM}bucket name: {created_name}{RESET}")
        print(f"  {DIM}arn:         arn:aws:s3:::{created_name}{RESET}")

        settings = resource.read(client, created_name)
        warnings = resource.check(settings)

        encryption_now = settings.get("encryption") or {}
        versioning_now = settings.get("versioning") or {}
        print(f"\n  {DIM}what AWS actually gave us:{RESET}")
        print(f"    encryption:     {encryption_now.get('algorithm') or 'none'}")
        print(f"    versioning:     "
              f"{'on' if versioning_now.get('enabled') else 'off'}")
        print(f"    public blocks:  "
              f"{settings.get('public_access_block') or 'not configured'}")
        print(f"    refuses HTTP:   {settings.get('policy_denies_http')}")

        if settings.get("unreadable"):
            for setting, permission in settings["unreadable"].items():
                fail(f"could not read {setting}: missing {permission}")

        # ---- The divergences this script exists to catch ---------------------
        #
        # AWS has moved twice to make insecure buckets harder to create, and
        # moto has not followed. Both paths below are correct code that a new
        # bucket can no longer reach. Neither is a failure; both need saying.
        encryption = settings.get("encryption") or {}
        if encryption.get("enabled"):
            note("AWS encrypted this bucket itself, as it has for every new "
                 "bucket since January 2023. moto does not, so the "
                 "unencrypted-bucket rule is tested but cannot fire on "
                 "anything created today.")
        else:
            note("this bucket came back unencrypted, which contradicts AWS's "
                 "documented behaviour since January 2023. Worth investigating.")

        ids = {w["control"]["id"] for w in cited(warnings)}

        pab = settings.get("public_access_block") or {}
        if all(pab.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls",
                                    "BlockPublicPolicy", "RestrictPublicBuckets")):
            note("AWS blocked public access on this bucket itself, as it has "
                 "for every new bucket since April 2023. CIS 2.1.4 therefore "
                 "cannot fail on a newly created bucket. It still fails on "
                 "buckets made before that date, and on any bucket where "
                 "someone has since turned the blocks off.")
        else:
            check("2.1.4" in ids, "scanner flagged public access is not blocked "
                                  "(CIS 2.1.4)")

        check("2.1.1" in ids, "scanner flagged plain HTTP is accepted "
                              "(CIS 2.1.1)")

        # ---- Fix everything it can -------------------------------------------
        actionable = fixable(warnings)
        check(len(actionable) >= 2, f"{len(actionable)} findings are fixable")

        for w in actionable:
            applied, message = resource.fix(client, created_name, w, {})
            if not applied:
                fail(f"fix failed: {message}")
                print(f"        {DIM}{w['message'][:70]}...{RESET}")

        # ---- Confirm ---------------------------------------------------------
        after = resource.check(resource.read(client, created_name))
        remaining = {w["control"]["id"] for w in cited(after)}

        check(summarize(after)[CRITICAL] == 0,
              "re-scan shows no critical findings left")
        check("2.1.4" not in remaining, "public access is now blocked")
        check("2.1.1" not in remaining, "plain HTTP is now refused")

        if remaining == {"2.1.2"}:
            ok("only the manual control (MFA delete) remains, as expected")
        elif remaining:
            note(f"controls still failing after fixes: {sorted(remaining)}")

    except PermissionDenied as e:
        fail(f"missing IAM permission {e.permission}")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "AccessDenied":
            fail(f"the IAM policy is missing something: {e.response['Error']['Message']}")
        else:
            fail(f"{code}: {e.response['Error']['Message']}")
    finally:
        if created_name and not KEEP:
            deleted, message = resource.delete(client, created_name,
                                               {"force": True})
            check(deleted, f"cleaned up {created_name}")
            if not deleted:
                print(f"        {message}")
        elif created_name:
            note(f"left {created_name} in place")


# ----------------------------------------------------------------- Key pairs


def smoke_key_pair(region):
    heading("Key pairs")

    resource = registry.KEY_PAIR
    client = resource.get_client(region)
    name = f"scp-smoke-{suffix()}"
    imported = None

    # Generated into a temporary directory rather than ~/.ssh, so a smoke test
    # never leaves keys in the place real ones live.
    workspace = tempfile.mkdtemp(prefix="scp-smoke-")

    try:
        print(f"  {DIM}key name: {name}{RESET}")

        generated, public_key, private_path = kp.generate_locally(
            name, directory=workspace
        )
        if not check(generated, "ssh-keygen produced a key pair locally"):
            print(f"        {public_key}")
            return

        private_size = Path(private_path).stat().st_size
        print(f"\n  {DIM}private key:  {private_path}  "
              f"({private_size} bytes, stays on this machine){RESET}")
        print(f"  {DIM}public key:   {private_path}.pub{RESET}")
        print(f"  {DIM}public key material, which is all that gets sent:{RESET}")
        print(f"    {public_key}")

        # Deliberately never printed: the contents of the private key file.
        # This script is run in front of people and its output gets pasted into
        # reports. The path is useful; the bytes are a secret.

        check(Path(private_path).exists(),
              "the private key was written to this machine")
        check(public_key.startswith("ssh-ed25519"),
              "ssh-keygen defaulted to ED25519")

        # The property the whole module is built around, checked rather than
        # assumed: what gets sent is the public half and nothing else.
        check("PRIVATE KEY" not in public_key,
              "the material about to be sent contains no private key")

        ok_import, imported, problems = resource.create(
            client, {"name": name, "public_key": public_key}
        )
        if not check(ok_import, "AWS accepted the public key"):
            print(f"        {imported}")
            imported = None
            return
        for p in problems:
            note(p)

        settings = resource.read(client, imported)

        print(f"\n  {DIM}what AWS now holds:{RESET}")
        print(f"    name:         {settings['key_name']}")
        print(f"    id:           {settings['key_pair_id']}")
        print(f"    type:         {settings['key_type']}")
        print(f"    fingerprint:  {settings['fingerprint']}")

        check(settings["key_type"] == "ED25519",
              "AWS reports it back as an ED25519 key")
        check(settings["managed_by_us"],
              "the key is tagged as created by this tool")

        warnings = resource.check(settings)
        unused = [w for w in warnings if w["rule_id"].endswith(":unused")]
        check(len(unused) == 1,
              "a key no instance uses is reported as unused")
        check(fixable(warnings) == [],
              "no key pair finding offers an automatic fix")

        # A private key AWS was never given cannot be recovered from AWS.
        stored = client.describe_key_pairs(KeyNames=[imported])["KeyPairs"][0]
        check("KeyMaterial" not in stored,
              "AWS holds no private key material for this pair")

    except kp.InvalidPublicKey as e:
        fail(f"the generated key was rejected by validation: {e}")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("UnauthorizedOperation", "AccessDenied"):
            fail(f"the IAM policy is missing something: {e.response['Error']['Message']}")
        else:
            fail(f"{code}: {e.response['Error']['Message']}")
    finally:
        if imported and not KEEP:
            removed, message = resource.delete(client, imported, {})
            check(removed, f"cleaned up {imported}")
            if not removed:
                print(f"        {message}")
        elif imported:
            note(f"left key pair {imported} in place")

        shutil.rmtree(workspace, ignore_errors=True)


# ------------------------------------------------------------------ Instances


def smoke_instance(region):
    """Launches one real instance, audits it, and terminates it.

    Opt-in, because this is the only section that spends money. A smoke test
    that quietly starts a server is a bad default however small the server is:
    the whole point of running it is that you can do so without thinking, and
    something you do without thinking should not have a running cost.

    A t3.micro is free-tier eligible and about a cent an hour otherwise, so the
    realistic cost of one run is nothing. The reason for the flag is the habit,
    not the amount.
    """
    heading("Instances")

    resource = registry.INSTANCE
    client = resource.get_client(region)
    name = f"scp-smoke-{suffix()}"
    instance_id = None

    try:
        print(f"  {DIM}name:          {name}{RESET}")
        print(f"  {DIM}type:          {ec2i.DEFAULT_INSTANCE_TYPE}{RESET}")

        image_id, err = ec2i.latest_ami(region)
        if not check(image_id is not None, "looked up the current machine image"):
            print(f"        {err}")
            return
        print(f"  {DIM}image:         {image_id}{RESET}")

        # The guardrail, against the real API rather than a mock.
        refused, message, _ = resource.create(client, {
            "name": f"{name}-toobig", "region": region,
            "instance_type": "p4d.24xlarge",
        })
        check(not refused, "refused an instance type off the allowlist")
        check("allowlist" in message, "the refusal explains itself")

        launched, instance_id, problems = resource.create(client, {
            "name": name, "region": region,
        })
        if not check(launched, "launched a private instance"):
            print(f"        {instance_id}")
            instance_id = None
            return
        for p in problems:
            note(p)

        print(f"  {DIM}instance id:   {instance_id}{RESET}")

        # The disk is attached a moment after RunInstances returns, so reading
        # encryption state immediately can come back unknown. Waiting also
        # proves the instance genuinely boots rather than failing after the
        # API call succeeded.
        print(f"  {DIM}waiting for it to start (up to a minute)...{RESET}")
        try:
            client.get_waiter("instance_running").wait(
                InstanceIds=[instance_id],
                WaiterConfig={"Delay": 5, "MaxAttempts": 24},
            )
            ok("the instance reached the running state")
        except WaiterError:
            fail("the instance never reached the running state")

        settings = resource.read(client, instance_id)["instance"]

        print(f"\n  {DIM}what AWS actually gave us:{RESET}")
        print(f"    state:          {settings['state']}")
        print(f"    type:           {settings['instance_type']}")
        print(f"    private ip:     {settings['private_ip']}")
        print(f"    public ip:      {settings['public_ip'] or 'none'}")
        print(f"    key pair:       {settings['key_name'] or 'none'}")
        print(f"    IMDSv2 forced:  {settings['imdsv2_required']}")
        print(f"    hop limit:      {settings['metadata_hop_limit']}")
        print(f"    disk encrypted: {settings['root_volume_encrypted']}")

        check(settings["imdsv2_required"],
              "the metadata service requires a session token (CIS 5.7)")
        check(settings["metadata_hop_limit"] == 1,
              "the metadata hop limit is 1, so containers cannot reach it")

        # The bug moto caught: a default subnet assigns a public address unless
        # the request explicitly declines one. Confirmed here against the real
        # API, because this is the check that matters most for the claim the
        # tool makes about instances it creates.
        check(settings["public_ip"] is None,
              "no public address, despite the subnet default assigning one")

        check(settings["root_volume_encrypted"] is True,
              "the disk was encrypted at creation")
        check(settings["managed_by_us"],
              "the instance is tagged as created by this tool")

        warnings = resource.check(resource.read(client, instance_id))
        criticals = [w for w in warnings if w["level"] == CRITICAL]
        check(criticals == [], "the scanner finds nothing critical")
        if warnings:
            print(f"\n  {DIM}informational findings:{RESET}")
            for w in warnings:
                print(f"    - {w['message'][:100]}...")

        # ---- The cross-resource loop -------------------------------------
        #
        # The key pair scanner calls a key unused until something uses it.
        # Only a real launch proves the two halves agree on what that means:
        # the key module asks about instances, the instance module records a
        # key name, and nothing in the offline suite forces them to match.
        key_name = f"{name}-key"
        attached_id = None
        try:
            generated, public_key, _ = kp.generate_locally(
                key_name, directory=tempfile.mkdtemp(prefix="scp-smoke-")
            )
            if not generated:
                note(f"skipped the key attachment check: {public_key}")
                return

            registry.KEY_PAIR.create(client, {"name": key_name,
                                              "public_key": public_key})

            before = registry.KEY_PAIR.check(
                registry.KEY_PAIR.read(client, key_name))
            check(any(w["rule_id"].endswith(":unused") for w in before),
                  "a freshly imported key is reported as unused")

            ok_launch, attached_id, _ = resource.create(client, {
                "name": f"{name}-with-key", "region": region,
                "key_name": key_name,
            })
            if not check(ok_launch, "launched a second instance with the key"):
                print(f"        {attached_id}")
                attached_id = None
                return

            print(f"  {DIM}second instance: {attached_id}{RESET}")

            attached = resource.read(client, attached_id)["instance"]
            check(attached["key_name"] == key_name,
                  f"the instance reports '{key_name}' attached")

            after = registry.KEY_PAIR.check(
                registry.KEY_PAIR.read(client, key_name))
            check(not any(w["rule_id"].endswith(":unused") for w in after),
                  "the key is no longer reported as unused")

        finally:
            if attached_id and not KEEP:
                stopped, message = resource.delete(client, attached_id, {})
                check(stopped, f"terminated {attached_id}")
                if not stopped:
                    print(f"        {RED}{message}{RESET}")
                    print(f"        {RED}TERMINATE THIS BY HAND. IT IS "
                          f"BILLING.{RESET}")
            elif attached_id:
                note(f"left {attached_id} RUNNING and billing")

            if not KEEP:
                registry.KEY_PAIR.delete(client, key_name, {})

    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("UnauthorizedOperation", "AccessDenied"):
            fail(f"the IAM policy is missing something: {e.response['Error']['Message']}")
        else:
            fail(f"{code}: {e.response['Error']['Message']}")
    finally:
        # Unlike every other teardown here, skipping this one costs money.
        if instance_id and not KEEP:
            stopped, message = resource.delete(client, instance_id, {})
            check(stopped, f"terminated {instance_id}")
            if not stopped:
                print(f"        {RED}{message}{RESET}")
                print(f"        {RED}TERMINATE THIS BY HAND. IT IS BILLING."
                      f"{RESET}")
        elif instance_id:
            note(f"left {instance_id} RUNNING and billing. Terminate it with "
                 f"`python scripts/make_vulnerable.py --clean`.")


# ------------------------------------------------------------------- Networks


def smoke_group_derived_placement(client, name, region, vpc_id, by_role):
    """Launches with security groups and no subnet, and checks where it lands.

    The one path nothing else exercises. Every other launch in this file either
    names a subnet or passes neither groups nor a subnet, so the code that
    reads the network back off the groups has never run against real AWS.

    moto cannot stand in for it either, and not by omission. The behaviour
    being worked around is AWS rejecting a machine whose security groups belong
    to a different network from its subnet; moto does not enforce that, so
    against moto the old code path - reach for the account's default subnet
    while holding a group from somewhere else - succeeds. The offline suite can
    prove the instance lands in the groups' network. Only a real account can
    prove the alternative would have been refused.

    The machine created here is left for the cascade a few lines later, which
    is the point: it should appear in the deletion plan for this network, and
    it only will if it landed where the groups said.
    """
    print(f"\n  {DIM}checking placement derived from security groups{RESET}")

    made, group_id, _ = registry.SECURITY_GROUP.create(client, {
        "name": f"{name}-placement-sg",
        "description": "Smoke test. Names the network by itself.",
        "vpc_id": vpc_id,
        "rules": [],
    })
    if not check(made, "created a group in the new network"):
        print(f"        {group_id}")
        return

    # No subnet_id. The groups are the only statement of intent available.
    launched, derived_id, problems = registry.INSTANCE.create(client, {
        "name": f"{name}-derived", "region": region,
        "security_group_ids": [group_id],
    })
    if not check(launched, "launched with groups and no subnet named"):
        print(f"        {derived_id}")
        return

    settings = registry.INSTANCE.read(client, derived_id)["instance"]
    subnet_ids = {s["subnet_id"] for s in by_role.values()}

    print(f"  {DIM}derived: {derived_id} landed in "
          f"{settings.get('subnet_id')}{RESET}")

    check(settings.get("vpc_id") == vpc_id,
          "it landed in the groups' network, not the account default")
    check(settings.get("subnet_id") in subnet_ids,
          "and in one of that network's own subnets")

    # Given a choice between a routable subnet and an isolated one, and no
    # instruction either way, the isolated one wins. Being unreachable is a
    # nuisance noticed in a minute; being routable is a protection lost quietly.
    check(settings.get("subnet_id") == by_role["private"]["subnet_id"],
          "specifically the subnet with no route to the internet")

    note = next((p for p in problems if "No subnet was named" in p), None)
    if check(note is not None, "the placement nobody chose was disclosed"):
        print(f"  {DIM}{note}{RESET}")


def smoke_network(region, with_instances):
    """Builds a network, audits it, and takes it apart again.

    Teardown is the reason this section exists. Everything else in the tool
    deletes in one call; a VPC refuses to go while anything lives in it and
    reports that as DependencyViolation naming nothing. moto answers all of
    this from a dictionary, instantly and in any order, so the ordering the
    teardown was written for has never actually been tested. This is the part
    most likely to differ, and a network that will not delete is the failure
    you would least want during a demonstration.

    Free unless --with-instances is set, which adds the occupied case.
    """
    heading("Networks")

    resource = registry.VPC
    client = resource.get_client(region)
    name = f"scp-smoke-{suffix()}"
    vpc_id = None

    try:
        print(f"  {DIM}name: {name}{RESET}")

        refused, message, _ = resource.create(client, {
            "name": f"{name}-nat", "region": region, "with_nat_gateway": True,
        })
        check(not refused, "refused to create a NAT gateway")
        check("$32" in message, "the refusal names the monthly cost")

        created, vpc_id, problems = resource.create(client, {
            "name": name, "region": region,
        })
        if not check(created, "created a network"):
            print(f"        {vpc_id}")
            vpc_id = None
            return
        for p in problems:
            note(p)

        print(f"  {DIM}vpc id: {vpc_id}{RESET}")

        settings = resource.read(client, vpc_id)
        by_role = {s["declared_role"]: s for s in settings["subnets"]}

        print(f"\n  {DIM}subnets AWS actually created:{RESET}")
        for subnet in settings["subnets"]:
            reach = "reaches the internet" if subnet["reaches_internet"] \
                else "no route out"
            print(f"    {subnet['name']:<26} {subnet['cidr']:<15} "
                  f"{subnet['availability_zone']:<12} {reach}")

        check(set(by_role) == {"public", "private"},
              "one public subnet and one private subnet")
        check(by_role["public"]["reaches_internet"] is True,
              "the public subnet routes to the internet gateway")

        # The claim the whole VPC exercise rests on. Asserted against the
        # routing rather than the name or any instance setting.
        check(by_role["private"]["reaches_internet"] is False,
              "the private subnet has no route to the internet at all")

        check(all(not s["auto_assign_public_ip"] for s in settings["subnets"]),
              "no subnet hands out public addresses automatically")
        check(all(not s["using_main_route_table"] for s in settings["subnets"]),
              "each subnet has its own route table")

        # The parameter-name bug: boto3 wants EnableDnsSupport, the AWS docs
        # write enableDnsSupport, and getting it wrong raises an exception
        # that is not a ClientError and so escapes the handler.
        dns = client.describe_vpc_attribute(
            VpcId=vpc_id, Attribute="enableDnsHostnames"
        )["EnableDnsHostnames"]["Value"]
        check(dns is True, "DNS hostnames are enabled")

        warnings = resource.check(settings)
        criticals = [w for w in warnings if w["level"] == CRITICAL]
        check(criticals == [], "the scanner finds nothing critical")

        ids = {w["control"]["id"] for w in cited(warnings)}
        check("3.7" in ids, "flow logs are reported missing (CIS 3.7)")

        # ---- Teardown, occupied and empty -------------------------------
        if with_instances:
            launched, instance_id, _ = registry.INSTANCE.create(client, {
                "name": f"{name}-resident", "region": region,
                "subnet_id": by_role["private"]["subnet_id"],
            })
            if check(launched, "launched a machine inside the network"):
                print(f"  {DIM}resident: {instance_id}{RESET}")

                smoke_group_derived_placement(client, name, region, vpc_id,
                                              by_role)

                blocked, message = resource.delete(client, vpc_id, {})
                check(not blocked,
                      "refused to delete a network with a machine in it")
                check(instance_id in message,
                      "the refusal names the machine that would be destroyed")

                plan = vpcs.plan_deletion(client, vpc_id)
                kinds = [kind for kind, _, _ in plan]
                check(kinds[0] == "server", "the plan removes machines first")
                check(kinds[-1] == "network", "the network itself goes last")

                # The group-derived machine has to show up here. If it had
                # landed in the account's default network instead, this plan
                # would not mention it and the cascade would leave it running.
                check(len([k for k in kinds if k == "server"]) == 2,
                      "both machines appear in this network's deletion plan")
                print(f"\n  {DIM}cascade would remove {len(plan)} things:{RESET}")
                for kind, item_id, label in plan:
                    print(f"    {kind:<17} {item_id:<24} {label}")

                print(f"\n  {DIM}terminating and deleting, this takes a "
                      f"minute...{RESET}")

        removed, message = resource.delete(client, vpc_id,
                                           {"force": with_instances})
        if check(removed, f"deleted {vpc_id} and everything in it"):
            vpc_id = None
        else:
            print(f"        {RED}{message}{RESET}")
            return

        remaining = [v["id"] for v in resource.list_all(client, True)]
        check(vpc_id not in remaining, "the network is really gone")

    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("UnauthorizedOperation", "AccessDenied"):
            fail(f"the IAM policy is missing something: {e.response['Error']['Message']}")
        else:
            fail(f"{code}: {e.response['Error']['Message']}")
    finally:
        if vpc_id and not KEEP:
            removed, message = resource.delete(client, vpc_id, {"force": True})
            check(removed, f"cleaned up {vpc_id}")
            if not removed:
                print(f"        {RED}{message}{RESET}")
                print(f"        {RED}A leftover network blocks the account's "
                      f"VPC limit. Remove it by hand.{RESET}")
        elif vpc_id:
            note(f"left network {vpc_id} in place")


# ------------------------------------------------------------- Account access


def smoke_account_audit(region):
    """Audits IAM against the real account. Creates nothing and costs nothing.

    Three things here cannot be checked offline at all. moto's credential
    report has no root row, so every root finding is invisible against it. moto
    has no Access Analyzer, so that check is always recorded as unread. And
    moto answers GetCredentialReport immediately, so the waiting that a real
    account requires never happens.
    """
    heading("Account access")

    resource = registry.IAM
    client = resource.get_client(region)

    listed = resource.list_all(client, only_ours=False)
    check(len(listed) == 1, "the account is one row, not a list of users")

    account_id = listed[0]["id"]
    started = time.time()
    settings = resource.read(client, account_id)
    elapsed = time.time() - started

    if not check(settings is not None, "the account read back"):
        return

    print(f"        read took {elapsed:.1f}s")

    skipped = settings["unreadable"]
    if skipped:
        for name, permission in skipped.items():
            note(f"could not check {name}: missing {permission}")
    else:
        ok("every check ran; nothing was skipped for want of a permission")

    # The two things moto cannot show at all.
    if settings.get("root_report") is not None:
        ok("the credential report includes the root account row")
    else:
        fail("no root row in the credential report - every root finding "
             "below is missing, and moto never shows this")

    if settings.get("analyzer_count") is not None:
        ok(f"Access Analyzer answered: {settings['analyzer_count']} analyzer(s) "
           f"in {region}")

    check(resource.read(client, "000000000000") is None,
          "asking about another account returns nothing rather than this one")

    warnings = resource.check(settings)
    counts = summarize(warnings)
    print(f"\n        {counts['critical']} critical, {counts['warning']} "
          f"warning, {counts['info']} informational")

    check(not fixable(warnings),
          "nothing here is offered as an automatic fix")

    described = resource.describe(settings)
    check("users" not in described,
          "the description does not restate every finding")

    print()
    print_warnings(warnings)


# ---------------------------------------------------------------- The routes


def smoke_api(region):
    """Drives the HTTP layer against the real account.

    Everything else here calls the registry adapters directly, which is one
    layer below the routes. That was fine while the only caller was a person
    at a terminal; now a web page depends on the routes and nothing had ever
    exercised them against anything but moto.

    TestClient calls the app in-process, so there is no port to bind - and
    with no moto around it, the boto3 calls underneath go to the real
    account. Free: a security group and a network cost nothing.
    """
    heading("The routes")

    from fastapi.testclient import TestClient
    from api.app import app

    # Somewhere disposable, so a smoke run does not append to the real log.
    log = Path(tempfile.mkdtemp(prefix="scp-smoke-audit-")) / "audit.log"
    os.environ["SCP_AUDIT_LOG"] = str(log)

    client = TestClient(app, base_url="http://127.0.0.1:8000")
    name = f"scp-smoke-{suffix()}"
    group_id = None

    try:
        check(client.get("/health").json() == {"status": "ok"},
              "the API answers")

        # ---- The guards, which cost nothing to try ----------------------
        rebound = client.get("/resources", headers={"Host": "evil.example"})
        check(rebound.status_code == 403,
              "a request for a rebound hostname is refused")

        cross = client.post(f"/resources/security-group/cleanup?force=true"
                            f"&confirm=security-group",
                            headers={"Origin": "https://evil.example"})
        check(cross.status_code == 403,
              "a write from another site's page is refused")

        guessed = client.post("/resources/security-group/cleanup?force=true"
                              "&confirm=security-group")
        check(guessed.status_code == 400,
              "a guessed cleanup confirmation is refused")

        # ---- What the forms are offered ---------------------------------
        options = client.get("/resources/security-group/options").json()["options"]
        check(any(o["value"].startswith("vpc-") for o in options["vpc_id"]),
              "the form is offered this account's real networks")

        instance_options = client.get("/resources/instance/options").json()["options"]
        check(set(o["value"] for o in instance_options["instance_type"])
              == set(ec2i.ALLOWED_INSTANCE_TYPES),
              "the size menu is the allowlist itself, not a copy of it")

        # ---- Create, scan, fix, delete, through the routes ---------------
        created = client.post("/resources/security-group", json={
            "name": name,
            "description": "smoke test of the HTTP layer",
            "rules": [{"protocol": "tcp", "from_port": 22, "to_port": 22,
                       "source": "0.0.0.0/0"}],
        })
        if not check(created.status_code == 201, "created a group over HTTP"):
            print(f"        {RED}{created.text}{RESET}")
            return
        group_id = created.json()["resource_id"]
        print(f"        {DIM}{group_id}{RESET}")

        scanned = client.get(f"/resources/security-group/{group_id}").json()
        check(scanned["counts"]["critical"] == 1,
              "the scan over HTTP finds the open port")
        check(scanned["settings"] is not None,
              "the scan says what the group is, not only what is wrong")

        fixable_here = [w for w in scanned["warnings"]
                        if w.get("fix") and w.get("rule_id")]
        if check(bool(fixable_here), "the finding is offered as fixable"):
            fixed = client.post(
                f"/resources/security-group/{group_id}/fix",
                json={"rule_id": fixable_here[0]["rule_id"]},
            )
            check(fixed.status_code == 200, "the fix applied over HTTP")
            rescanned = client.get(f"/resources/security-group/{group_id}").json()
            check(rescanned["counts"]["critical"] == 0,
                  "and the finding is gone on a rescan")

        # ---- The destructive guard, on something real -------------------
        forced = client.delete(f"/resources/security-group/{group_id}"
                               "?force=true")
        check(forced.status_code == 400,
              "a forced delete with no confirmation is refused")

        plan = client.get(f"/resources/security-group/{group_id}"
                          "/deletion-plan").json()
        check(plan["confirm_with"] == group_id,
              "the deletion plan says what to echo back")

        deleted = client.delete(f"/resources/security-group/{group_id}")
        if check(deleted.status_code == 200, "deleted it over HTTP"):
            group_id = None

        # ---- The audit log ----------------------------------------------
        entries = [json.loads(line) for line in
                   log.read_text().splitlines()] if log.exists() else []
        check(any(e.get("outcome") == "refused" for e in entries),
              "refusals are recorded, and they leave no trace in the account")
        check(any(e.get("outcome") == "done" for e in entries),
              "so are the things that happened")
        check(not any("/resources/security-group\"" in str(e.get("path", ""))
                      and e.get("method") == "GET" for e in entries),
              "reads are not recorded, which is what keeps the log readable")

    except ClientError as e:
        fail(f"{e.response['Error']['Code']}: {e.response['Error']['Message']}")
    finally:
        os.environ.pop("SCP_AUDIT_LOG", None)
        shutil.rmtree(log.parent, ignore_errors=True)
        if group_id and not KEEP:
            registry.SECURITY_GROUP.delete(
                registry.SECURITY_GROUP.get_client(region), group_id, {})


# ------------------------------------------------------------- Disk backups


def smoke_snapshots(region):
    """Audits EBS snapshots against the real account. Creates nothing, free.

    Almost all of this is here because moto disagrees with AWS. It ignores
    OwnerIds and RestorableByUserIds entirely, so neither filter is ever
    exercised against something that implements them, and it answers
    InvalidSnapshot.NotFound to every unusable ID where AWS distinguishes
    three cases that all have to arrive as the same None.
    """
    heading("Disk backups")

    resource = registry.SNAPSHOT
    client = resource.get_client(region)

    # The two rejections moto cannot produce. A well-formed ID that does not
    # exist is one code, an ID of the wrong length is another, and something
    # that is not an ID at all is a third; all three mean "no such snapshot"
    # and all three have to reach the routes as a 404 rather than a 500.
    check(resource.read(client, "snap-00000000000000000") is None,
          "a well-formed ID for nothing reads back as nothing")
    check(resource.read(client, "not-a-snapshot") is None,
          "an ID that is not one reads back as nothing rather than raising")

    mine = snapshots.account_id(client)
    owned = snapshots.list_snapshots(client)
    check(all(s.get("OwnerId") == mine for s in owned),
          "every backup listed belongs to this account")
    print(f"        {DIM}this account owns {len(owned)} backup(s) in "
          f"{region}{RESET}")

    # The whole reason this module exists, in one call.
    exposed = snapshots.publicly_restorable(client)
    if exposed:
        # Not a failure of the tool. A true finding about the account, and the
        # worst one this tool can report.
        note(f"{len(exposed)} backup(s) can be restored by anyone with an AWS "
             f"account: {', '.join(s['SnapshotId'] for s in exposed)}")
        print(f"        {RED}These are readable copies of disks and anyone "
              f"can take one.{RESET}")
    else:
        ok("no backup in this account can be restored by the public")

    if not owned:
        print(f"        {DIM}nothing to scan. An account with no backups is "
              f"the good version of this answer.{RESET}")
        return

    findings = []
    unanswered = 0
    for snapshot in owned:
        settings = resource.read(client, snapshot["SnapshotId"])
        # Deleted between the listing and this read. Not an error.
        if settings is None:
            continue
        if settings["public"] is None:
            unanswered += 1
        findings.extend(resource.check(settings))

    check(unanswered == 0,
          "who can restore each backup was readable for every one of them")

    counts = summarize(findings)
    print(f"\n        {counts['critical']} critical, {counts['warning']} "
          f"warning, {counts['info']} informational")

    check(not fixable(findings), "nothing here is offered as an automatic fix")
    check(not cited(findings),
          "no finding claims a published control, because none covers this")

    if findings:
        print()
        print_warnings(findings)


# ---------------------------------------------------------------------- Sweep


def report_leftovers(region):
    """Lists anything tagged as ours that is still in the account."""
    heading("Leftovers")

    for resource in registry.REGISTRY.values():
        # Leftovers means things this tool created and did not remove. An
        # audited type creates nothing, so everything it lists is someone
        # else's and reporting it here would read as a failure to tidy up.
        if resource.read_only:
            continue

        try:
            found = resource.list_all(resource.get_client(region), True)
        except (ClientError, PermissionDenied) as e:
            note(f"could not list {resource.label.lower()}s: {e}")
            continue

        if not found:
            ok(f"no {resource.label.lower()}s left behind")
            continue

        note(f"{len(found)} {resource.label.lower()}(s) still tagged as "
             "created by this tool:")
        for item in found:
            print(f"        {item['id']}  {item['name']}")

        # Every other leftover is untidy. A leftover instance is expensive.
        if resource.key == "instance":
            print(f"        {RED}These are running and billing. Terminate "
                  f"them:{RESET}")
            print(f"        {RED}  python scripts/make_vulnerable.py "
                  f"--clean{RESET}")


def main():
    global KEEP

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--keep", action="store_true",
                        help="do not delete what this script creates")
    parser.add_argument("--with-instances", action="store_true",
                        help="also launch and terminate a real t3.micro")
    args = parser.parse_args()
    KEEP = args.keep

    print(f"Smoke test against live AWS in {args.region}")
    if KEEP:
        print(f"{YELLOW}--keep is set: resources will be left behind{RESET}")
    if args.with_instances:
        print(f"{YELLOW}--with-instances is set: a real "
              f"{ec2i.DEFAULT_INSTANCE_TYPE} will be launched and "
              f"terminated{RESET}")
        if KEEP:
            print(f"{RED}--keep and --with-instances together will leave a "
                  f"server running and billing.{RESET}")

    if not confirm_identity(args.region):
        return 1

    try:
        smoke_security_group(args.region)
        smoke_bucket(args.region)
        smoke_key_pair(args.region)
        if args.with_instances:
            smoke_instance(args.region)
        else:
            heading("Instances")
            print(f"  {DIM}skipped. Pass --with-instances to launch and "
                  f"terminate a real one.{RESET}")

        # Networks are free, so this runs either way. --with-instances adds
        # the occupied-teardown case, which is the interesting half.
        smoke_network(args.region, args.with_instances)

        # Read-only and free, so these always run.
        smoke_account_audit(args.region)
        smoke_snapshots(args.region)

        # The HTTP layer, which everything above reaches one level below.
        smoke_api(args.region)

        report_leftovers(args.region)
    except Exception:
        print(f"\n{RED}Unhandled error{RESET}")
        traceback.print_exc()
        results["failed"] += 1

    heading("Summary")
    print(f"  {results['passed']} passed, {results['failed']} failed, "
          f"{len(results['notes'])} note(s)")

    if results["notes"]:
        print("\n  Notes are things that are true but worth knowing:")
        for n in results["notes"]:
            print(f"    - {n}")

    if results["failed"]:
        print(f"\n{RED}Something is wrong against real AWS that the offline "
              f"suite does not catch.{RESET}")
        return 1

    print(f"\n{GREEN}The tool works against a real account.{RESET}")
    return 0


KEEP = False

if __name__ == "__main__":
    sys.exit(main())
