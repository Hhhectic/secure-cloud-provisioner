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

# This is an entrypoint, and the two that existed when environment.py was
# written are not the only ones. Without this the Azure sections below find no
# credentials and skip themselves, on a machine whose .env is correct and
# complete - which is the same quiet failure environment.py was written to end,
# reappearing one script over. AWS is unaffected either way: boto3 reads
# ~/.aws itself, which is why nobody noticed.
import environment

environment.load()

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, WaiterError

from api import registry
from aws import key_pairs as kp
from aws import instances as ec2i
from aws import security_groups as sg_module
from aws import snapshots
from aws import vpcs
from aws import alarms
from aws.s3_buckets import PermissionDenied
from az.common import AzureNotConfigured
from scanner.common import (summarize, fixable, cited, print_warnings,
                            CRITICAL, WARNING, INFO)

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

        # What the machine has been doing, which lives in CloudWatch rather
        # than EC2. moto answers this call and never has a data point for it,
        # so None is the only answer the offline suite has ever seen - and it
        # is also the right answer here, because basic metrics are published
        # every five minutes and this machine is younger than that. The check
        # is that the call is permitted and the absence is handled, not that a
        # number came back.
        usage = ec2i.read_cpu_usage(client, instance_id)
        if usage is None:
            ok("no processor readings yet, which is correct for a machine "
               "this new and is not reported as idle")
        else:
            ok(f"processor readings arrived: {usage['average']:.1f}% average "
               f"over {usage['hours']}h from {usage['samples']} sample(s)")
            check(not any(w["rule"]["setting"] == "idle"
                          for w in resource.check(resource.read(client,
                                                                instance_id))
                          if w.get("rule"))
                  or usage["average"] < 5,
                  "and a machine is only called idle when the numbers say so")

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


# ------------------------------------------------------------- The blueprint


def smoke_blueprint(region):
    """The whole bastion architecture, built through the HTTP endpoint.

    The strongest thing this tool does and, until now, the least verified: the
    offline suite builds it against moto, and moto does not enforce the
    cross-VPC rejection or the routing that half of this arrangement depends
    on. What is being checked is not that six resources appeared, but that the
    relationships between them are the ones that make it safe.

    Keys are generated here with ssh-keygen and only the public halves are
    posted, which is the same bargain the web page makes with WebCrypto. This
    also covers the endpoint's refusal to build without them.

    Launches two t3.micro instances and terminates them.
    """
    heading("Blueprint: bastion architecture")

    from fastapi.testclient import TestClient
    from api.app import app
    from blueprints import bastion as bp

    client = TestClient(app, base_url="http://127.0.0.1:8000")
    ec2 = registry.VPC.get_client(region)
    name = f"scp-smoke-{suffix()}"
    key_dir = tempfile.mkdtemp(prefix="scp-smoke-keys-")
    created = {}

    try:
        # ---- The refusal, which costs nothing -----------------------------
        refused = client.post("/blueprints/bastion", json={"name": name})
        check(refused.status_code == 400,
              "the endpoint refuses to build without supplied public keys")
        check("will not create a private key" in refused.json()["detail"],
              "and says it will not make one for you")

        # ---- Two pairs, generated where the private halves should live ----
        public_halves = {}
        for role in (bp.BASTION_KEY, bp.PRIVATE_KEY):
            made, material, path = kp.generate_locally(
                f"{name}-{role}", directory=key_dir)
            if not check(made, f"generated {role} on this machine"):
                print(f"        {RED}{material}{RESET}")
                return
            public_halves[role] = material

        check(all("PRIVATE KEY" not in m for m in public_halves.values()),
              "only public halves are about to leave this machine")
        check(len(set(public_halves.values())) == 2,
              "the two pairs are genuinely different")

        # ---- Build it ------------------------------------------------------
        print(f"  {DIM}building {name}, two machines, this takes a "
              f"minute{RESET}")
        built = client.post("/blueprints/bastion", json={
            "name": name,
            "region": region,
            "with_instances": True,
            "public_keys": public_halves,
        }, timeout=600)

        if not check(built.status_code == 200, "built the whole arrangement"):
            print(f"        {RED}{built.text[:400]}{RESET}")
            return

        body = built.json()
        created = body["created"]
        if not check(body["ok"], "the build reports success"):
            for p in body["problems"]:
                print(f"        {RED}{p}{RESET}")
            return

        for kind, identifier in created.get("order", []):
            print(f"        {DIM}{kind:<18} {identifier}{RESET}")

        # ---- The relationships, which are the actual product ---------------
        vpc_id = created["vpc"]
        settings = vpcs.read_vpc_for_scanning(ec2, vpc_id)

        private_subnet = next(
            (s for s in settings["subnets"]
             if s.get("declared_role") == "private"), None)
        public_subnet = next(
            (s for s in settings["subnets"]
             if s.get("declared_role") == "public"), None)
        check(private_subnet and public_subnet,
              "the network has a public and a private subnet")

        bastion = ec2i.read_instance_for_scanning(ec2,
                                                  created["bastion_instance"])
        private = ec2i.read_instance_for_scanning(ec2,
                                                  created["private_instance"])

        check(private["subnet_id"] == private_subnet["subnet_id"],
              "the private machine is in the subnet with no route out")
        check(bastion["subnet_id"] == public_subnet["subnet_id"],
              "the bastion is in the subnet that reaches the internet")
        check(private.get("public_ip") is None,
              "the private machine has no public address")
        check(bastion.get("public_ip"),
              "the bastion has one, which is the only way in")
        check(bastion["key_name"] != private["key_name"],
              "the two machines use different keys, so one does not open both")

        # The protection that survives the bastion's address changing.
        rules = sg_module.read_group_for_scanning(ec2, created["private_sg"])
        check(any(r["source"].startswith("sg:") for r in rules),
              "the private firewall trusts the bastion's group, not an address")
        check(not any(r["source"] in ("0.0.0.0/0", "::/0") for r in rules),
              "and trusts nothing on the internet")

        # ---- What the scanner makes of it ----------------------------------
        findings = registry.INSTANCE.check(
            registry.INSTANCE.read(ec2, created["private_instance"]))
        check(summarize(findings)[CRITICAL] == 0,
              "the scanner finds nothing critical on the private machine")

        check(any("ProxyJump" in line or "-J " in line
                  for line in body["instructions"]),
              "the connection instructions route through the bastion")

    except ClientError as e:
        fail(f"{e.response['Error']['Code']}: {e.response['Error']['Message']}")
    finally:
        shutil.rmtree(key_dir, ignore_errors=True)
        if created and not KEEP:
            _tear_down_blueprint(ec2, region, created)
        elif created:
            note(f"left blueprint {name} in place")


def _tear_down_blueprint(ec2, region, created):
    """The two steps the teardown instructions describe.

    The cascade takes everything inside the network. Key pairs are
    account-level and survive it, which is the whole reason this is two
    operations rather than one.
    """
    vpc_id = created.get("vpc")
    if vpc_id:
        print(f"  {DIM}terminating and deleting, this takes a minute{RESET}")
        removed, message = registry.VPC.delete(ec2, vpc_id, {"force": True})
        check(removed, f"deleted {vpc_id} and both machines with it")
        if not removed:
            print(f"        {RED}{message}{RESET}")

    key_client = registry.KEY_PAIR.get_client(region)
    survivors = []
    for role in ("bastion-key", "private-key"):
        key_name = created.get(role)
        if not key_name:
            continue
        if kp.read_key_pair_for_scanning(key_client, key_name):
            survivors.append(key_name)

    check(len(survivors) == 2,
          "both key pairs survived the cascade, as account-level things do")

    for key_name in survivors:
        gone, message = kp.delete_key_pair(key_client, key_name)
        check(gone, f"removed {key_name}")


# ------------------------------------------------------------- Workload

# CloudWatch basic monitoring publishes every five minutes, and a machine has
# to have been running for one of those windows before there is anything to
# read. Ten minutes is two windows, which is enough slack for the first to be
# missed.
WORKLOAD_WAIT_SECONDS = 10 * 60
WORKLOAD_POLL_SECONDS = 60


def smoke_workload(region):
    """Waits for a real machine's processor readings and checks what is said.

    smoke_instance already asks for readings, but it asks seconds after launch
    when the honest answer is None, so it can only check that the call is
    permitted and that the absence is handled. Nothing automated has ever seen
    this finding fire. It was confirmed once by hand, against a machine
    deliberately pegged at 83%, and that has not been repeatable since.

    This tests the idle band instead, because an ordinary machine reaches it
    without being made to: a t3.micro doing nothing settles near zero. That
    covers the metric plumbing, the window and period pairing, the band
    boundaries against real numbers, and the choice to report idleness as a
    note rather than a warning. It does not cover the saturated band, which
    would mean generating load, and the boundary between them is already
    pinned offline.

    Slow on purpose: it waits for AWS to publish. Behind its own flag for
    that reason as much as for the instance it launches.
    """
    heading("Workload readings")

    resource = registry.INSTANCE
    client = resource.get_client(region)
    name = f"scp-smoke-idle-{suffix()}"
    instance_id = None

    try:
        launched, instance_id, problems = ec2i.launch_instance(
            client, name=name, region=region)
        if not check(launched, "launched a machine to be measured"):
            print(f"        {RED}{instance_id}{RESET}")
            instance_id = None
            return
        for p in problems:
            note(p)
        print(f"  {DIM}{instance_id}, waiting for it to start{RESET}")

        client.get_waiter("instance_running").wait(InstanceIds=[instance_id])

        # The window that broke against a real account. A fortnight at
        # five-minute sampling is more data points than GetMetricStatistics
        # will return, and the failure arrived as a ClientError that
        # read_cpu_usage turned into "no readings" - a busy machine reported
        # as unmeasured. period_for_window widens the sampling instead, and
        # only a real account can say whether it widened it enough.
        wide = ec2i.read_cpu_usage(client, instance_id, hours=24 * 14)
        ok("a fortnight-wide window is accepted rather than refused for "
           "asking too many data points")

        print(f"  {DIM}waiting up to {WORKLOAD_WAIT_SECONDS // 60} minutes for "
              f"CloudWatch to publish{RESET}")

        usage = None
        deadline = time.time() + WORKLOAD_WAIT_SECONDS
        while time.time() < deadline:
            usage = ec2i.read_cpu_usage(client, instance_id)
            if usage:
                break
            waited = int(WORKLOAD_WAIT_SECONDS - (deadline - time.time()))
            print(f"        {DIM}nothing yet, {waited // 60}m elapsed{RESET}")
            time.sleep(WORKLOAD_POLL_SECONDS)

        if not check(usage is not None,
                     f"readings arrived within {WORKLOAD_WAIT_SECONDS // 60} "
                     f"minutes"):
            note("CloudWatch was slower than this test is willing to wait. "
                 "That is not a failure of the tool, and the machine has "
                 "been terminated either way.")
            return

        print(f"        {DIM}{usage['average']:.1f}% average, "
              f"{usage['peak']:.1f}% peak, {usage['samples']} sample(s) over "
              f"{usage['hours']}h{RESET}")

        check(usage["samples"] >= 1, "with at least one real data point")
        check(0 <= usage["average"] <= 100,
              "and an average inside the range a percentage can occupy")

        # ---- What the scanner makes of it ---------------------------------
        warnings = resource.check(resource.read(client, instance_id))
        workload = [w for w in warnings if "processor use" in w["message"]]

        if not check(len(workload) == 1,
                     "the scanner says exactly one thing about the workload"):
            return

        finding = workload[0]
        print(f"        {DIM}{finding['message'][:150]}{RESET}")

        check(f"{usage['average']:.1f}%" in finding["message"],
              "quoting the number it actually read")

        # A machine that has done nothing is idle, and idle is a note. A
        # standby is idle on purpose, and warning about it would train people
        # to ignore the level that matters.
        check(finding["level"] == INFO,
              "an idle machine is reported as a note, not as a warning")
        check("idle" in finding["message"].lower(),
              "and is described as idle rather than as a fault")
        check(not finding.get("fix"),
              "with nothing offered to fix, because only its owner knows "
              "whether it is finished with")
        check(not finding.get("control"),
              "and no citation, because no benchmark covers paying for idle "
              "machines")

    except ClientError as e:
        fail(f"{e.response['Error']['Code']}: {e.response['Error']['Message']}")
    finally:
        if instance_id and not KEEP:
            stopped, message = ec2i.terminate_instance(client, instance_id)
            check(stopped, f"terminated {instance_id}")
            if not stopped:
                print(f"        {RED}{message}{RESET}")
                print(f"        {RED}This is running and billing. Terminate "
                      f"it by hand.{RESET}")
        elif instance_id:
            note(f"left {instance_id} running and billing")


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
        #
        # This group is deliberately open to the whole internet, because the
        # rest of the section needs a real finding to scan and then fix. Since
        # the pre-flight gate arrived that is no longer something the routes
        # will do quietly, so the refusal is asserted first and the create then
        # says out loud that it means it. Asking for the open group without the
        # flag and getting it would be the failure.
        spec = {
            "name": name,
            "description": "smoke test of the HTTP layer",
            "rules": [{"protocol": "tcp", "from_port": 22, "to_port": 22,
                       "source": "0.0.0.0/0"}],
        }

        refused = client.post("/resources/security-group", json=spec)
        check(refused.status_code == 400,
              "a group open to the whole internet is refused before creation")
        if refused.status_code == 400:
            check(any(w["control"] and w["control"]["id"] == "5.3"
                      for w in refused.json()["detail"]["warnings"]),
                  "and the refusal carries the CIS 5.3 finding that caused it")

        listed_now = client.get("/resources/security-group").json()["resources"]
        check(not any(g["name"] == name for g in listed_now),
              "and nothing was created by the attempt")

        created = client.post("/resources/security-group?accept_risk=true",
                              json=spec)
        if not check(created.status_code == 201,
                     "created a group over HTTP once the risk was accepted"):
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


def smoke_roles(region):
    """Reads every role and says what it can reach. Creates nothing, free.

    Three things here cannot be exercised offline at all. moto has no
    AWS-managed policies, so a role carrying AdministratorAccess reads back
    with an unreadable document against the fake and a real one against AWS -
    the difference between reporting full administrative access and reporting
    a policy that could not be read. moto also creates no service-linked
    roles, so the filter keeping AWS's own dozens out of the listing is only
    ever meaningful here. And an instance profile is only attached to a
    machine in an account that has machines.
    """
    heading("Roles")

    resource = registry.ROLE
    client = resource.get_client(region)

    check(resource.read(client, "scp-no-such-role-anywhere") is None,
          "a role that does not exist reads back as nothing, not an error")

    ours = resource.list_all(client, only_ours=True)
    everything = resource.list_all(client, only_ours=False)

    check(len(everything) >= len(ours),
          "excluding AWS's own service roles never adds any")
    service_roles = len(everything) - len(ours)
    if service_roles:
        ok(f"{service_roles} AWS service-linked role(s) correctly left out of "
           f"the listing")
    else:
        note("this account has no AWS service-linked roles, so the filter "
             "cannot be shown to exclude anything")

    if not ours:
        print(f"        {DIM}no roles written by anyone here. An account with "
              f"none is a legitimate answer, not a failed scan.{RESET}")
        return

    print(f"        {DIM}{len(ours)} role(s) somebody here wrote{RESET}")

    findings = []
    unreadable_documents = 0
    for entry in ours:
        settings = resource.read(client, entry["id"])
        if settings is None:
            continue
        for policy in settings.get("policies") or []:
            if policy.get("document") is None:
                unreadable_documents += 1
        findings.extend(resource.check(settings))

    # The one moto cannot answer. Offline every attached AWS-managed policy
    # comes back as a document this tool could not read, because moto has none
    # of them; here they should all resolve.
    check(unreadable_documents == 0,
          "every policy attached to every role could be read")

    counts = summarize(findings)
    print(f"\n        {counts['critical']} critical, {counts['warning']} "
          f"warning, {counts['info']} informational")

    check(not fixable(findings),
          "nothing about a role is offered as an automatic fix")

    if findings:
        print()
        print_warnings(findings)


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


# ------------------------------------------------------------------- Alarms


def smoke_alarms(region, with_email=None):
    """Alarms against the real account. Free, and creates at most two.

    Ten alarms are free forever and an SNS topic costs nothing, so this runs
    on every pass. It is worth running because more of this module rests on
    unverified assumptions about AWS than any other: moto implements neither
    call that switches an alarm's notifications on or off, publishes no
    billing metrics at all, and marks an email subscription confirmed the
    instant it is made, which is the one thing the unconfirmed-subscriber
    finding exists to catch.

    --with-alarm-email sends a real confirmation email to a real person, so
    the subscription half is opt-in. Everything else here is silent.
    """
    heading("Alarms")

    resource = registry.ALARM
    client = resource.get_client(region)
    created = []
    topic_arn = None

    try:
        # ---- How many already exist, and can we still afford one? ----------
        existing = alarms.count_alarms(client)
        print(f"        {DIM}{existing} alarm(s) already in {region}; the "
              f"first {alarms.FREE_TIER_ALARM_LIMIT} are free{RESET}")

        if existing >= alarms.FREE_TIER_ALARM_LIMIT - 1:
            note(f"{existing} alarms already exist, so creating more would "
                 f"start a monthly charge. The creating half of this section "
                 f"is skipped; the refusal below is the behaviour that matters.")
            ok_refused, message, _ = alarms.create_alarm(
                client, name="scp-smoke-should-refuse", namespace="AWS/EC2",
                metric_name="CPUUtilization", threshold=80.0, region=region)
            check(not ok_refused,
                  "and the eleventh alarm is refused rather than billed")
            return

        # ---- Reading something that is not there ----------------------------
        #
        # describe_alarms answers an unknown name with an empty list rather
        # than by raising, which is the opposite of most of AWS. If that ever
        # changed, every 404 in the routes would become a 500.
        check(resource.read(client, f"scp-no-such-alarm-{suffix()}") is None,
              "an alarm that does not exist reads back as nothing, not an error")

        # ---- Does this account publish spending figures at all? -------------
        #
        # moto answers this with an empty list every time, so 'not_enabled' is
        # the only answer the offline suite has ever seen.
        status = alarms.billing_metrics_available(
            alarms.get_client(alarms.BILLING_REGION))
        if status == "ready":
            ok("this account publishes spending figures, so a billing alarm "
               "will receive data")
        elif status == "not_enabled":
            note("'Receive Billing Alerts' is off for this account, so a "
                 "spending alarm will sit with no data until somebody turns "
                 "it on in the Billing console. There is no API for that "
                 "switch.")
        else:
            note(f"could not tell whether spending figures are published: "
                 f"{status}")

        # ---- The refusal that only makes sense against a real region --------
        if region != alarms.BILLING_REGION:
            refused, message, _ = alarms.create_alarm(
                client, name=f"scp-smoke-doomed-{suffix()}",
                namespace=alarms.BILLING_NAMESPACE,
                metric_name=alarms.BILLING_METRIC, threshold=5.0, region=region)
            check(not refused and alarms.BILLING_REGION in message,
                  f"a spending alarm is refused in {region} rather than built "
                  f"somewhere it could never receive data")
        else:
            other = "eu-west-2"
            refused, message, _ = alarms.create_alarm(
                alarms.get_client(other), name=f"scp-smoke-doomed-{suffix()}",
                namespace=alarms.BILLING_NAMESPACE,
                metric_name=alarms.BILLING_METRIC, threshold=5.0, region=other)
            check(not refused and alarms.BILLING_REGION in message,
                  f"a spending alarm is refused in {other} rather than built "
                  f"somewhere it could never receive data")

        # ---- Build one for real ---------------------------------------------
        name = f"scp-smoke-cpu-{suffix()}"
        made, result, problems = alarms.create_alarm(
            client, name=name, namespace=alarms.CPU_NAMESPACE,
            metric_name=alarms.CPU_METRIC, threshold=80.0, region=region,
            notify=True, email=with_email)

        if not check(made, f"created an alarm: {result}"):
            fail(result)
            return
        created.append(name)
        for p in problems:
            note(p)

        settings = resource.read(client, name)
        if not check(settings is not None, "and it reads back"):
            return

        # A brand new alarm has no data yet, so AWS starts it here. Worth
        # asserting because it is the same state a permanently dead alarm sits
        # in, and telling them apart is the whole point of the scanner.
        print(f"        {DIM}state on creation: {settings['state']}{RESET}")
        check(settings["evaluation_periods"] == 2,
              "a CPU alarm needs two readings, so one spike does not set it off")
        check(settings["period"] == 300, "and checks every five minutes")

        # ---- Tags, which describe_alarms does not return --------------------
        #
        # The analogue of the DescribeTags lesson: only_ours depends entirely
        # on a separate call, and if that call stopped working every alarm in
        # the account would look like one this tool created.
        ours = {a["id"] for a in resource.list_all(client, only_ours=True)}
        every = {a["id"] for a in resource.list_all(client, only_ours=False)}
        check(name in ours, "the new alarm is recognised as one this tool made")
        check(ours <= every, "and 'only ours' is a subset of everything")
        if len(every) > len(ours):
            ok(f"{len(every) - len(ours)} alarm(s) in this account are "
               f"correctly not claimed as ours")
        elif existing:
            note("every alarm in this account carries this tool's tag, so the "
                 "filter cannot be shown to exclude anything here")

        # ---- Who would actually hear it -------------------------------------
        topic_arn = (settings.get("alarm_actions") or [None])[0]
        subs = settings.get("subscriptions")

        if with_email:
            # The finding moto can never produce. AWS returns the literal
            # string PendingConfirmation until somebody opens the email.
            if check(subs is not None and len(subs) > 0,
                     f"{with_email} is subscribed to the alert topic"):
                pending = [s for s in subs if not s["confirmed"]]
                if pending:
                    ok("and AWS reports it unconfirmed, which is what the "
                       "offline suite has to use a stub to see")
                    findings = resource.check(settings)
                    check(any(w["rule"]["setting"] in
                              ("no_confirmed_subscribers",
                               "unconfirmed_subscribers")
                              for w in findings),
                          "and the scanner says the alarm reaches nobody yet")
                else:
                    note("the subscription is already confirmed, so this "
                         "address has been through this before")
        elif subs:
            # The topic is shared by every alarm this tool makes, and a
            # confirmed email subscription cannot be undone by running this
            # script. So one earlier --with-alarm-email run removes "an alarm
            # nobody is listening to" from this account permanently, and
            # asserting it here would fail forever for a reason that is not a
            # defect. The same shape as the tag-filter note above.
            note(f"the alert topic already has {len(subs)} subscriber(s) from "
                 f"an earlier --with-alarm-email run, so an alarm with no "
                 f"destination cannot be produced in this account. Remove "
                 f"them in SNS to see that finding again.")

            # The opposite assertion is still worth making, and is the one
            # that would catch a scanner reporting silence that is not there.
            findings = resource.check(settings)
            check(not any(w["rule"]["setting"] == "no_subscribers"
                          for w in findings),
                  "and the scanner does not claim nobody is listening when "
                  "somebody is")
        else:
            check(subs == [],
                  "with no address given, the topic exists and nobody is on it")
            findings = resource.check(settings)
            check(any(w["rule"]["setting"] == "no_subscribers"
                      for w in findings),
                  "and the scanner calls that out rather than passing it")

        # ---- The two calls moto does not implement --------------------------
        #
        # NotImplementedError is caught alongside ClientError because moto
        # raises it for these two, and a bare NotImplementedError is not a
        # ClientError - the same shape as the ParamValidationError lesson.
        # Against AWS neither is raised; catching both means a dry run of this
        # script against the fake reports a note instead of abandoning
        # everything after this point.
        try:
            client.disable_alarm_actions(AlarmNames=[name])
            muted = resource.read(client, name)
            check(muted["actions_enabled"] is False,
                  "notifications can be switched off, which moto cannot do")

            finding = next(w for w in resource.check(muted)
                           if w["rule"]["setting"] == "actions_disabled")
            fixed, message = resource.fix(client, name, finding, {})
            check(fixed, "and the fix switches them back on")
            check(resource.read(client, name)["actions_enabled"] is True,
                  "which the alarm confirms when read back")
        except NotImplementedError:
            note("this endpoint does not implement switching alarm actions "
                 "on or off, which means this is not a real AWS account")
        except ClientError as e:
            fail(f"toggling alarm actions failed: "
                 f"{e.response['Error']['Message']}")

        # ---- The routes, against the real account ---------------------------
        _smoke_alarm_routes(region)

    finally:
        if created and not KEEP:
            for name in created:
                deleted, message = alarms.delete_alarm(client, name)
                check(deleted, f"deleted {name}")
        elif created:
            note(f"--keep is set, so {len(created)} alarm(s) were left behind")

        if topic_arn:
            # Deliberately not deleted. The topic is shared by every alarm this
            # tool makes, a teammate's alarm may be pointed at it, and removing
            # it would silently take their notifications with it. The IAM
            # policy denies sns:DeleteTopic for the same reason.
            print(f"        {DIM}the alert topic is left in place; other "
                  f"alarms may be using it{RESET}")


def _smoke_alarm_routes(region):
    """The pre-flight refusal, over HTTP, against the real account."""
    from fastapi.testclient import TestClient
    from api.app import app

    client = TestClient(app, base_url="http://127.0.0.1:8000")

    refused = client.post(f"/resources/alarm?region={region}", json={
        "name": f"scp-smoke-silent-{suffix()}",
        "namespace": alarms.CPU_NAMESPACE,
        "metric_name": alarms.CPU_METRIC,
        "threshold": 80.0,
        "notify": False,
    })

    check(refused.status_code == 400,
          "the API refuses to build an alarm that would tell nobody")
    if refused.status_code == 400:
        detail = refused.json()["detail"]
        check(any("tell no one" in w["message"] for w in detail["warnings"]),
              "and the refusal carries the finding that caused it")

    listed = client.get(f"/resources/alarm?region={region}&only_ours=true")
    check(listed.status_code == 200, "and alarms list over HTTP")


# ---------------------------------------------------------------------- Sweep


# ----------------------------------------------------------------------- Azure
#
# Everything above this line has been run against a real AWS account many times.
# Nothing below it has ever run against a real subscription, which is the point:
# the Azure findings, and now the create and delete paths with them, are tested
# logic rather than measured behaviour. This is the instrument for changing
# that, and until somebody points it at a subscription it is untested code too.
#
# Two differences from the AWS sections, both deliberate:
#
#   - They skip rather than fail when Azure is not configured. This script's
#     subject is AWS and every existing invocation of it expects to pass without
#     an Azure credential in sight.
#   - The reads run whenever a subscription is reachable; the writes need
#     --with-azure-resources. A storage account costs almost nothing and a key
#     vault nothing at all, but a deleted vault keeps its name for the whole
#     soft-delete retention period, so every write run burns a name that cannot
#     be reused. That is a cost of a different kind and it deserves a flag.


def azure_configured():
    """Whether a subscription can be reached at all, without asserting anything.

    Called before the sections rather than inside them so that "not configured"
    is reported once, as a skip, instead of five times as failures.
    """
    try:
        registry.AZURE_STORAGE.get_client(None)
        return True
    except AzureNotConfigured:
        return False


def confirm_azure_identity():
    heading("Azure credentials")
    try:
        from az.common import subscription_id
        found = subscription_id()
    except AzureNotConfigured as e:
        fail(str(e))
        return None

    # The subscription id is not a secret, but printing it whole in a terminal
    # somebody is about to screenshot for a report is a habit worth not having.
    print(f"  {DIM}subscription {found[:8]}…{found[-4:]}{RESET}")
    ok("Azure credentials work")
    return found


def _azure_sweep(resource, location, expect_write):
    """Lists and scans every one of a type the subscription already has.

    Free, and the half of an Azure run that needs no flag. It is also the only
    part that exercises the readers against shapes this project did not create -
    an account somebody made in the portal years ago is exactly where a getattr
    default or an unreadable setting will first be wrong.
    """
    client = resource.get_client(location)
    found = resource.list_all(client, False)
    ok(f"listed {len(found)} {resource.label.lower()}(s)")

    if not found:
        note(f"no {resource.label.lower()}s in this subscription, so nothing "
             "was scanned. The reader is unproven until there is one.")
        return

    for item in found[:5]:
        settings = resource.read(client, item["id"])
        if settings is None:
            fail(f"{item['name']}: listed but could not be read back")
            continue

        warnings = resource.check(settings)
        counts = summarize(warnings)
        print(f"  {DIM}{item['name']}: {counts[CRITICAL]} critical, "
              f"{counts[WARNING]} warning, {counts[INFO]} info{RESET}")

        # The reader records what it could not see rather than scoring it
        # clean. Against a real subscription this is where a permission gap
        # shows up, and it is the whole reason the field exists.
        for setting, reason in (settings.get("unreadable") or {}).items():
            note(f"{item['name']}: could not check {setting} - {reason}")

    if len(found) > 5:
        print(f"  {DIM}…and {len(found) - 5} more, not scanned{RESET}")

    if expect_write:
        ok(f"{resource.label.lower()}s are writable through the registry")


def smoke_azure_storage(location, with_writes, resource_group=None):
    """Exercises the storage type. resource_group, when given, is used as-is.

    Inventing a group per run means the principal needs to create resource
    groups, which is a subscription-wide grant - and a tool whose subject is
    least privilege should not require one to test itself. Pointed at a group
    that already exists, `ensure_resource_group` finds it and returns without
    writing, so Contributor on that one group is the whole requirement.

    A supplied group is never deleted. It is somebody's, this script did not
    make it, and the AWS half has never removed a container it was handed.
    """
    heading("Azure storage accounts")

    resource = registry.AZURE_STORAGE
    _azure_sweep(resource, location, expect_write=not resource.read_only)

    if not with_writes:
        print(f"  {DIM}writes skipped. Pass --with-azure-resources to create "
              f"and delete a real account.{RESET}")
        return

    client = resource.get_client(location)
    supplied_group = bool(resource_group)
    group = resource_group or f"scp-smoke-{suffix()}"
    name = f"scpsmoke{suffix()}"        # 3-24 lowercase alphanumeric, no hyphens
    created = None

    if supplied_group:
        print(f"  {DIM}using resource group {group}, which this script will "
              f"not create or delete{RESET}")

    try:
        try:
            made, created, problems = resource.create(client, {
                "name": name, "resource_group": group, "region": location,
                "secure_by_default": False,
            })
        except Exception as e:
            # "whether the login the tool runs under actually grants what the
            # tool needs" is in this script's own docstring as the thing moto
            # structurally cannot check, and on the AWS side every gap arrives
            # as a sentence naming the missing action. Azure's SDK raises
            # instead, so without this the first missing role ends the run with
            # a traceback about an HTTP response - which names the action, but
            # buried in the one format nobody reads as advice.
            detail = str(e)
            if "AuthorizationFailed" in detail or "does not have authorization" in detail:
                action = "unknown action"
                if "perform action '" in detail:
                    action = detail.split("perform action '")[1].split("'")[0]
                fail(f"the service principal cannot {action}")
                print(f"        Azure reads and writes are separate grants. The "
                      f"read sweep above worked, so this is a role that covers "
                      f"listing but not creating.")
                if supplied_group:
                    print(f"        Grant Contributor on {group}.")
                else:
                    print(f"        Grant Contributor on an existing resource "
                          f"group and pass --azure-resource-group, which needs "
                          f"a far narrower grant than letting this script "
                          f"create one.")
                return
            raise

        if not check(made, "created a storage account with no hardening"):
            print(f"        {created}")
            created = None
            return
        for p in problems:
            note(p)

        settings = resource.read(client, created)
        if not check(settings is not None, "read it back after creating it"):
            return

        warnings = resource.check(settings)
        print(f"\n  {DIM}what Azure actually gave us:{RESET}")
        print(f"    public blob access: {settings.get('allow_blob_public_access')}")
        print(f"    https only:         {settings.get('supports_https_traffic_only')}")
        print(f"    minimum TLS:        {settings.get('minimum_tls_version')}")
        print(f"    shared key:         {settings.get('allow_shared_key_access')}")

        # The claim check_storage_spec makes: what the form said before it was
        # built is what the scanner says after. Asserted here against a real
        # account rather than against a stub of one.
        before = {w["rule"]["setting"] for w in resource.check_spec(
            {"name": name, "secure_by_default": False})}
        after = {w["rule"]["setting"] for w in warnings}
        check(before <= after,
              "every finding predicted before creation is present after it")
        if before - after:
            print(f"        predicted but absent: {sorted(before - after)}")

    finally:
        if created and not KEEP:
            gone, message = resource.delete(client, created, {"force": True})
            check(gone, f"deleted {created}")
            if not gone:
                print(f"        {message}")
            note(f"the name '{created}' is retained for the soft-delete "
                 "period and cannot be reused until it lapses")
        elif created:
            note(f"--keep: storage account {created} left behind in {group}")
        if created and not supplied_group:
            # Only once something actually reached Azure, and only for a group
            # this script invented. The first version said it unconditionally
            # and printed it after a create that had failed before touching the
            # subscription, naming a resource group that was never made.
            note(f"resource group {group} was created by this run and is not "
                 "removed by it; delete it in the portal, or pass "
                 "--azure-resource-group next time to reuse one")


def smoke_azure_keyvault(location, with_writes):
    heading("Azure key vaults")

    resource = registry.AZURE_KEYVAULT
    _azure_sweep(resource, location, expect_write=not resource.read_only)

    if not with_writes:
        print(f"  {DIM}writes skipped. Pass --with-azure-resources to create "
              f"and delete a real vault.{RESET}")
        return

    note("a deleted vault keeps its name for the soft-delete retention "
         "period, so this run consumes a name permanently")


def smoke_azure_nsg(location):
    heading("Azure network security groups")

    resource = registry.AZURE_NSG
    _azure_sweep(resource, location, expect_write=False)

    # Not a gap to be filled later without deciding something first, so it is
    # stated here rather than left as silence in a passing run.
    print(f"  {DIM}read-only by design: an NSG rule carries a priority "
          f"deciding which of several overlapping rules wins, so neither "
          f"creating nor fixing one can be judged from a single rule.{RESET}")


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
        except AzureNotConfigured:
            # Azure storage and key vaults became writable, which put them in
            # this loop for the first time. Without a subscription configured
            # they cannot be asked, and this script's whole subject is AWS -
            # so a missing Azure credential must not end an AWS run. It is
            # skipped rather than noted: nothing was created there either.
            continue
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
    parser.add_argument("--with-alarm-email", metavar="ADDRESS",
                        help="subscribe this address to the alert topic. "
                             "Sends a real confirmation email, which is the "
                             "only way to see the state moto cannot produce")
    parser.add_argument("--with-workload", action="store_true",
                        help="launch a machine and wait for CloudWatch to "
                             "publish its processor readings, then check what "
                             "the scanner says about them. Slow: about ten "
                             "minutes of waiting")
    parser.add_argument("--with-blueprint", action="store_true",
                        help="also build and tear down the whole bastion "
                             "architecture, which launches two t3.micro")
    parser.add_argument("--azure-location", default="eastus",
                        help="where Azure resources go. Azure carries the "
                             "location on the resource rather than the client, "
                             "so this is not --region and cannot be")
    parser.add_argument("--with-azure-resources", action="store_true",
                        help="also create and delete a real Azure storage "
                             "account. The Azure reads run whenever a "
                             "subscription is reachable; this adds the writes")
    parser.add_argument("--azure-resource-group", metavar="NAME",
                        help="put the created resources in this existing "
                             "group instead of inventing one. Needs only "
                             "Contributor on that group; inventing one needs "
                             "permission to create groups across the "
                             "subscription. The group is never deleted")
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

        # Free, and creates at most two alarms inside the always-free ten.
        smoke_alarms(args.region, with_email=args.with_alarm_email)
        smoke_roles(args.region)
        smoke_snapshots(args.region)

        # The HTTP layer, which everything above reaches one level below.
        smoke_api(args.region)

        if args.with_workload:
            smoke_workload(args.region)
        else:
            heading("Workload readings")
            print(f"  {DIM}skipped. Pass --with-workload to launch a machine "
                  f"and wait for its readings.{RESET}")

        if args.with_blueprint:
            smoke_blueprint(args.region)
        else:
            heading("Blueprint: bastion architecture")
            print(f"  {DIM}skipped. Pass --with-blueprint to build and tear "
                  f"down a real one.{RESET}")

        # Azure last, and skipped entirely when no subscription is reachable.
        # Every existing invocation of this script expects to pass on an AWS
        # machine, and a missing Azure credential is not an AWS failure.
        if azure_configured():
            confirm_azure_identity()
            smoke_azure_storage(args.azure_location, args.with_azure_resources,
                                resource_group=args.azure_resource_group)
            smoke_azure_keyvault(args.azure_location, args.with_azure_resources)
            smoke_azure_nsg(args.azure_location)
        else:
            heading("Azure")
            print(f"  {DIM}skipped: no subscription configured. Put the "
                  f"AZURE_* values in .env to include it.{RESET}")
            note("Azure was not exercised. Nothing in az/ has yet run against "
                 "a real subscription, so its findings and its create and "
                 "delete paths remain tested logic rather than measured "
                 "behaviour.")

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
