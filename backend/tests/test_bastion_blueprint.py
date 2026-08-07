"""Tests for the bastion blueprint.

The individual resources are covered elsewhere. What matters here is whether
they were put together correctly, because that is the failure this blueprint
exists to prevent: every piece created properly, and the private machine
sitting in the public subnet.

Keys are generated into a temporary directory so a test run never writes to
~/.ssh.
"""

import os
import shutil
import tempfile

import boto3
import pytest
from moto import mock_aws

from aws import instances as ec2i
from aws import security_groups as sg
from aws import vpcs
from blueprints import bastion
from scanner.rules import check_firewall_rules
from scanner.common import CRITICAL, INFO, summarize

REGION = "us-east-1"
MY_IP = "203.0.113.25"


@pytest.fixture
def ec2():
    with mock_aws():
        yield boto3.client("ec2", region_name=REGION)


@pytest.fixture
def keys(monkeypatch):
    """A throwaway directory, and a fixed public address.

    my_public_ip reaches out to the network, which a test must not do.
    """
    folder = tempfile.mkdtemp(prefix="scp-blueprint-")
    monkeypatch.setattr(sg, "my_public_ip", lambda: MY_IP)
    yield folder
    shutil.rmtree(folder, ignore_errors=True)


def _build(ec2, keys, **kwargs):
    return bastion.build(ec2, "demo", region=REGION, report=lambda *a: None,
                         key_directory=keys, **kwargs)


# ------------------------------------------------------------ The arrangement


def test_it_builds_every_piece(ec2, keys):
    ok, created, _ = _build(ec2, keys)
    assert ok

    assert set(created) >= {
        "vpc", bastion.BASTION_KEY, bastion.PRIVATE_KEY,
        "bastion_sg", "private_sg", "bastion_instance", "private_instance",
    }


def test_the_private_machine_is_in_the_private_subnet(ec2, keys):
    """The mistake this blueprint exists to prevent.

    Every resource can be created correctly and the result still be wrong, if
    the private machine ends up somewhere with a route to the internet.
    """
    ok, created, _ = _build(ec2, keys)
    assert ok

    layout = vpcs.read_vpc_for_scanning(ec2, created["vpc"])
    private_subnet = next(s for s in layout["subnets"]
                          if s["declared_role"] == "private")
    public_subnet = next(s for s in layout["subnets"]
                         if s["declared_role"] == "public")

    private = ec2.describe_instances(
        InstanceIds=[created["private_instance"]]
    )["Reservations"][0]["Instances"][0]
    bastion_instance = ec2.describe_instances(
        InstanceIds=[created["bastion_instance"]]
    )["Reservations"][0]["Instances"][0]

    assert private["SubnetId"] == private_subnet["subnet_id"]
    assert bastion_instance["SubnetId"] == public_subnet["subnet_id"]
    assert private_subnet["reaches_internet"] is False


def test_only_the_bastion_gets_a_public_address(ec2, keys):
    ok, created, _ = _build(ec2, keys)

    bastion_settings = ec2i.read_instance_for_scanning(
        ec2, created["bastion_instance"])
    private_settings = ec2i.read_instance_for_scanning(
        ec2, created["private_instance"])

    assert bastion_settings["public_ip"]
    assert private_settings["public_ip"] is None


def test_the_private_group_trusts_the_bastion_group_not_an_address(ec2, keys):
    """The relationship that makes the whole thing work."""
    ok, created, _ = _build(ec2, keys)

    rules = sg.read_group_for_scanning(ec2, created["private_sg"])
    assert [r["source"] for r in rules] == [f"sg:{created['bastion_sg']}"]

    findings = check_firewall_rules(rules)
    assert [w["level"] for w in findings] == [INFO]
    assert created["bastion_sg"] in findings[0]["message"]


def test_the_bastion_group_allows_one_address_only(ec2, keys):
    ok, created, _ = _build(ec2, keys)

    rules = sg.read_group_for_scanning(ec2, created["bastion_sg"])
    assert [r["source"] for r in rules] == [f"{MY_IP}/32"]
    assert check_firewall_rules(rules) == []


def test_the_two_machines_use_different_keys(ec2, keys):
    """One key would work. Two mean the bastion falling does not hand over
    the private machine as well."""
    ok, created, _ = _build(ec2, keys)

    bastion_key = ec2i.read_instance_for_scanning(
        ec2, created["bastion_instance"])["key_name"]
    private_key = ec2i.read_instance_for_scanning(
        ec2, created["private_instance"])["key_name"]

    assert bastion_key != private_key
    assert bastion_key == created[bastion.BASTION_KEY]
    assert private_key == created[bastion.PRIVATE_KEY]


def test_the_result_has_nothing_critical_anywhere(ec2, keys):
    """The point of a blueprint: correct without the user knowing why."""
    ok, created, _ = _build(ec2, keys)

    for group in (created["bastion_sg"], created["private_sg"]):
        findings = check_firewall_rules(sg.read_group_for_scanning(ec2, group))
        assert summarize(findings)[CRITICAL] == 0

    network = vpcs.read_vpc_for_scanning(ec2, created["vpc"])
    from scanner.vpc_rules import check_vpc
    assert summarize(check_vpc(network))[CRITICAL] == 0


def test_private_keys_stay_on_this_machine(ec2, keys):
    """Nothing sent to AWS should be recoverable as a private key."""
    from pathlib import Path

    ok, created, _ = _build(ec2, keys)

    for key_name in (created[bastion.BASTION_KEY], created[bastion.PRIVATE_KEY]):
        assert (Path(keys) / key_name).exists()

        stored = ec2.describe_key_pairs(KeyNames=[key_name])["KeyPairs"][0]
        assert "KeyMaterial" not in stored


# ----------------------------------------------------------- Without machines


def test_it_can_build_everything_except_the_machines(ec2, keys):
    """For a demonstration that should not cost anything."""
    ok, created, _ = _build(ec2, keys, with_instances=False)
    assert ok

    assert "vpc" in created
    assert "private_sg" in created
    assert "bastion_instance" not in created
    assert ec2i.list_instances(ec2, only_ours=True) == []


# ------------------------------------------------------------------ Failure


def test_a_failure_reports_what_already_exists(ec2, keys):
    """Nothing rolls back, and that is deliberate.

    Silently destroying half-built infrastructure is a worse failure than
    leaving it and saying so, especially when one of the pieces might be a
    machine that is already doing something.
    """
    def refuse(*args, **kwargs):
        return False, "refused for the test", []

    original = ec2i.launch_instance
    ec2i.launch_instance = refuse
    try:
        ok, created, problems = _build(ec2, keys)
    finally:
        ec2i.launch_instance = original

    assert not ok
    assert created["vpc"]
    assert created["bastion_sg"]
    assert [kind for kind, _ in created["order"]][0] == "vpc"
    assert any("refused for the test" in p for p in problems)


def test_teardown_instructions_name_the_cascade():
    lines = "\n".join(bastion.teardown_instructions({
        "vpc": "vpc-123",
        bastion.BASTION_KEY: "demo-bastion-key",
        bastion.PRIVATE_KEY: "demo-private-key",
    }))
    assert "vpc-123" in lines
    assert "everything inside" in lines
    assert "not part of the network" in lines
    # The key pairs survive the cascade, so a teardown has to name them.
    assert "demo-bastion-key" in lines
    assert "demo-private-key" in lines


def test_teardown_instructions_name_no_interface():
    """Printed by the CLI and rendered in the web page.

    It used to give command line menu numbers, which were wrong for a web user
    the moment there was one - and told them to go open a terminal for two
    things the page can already do.
    """
    lines = "\n".join(bastion.teardown_instructions({
        "vpc": "vpc-123", bastion.BASTION_KEY: "demo-bastion-key",
    }))
    for interface in ("main.py", "->", "menu", "option"):
        assert interface not in lines, interface


# -------------------------------------------------------------- Instructions


def test_connection_instructions_use_proxyjump_and_say_why(ec2, keys):
    ok, created, _ = _build(ec2, keys)

    details = bastion.connection_details(ec2, created)
    lines = "\n".join(bastion.connection_instructions(details,
                                                      key_directory=keys))

    assert "ssh -J" in lines
    assert details["bastion_public_ip"] in lines
    assert details["private_ip"] in lines
    assert "worse" in lines


def test_instructions_are_honest_when_addresses_are_not_ready():
    lines = bastion.connection_instructions(
        {"bastion_public_ip": None, "private_ip": None,
         "bastion_key": "k", "private_key": "k2"}
    )
    assert any("assigned as the machines start" in line for line in lines)


# ------------------------------------------------- Driven over HTTP


def _public_half(comment):
    """A real public key. The blueprint validates before importing, so a
    placeholder string fails for the wrong reason."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    key = ed25519.Ed25519PrivateKey.generate()
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    ).decode() + f" {comment}"


def test_supplied_public_keys_are_imported_and_nothing_is_generated(ec2, keys):
    """The whole reason this blueprint could not be an endpoint.

    generate_locally writes private keys to the disk of whatever machine runs
    it. From a terminal that machine is the user's own, which is the point.
    From a web request it is the server, which would put two secrets on the
    API host and give the person who asked for them neither.
    """
    supplied = {
        bastion.BASTION_KEY: _public_half("bastion"),
        bastion.PRIVATE_KEY: _public_half("private"),
    }

    def explode(*args, **kwargs):
        raise AssertionError("generate_locally must not run when keys are given")

    import aws.key_pairs as kp_module
    original = kp_module.generate_locally
    kp_module.generate_locally = explode
    try:
        ok, created, problems = _build(ec2, keys, with_instances=False,
                                       public_keys=supplied)
    finally:
        kp_module.generate_locally = original

    assert ok, problems
    assert created[bastion.BASTION_KEY] == "demo-bastion-key"
    assert created[bastion.PRIVATE_KEY] == "demo-private-key"

    # Nothing was written to the key directory, because nothing was generated.
    assert os.listdir(keys) == []

    # AWS holds both, and holds only public material.
    registered = {k["KeyName"] for k in ec2.describe_key_pairs()["KeyPairs"]}
    assert {"demo-bastion-key", "demo-private-key"} <= registered


def test_a_missing_supplied_key_stops_the_build_rather_than_generating_one(ec2, keys):
    """Refusing beats defaulting. A build that quietly fell back to generating
    would put a private key on the server for anyone who omitted a field."""
    ok, created, problems = _build(
        ec2, keys, with_instances=False,
        public_keys={bastion.BASTION_KEY: _public_half("bastion")},
    )

    assert not ok
    assert any(bastion.PRIVATE_KEY in p for p in problems), problems
    assert os.listdir(keys) == []
