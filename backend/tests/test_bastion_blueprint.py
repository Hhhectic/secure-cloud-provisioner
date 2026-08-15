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
import subprocess
import tempfile
from pathlib import Path

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


def test_the_instructions_start_by_making_the_keys_private(ec2, keys):
    """ssh refuses a key other people on the machine could read, and a browser
    downloads one as exactly that - 0644, every time, by the route this tool
    recommends.

    These instructions went straight to ssh-add, so anyone who followed them
    got a wall of hashes about an unprotected key file instead of a shell. The
    keygen panel said chmod 600 and this did not, so generating the keys here
    and then reading this gave you the half without it.

    Asserted before ssh-add rather than merely present: an order that puts the
    fix after the thing it fixes is the same failure with more words.
    """
    details = bastion.connection_details(ec2, created=_build(ec2, keys)[1])
    lines = bastion.connection_instructions(details, key_directory=keys)
    joined = "\n".join(lines)

    assert "chmod 600" in joined
    assert joined.index("chmod 600") < joined.index("ssh-add")


def test_downloaded_keys_are_filed_before_anything_expects_them_there(ec2, keys):
    """The step before the chmod, and the same shape of gap.

    Every command in these instructions names ~/.ssh, and a browser cannot put
    anything there - it downloads to wherever downloads go. So somebody
    generating key pairs with frontend/keygen.js and building from the page
    got a chmod and two ssh-adds aimed at a directory the files were not in.

    Ordered rather than merely present, for the reason the chmod test gives:
    a move that happens after the chmod is a chmod against nothing.
    """
    details = bastion.connection_details(ec2, created=_build(ec2, keys)[1])
    joined = "\n".join(bastion.connection_instructions(
        details, key_directory=keys, keys_were_downloaded=True))

    assert "mv ~/Downloads/" in joined
    assert joined.index("mv ~/Downloads/") < joined.index("chmod 600")
    # Both key filenames travel with the move, not just the bastion's.
    assert details["bastion_key"] in joined
    assert details["private_key"] in joined


def test_the_move_step_is_absent_for_keys_that_were_never_downloaded(ec2, keys):
    """The CLI writes its pairs straight to disk with ssh-keygen, so telling it
    to move them out of ~/Downloads would name a path that does not exist."""
    details = bastion.connection_details(ec2, created=_build(ec2, keys)[1])
    joined = "\n".join(bastion.connection_instructions(details,
                                                       key_directory=keys))

    assert "~/Downloads" not in joined
    assert "chmod 600" in joined


def test_the_connect_script_holds_no_key_material(ec2, keys):
    """The property the whole key-pair design exists to protect.

    A private half goes from WebCrypto to a download and nowhere else. This
    server has never held one, so a script it generates cannot contain one -
    but the check is worth making directly rather than inferring it, because
    the failure would be silent and total: a private key in a response body is
    in the logs, in the proxy, and in everything between.
    """
    details = bastion.connection_details(ec2, created=_build(ec2, keys)[1])
    script = bastion.connect_script(details, key_directory=keys)

    assert "PRIVATE KEY" not in script
    assert "BEGIN OPENSSH" not in script
    # The filenames are in there; the contents are not.
    assert details["bastion_key"] in script
    assert details["private_key"] in script


def test_the_connect_script_needs_no_ssh_agent(ec2, keys):
    """ssh-add inside a script adds to an agent that dies with the script.

    The printed instructions start an agent because a person runs them in a
    shell that outlives them. A script cannot, so it gives each hop its own
    key with -i - which is also why it works on a machine with no agent at
    all.
    """
    details = bastion.connection_details(ec2, created=_build(ec2, keys)[1])
    script = bastion.connect_script(details, key_directory=keys)

    assert "ssh-agent" not in script
    assert "ssh-add" not in script
    assert "IdentitiesOnly=yes" in script
    # Each hop names its own key, which is the point of building two.
    assert "ProxyCommand" in script


def test_the_connect_script_is_valid_shell(ec2, keys):
    """Parsed by bash rather than eyeballed.

    A generated script is assembled from an f-string carrying braces, quotes
    and backslashes, all of which mean something to both languages. `bash -n`
    catches an unbalanced one; nothing else here would until somebody ran it.
    """
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("no bash on this machine")

    details = bastion.connection_details(ec2, created=_build(ec2, keys)[1])
    script = Path(keys) / "connect.sh"
    script.write_text(bastion.connect_script(details, key_directory=keys))

    checked = subprocess.run([bash, "-n", str(script)],
                             capture_output=True, text=True)
    assert checked.returncode == 0, checked.stderr


def test_the_connect_script_files_the_keys_and_makes_them_private(ec2, keys,
                                                                  tmp_path):
    """The half that can be tested without a machine to connect to.

    Runs the real script against real files, with the final ssh replaced, and
    checks it does what the instructions promise: finds the keys wherever the
    browser left them, moves them into place, and leaves them readable only by
    the owner. That last one is what ssh refuses over, and it is the reason
    any of this exists.
    """
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("no bash on this machine")

    details = bastion.connection_details(ec2, created=_build(ec2, keys)[1])

    # Where the browser put them: not the target directory.
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    target = tmp_path / "dot-ssh"
    for which in ("bastion_key", "private_key"):
        made = downloads / details[which]
        made.write_text("not a real key, and the script never reads one\n")
        made.chmod(0o644)  # exactly what a browser download is

    script = tmp_path / "connect.sh"
    script.write_text(bastion.connect_script(details, key_directory=target))

    # A stub ssh on PATH, so the script's exec lands somewhere harmless. The
    # script is run from the downloads directory, which is where its own
    # search is meant to find the keys.
    stub = tmp_path / "bin"
    stub.mkdir()
    (stub / "ssh").write_text("#!/bin/sh\necho stub-ssh-reached\n")
    (stub / "ssh").chmod(0o755)

    ran = subprocess.run(
        [bash, str(script)], capture_output=True, text=True, cwd=downloads,
        env={"PATH": f"{stub}:/usr/bin:/bin", "HOME": str(tmp_path)},
    )

    assert ran.returncode == 0, ran.stderr
    assert "stub-ssh-reached" in ran.stdout, ran.stdout

    for which in ("bastion_key", "private_key"):
        filed = target / details[which]
        assert filed.exists(), f"{which} was not filed into {target}"
        assert not (downloads / details[which]).exists(), "and was moved, not copied"
        assert filed.stat().st_mode & 0o777 == 0o600, "ssh refuses anything looser"

    assert target.stat().st_mode & 0o777 == 0o700


def test_running_the_connect_script_twice_still_works(ec2, keys, tmp_path):
    """Somebody will. The first run moves the keys, so a second one has to
    find them where the first put them rather than fail on an absent file."""
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("no bash on this machine")

    details = bastion.connection_details(ec2, created=_build(ec2, keys)[1])
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    target = tmp_path / "dot-ssh"
    for which in ("bastion_key", "private_key"):
        (downloads / details[which]).write_text("placeholder\n")

    script = tmp_path / "connect.sh"
    script.write_text(bastion.connect_script(details, key_directory=target))

    stub = tmp_path / "bin"
    stub.mkdir()
    (stub / "ssh").write_text("#!/bin/sh\necho stub-ssh-reached\n")
    (stub / "ssh").chmod(0o755)
    env = {"PATH": f"{stub}:/usr/bin:/bin", "HOME": str(tmp_path)}

    first = subprocess.run([bash, str(script)], capture_output=True, text=True,
                           cwd=downloads, env=env)
    assert first.returncode == 0, first.stderr

    second = subprocess.run([bash, str(script)], capture_output=True, text=True,
                            cwd=downloads, env=env)
    assert second.returncode == 0, second.stderr
    assert "stub-ssh-reached" in second.stdout


def test_the_connect_script_says_what_is_missing_rather_than_failing_oddly(
        ec2, keys, tmp_path):
    """A key that is nowhere is the likeliest failure: somebody cleared their
    downloads, or ran this on a different machine from the one that built it.

    `set -e` alone would exit on the mv with a message about a file, naming
    neither which key nor where it was looked for.
    """
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("no bash on this machine")

    details = bastion.connection_details(ec2, created=_build(ec2, keys)[1])
    script = tmp_path / "connect.sh"
    script.write_text(bastion.connect_script(
        details, key_directory=tmp_path / "dot-ssh"))

    ran = subprocess.run(
        [bash, str(script)], capture_output=True, text=True, cwd=tmp_path,
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)},
    )

    assert ran.returncode != 0
    assert details["bastion_key"] in ran.stderr
    assert "Looked in" in ran.stderr


def test_no_script_before_the_addresses_exist(ec2, keys):
    """The same silence connection_instructions keeps, for the same reason: a
    script naming an empty address would fail in a way that looks like the
    machine refusing rather than the machine not being ready."""
    assert bastion.connect_script(
        {"bastion_public_ip": None, "private_ip": None,
         "bastion_key": "k", "private_key": "k2"}) is None


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
