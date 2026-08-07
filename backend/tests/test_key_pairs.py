"""Tests for key pair import and the rules over it.

The bulk of these cover validate_public_key, which is disproportionate to its
size and deliberate. It is the one place in this project where a user can hand
over a secret by mistake, and the check that catches it has to hold under every
future change to this file.
"""

import ast
from pathlib import Path

import boto3
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from moto import mock_aws

from api import registry
from aws import key_pairs as kp
from scanner.key_pair_rules import check_key_pair
from scanner.common import INFO, fixable, cited

REGION = "us-east-1"


def _public_half(private_key, comment="user@example"):
    """Serialises the public half of a freshly generated key pair.

    Two earlier attempts at hand-written fixtures were rejected, first by this
    project's own validator and then by moto, and both rejections were correct.
    An OpenSSH public key is a structured, length-prefixed encoding, and for
    RSA the contents have to be a usable modulus and exponent rather than
    plausible-looking bytes. Generating a real pair is shorter than encoding a
    fake one and cannot drift out of validity.

    The private keys exist only inside this test process and are never written
    anywhere, which given what this module is about is worth stating.
    """
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    ).decode() + f" {comment}"


ED25519 = _public_half(ed25519.Ed25519PrivateKey.generate())
RSA = _public_half(rsa.generate_private_key(public_exponent=65537,
                                            key_size=2048))


def _settings(**overrides):
    base = {
        "key_name": "demo",
        "key_pair_id": "key-0123456789abcdef0",
        "key_type": "ED25519",
        "fingerprint": "aa:bb:cc",
        "in_use": True,
        "managed_by_us": True,
    }
    base.update(overrides)
    return base


# --------------------------------------------------------- Public key checking


def test_an_ed25519_public_key_is_accepted():
    assert kp.validate_public_key(ED25519) == "ED25519"


def test_an_rsa_public_key_is_accepted():
    assert kp.validate_public_key(RSA) == "RSA"


def test_a_key_without_a_comment_is_accepted():
    assert kp.validate_public_key(" ".join(ED25519.split()[:2])) == "ED25519"


def test_surrounding_whitespace_is_tolerated():
    assert kp.validate_public_key(f"  {ED25519}\n") == "ED25519"


def test_a_private_key_is_refused():
    """The failure this whole function exists for.

    Someone copies id_ed25519 instead of id_ed25519.pub. Without this check the
    secret reaches an HTTP request body and this process's memory.
    """
    private = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gt\n"
        "-----END OPENSSH PRIVATE KEY-----"
    )
    with pytest.raises(kp.InvalidPublicKey) as exc:
        kp.validate_public_key(private)

    assert "private key" in str(exc.value).lower()


def test_the_refusal_does_not_echo_the_key_back():
    """An error message is a thing people paste into chat and bug reports."""
    private = ("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAsecret\n"
               "-----END RSA PRIVATE KEY-----")
    with pytest.raises(kp.InvalidPublicKey) as exc:
        kp.validate_public_key(private)

    assert "MIIEowIBAAKCAQEAsecret" not in str(exc.value)


def test_the_refusal_suggests_rotating_the_key():
    """It has been on a clipboard. Treat it as compromised."""
    private = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"
    with pytest.raises(kp.InvalidPublicKey) as exc:
        kp.validate_public_key(private)

    assert "fresh pair" in str(exc.value)


def test_an_empty_key_is_refused():
    for empty in ("", "   ", None):
        with pytest.raises(kp.InvalidPublicKey):
            kp.validate_public_key(empty)


def test_random_text_is_refused():
    with pytest.raises(kp.InvalidPublicKey) as exc:
        kp.validate_public_key("this is not a key at all")
    assert "ssh-ed25519" in str(exc.value)


def test_a_key_type_aws_rejects_is_named_clearly():
    ecdsa = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY= user@example"
    with pytest.raises(kp.InvalidPublicKey) as exc:
        kp.validate_public_key(ecdsa)

    assert "ECDSA" in str(exc.value)
    assert "ED25519" in str(exc.value)


def test_a_truncated_key_body_is_refused():
    with pytest.raises(kp.InvalidPublicKey) as exc:
        kp.validate_public_key("ssh-ed25519 !!!!notbase64!!!! user@example")
    assert "does not look like" in str(exc.value) or "base64" in str(exc.value)


def test_a_multiline_key_is_refused():
    with pytest.raises(kp.InvalidPublicKey):
        kp.validate_public_key("ssh-ed25519 AAAAC3Nz\nAaC1lZDI1NTE5 user")


# ----------------------------------------------------------- Import, over moto


def test_the_web_page_never_sends_a_private_key_to_the_api():
    """The browser generates the pair; only the public half is submitted.

    The companion to test_this_module_never_calls_create_key_pair. That one
    stops the server obtaining private key material from AWS; this one stops
    the page handing any back to the server. Both protect the same property
    from opposite directions, and the page is the side a reviewer is less
    likely to check.

    Read as text rather than parsed, because there is no JS engine here. It is
    a coarse check and it is still the one that would catch someone adding a
    private_key field to the JSON body in a hurry.
    """
    page = Path(__file__).resolve().parent.parent.parent / "frontend"
    if not page.is_dir():
        pytest.skip("frontend not present in this checkout")

    keygen = (page / "keygen.js").read_text()
    app = (page / "app.js").read_text()

    # The module that holds the secret cannot reach the network at all. This
    # is the structural half of the guarantee, and the same shape of argument
    # as aws/key_pairs.py never importing the call that returns one.
    for reaches_out in ("fetch(", "XMLHttpRequest", "WebSocket", "sendBeacon",
                        "navigator.clipboard", "api("):
        assert reaches_out not in keygen, f"keygen.js must not call {reaches_out}"

    # And in the page that does talk to the API, the private half is only ever
    # handed to a download.
    uses = [line.strip() for line in app.splitlines() if ".privateKey" in line]
    assert uses, "the page should be generating a key pair"
    for line in uses:
        assert line.startswith("download("), f"private key used for: {line}"

    # The submitted spec has a field for the public half and none for anything
    # else, which is what api/models.ResourceSpec accepts.
    assert '"public_key"' in app
    assert "private_key" not in app


@pytest.fixture
def ec2():
    with mock_aws():
        yield boto3.client("ec2", region_name=REGION)


def test_importing_registers_the_key_and_tags_it(ec2):
    ok, name, problems = kp.import_key_pair(ec2, "demo", ED25519)
    assert ok, name
    assert name == "demo"
    assert problems == []

    ours = kp.list_key_pairs(ec2, only_ours=True)
    assert [k["KeyName"] for k in ours] == ["demo"]


def test_importing_rsa_notes_the_preference_without_refusing(ec2):
    """RSA is supported and sometimes required. Advise, do not block."""
    ok, name, problems = kp.import_key_pair(ec2, "old-key", RSA)
    assert ok
    assert any("ED25519" in p for p in problems)


def test_importing_a_private_key_fails_before_any_aws_call(ec2):
    private = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"
    ok, message, _ = kp.import_key_pair(ec2, "oops", private)

    assert not ok
    assert "private key" in message.lower()
    assert kp.list_key_pairs(ec2) == []


def test_a_duplicate_name_is_reported_not_overwritten(ec2):
    """AWS will not replace a key pair, and neither should this."""
    kp.import_key_pair(ec2, "demo", ED25519)
    ok, name, problems = kp.import_key_pair(ec2, "demo", RSA)

    assert ok
    assert name == "demo"
    assert any("already existed" in p for p in problems)


def test_this_module_never_calls_create_key_pair():
    """The design property, asserted rather than trusted to code review.

    create_key_pair returns private key material in the response body. If it
    ever appears in this module, the guarantee that no secret passes through
    this process is gone, and that is not the sort of thing to rely on someone
    noticing in a diff.

    Parsing the syntax tree rather than grepping the text, so that discussing
    create_key_pair in a docstring is fine and calling it is not.
    """
    tree = ast.parse(Path(kp.__file__).read_text())

    called = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    } | {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }

    assert "create_key_pair" not in called, (
        "aws/key_pairs.py calls create_key_pair, which returns private key "
        "material into this process. Use import_key_pair."
    )


# ------------------------------------------------------------------ The rules


def test_a_used_ed25519_key_is_clean():
    assert check_key_pair(_settings()) == []


def test_rsa_is_informational_not_a_fault():
    warnings = check_key_pair(_settings(key_type="RSA"))
    assert len(warnings) == 1
    assert warnings[0]["level"] == INFO
    assert warnings[0]["fix"] is None


def test_the_rsa_message_admits_what_it_cannot_check():
    """AWS does not expose key length, so a 1024-bit key looks like any other."""
    w = check_key_pair(_settings(key_type="RSA"))[0]
    assert "how long" in w["message"]


def test_an_unused_key_is_reported():
    warnings = check_key_pair(_settings(in_use=False))
    assert len(warnings) == 1
    assert warnings[0]["rule_id"] == "demo:unused"


def test_key_pair_findings_carry_no_citation():
    """No published benchmark covers EC2 key pairs. Do not imply otherwise."""
    warnings = check_key_pair(_settings(key_type="RSA", in_use=False))
    assert len(warnings) == 2
    assert cited(warnings) == []


def test_no_key_pair_finding_is_automatically_fixable():
    """Replacing or deleting an SSH key can lock people out of machines."""
    warnings = check_key_pair(_settings(key_type="RSA", in_use=False))
    assert fixable(warnings) == []


def test_a_missing_key_produces_no_findings():
    assert check_key_pair(None) == []


# --------------------------------------------------------- Through the registry


def test_key_pairs_are_a_registered_resource_type():
    assert "key-pair" in registry.REGISTRY


def test_creating_without_a_public_key_explains_the_design(ec2):
    ok, message, _ = registry.KEY_PAIR.create(ec2, {"name": "demo"})
    assert not ok
    assert "does not create private keys" in message


def test_the_full_lifecycle_through_the_registry(ec2):
    resource = registry.KEY_PAIR

    ok, name, _ = resource.create(ec2, {"name": "demo", "public_key": ED25519})
    assert ok

    listed = resource.list_all(ec2, only_ours=True)
    assert [k["id"] for k in listed] == ["demo"]

    settings = resource.read(ec2, name)
    assert settings["key_type"] == "ED25519"
    assert settings["managed_by_us"] is True

    # Nothing is running, so the key is correctly reported as unused.
    warnings = resource.check(settings)
    assert [w["rule_id"] for w in warnings] == ["demo:unused"]

    removed, message = resource.delete(ec2, name, {})
    assert removed, message
    assert resource.list_all(ec2, only_ours=True) == []


def test_the_delete_message_says_running_instances_are_unaffected(ec2):
    """People hesitate to delete keys because they fear locking themselves out."""
    kp.import_key_pair(ec2, "demo", ED25519)
    ok, message = kp.delete_key_pair(ec2, "demo")

    assert ok
    assert "unaffected" in message


def test_cleanup_removes_only_managed_keys(ec2):
    kp.import_key_pair(ec2, "ours", ED25519)
    ec2.import_key_pair(KeyName="theirs",
                        PublicKeyMaterial=RSA.encode())

    results = kp.cleanup_all_managed_key_pairs(ec2)
    assert [name for name, ok, _ in results] == ["ours"]

    remaining = [k["KeyName"] for k in kp.list_key_pairs(ec2)]
    assert remaining == ["theirs"]
