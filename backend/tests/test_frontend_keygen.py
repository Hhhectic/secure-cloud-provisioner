"""Runs the browser's key generator, for real, through Node.

The rest of the suite tests Python. This one shells out, because the code
being protected is JavaScript and the only honest way to test a key generator
is to generate a key and see whether anything can use it.

keygen.js needs WebCrypto, btoa, atob and TextEncoder, all of which Node has
as globals, so the file runs unmodified - the shipping code, not a port of it.
The assertion that matters is made by ssh-keygen: given the private half this
produced, derive the public half and see whether it matches the one that was
sent to AWS.

Skipped when Node is absent. Somebody without it should get a clear skip
rather than a red build for a dependency the rest of the project does not
have. GitHub's runners ship Node, so CI does run it.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

from aws.key_pairs import validate_public_key

FRONTEND = Path(__file__).resolve().parent.parent.parent / "frontend"
SUITE = FRONTEND / "keygen.test.mjs"


needs_node = pytest.mark.skipif(
    shutil.which("node") is None or not SUITE.exists(),
    reason="node is not installed, or the frontend is absent from this checkout",
)


@pytest.fixture(scope="module")
def keygen_run():
    """Runs the JavaScript suite once and hands its output to both tests."""
    return subprocess.run(
        ["node", str(SUITE)], capture_output=True, text=True, timeout=120,
    )


@needs_node
def test_the_browser_generates_keys_ssh_can_actually_use(keygen_run):
    """The check that could not be made until Node was installed.

    The byte layouts were previously verified by writing the same encoder a
    second time in Python and testing that one, which proves the algorithm and
    says nothing about the file a browser loads.
    """
    assert keygen_run.returncode == 0, keygen_run.stdout + keygen_run.stderr

    output = keygen_run.stdout
    assert "ssh-keygen derives exactly the public key we generated" in output
    assert "FAIL" not in output, output


@needs_node
def test_a_browser_without_ed25519_still_gets_a_usable_key(keygen_run):
    """The fallback branch, which nobody on a current browser reaches.

    Forced in the JavaScript by refusing Ed25519 the way an older engine does,
    and then verified the same way as the real path.
    """
    assert "a browser without Ed25519 gets an RSA key" in keygen_run.stdout
    assert "the algorithm agrees (ssh-rsa)" in keygen_run.stdout


@needs_node
def test_the_generated_public_key_passes_this_tools_own_validator():
    """The other end of the same journey.

    ssh-keygen says the key works. This says the tool would accept it, using
    the validator that stands between a user and sending AWS the wrong half of
    a key pair.
    """
    emitted = subprocess.run(
        ["node", "-e", f"""
        const {{ readFileSync }} = require("node:fs");
        const src = readFileSync({str(SUITE.parent / "keygen.js")!r}, "utf8");
        const KeyGen = new Function(src + "\\nreturn KeyGen;")();
        KeyGen.generate("pytest (secure-cloud-provisioner)")
              .then(p => console.log(p.publicKey));
        """],
        capture_output=True, text=True, timeout=120,
    )
    assert emitted.returncode == 0, emitted.stderr

    public_key = emitted.stdout.strip()
    assert validate_public_key(public_key) == "ED25519"

    # The thing this whole design exists to prevent.
    assert "PRIVATE KEY" not in public_key
