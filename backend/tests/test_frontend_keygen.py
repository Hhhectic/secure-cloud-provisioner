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
PAGE_SUITE = FRONTEND / "app.test.mjs"


needs_node = pytest.mark.skipif(
    shutil.which("node") is None or not SUITE.exists(),
    reason="node is not installed, or the frontend is absent from this checkout",
)

# The page suite additionally needs jsdom, which is a devDependency rather
# than something the page itself uses. Skipped separately so a checkout with
# Node but no `npm install` still runs the key generator, which needs nothing.
needs_jsdom = pytest.mark.skipif(
    shutil.which("node") is None
    or not (FRONTEND / "node_modules" / "jsdom").is_dir(),
    reason="jsdom is not installed; run `npm install` in frontend/",
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


# ------------------------------------------------------------------ The page


@pytest.fixture(scope="module")
def page_run():
    """Loads index.html, keygen.js and app.js into a DOM, once."""
    return subprocess.run(
        ["node", str(PAGE_SUITE)], capture_output=True, text=True, timeout=180,
    )


@needs_jsdom
def test_the_page_sends_what_the_form_was_told(page_run):
    """The path no backend test can reach.

    Everything server-side checks what it received. Nothing checked that the
    thing a person chose in a menu is the thing that arrives - and a firewall
    rule that is not the one somebody picked is exactly the failure this
    project exists to prevent.
    """
    assert page_run.returncode == 0, page_run.stdout + page_run.stderr
    assert "FAIL" not in page_run.stdout, page_run.stdout

    for claim in (
        "the chosen network is carried through, not the label",
        "a single port becomes a range of one, not a null",
        "ports are numbers, which is what the API validates",
    ):
        assert claim in page_run.stdout, claim


@needs_jsdom
def test_the_menus_are_built_from_the_api_not_from_the_page(page_run):
    """Guards the reason /resources/{type}/options exists.

    A menu hardcoded in JavaScript is a second copy of an allowlist enforced
    in Python, wrong at a different time from the first.
    """
    assert "the protocol menu is populated from the API, not hardcoded" in page_run.stdout
    # The duplicate a user reported: a blank first row captioned with a value
    # that also appeared in the list.
    assert "and lists TCP exactly once" in page_run.stdout


@needs_jsdom
def test_an_untouched_rule_row_sends_no_rule(page_run):
    """An empty row is an empty row, not a rule with a null source."""
    assert "and sends no rules at all rather than one with a null source" in page_run.stdout


@needs_jsdom
def test_the_page_offers_no_create_form_for_an_audited_type(page_run):
    """read_only travels all the way to the interface, so a button that could
    only ever be refused is never drawn."""
    assert "an audited type offers no create form and says why" in page_run.stdout
