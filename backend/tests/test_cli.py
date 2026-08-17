"""The CLI as a second surface over the registry.

There were no tests here at all, which is uncomfortable for the surface most
likely to drift: main.py is a second front end over the same ResourceType
entries the page drives, and it has drifted before in a way that mattered. It
paired an alarm's namespace and metric correctly while api/registry.py did not,
so the same tool built a working alarm from the terminal and a permanently
silent one from the page.

These do not drive the menus - they are interactive and read from stdin. What
they pin is the property that made that drift possible: whether the two
surfaces run the same checks over the same specs before they build anything.
"""

import ast
from pathlib import Path

import pytest

from api import registry
from scanner.common import CRITICAL, worst_level

MAIN = Path(__file__).resolve().parent.parent / "main.py"

# Calls that bring a cloud resource into existence.
#
# bastion.build is deliberately absent: a blueprint is a composition of several
# resources rather than a ResourceType, it has no check_spec of its own, and
# what it builds is reported by scanning the pieces afterwards.
CREATE_CALLS = {"create", "create_bucket", "create_security_group",
                "launch_instance"}

# Menus that create without a pre-flight, and the reason each is allowed to.
#
# Neither type's scanner has anything to say about a spec: importing a public
# key and choosing a network CIDR are both decisions with no dangerous form.
# The guard below re-derives that rather than trusting this comment, so adding
# a rule to either scanner fails here and sends somebody back to the menu.
NO_PREFLIGHT = {
    "key_pair_menu": registry.KEY_PAIR,
    "network_menu": registry.VPC,
}


def _functions():
    return [n for n in ast.walk(ast.parse(MAIN.read_text()))
            if isinstance(n, ast.FunctionDef)]


def _called_names(fn):
    names = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            func = node.func
            names.add(func.attr if isinstance(func, ast.Attribute)
                      else getattr(func, "id", None))
    return names


def test_every_menu_that_creates_something_runs_the_pre_flight_first():
    """The divergence this found, in the one menu that had no check at all.

    bucket_menu called create_bucket directly and described the deliberately
    weak option in three hand-written sentences - no encryption, no versioning,
    no public access block. The scanner reports five findings for that spec,
    two of them critical, and the description had stopped mentioning two of
    them. Meanwhile POST /resources/bucket refused the same spec outright, so
    the same tool declined a configuration on one surface and built it quietly
    on the other after a single y/N.
    """
    missing = []
    for fn in _functions():
        called = _called_names(fn)
        if not (called & CREATE_CALLS):
            continue
        if fn.name in NO_PREFLIGHT:
            continue
        if "check_spec" not in called:
            missing.append(fn.name)

    assert missing == [], (
        f"these menus create without running check_spec: {missing}. The page "
        "runs it for every type, and a surface that skips it is a surface "
        "that builds what the other one refuses."
    )


@pytest.mark.parametrize("menu,resource_type", sorted(
    NO_PREFLIGHT.items(), key=lambda kv: kv[0]))
def test_the_menus_with_no_pre_flight_have_nothing_to_check(menu, resource_type):
    """The exemption above, re-derived rather than believed.

    A menu is allowed to skip the pre-flight only while its scanner would
    return nothing whatever the form said. The moment somebody writes a rule
    for one of these types that stops being true, and this fails rather than
    the omission going quiet - which is how the exemption avoids becoming the
    thing it was granted against.
    """
    for spec in ({}, {"name": "probe", "region": "us-east-1"},
                 {"name": "probe", "region": "us-east-1",
                  "cidr": "0.0.0.0/0", "public_key": "ssh-ed25519 AAAA"}):
        assert resource_type.check_spec(spec) == [], (
            f"{menu} skips the pre-flight, but {resource_type.key} now reports "
            "something. Give the menu a check_spec call and take it out of "
            "NO_PREFLIGHT."
        )


def test_a_deliberately_weak_bucket_is_critical_on_both_surfaces():
    """What the CLI now has to show somebody before it builds one.

    Stated as a property of the spec rather than of either surface, because
    the failure was that only one of them asked.
    """
    weak = registry.BUCKET.check_spec(
        {"name": "scp-probe", "region": "us-east-1", "secure_by_default": False})

    assert worst_level(weak) == CRITICAL
    assert len(weak) > 3, (
        "the hand-written description this replaced named three problems; the "
        "point of running the scanner is that it cannot fall behind the rules"
    )


def test_the_secure_option_is_not_dressed_as_perfect():
    """Secure by default still has things to say, and says them at info.

    A menu that printed nothing for the secure option would teach people that
    silence is available, which is the habit this whole tool is against.
    """
    good = registry.BUCKET.check_spec(
        {"name": "scp-probe", "region": "us-east-1", "secure_by_default": True})

    assert good, "the secure option should still report what it does not do"
    assert worst_level(good) not in (CRITICAL, "warning")


def test_the_cli_does_not_keep_its_own_copy_of_which_scanner_a_type_uses():
    """security_group_menu called check_firewall_rules directly.

    It was the same call registry._sg_check_spec makes, so the two agreed -
    until somebody added a rule to one of them. Going through the registry is
    what makes "the CLI and the page scan identically" a fact rather than a
    coincidence that has held so far.
    """
    source = MAIN.read_text()
    creating = source[source.index("def security_group_menu"):]
    creating = creating[:creating.index("\ndef ")]

    assert "registry.SECURITY_GROUP.check_spec" in creating
    assert "check_firewall_rules(rules)" not in creating


def _dict_keys(fn):
    """Every string key of every dict literal built inside one function."""
    keys = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Dict):
            keys.update(k.value for k in node.keys
                        if isinstance(k, ast.Constant) and isinstance(k.value, str))
    return keys


@pytest.mark.parametrize("menu, field", [("instance_menu", "instance_type"),
                                         ("azure_vm_menu", "vm_size")])
def test_a_machine_menu_asks_which_size_rather_than_choosing_one(menu, field):
    """A size the tool refuses is the guardrail. A size it never asks about is
    the menu quietly deciding for you.

    `instance_menu` asked for a network, a subnet, a key pair and a public
    address, then built a spec with no `instance_type` in it - so
    `launch_instance` fell through to `DEFAULT_INSTANCE_TYPE` and every machine
    the CLI has ever started has been a `t3.micro`, while the page offered
    twelve. Harmless in itself, the smallest size on the allowlist, but it is
    the same shape as the alarm defect and the bucket pre-flight: two surfaces
    over one registry, one of them quietly narrower than the other.

    `azure_vm_menu` is parametrized alongside it because it always did ask, and
    that is exactly what made this hard to see - the CLI looked as though both
    machine menus offered a size.

    Asserted against the registry's own option list rather than a written-out
    allowlist, so a size added to `aws/instances.py` needs no edit here.
    """
    fn = next(f for f in _functions() if f.name == menu)

    assert field in _dict_keys(fn), (
        f"{menu} builds a spec with no {field!r} in it, so the size somebody "
        f"chose - or did not choose - never reaches the cloud call")
    assert "options" in _called_names(fn), (
        f"{menu} should read its sizes from the registry's options, so the "
        f"menu cannot offer something the tool would then refuse")
