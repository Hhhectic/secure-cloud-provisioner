"""What Azure will accept as a name, checked before anything is attempted.

Ported from `archive/streamlit-gui/preflight.py`, which had the rules and could
only apply them to a form. They belong here instead, where every caller reaches
them: the CLI, the routes and the smoke test all go through `az/` and none of
them went through that page.

**These are refusals, not findings.** A name Azure will reject is not a
security judgement and does not belong in a warning list - it is a request that
cannot succeed, and the tool should say so in the same breath rather than
sending it and translating whatever comes back. That is the distinction
CLAUDE.md draws under *Guardrails are refusals, not warnings*.

Checked locally *before* the availability call, because the two answer
different questions and only one of them costs a round trip. "Is this a legal
name" is decided by a regular expression that has not changed in years; "is
somebody already using it" needs Azure and, for storage accounts and vaults,
depends on every other customer in the world. Asking the second about a name
that fails the first wastes a call to be told something less specific: Azure
answers a malformed storage account name with the same generic refusal it uses
for a taken one, so the caller learns "no" without learning "you used a capital
letter".

Each rule is stated as the constraint rather than as the regular expression,
because the person reading the message is being asked to pick a different name
and needs to know what the shape is.
"""

import re

# One entry per kind: the pattern, the sentence describing what is allowed, and
# any extra rule the pattern cannot express.
#
# A table rather than a function each, because every one of these is the same
# operation with different constants and the differences are the interesting
# part. Kinds are the registry's own type keys where one exists, so a caller
# holding a ResourceType does not have to translate.
_RULES = {
    "azure-storage": (
        r"[a-z0-9]{3,24}",
        "3 to 24 characters, lowercase letters and numbers only, with no "
        "hyphens. The name is global to all of Azure.",
    ),
    "azure-keyvault": (
        r"[A-Za-z][A-Za-z0-9-]{1,22}[A-Za-z0-9]",
        "3 to 24 characters of letters, numbers and hyphens, starting with a "
        "letter and not ending with a hyphen. The name is global to all of "
        "Azure.",
    ),
    "azure-nsg": (
        r"[A-Za-z0-9][A-Za-z0-9._\-]{0,78}[A-Za-z0-9_]",
        "1 to 80 characters of letters, numbers, underscores, periods and "
        "hyphens, starting with a letter or number and ending with a letter, "
        "number or underscore.",
    ),
    "azure-vnet": (
        r"[A-Za-z0-9][A-Za-z0-9._\-]{0,62}[A-Za-z0-9_]",
        "2 to 64 characters of letters, numbers, underscores, periods and "
        "hyphens, starting with a letter or number and ending with a letter, "
        "number or underscore.",
    ),
    # Azure allows up to 64 for a Linux machine name, but the name also becomes
    # the host name, and this tool derives the network interface and disk names
    # from it. 60 leaves room for those suffixes to stay inside their own
    # limits rather than failing three calls into a create that has already
    # built a network.
    "azure-vm": (
        r"[A-Za-z0-9][A-Za-z0-9-]{0,59}",
        "1 to 60 characters of letters, numbers and hyphens, starting with a "
        "letter or number.",
    ),
    "resource-group": (
        r"[A-Za-z0-9._()\-]{1,90}",
        "1 to 90 characters of letters, numbers, underscores, periods, "
        "hyphens and parentheses, not ending in a period.",
    ),
    "container": (
        r"[a-z0-9]([a-z0-9-]{1,61}[a-z0-9])",
        "3 to 63 characters of lowercase letters, numbers and single hyphens, "
        "starting and ending with a letter or number.",
    ),
}


def check(kind, name):
    """Whether Azure will accept `name` for `kind`. Returns (ok, message).

    Returns (True, None) when the name is legal. The message on a refusal names
    the value, says what is allowed, and stops - it deliberately does not
    suggest a corrected name, because the correction people want is almost
    never the one an algorithm picks and offering a wrong one invites it being
    accepted.

    An unknown kind is not an error. This is called from create paths, and a
    resource type nobody wrote a rule for should not be blocked from being
    created by the module that exists to catch typos - Azure will still refuse
    a genuinely illegal name. Silence here means "no opinion", not "fine".
    """
    if kind not in _RULES:
        return True, None

    pattern, allowed = _RULES[kind]

    if not name:
        return False, f"A name is required. It must be {allowed[0].lower()}{allowed[1:]}"

    if not re.fullmatch(pattern, name):
        return False, (
            f"Azure will not accept '{name}' as a {_label(kind)} name. It must "
            f"be {allowed[0].lower()}{allowed[1:]}"
        )

    # Two rules no regular expression above expresses, both real and both
    # things Azure rejects only once the request has been sent.
    if kind == "resource-group" and name.endswith("."):
        return False, (
            f"Azure will not accept '{name}' as a resource group name: it "
            "cannot end with a period."
        )

    if kind == "container" and "--" in name:
        return False, (
            f"Azure will not accept '{name}' as a container name: hyphens "
            "cannot be doubled."
        )

    return True, None


def _label(kind):
    """The kind as a person would say it, for the refusal message."""
    return {
        "azure-storage": "storage account",
        "azure-keyvault": "key vault",
        "azure-nsg": "network security group",
        "azure-vnet": "virtual network",
        "azure-vm": "virtual machine",
        "resource-group": "resource group",
        "container": "container",
    }.get(kind, kind)
