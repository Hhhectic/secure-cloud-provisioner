"""Findings somebody has looked at and decided to live with.

Intent is not in the control plane. A bucket readable by the whole internet
looks identical whether it is a leak or a personal website, and no rule can
tell them apart, because the difference is why somebody did it. Benchmarking
against Prowler made this concrete: both tools call a deliberately public
static site critical, and both are right.

The alternatives were worse. A heuristic - "website hosting is on, so it is
probably meant to be public" - is a guess dressed as a fact, and attackers
enable website hosting too. Asking a model to judge intent is the same guess
with less explainability, non-deterministic, and wrong in the direction that
hides a leak. So the answer is to ask the person who knows, and write it down.

What an acknowledgement does and does not do
--------------------------------------------
It never hides anything. The finding keeps its level, stays in the list and
stays in the counts; it gains an "acknowledged" field and is counted
separately as well. Something you cannot see is something you cannot review,
and a suppression list that empties the screen is how people stop reading the
screen.

There are no patterns. An acknowledgement names one rule_id exactly, because
one wildcard entry silencing a whole class of finding is how these go wrong.

Nothing in this tool writes this file. It is edited by hand and committed, so
every acknowledgement is a diff with an author on it. An endpoint that created
acknowledgements would be a remote "stop reporting this" API on a service that
holds credentials and has no login, which is the opposite of what the rest of
api/app.py spends its time preventing.

And the acknowledgements are themselves audited: one that has expired, or that
matches nothing in the account any more, is reported as a finding. A skipped
check is a finding rather than a silence, and an acknowledgement is a skipped
check.
"""

import json
import os
from datetime import date, datetime
from pathlib import Path

from scanner.common import WARNING, INFO, warning as _warning

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "acknowledged.json"

# How long an acknowledgement may run before it has to be looked at again.
# Applied when an entry gives no "until" of its own: an acknowledgement with no
# end date is a decision nobody ever revisits.
DEFAULT_DAYS = 180


def path():
    """Where acknowledgements are read from. SCP_ACKNOWLEDGED overrides."""
    override = os.environ.get("SCP_ACKNOWLEDGED")
    return Path(override).expanduser() if override else DEFAULT_PATH


def load(source=None):
    """Reads the acknowledgements, or returns none.

    A missing file is the normal case and means nothing is acknowledged. A
    malformed one is not: it is returned as empty so the scan still runs, and
    the caller is told, because silently ignoring a file somebody wrote would
    leave them believing a finding was acknowledged when it was not.
    """
    where = Path(source) if source else path()
    if not where.exists():
        return [], None

    try:
        loaded = json.loads(where.read_text())
    except (OSError, ValueError) as e:
        return [], f"{where} could not be read ({e}), so nothing is acknowledged"

    entries = loaded.get("acknowledgements", loaded) if isinstance(loaded, dict) else loaded
    if not isinstance(entries, list):
        return [], f"{where} does not contain a list of acknowledgements"

    return [e for e in entries if isinstance(e, dict) and e.get("rule_id")], None


def _expires_on(entry):
    """The date this acknowledgement stops applying, or None if unparseable."""
    stated = entry.get("until")
    if stated:
        try:
            return date.fromisoformat(stated)
        except ValueError:
            return None

    made = entry.get("on")
    if not made:
        return None
    try:
        return date.fromordinal(date.fromisoformat(made).toordinal() + DEFAULT_DAYS)
    except ValueError:
        return None


def apply(warnings, entries=None, today=None):
    """Marks the warnings somebody has acknowledged. Removes nothing.

    Returns the same list, with an "acknowledged" field on those that matched.
    Matching is exact on rule_id: no prefixes, no globs.
    """
    entries = entries if entries is not None else load()[0]
    today = today or date.today()

    by_rule = {}
    for entry in entries:
        expires = _expires_on(entry)
        if expires and expires < today:
            continue  # lapsed, so the finding speaks at full volume again
        by_rule[entry["rule_id"]] = entry

    for w in warnings:
        entry = by_rule.get(w.get("rule_id"))
        if not entry:
            continue
        w["acknowledged"] = {
            "reason": entry.get("reason", ""),
            "by": entry.get("by", "unknown"),
            "on": entry.get("on"),
            "until": (_expires_on(entry).isoformat()
                      if _expires_on(entry) else None),
        }

    return warnings


def _resource_of(rule_id):
    """The resource half of a rule id.

    Rule ids are `<resource>:<setting>`, except a security group rule's, which
    is `<group>:<rule>:<setting>`. The resource is the first field either way.
    """
    return (rule_id or "").split(":")[0]


def audit(warnings, entries=None, today=None, problem=None, scanned=None):
    """Findings about the acknowledgements themselves.

    An acknowledgement is a decision to stop looking at something. Left
    unexamined it becomes a decision nobody remembers making, about a resource
    that may no longer be the one it was written for.

    `scanned` is the set of resource ids this scan actually looked at, and
    entries about anything else are left alone. Without it the unmatched check
    compares every acknowledgement against one resource's findings and reports
    each one that is not about *that* resource - which is most of them, every
    time. Two entries for one S3 bucket produced two informational findings on
    every scan of every other resource in either cloud, and the message had to
    hedge with "or it is about a resource this scan did not look at" because it
    genuinely could not tell the two apart.

    None means no scope, which is the whole-account sweep this cannot do from
    a single resource: there, an entry matching nothing really has outlived
    whatever it was written for.
    """
    entries = entries if entries is not None else load()[0]
    today = today or date.today()
    found = []

    if problem:
        found.append(_warning(
            WARNING,
            f"The acknowledgements could not be read, so nothing is being "
            f"treated as acknowledged: {problem}. Every finding below is "
            "reported at full volume, which is the safe direction, but it is "
            "not what whoever wrote that file intended.",
            {"rule_id": "acknowledgements:unreadable",
             "resource_id": "acknowledgements",
             "setting": "unreadable"},
        ))

    live = {w.get("rule_id") for w in warnings}

    for entry in entries:
        rule_id = entry["rule_id"]
        expires = _expires_on(entry)

        # Both checks below are about this entry's own resource, so neither can
        # be answered while looking at a different one. An expired entry is
        # scoped for the same reason as an unmatched one: the finding it stops
        # suppressing is on that resource, and that is where saying so helps.
        if scanned is not None and _resource_of(rule_id) not in scanned:
            continue

        if expires and expires < today:
            found.append(_warning(
                WARNING,
                f"The acknowledgement for {rule_id} ran out on "
                f"{expires.isoformat()}. Whatever was accepted then is being "
                "reported again now. Either the reason still holds and the "
                "entry needs renewing, or it does not and the finding needs "
                "acting on.",
                {"rule_id": f"acknowledgements:{rule_id}:expired",
                 "resource_id": "acknowledgements", "setting": "expired"},
            ))
            continue

        if rule_id not in live:
            found.append(_warning(
                INFO,
                f"Nothing in this scan matches the acknowledgement for "
                f"{rule_id}. Either the finding has been fixed, in which case "
                "the entry can go, or it is about a resource this scan did "
                "not look at. An acknowledgement outliving the thing it was "
                "written for is how one quietly comes to cover something else.",
                {"rule_id": f"acknowledgements:{rule_id}:unmatched",
                 "resource_id": "acknowledgements", "setting": "unmatched"},
            ))

    return found


def count(warnings):
    """How many of these findings somebody has already decided to live with."""
    return sum(1 for w in warnings if w.get("acknowledged"))
