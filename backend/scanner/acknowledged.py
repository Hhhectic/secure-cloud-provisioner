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

Who may write this file, and what that costs
--------------------------------------------
This module used to say nothing in the tool wrote this file at all, and that
the write belonged in the CLI because an endpoint would be a remote "stop
reporting this" API on a service holding credentials with no login. The write
is now `record()` below, reached by `POST /acknowledgements`.

The reason the old argument does not survive contact with the rest of this
program: the same API already exposes `DELETE /resources/{type}/{id}` with
force, which destroys infrastructure. If the guards on that path are trusted
for deletion they are trusted for suppression, and suppression is the smaller
of the two - it dims a finding rather than removing a machine. The middleware
in api/app.py refuses any write carrying another site's Origin and any request
whose Host is not this machine, which is the cross-site POST the old note was
written against.

What the move does cost is that an acknowledgement is no longer necessarily a
commit with an author on it. That was real provenance and a browser cannot
reproduce it, so the guards below stand in for it: `by` is required and cannot
be blank, a reason under fifteen characters is refused, an entry must name a
rule id that already exists, `confirm` must repeat that id, and every
acknowledgement now expires within a year whatever the request asks for. The
file is still a diff somebody has to commit for the decision to reach anybody
else's checkout.

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

# The longest any *newly written* acknowledgement may run.
#
# Enforced on the write path only, never on read: an entry already in the file
# with a longer date keeps it, because silently re-interpreting somebody's
# committed decision is worse than the long date is. The cap exists because an
# expiry is the only thing making these self-limiting, and a far-future one
# turns the mechanism off while looking like it is on - a working tree here
# carried `"until": "2100-06-07"` on a finding somebody was mid-debugging.
MAX_DAYS = 365

# The shortest reason that is one. A reason is read by somebody deciding
# whether the decision still holds, and "ok" does not survive that reading.
MIN_REASON = 15


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


# ------------------------------------------------------------- writing one


def check_entry(rule_id, reason, by, until, confirm, live_rule_ids, today=None):
    """Whether this may be written. Returns an error sentence, or None.

    Separate from `record` so a caller can be refused before anything is
    opened, and so the refusals are testable without a filesystem. Every one
    of them is a sentence aimed at the person who typed the thing, which is
    the same standard the warnings themselves are held to.
    """
    today = today or date.today()

    # Named twice, the demand every forced delete already makes. A boolean is
    # one character from being set by a copied example; repeating the id is
    # not something a request makes by accident.
    if confirm != rule_id:
        return (
            "To acknowledge a finding, confirm has to repeat its rule id "
            f"exactly. Expected '{rule_id}'."
        )

    # No wildcards, ever. One entry silencing a class of finding is how these
    # go wrong, and the reader matches exactly - so a pattern would not work
    # anyway, it would just look like it had.
    #
    # Deliberately not a check that the id contains a colon. Most rule ids are
    # `<resource>:<setting>`, but a security group's per-rule findings use the
    # SecurityGroupRuleId straight from AWS - a bare `sgr-...` - and that is
    # the flagship finding of the whole tool. Requiring the colon refused an
    # open SSH port, which is the thing this most exists to report. The real
    # guard against a made-up id is the live_rule_ids check below; this one
    # only has to stop somebody reaching for a glob.
    if "*" in rule_id:
        return (
            f"'{rule_id}' is not a rule id. An acknowledgement names one "
            "finding exactly, and there are no patterns - the reader matches "
            "exactly, so a wildcard would silence nothing while looking as "
            "though it had."
        )

    # The finding has to exist. Without this the API accepts an entry for
    # anything at all, including a rule id somebody expects to see later -
    # which is an acknowledgement written before the thing it excuses.
    if rule_id not in live_rule_ids:
        return (
            f"Nothing in the current scan reports '{rule_id}'. An "
            "acknowledgement is written against a finding that exists; "
            "scan the resource first."
        )

    if len((reason or "").strip()) < MIN_REASON:
        return (
            "A reason this short is not one. Somebody else has to be able to "
            "read it later and decide whether it still holds."
        )

    if not (by or "").strip():
        return "An acknowledgement with no author is anonymous."

    try:
        expires = date.fromisoformat(until)
    except (TypeError, ValueError):
        return f"'{until}' is not a date in YYYY-MM-DD form."

    if expires <= today:
        return f"{until} has already passed, so that entry would do nothing."

    if expires.toordinal() - today.toordinal() > MAX_DAYS:
        latest = date.fromordinal(today.toordinal() + MAX_DAYS)
        return (
            f"{until} is further out than {MAX_DAYS} days. An acknowledgement "
            "that outlives everyone's memory of writing it is the thing the "
            f"expiry exists to prevent. The latest allowed is {latest}."
        )

    return None


def record(entry, source=None):
    """Writes one entry into the file, preserving everything already there.

    Read, modify, write rather than append: the file is JSON carrying a
    comment block that explains itself, and an append would either destroy it
    or produce something that no longer parses.

    Validation is `check_entry`, which the caller runs first. This function
    writes what it is given.
    """
    where = Path(source) if source else path()

    if where.exists():
        document = json.loads(where.read_text())
    else:
        document = {"acknowledgements": []}

    # The file is allowed to be a bare list; normalising here means the shape
    # written is always the documented one.
    if isinstance(document, list):
        document = {"acknowledgements": document}

    document.setdefault("acknowledgements", []).append(entry)
    where.write_text(json.dumps(document, indent=2) + "\n")
    return where


def remove(rule_id, source=None):
    """Takes one rule's acknowledgements back out. Returns (removed, path).

    `removed` is the entries that were dropped, so the caller can say what the
    decision was rather than only that there is no longer one. That matters
    more here than it would for most deletes: the thing being thrown away is
    somebody's written reason, and echoing it back is the only record left of
    what it said once the file no longer holds it.

    Deliberately lighter guards than `check_entry`. Everything that function
    protects is about *quietening* a finding - the direction that can hide a
    live exposure, on a service holding credentials with no login. This is the
    other direction: the worst a wrong call here can do is report something at
    full volume that somebody had already decided about, which is the state the
    tool starts in and the one it is safe to be wrong towards.

    Removes every entry for the id rather than the first. Nothing stops the
    file holding two for one rule - `record` appends and does not look - and
    leaving one behind would answer "un-accepted" while the finding stayed
    dimmed, which is the one outcome that would make this untrustworthy.
    """
    where = Path(source) if source else path()
    if not where.exists():
        return [], where

    document = json.loads(where.read_text())
    if isinstance(document, list):
        document = {"acknowledgements": document}

    entries = document.get("acknowledgements", [])
    removed = [e for e in entries if isinstance(e, dict)
               and e.get("rule_id") == rule_id]
    if not removed:
        return [], where

    document["acknowledgements"] = [e for e in entries if e not in removed]
    where.write_text(json.dumps(document, indent=2) + "\n")
    return removed, where
