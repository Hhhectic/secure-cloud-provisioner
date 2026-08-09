"""Tests for findings somebody has decided to live with.

The whole risk of a suppression mechanism is that it suppresses. Most of what
is protected here is what an acknowledgement must *not* be able to do: hide a
finding, cover more than one, outlive its reason, or be created by anything
other than a person editing a file.
"""

import json
from datetime import date, timedelta
from pathlib import Path

import pytest

from scanner import acknowledged
from scanner.common import CRITICAL, WARNING, INFO, summarize, warning as _warning

TODAY = date(2026, 8, 9)


def _finding(rule_id, level=CRITICAL):
    return _warning(level, f"something about {rule_id}",
                    {"rule_id": rule_id, "resource_id": "demo",
                     "setting": rule_id.split(":")[-1]})


def _entry(rule_id, **overrides):
    base = {"rule_id": rule_id, "reason": "on purpose", "by": "someone",
            "on": "2026-08-01", "until": "2027-01-01"}
    base.update(overrides)
    return base


# ------------------------------------------------------------- what it does


def test_an_acknowledged_finding_keeps_its_level_and_its_place():
    """The property everything else here depends on.

    A suppression list that empties the screen is how people stop reading the
    screen. This one can make a finding quieter; it can never make it absent.
    """
    findings = [_finding("bucket:public_policy"), _finding("bucket:versioning",
                                                           WARNING)]
    out = acknowledged.apply(findings, [_entry("bucket:public_policy")],
                             today=TODAY)

    assert len(out) == 2, "nothing may be removed"
    assert out[0]["level"] == CRITICAL, "and nothing downgraded"
    assert out[0]["acknowledged"]["reason"] == "on purpose"
    assert out[0]["acknowledged"]["by"] == "someone"
    assert "acknowledged" not in out[1]


def test_the_counts_report_it_as_well_as_the_severity():
    """An acknowledged critical is still a critical. A tally that quietly
    excluded it would be the thing this module exists to avoid."""
    findings = acknowledged.apply([_finding("bucket:public_policy")],
                                  [_entry("bucket:public_policy")], today=TODAY)

    counts = summarize(findings)
    assert counts[CRITICAL] == 1
    assert counts["acknowledged"] == 1


def test_matching_is_exact_and_there_are_no_wildcards():
    """One pattern silencing a class of finding is how these go wrong."""
    findings = [_finding("bucket:public_policy"),
                _finding("other-bucket:public_policy")]

    for pattern in ("*", "bucket:*", "bucket", ":public_policy", "public_policy"):
        out = acknowledged.apply([dict(f) for f in findings],
                                 [_entry(pattern)], today=TODAY)
        assert not any(w.get("acknowledged") for w in out), pattern

    out = acknowledged.apply([dict(f) for f in findings],
                             [_entry("bucket:public_policy")], today=TODAY)
    assert [bool(w.get("acknowledged")) for w in out] == [True, False], \
        "an acknowledgement covers the one finding it names"


# ------------------------------------------------------------- expiry


def test_a_lapsed_acknowledgement_stops_applying():
    findings = acknowledged.apply(
        [_finding("bucket:public_policy")],
        [_entry("bucket:public_policy", until="2026-08-08")], today=TODAY)

    assert "acknowledged" not in findings[0], \
        "the finding speaks at full volume again"


def test_an_acknowledgement_with_no_end_date_still_gets_one():
    """A decision nobody revisits is how a suppression list rots."""
    entry = _entry("bucket:public_policy", on="2026-01-01", until=None)
    entry.pop("until")

    assert "acknowledged" not in acknowledged.apply(
        [_finding("bucket:public_policy")], [entry], today=TODAY)[0], \
        "180 days after it was made, it has lapsed"

    fresh = _entry("bucket:public_policy", on="2026-08-01", until=None)
    fresh.pop("until")
    assert acknowledged.apply([_finding("bucket:public_policy")], [fresh],
                              today=TODAY)[0].get("acknowledged")


# ------------------------------------------------- the list audits itself


def test_a_lapsed_acknowledgement_is_reported():
    """A skipped check is a finding, not a silence - and an acknowledgement
    is a skipped check."""
    found = acknowledged.audit(
        [_finding("bucket:public_policy")],
        [_entry("bucket:public_policy", until="2026-08-08")], today=TODAY)

    assert len(found) == 1
    assert found[0]["level"] == WARNING
    assert "ran out" in found[0]["message"]


def test_an_acknowledgement_matching_nothing_is_reported():
    """One that outlives the thing it was written for is how it quietly comes
    to cover something else."""
    found = acknowledged.audit([_finding("bucket:versioning")],
                               [_entry("bucket:public_policy")], today=TODAY)

    assert len(found) == 1
    assert found[0]["level"] == INFO
    assert "matches the acknowledgement" in found[0]["message"]


def test_a_live_acknowledgement_is_not_complained_about():
    assert acknowledged.audit([_finding("bucket:public_policy")],
                              [_entry("bucket:public_policy")],
                              today=TODAY) == []


# ------------------------------------------------------------- the file


def test_a_missing_file_acknowledges_nothing_and_is_not_an_error(tmp_path):
    entries, problem = acknowledged.load(tmp_path / "absent.json")
    assert entries == []
    assert problem is None


def test_an_unreadable_file_is_reported_rather_than_ignored(tmp_path):
    """Silently ignoring it would leave somebody believing a finding was
    acknowledged when it was not."""
    broken = tmp_path / "acknowledged.json"
    broken.write_text("{ not json")

    entries, problem = acknowledged.load(broken)
    assert entries == []
    assert problem and "could not be read" in problem

    found = acknowledged.audit([], [], today=TODAY, problem=problem)
    assert found and found[0]["level"] == WARNING
    assert "full volume" in found[0]["message"]


def test_entries_without_a_rule_id_are_dropped(tmp_path):
    where = tmp_path / "acknowledged.json"
    where.write_text(json.dumps({"acknowledgements": [
        {"reason": "no rule_id, so it names nothing"},
        {"rule_id": "bucket:public_policy", "reason": "fine"},
    ]}))

    entries, _ = acknowledged.load(where)
    assert [e["rule_id"] for e in entries] == ["bucket:public_policy"]


# --------------------------------------------------- nothing writes it


def test_no_part_of_the_api_writes_acknowledgements():
    """The constraint that makes the rest of this safe.

    An endpoint that created acknowledgements would be a remote "stop
    reporting this" API on a service that holds credentials and has no login.
    Combined with a cross-site POST it would be a drive-by suppression of a
    critical finding, which is the one thing the middleware in app.py was
    added to prevent.
    """
    api = Path(__file__).resolve().parent.parent / "api"
    source = "\n".join(f.read_text() for f in api.glob("*.py"))

    assert "acknowledged" in source, "the API should be reading them"

    for writes in ("acknowledged.json", "SCP_ACKNOWLEDGED",
                   "acknowledged.path()", ".write_text", "open("):
        if writes in source:
            # open() and write_text may appear for other reasons; only their
            # use anywhere near acknowledgements is the problem.
            for line in source.splitlines():
                if writes in line:
                    assert "acknowledg" not in line.lower(), line


def test_the_committed_file_parses_and_names_real_rule_ids():
    """A typo here is an acknowledgement that silently covers nothing."""
    entries, problem = acknowledged.load()
    assert problem is None

    for entry in entries:
        assert ":" in entry["rule_id"], entry
        assert entry.get("reason"), f"{entry['rule_id']} gives no reason"
        assert entry.get("by"), f"{entry['rule_id']} names nobody"
        assert entry.get("on"), f"{entry['rule_id']} has no date"
