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


# ------------------------------------------- only one place writes it

# This section used to assert that *nothing* in api/ wrote an acknowledgement,
# and that the writer lived in main.py where no route could reach it. That was
# a real constraint and it has been deliberately reversed: the CLI's option 15
# is gone and POST /acknowledgements writes instead, because a tool whose only
# route to a documented feature is a terminal is a tool that feature does not
# reach. What replaces the constraint is that the write is guarded and that
# the file is still the record - see scanner/acknowledged.check_entry, and the
# refusals exercised further down.


def test_the_api_reaches_the_writer_through_exactly_one_function():
    """Not "nothing writes", but "one thing writes, and it validates first".

    The old assertion was that api/ contained no write path at all. Now that
    it does, what matters is that there is one of them: a second place
    assembling this file's JSON is how a guard gets bypassed by the route that
    forgot to call it.
    """
    api = Path(__file__).resolve().parent.parent / "api"
    source = "\n".join(f.read_text() for f in api.glob("*.py"))

    assert "acknowledged.record(" in source, "the API writes through record()"
    assert "acknowledged.check_entry(" in source, "and validates before it"

    # Nothing in api/ opens the file itself. The route hands an entry to
    # scanner/acknowledged.py and that module owns the format.
    for line in source.splitlines():
        if "acknowledg" not in line.lower():
            continue
        for writes in ("acknowledged.json", "SCP_ACKNOWLEDGED",
                       ".write_text", "open("):
            assert writes not in line, line


def test_an_acknowledgement_can_be_taken_back(tmp_path):
    """The counterpart of record(). A decision somebody made has to be one
    somebody can unmake, or the only way out of a stale entry is a text
    editor."""
    where = tmp_path / "acknowledged.json"
    where.write_text(json.dumps({"acknowledgements": [
        {"rule_id": "bucket:public_policy", "reason": "the CV site, on purpose",
         "by": "ada", "on": "2026-01-01", "until": "2026-12-01"},
        {"rule_id": "bucket:encryption_kms", "reason": "kms costs money here",
         "by": "ada", "on": "2026-01-01", "until": "2026-12-01"},
    ]}))

    removed, path_used = acknowledged.remove("bucket:public_policy", where)

    assert [e["rule_id"] for e in removed] == ["bucket:public_policy"]
    assert path_used == where
    # What it said comes back with it: the file no longer holds the reason,
    # and the caller is the last place it exists.
    assert removed[0]["reason"] == "the CV site, on purpose"

    left, _ = acknowledged.load(where)
    assert [e["rule_id"] for e in left] == ["bucket:encryption_kms"], (
        "and nothing else in the file is touched")


def test_taking_back_something_that_was_never_accepted_changes_nothing(tmp_path):
    where = tmp_path / "acknowledged.json"
    where.write_text(json.dumps({"acknowledgements": [
        {"rule_id": "bucket:public_policy", "reason": "on purpose", "by": "ada"},
    ]}))
    before = where.read_text()

    removed, _ = acknowledged.remove("bucket:nothing_like_this", where)

    assert removed == []
    assert where.read_text() == before, "the file is not rewritten for nothing"


def test_every_entry_for_one_rule_is_taken_back_not_just_the_first(tmp_path):
    """record() appends and does not look, so the file can hold two for one
    rule. Leaving one behind would answer "no longer accepted" while the
    finding stayed dimmed, which is the one result that would make this
    untrustworthy."""
    where = tmp_path / "acknowledged.json"
    where.write_text(json.dumps({"acknowledgements": [
        {"rule_id": "bucket:public_policy", "reason": "first", "by": "ada"},
        {"rule_id": "bucket:encryption_kms", "reason": "unrelated", "by": "ada"},
        {"rule_id": "bucket:public_policy", "reason": "written twice", "by": "bo"},
    ]}))

    removed, _ = acknowledged.remove("bucket:public_policy", where)

    assert len(removed) == 2
    left, _ = acknowledged.load(where)
    assert [e["rule_id"] for e in left] == ["bucket:encryption_kms"]


def test_a_removed_acknowledgement_stops_dimming_the_finding(tmp_path):
    """End to end over the two functions that matter: apply() marks it, remove()
    unmarks it, and nothing else about the finding changes."""
    where = tmp_path / "acknowledged.json"
    where.write_text(json.dumps({"acknowledgements": [
        {"rule_id": "bucket:public_policy", "reason": "the CV site, on purpose",
         "by": "ada", "on": "2026-01-01", "until": "2026-12-01"},
    ]}))

    def scan():
        return [_warning(CRITICAL, "anyone can read it",
                         {"rule_id": "bucket:public_policy",
                          "resource_id": "bucket", "setting": "public_policy"})]

    before = acknowledged.apply(scan(), acknowledged.load(where)[0], today=TODAY)
    assert before[0].get("acknowledged")
    assert acknowledged.count(before) == 1

    acknowledged.remove("bucket:public_policy", where)

    after = acknowledged.apply(scan(), acknowledged.load(where)[0], today=TODAY)
    assert not after[0].get("acknowledged"), "it speaks at full volume again"
    assert after[0]["level"] == CRITICAL, "and at the severity it always had"
    assert acknowledged.count(after) == 0


def test_the_write_is_refused_without_the_rule_id_repeated():
    """The same demand every forced delete here makes.

    A boolean is one character from being set by a copied example. Repeating
    the id is not something a request does by accident, which is the property
    wanted against a forged one.
    """
    problem = acknowledged.check_entry(
        rule_id="bucket:public_policy", reason="a personal CV site, on purpose",
        by="richard", until="2027-01-01", confirm="",
        live_rule_ids={"bucket:public_policy"}, today=TODAY)

    assert problem and "confirm" in problem


def test_a_rule_nothing_reports_cannot_be_acknowledged():
    """The strongest of the guards, and the one with no CLI equivalent.

    The route re-scans and passes what it found. An acknowledgement written
    against a finding that does not exist is one nobody can check, and it
    would sit in the file until the audit reported it as matching nothing.
    """
    problem = acknowledged.check_entry(
        rule_id="bucket:invented", reason="this finding is not real at all",
        by="richard", until="2027-01-01", confirm="bucket:invented",
        live_rule_ids={"bucket:public_policy"}, today=TODAY)

    assert problem and "Nothing in the current scan" in problem


def test_a_wildcard_is_refused_rather_than_matched_loosely():
    """There are no patterns, and a request that tries one is told so.

    apply() matches exactly, so a wildcard entry would silence nothing while
    looking like it silenced a class. Refusing it is the difference between a
    mistake and a mistake nobody notices.
    """
    problem = acknowledged.check_entry(
        rule_id="bucket:*", reason="everything about this bucket is fine",
        by="richard", until="2027-01-01", confirm="bucket:*",
        live_rule_ids={"bucket:public_policy"}, today=TODAY)

    assert problem and "not a rule id" in problem


def test_a_security_group_rule_id_is_acceptable_despite_having_no_colon():
    """The shape that broke the first version of the colon check.

    Every other rule id here is `<resource>:<setting>`, so requiring a colon
    looked like a free sanity check. A security group's per-rule finding uses
    the SecurityGroupRuleId straight from AWS, which is a bare `sgr-...`, and
    that finding is an administration port open to the internet - the single
    thing this tool most exists to report, and therefore the one most likely
    to be deliberate on a jump box and want acknowledging.
    """
    assert acknowledged.check_entry(
        rule_id="sgr-0a1b2c3d4e5f", reason="deliberate jump box, reviewed Aug",
        by="richard", until="2027-01-01", confirm="sgr-0a1b2c3d4e5f",
        live_rule_ids={"sgr-0a1b2c3d4e5f"}, today=TODAY) is None


def test_an_expiry_beyond_a_year_is_refused():
    """The expiry is what makes these self-limiting.

    A far-future date turns the mechanism off while leaving it looking on.
    Enforced on the way in only: an entry already committed with a longer date
    keeps it, because re-interpreting somebody's recorded decision is worse
    than the date is.
    """
    problem = acknowledged.check_entry(
        rule_id="bucket:public_policy", reason="a personal CV site, on purpose",
        by="richard", until="2100-06-07", confirm="bucket:public_policy",
        live_rule_ids={"bucket:public_policy"}, today=TODAY)

    assert problem and str(acknowledged.MAX_DAYS) in problem


def test_a_reason_too_short_and_an_author_missing_are_both_refused():
    """Both survive from the CLI, which had them and was the only way in."""
    common = dict(rule_id="bucket:public_policy", until="2027-01-01",
                  confirm="bucket:public_policy",
                  live_rule_ids={"bucket:public_policy"}, today=TODAY)

    assert "not one" in acknowledged.check_entry(reason="ok", by="richard",
                                                 **common)
    assert "anonymous" in acknowledged.check_entry(
        reason="a personal CV site, on purpose", by="   ", **common)


def test_a_good_entry_passes_every_check():
    """The one that would catch a guard tightened until nothing gets through."""
    assert acknowledged.check_entry(
        rule_id="bucket:public_policy", reason="a personal CV site, on purpose",
        by="richard", until="2027-01-01", confirm="bucket:public_policy",
        live_rule_ids={"bucket:public_policy"}, today=TODAY) is None


def test_the_committed_file_parses_and_names_real_rule_ids():
    """A typo here is an acknowledgement that silently covers nothing.

    This used to require a colon in every rule id, on the belief that they are
    all `<resource>:<setting>`. Most are, but a security group's per-rule
    findings carry the SecurityGroupRuleId from AWS - a bare `sgr-...` - so
    acknowledging an open SSH port, which is this tool's flagship finding,
    produces an entry that assertion would have failed. What actually matters
    is that an entry names something and says who and why, which is what is
    checked now.
    """
    entries, problem = acknowledged.load()
    assert problem is None

    for entry in entries:
        assert entry["rule_id"].strip(), entry
        assert "*" not in entry["rule_id"], f"{entry['rule_id']} is a pattern"
        assert entry.get("reason"), f"{entry['rule_id']} gives no reason"
        assert entry.get("by"), f"{entry['rule_id']} names nobody"
        assert entry.get("on"), f"{entry['rule_id']} has no date"


# ------------------------------------- an entry about something else entirely


def test_an_entry_about_another_resource_is_not_reported_by_this_scan():
    """The unmatched check compares against one resource's findings.

    Two entries for one S3 bucket produced two informational findings on every
    scan of every other resource, in both clouds - an Azure storage account
    reporting that nothing in it matched an acknowledgement written about a
    bucket. The message had to hedge with "or it is about a resource this scan
    did not look at" precisely because it could not tell the two cases apart.
    Scoping the audit to what was scanned is what lets it stop guessing.
    """
    found = acknowledged.audit(
        [_finding("azureaccount:public_blob_access")],
        [_entry("bucket:public_policy")],
        today=TODAY, scanned={"azureaccount"})

    assert found == []


def test_the_entrys_own_resource_still_reports_it_as_unmatched():
    """Scoping must not silence the case the check exists for.

    Scanning the very bucket an acknowledgement names, and not finding the
    thing it accepts, means the finding was fixed and the entry can go.
    """
    found = acknowledged.audit(
        [_finding("bucket:versioning")],
        [_entry("bucket:public_policy")],
        today=TODAY, scanned={"bucket"})

    assert len(found) == 1
    assert "matches the acknowledgement" in found[0]["message"]


def test_a_lapsed_entry_about_another_resource_is_also_left_alone():
    """Expiry is scoped for the same reason.

    The finding an expired entry stops suppressing is on that resource, so
    that is where saying so helps. Reported here it is the same noise on every
    unrelated scan.
    """
    assert acknowledged.audit(
        [_finding("azureaccount:public_blob_access")],
        [_entry("bucket:public_policy", until="2026-08-08")],
        today=TODAY, scanned={"azureaccount"}) == []

    lapsed = acknowledged.audit(
        [_finding("bucket:versioning")],
        [_entry("bucket:public_policy", until="2026-08-08")],
        today=TODAY, scanned={"bucket"})
    assert len(lapsed) == 1 and "ran out" in lapsed[0]["message"]


def test_a_security_group_rule_id_still_resolves_to_its_group():
    """Most rule ids are resource:setting; a firewall rule's has three fields.

    <group>:<rule>:<setting>, so taking the first field is what makes scoping
    work for both shapes rather than only the common one.
    """
    found = acknowledged.audit(
        [_finding("sg-1:ssh-from-anywhere:open_22")],
        [_entry("sg-1:ssh-from-anywhere:open_22")],
        today=TODAY, scanned={"sg-1"})

    assert found == []


def test_no_scope_still_audits_everything():
    """None is the whole-account sweep, where an unmatched entry really is one.

    Kept so the check has somewhere honest to live once something scans wide
    enough to answer it.
    """
    found = acknowledged.audit([_finding("bucket:versioning")],
                               [_entry("elsewhere:public_policy")],
                               today=TODAY)

    assert len(found) == 1




# ------------------------------------------------- writing one, through the API


def test_record_writes_an_entry_the_reader_then_honours(tmp_path, monkeypatch):
    """The round trip, which is the whole point of the file.

    This used to load the CLI by path and call main._append_acknowledgement.
    The writer is scanner.acknowledged.record now, reached by
    POST /acknowledgements, and the CLI no longer has an acknowledge option at
    all.
    """
    where = tmp_path / "acknowledged.json"
    monkeypatch.setenv("SCP_ACKNOWLEDGED", str(where))

    entry = {"rule_id": "bucket:public_policy", "reason": "a personal CV site",
             "by": "richard", "on": "2026-08-14", "until": "2027-02-14"}
    acknowledged.record(entry)

    entries, problem = acknowledged.load()
    assert problem is None
    assert entries == [entry]

    # And the reader treats it as live rather than merely present.
    found = [_finding("bucket:public_policy")]
    acknowledged.apply(found, entries, today=date(2026, 8, 15))
    assert found[0]["acknowledged"]["by"] == "richard"


def test_writing_a_second_entry_keeps_the_first_and_the_comment(tmp_path, monkeypatch):
    """Read-modify-write, not append: the file carries a comment block
    explaining itself and an append would either destroy it or produce
    something that is not JSON."""
    where = tmp_path / "acknowledged.json"
    where.write_text(json.dumps({
        "_comment": ["why this file exists"],
        "acknowledgements": [{"rule_id": "first:setting", "by": "someone",
                              "on": "2026-01-01"}],
    }, indent=2))
    monkeypatch.setenv("SCP_ACKNOWLEDGED", str(where))

    acknowledged.record({"rule_id": "second:setting", "by": "else",
                         "on": "2026-08-14"})

    document = json.loads(where.read_text())
    assert document["_comment"] == ["why this file exists"]
    assert [e["rule_id"] for e in document["acknowledgements"]] == [
        "first:setting", "second:setting"]


def test_the_cli_no_longer_writes_acknowledgements():
    """The other half of the move, asserted rather than assumed.

    Leaving the CLI writer in place beside the new route would be two ways to
    write this file with one set of guards between them - which is the failure
    test_the_api_reaches_the_writer_through_exactly_one_function describes,
    arrived at from the other direction. The demo feedback was that CLI
    functions should be minimal; this is the one that moved.
    """
    cli = (Path(__file__).resolve().parent.parent / "main.py").read_text()

    assert "_append_acknowledgement" not in cli
    assert "def acknowledge_menu" not in cli
    # And the menu does not offer an option that no longer exists.
    assert "Acknowledge a finding" not in cli
