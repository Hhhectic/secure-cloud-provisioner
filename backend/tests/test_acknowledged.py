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


def _cli():
    """backend/main.py, loaded by path rather than by name.

    `import main` is ambiguous in this repository and resolves to the *wrong*
    one under pytest: there is a main.py at the root - the older Azure app -
    and it wins. Same shape of trap as backend/az/ not being called
    backend/azure/, and worth the four lines to be unambiguous about which
    program is under test.
    """
    import importlib.util

    where = Path(__file__).resolve().parent.parent / "main.py"
    spec = importlib.util.spec_from_file_location("scp_cli", where)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

# ----------------------------------------------- writing one, from the CLI only


def test_the_cli_writes_an_entry_the_reader_then_honours(tmp_path, monkeypatch):
    """The round trip. Written by hand until now, which meant leaving the tool.

    The writer lives in main.py rather than anywhere api/ can reach, and that
    placement is the security argument rather than an accident of layout: a
    person at a terminal is already authenticated by having the shell, where
    the HTTP API has no login at all.
    """
    main = _cli()

    where = tmp_path / "acknowledged.json"
    monkeypatch.setenv("SCP_ACKNOWLEDGED", str(where))

    entry = {"rule_id": "bucket:public_policy", "reason": "a personal CV site",
             "by": "richard", "on": "2026-08-14", "until": "2027-02-14"}
    main._append_acknowledgement(entry)

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
    main = _cli()

    where = tmp_path / "acknowledged.json"
    where.write_text(json.dumps({
        "_comment": ["why this file exists"],
        "acknowledgements": [{"rule_id": "first:setting", "by": "someone",
                              "on": "2026-01-01"}],
    }, indent=2))
    monkeypatch.setenv("SCP_ACKNOWLEDGED", str(where))

    main._append_acknowledgement({"rule_id": "second:setting", "by": "else",
                                  "on": "2026-08-14"})

    document = json.loads(where.read_text())
    assert document["_comment"] == ["why this file exists"]
    assert [e["rule_id"] for e in document["acknowledgements"]] == [
        "first:setting", "second:setting"]


def test_the_writer_is_not_reachable_from_the_api(tmp_path):
    """The other half of test_no_part_of_the_api_writes_acknowledgements.

    That one reads api/*.py. This one says the writer is somewhere api/ does
    not import: main.py is the CLI entrypoint and nothing under api/ imports
    it, so no HTTP route can reach the function however it is called.
    """
    api = Path(__file__).resolve().parent.parent / "api"
    source = "\n".join(f.read_text() for f in api.glob("*.py"))

    assert "import main" not in source
    assert "from main" not in source
    assert "_append_acknowledgement" not in source

    # And scanner/acknowledged.py, which api/ *does* import, still only reads.
    reader = (Path(__file__).resolve().parent.parent
              / "scanner" / "acknowledged.py").read_text()
    for writes in (".write_text", ".write(", "json.dump("):
        assert writes not in reader, writes
