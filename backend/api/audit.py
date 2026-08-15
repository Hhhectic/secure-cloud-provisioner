"""A local record of everything this tool changed, or refused to.

CloudTrail already records what reached AWS, and it is the authority. This is
not a replacement for it and would be a poor one: it can be deleted by anyone
who can run the tool, and it stops at the edge of this process.

It answers a different question. CloudTrail says an API call happened; it does
not say that a person asked for something and was told no. The refusals are
half the point of this tool - a cascade that demanded a typed ID, a cleanup
that would not take a guessable confirmation, a request from a page on another
site - and none of them leave any trace in an account, because nothing
happened. A log that only recorded successes would describe the tool as doing
less than it does.

Reads are not recorded. Scanning is the safe half and logging it would bury
the eight lines a day that matter under a few thousand that do not.

The file is opened per write rather than held open, because the process is
long-lived, does very little of this, and a handle kept for hours is a handle
that outlives a log rotation.
"""

import json
import os
import time
from pathlib import Path

# Somewhere outside the repository by default: a log of infrastructure changes
# is not source, and the one place it must never end up is a commit.
DEFAULT_PATH = Path.home() / ".secure-cloud-provisioner" / "audit.log"

WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")


def path():
    """Where the log is written. SCP_AUDIT_LOG overrides."""
    override = os.environ.get("SCP_AUDIT_LOG")
    return Path(override).expanduser() if override else DEFAULT_PATH


def record(**fields):
    """Appends one JSON line. Never raises.

    A tool that fell over because it could not write its own log would be
    worse than one that quietly lost a line of it, and this is the only part
    of the process that runs on every request whether or not it is needed.
    """
    entry = {"at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **fields}
    try:
        destination = path()
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with destination.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, default=str) + "\n")
        # It records which machines were destroyed and when. That is nobody
        # else's business on a shared machine.
        os.chmod(destination, 0o600)
    except OSError:
        pass


def read_recent(limit=25):
    """The most recent entries, newest first. Never raises.

    Written since the first commit and never readable, which made the log a
    file somebody had to know about and go and find. The dashboard shows it
    because the refusals are the half of this tool's behaviour that leaves no
    trace anywhere else - a cascade that demanded a typed ID and did not get
    one is invisible in CloudTrail, because nothing happened.

    Reads only what it needs from the end of the file rather than parsing all
    of it: this grows for as long as the tool is used and the page wants the
    last twenty lines.

    A malformed line is skipped rather than fatal. The writer never raises,
    so a line truncated by a full disk is a thing that can exist, and one bad
    line should not take the panel with it.
    """
    where = path()
    try:
        if not where.exists():
            return []
        with where.open("r", encoding="utf-8") as handle:
            lines = handle.readlines()[-limit * 2:]
    except OSError:
        return []

    found = []
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            found.append(json.loads(line))
        except ValueError:
            continue
        if len(found) >= limit:
            break
    return found


def describe(status):
    """A word for what happened, from the status code alone.

    Deliberately coarse. The interesting distinction is did it happen, was it
    refused, or did it break - not which of four hundreds it was.
    """
    if status < 300:
        return "done"
    if status in (400, 403, 405, 409):
        return "refused"
    if status == 404:
        return "not found"
    if status == 422:
        return "rejected"
    return "failed"
