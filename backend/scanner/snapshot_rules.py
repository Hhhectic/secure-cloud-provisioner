"""Security rules for evaluating EBS snapshots.

Contains pure Python evaluation logic with no external AWS dependencies.

Three findings, and the first one is the reason this module exists. A snapshot
marked readable by everyone is a complete copy of a disk that any AWS account
can take, silently and without leaving a trace on this side. It is the rare
finding that is both catastrophic and a single setting.

Nothing here carries a citation. The published benchmark this tool cites, CIS
AWS Foundations, has no control covering who may restore a snapshot; the
control usually quoted for it belongs to a different AWS standard that this
tool does not assess against. Encryption is likewise covered for volumes
rather than for snapshots of them. Stretching either to fit would be the same
fabricated citation that scanner/controls.py refuses elsewhere, so these
findings stand on being true rather than on being numbered.

Nothing here is automatically fixable. See aws/snapshots.apply_fix.
"""

from scanner.common import (
    CRITICAL,
    WARNING,
    INFO,
    warning as _warning,
    summarize,
    fixable,
    cited,
    worst_level,
    print_warnings,
)

# What the audit could not ask about, in the words a finding uses. Mirrors
# scanner/iam_rules.CHECK_LABELS.
CHECK_LABELS = {
    "restore_permission": "who is allowed to restore this backup",
}


def _target(snapshot_id, setting):
    return {
        "rule_id": f"{snapshot_id}:{setting}",
        "resource_id": snapshot_id,
        "setting": setting,
    }


def _plural(count, word):
    return word if count == 1 else word + "s"


def check_snapshot(settings):
    """Evaluates one snapshot and returns detected risks.

    Expects the shape produced by aws.snapshots.read_snapshot_for_scanning():
        {
          "snapshot_id": str,
          "description": str,
          "volume_size": int | None,
          "encrypted": bool,
          "public": bool | None,
          "shared_with": [account id, ...],
          "unreadable": {check name: permission},
        }

    "public": None means the question was not answered, which is reported as a
    finding of its own rather than passed over.
    """
    if not settings:
        return []

    snapshot_id = settings.get("snapshot_id", "this backup")
    unreadable = settings.get("unreadable") or {}
    warnings = []

    # ---- Checks that did not happen ------------------------------------------
    #
    # First, and before the findings below can reassure anyone. A snapshot
    # whose permissions could not be read is the one case where this scanner
    # can be confidently, dangerously wrong.
    for name, permission in unreadable.items():
        label = CHECK_LABELS.get(name, name)
        warnings.append(_warning(
            WARNING,
            f"Could not check {label}. The login this tool is using was "
            f"refused {permission}, so this part of the audit did not run. "
            "This backup is not being reported as private; it is being "
            "reported as unexamined, which is not the same thing.",
            _target(snapshot_id, f"unreadable_{name}"),
        ))

    # ---- Readable by anyone --------------------------------------------------
    if settings.get("public") is True:
        size = settings.get("volume_size")
        measure = f"{size} GB " if size else ""
        warnings.append(_warning(
            CRITICAL,
            f"Anyone with an AWS account can take a copy of this {measure}"
            "backup and read everything on it. That includes files deleted "
            "before it was taken, because deleting a file removes the entry "
            "pointing at it and leaves the contents on the disk. Passwords, "
            "keys and customer records in any of those places are readable "
            "too. Nothing is recorded when someone does this, so there is no "
            "way to learn afterwards whether anyone has, or who. Make it "
            "private now and treat anything secret that was on that disk as "
            "known to strangers. The command is: aws ec2 "
            f"modify-snapshot-attribute --snapshot-id {snapshot_id} "
            "--attribute createVolumePermission --operation-type remove "
            "--group-names all",
            _target(snapshot_id, "public"),
        ))

    # ---- Shared with named accounts ------------------------------------------
    #
    # Separate from the finding above and much milder. Sharing with a named
    # account is how legitimate work gets done; it is listed because nothing
    # about it is visible day to day and nothing expires it.
    shared = settings.get("shared_with") or []
    if shared:
        count = len(shared)
        who = ", ".join(shared[:5])
        if count > 5:
            who += f", and {count - 5} more"
        warnings.append(_warning(
            WARNING,
            f"This backup is shared with {count} other AWS "
            f"{_plural(count, 'account')}: {who}. That may well be "
            "deliberate. It is worth confirming anyway, because the sharing "
            "has no expiry date, nothing here records who asked for it or "
            "why, and it will outlast the arrangement that prompted it. "
            "Withdrawing it later does not reach any copy that has already "
            "been taken.",
            _target(snapshot_id, "shared_with_accounts"),
        ))

    # ---- Encryption ----------------------------------------------------------
    #
    # Last, and worth stating in terms of the finding above rather than as
    # compliance boilerplate: AWS refuses to make an encrypted snapshot public
    # at all, so this setting is what decides whether the critical finding is
    # even reachable.
    if settings.get("encrypted") is False:
        warnings.append(_warning(
            WARNING,
            "This backup is not encrypted. Beyond the usual reasons that "
            "matters, it is the setting that makes the worst mistake "
            "possible: AWS will not let an encrypted backup be shared with "
            "everyone, so an unencrypted one is the only kind that can be "
            "exposed to the whole internet by a single wrong click. "
            "Encryption cannot be turned on afterwards - copy the backup with "
            "encryption enabled, check the copy, then delete the original.",
            _target(snapshot_id, "unencrypted"),
        ))

    return warnings


def check_snapshots(snapshots):
    """Evaluates several snapshots at once, worst first.

    For an account-wide view, where the question is "is anything exposed" and
    the answer has to arrive already sorted. Every finding names the snapshot
    it came from, so they can be shown together without losing that.
    """
    warnings = []
    for settings in snapshots or []:
        warnings.extend(check_snapshot(settings))

    order = {CRITICAL: 0, WARNING: 1, INFO: 2}
    return sorted(warnings, key=lambda w: order.get(w["level"], 99))
