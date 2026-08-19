"""Security rules engine for evaluating S3 bucket settings.

Contains pure Python evaluation logic with no external AWS dependencies.

A bucket's settings arrive as one flat dict rather than a list of rules, so
each finding synthesises its own rule_id in the form "<bucket>:<setting>".
That keeps the warning contract identical to the firewall scanner: every
fixable warning names exactly one thing the fix endpoint can act on.
"""

from scanner.common import (
    CRITICAL,
    WARNING,
    INFO,
    warning as _warning,
    summarize,
    fixable,
    worst_level,
    print_warnings,
)

PUBLIC_GRANT_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers": "anyone on the internet",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers":
        "anyone with any AWS account",
}


def _target(bucket, setting):
    """Builds the fix target for one bucket setting."""
    return {
        "rule_id": f"{bucket}:{setting}",
        "resource_id": bucket,
        "setting": setting,
    }


SETTING_LABELS = {
    "public_access_block": "whether public access is blocked",
    "encryption": "whether files are encrypted",
    "versioning": "whether old file versions are kept",
    "public_acl_grants": "who has been granted access",
    "policy_is_public": "whether the permissions policy is public",
    "policy_denies_http": "whether unencrypted connections are refused",
    "logging_enabled": "whether access logging is on",
    # These two arrived after the table and were not added to it, so a refused
    # read of either fell back to the key and said "Could not check objects" or
    # "Could not check other_accounts" - the second being an identifier rather
    # than a sentence. Every key in aws/s3_buckets._READERS needs an entry
    # here; test_every_bucket_setting_has_wording asserts it rather than
    # trusting the next person to remember.
    "objects": "how many files there are",
    "other_accounts": "whether other accounts have been granted access",
    "website": "whether it serves a static website",
}


def _how_much_is_inside(settings):
    """A clause saying how much is behind an exposure, or nothing.

    An exposure finding could not previously say how much was exposed, so a
    world-readable empty bucket and a world-readable bucket holding two
    hundred files were reported in identical words. They are not the same
    event: one is a misconfiguration and the other is an incident.

    Returns "" when the contents could not be read, because a clause is
    added to a sentence that is already true and a missing one must not be
    read as "nothing in it". The unreadable list carries that separately, as
    it does for every other setting here.
    """
    if "objects" in (settings.get("unreadable") or {}):
        return ""

    inside = settings.get("objects")
    if not inside:
        return ""

    count = inside.get("count", 0)
    if not count:
        return ", though there is nothing in it at the moment"

    at_least = "at least " if inside.get("at_least") else ""
    thing = "object" if count == 1 else "objects"
    return f", and there {'is' if count == 1 else 'are'} {at_least}{count} {thing} in it"


def check_bucket_settings(settings):
    """Evaluates a bucket settings snapshot and returns detected risks.

    Expects the shape produced by aws.s3_buckets.read_bucket_for_scanning():
        {
          "bucket": str,
          "public_access_block": {BlockPublicAcls, IgnorePublicAcls,
                                  BlockPublicPolicy, RestrictPublicBuckets} | None,
          "encryption": {"enabled": bool, "algorithm": str | None},
          "versioning": {"enabled": bool, "mfa_delete": bool},
          "public_acl_grants": [{"uri": str, "permission": str}],
          "policy_is_public": bool | None,
          "logging_enabled": bool,
          "unreadable": {setting_name: iam_permission_needed},
        }

    Anything listed in "unreadable" is reported as an unchecked setting and then
    skipped. Silence would imply the setting is fine; a normal finding would
    assert something the scan never actually observed.
    """
    # No bucket to describe. Every other scanner here already had this line;
    # this one did not, so asking about a bucket that does not exist raised
    # an AttributeError three layers below the question.
    if not settings:
        return []

    bucket = settings.get("bucket", "unknown")
    unreadable = settings.get("unreadable") or {}
    warnings = []

    for name, permission in unreadable.items():
        label = SETTING_LABELS.get(name, name)
        warnings.append(_warning(
            WARNING,
            f"Could not check {label} on this bucket. The login this tool is "
            f"using is missing the {permission} permission, so this part of the "
            "audit was skipped. It is not a clean result.",
            _target(bucket, f"unreadable_{name}"),
        ))

    # ---- Public access block -------------------------------------------------
    pab = settings.get("public_access_block")

    if "public_access_block" in unreadable:
        pass
    elif not pab:
        warnings.append(_warning(
            CRITICAL,
            "Nothing is stopping this bucket from being made public. Someone "
            "could open it to the whole internet with a single setting change, "
            "and the files inside would be readable by anyone who finds the "
            "address. AWS has switched this protection on for every new bucket "
            "since April 2023, so either this bucket predates that or somebody "
            "turned it off deliberately. Both are worth understanding before "
            "you change it back.",
            _target(bucket, "public_access_block"),
            fix={
                "action": "block_public_access",
                "label": "Block all public access to this bucket",
            },
            control="S3_BLOCK_PUBLIC_ACCESS",
        ))
    else:
        missing = [k for k in (
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        ) if not pab.get(k)]

        if len(missing) == 4:
            # All four off is not "partly protected". AWS turns these on for
            # every new bucket, so all four being off means somebody turned
            # them off, which is a deliberate act rather than an oversight.
            warnings.append(_warning(
                CRITICAL,
                "Every one of the four protections against this bucket being "
                "made public is switched off. AWS turns them all on for new "
                "buckets, so somebody disabled these deliberately. Nothing is "
                "public yet, but any policy or permission change could expose "
                "the contents to anyone on the internet.",
                _target(bucket, "public_access_block"),
                fix={
                    "action": "block_public_access",
                    "label": "Turn all four public access blocks back on",
                },
                control="S3_BLOCK_PUBLIC_ACCESS",
            ))
        elif missing:
            warnings.append(_warning(
                CRITICAL,
                "This bucket is only partly protected from being made public. "
                f"{len(missing)} of the 4 safety switches are off, which leaves "
                "a path for the files inside to be exposed to the internet.",
                _target(bucket, "public_access_block"),
                fix={
                    "action": "block_public_access",
                    "label": "Turn on all four public access blocks",
                },
                control="S3_BLOCK_PUBLIC_ACCESS",
            ))

    # ---- Live public grants --------------------------------------------------
    for grant in settings.get("public_acl_grants") or []:
        who = PUBLIC_GRANT_URIS.get(grant.get("uri"), "a broad group of people")
        permission = grant.get("permission", "access")
        warnings.append(_warning(
            CRITICAL,
            f"This bucket currently grants {permission} to {who}. This is not a "
            "risk of exposure. It is exposure, right now.",
            _target(bucket, "public_acl"),
            fix={
                "action": "block_public_access",
                "label": "Revoke public access immediately",
            },
        ))

    if settings.get("policy_is_public"):
        warnings.append(_warning(
            CRITICAL,
            "The permissions policy attached to this bucket makes it public. "
            "Anyone who knows the address can reach the files inside"
            + _how_much_is_inside(settings) + ".",
            _target(bucket, "public_policy"),
            fix={
                "action": "block_public_access",
                "label": "Block the public policy",
            },
        ))

    # ---- Who else was let in on purpose --------------------------------------
    #
    # The gap Prowler covers as s3_bucket_cross_account_access, and the only
    # rule here that asks who can reach *into* a bucket rather than what it
    # exposes outward. It matters because it is invisible from every other
    # angle: an account named in the policy is not public, survives all four
    # public access blocks, does not appear in the console's public/not-public
    # summary, and looks identical to a correctly locked-down bucket.
    #
    # Uncited. CIS has no control for cross-account bucket access, and the
    # recommendation usually quoted at it belongs to a different AWS standard
    # than either of the two cited in this package.
    #
    # WARNING rather than CRITICAL, and this is the judgement in it: naming
    # another account is how legitimate sharing is *supposed* to be done, so
    # this is not a mistake in the way a public bucket is. What makes it worth
    # reporting is that nobody re-reads these, and the accounts stay long after
    # the arrangement ends. An acknowledgement is the right home for one that
    # is meant.
    others = settings.get("other_accounts")

    if "other_accounts" not in unreadable and others:
        named = ", ".join(others)
        how_many = ("one AWS account" if len(others) == 1
                    else f"{len(others)} AWS accounts")
        warnings.append(_warning(
            WARNING,
            f"This bucket's policy lets {how_many} outside this "
            f"one reach it: {named}. That is the correct way to share with a "
            "partner or another team, so it may be exactly right - but it is "
            "not visible as sharing anywhere in the console, and it keeps "
            "working long after whoever arranged it has moved on. Check the "
            "arrangement still holds, and that the permissions granted are "
            "only the ones it needs.",
            _target(bucket, "cross_account_policy"),
        ))

    # ---- Transport security --------------------------------------------------
    if "policy_denies_http" in unreadable:
        pass
    elif not settings.get("policy_denies_http"):
        warnings.append(_warning(
            WARNING,
            "This bucket accepts plain unencrypted connections as well as "
            "secure ones. Anyone positioned between a reader and this bucket "
            "could see the file contents in transit, or alter them. Refusing "
            "unencrypted connections outright closes that off, and normal "
            "access over HTTPS is unaffected.",
            _target(bucket, "deny_http"),
            fix={
                "action": "enforce_https",
                "label": "Refuse unencrypted connections",
            },
            control="S3_DENY_HTTP",
        ))

    # ---- Encryption ----------------------------------------------------------
    #
    # No CIS control covers this. Since 5 January 2023 AWS applies SSE-S3 to
    # every new bucket and the setting cannot be removed, so a genuinely
    # unencrypted bucket should no longer be reachable. The check stays for two
    # reasons: a scanner that trusts a platform guarantee without verifying it
    # is not doing its job, and the AES256-versus-KMS distinction below is still
    # a real choice the platform default does not make for you.
    encryption = settings.get("encryption") or {}
    if "encryption" in unreadable:
        pass
    elif not encryption.get("enabled"):
        warnings.append(_warning(
            CRITICAL,
            "Files in this bucket are not encrypted at rest. AWS has encrypted "
            "every new bucket by default since January 2023, so seeing this at "
            "all is unusual and worth looking into directly.",
            _target(bucket, "encryption"),
            fix={
                "action": "enable_encryption",
                "label": "Turn on encryption (AES-256)",
            },
        ))
    elif encryption.get("algorithm") == "AES256":
        warnings.append(_warning(
            INFO,
            "This bucket uses Amazon's own encryption keys, which is the "
            "default and is fine for most uses. If you need to control who can "
            "decrypt the files, or need a record of every decryption, switch to "
            "a KMS key.",
            _target(bucket, "encryption_kms"),
        ))

    # ---- Versioning ----------------------------------------------------------
    versioning = settings.get("versioning") or {}
    if "versioning" in unreadable:
        pass
    elif not versioning.get("enabled"):
        warnings.append(_warning(
            WARNING,
            "Versioning is off. If a file is overwritten or deleted, whether by "
            "accident or by ransomware, the old copy is gone permanently. "
            "Versioning keeps the previous copies so you can go back.",
            _target(bucket, "versioning"),
            fix={
                "action": "enable_versioning",
                "label": "Turn on versioning",
            },
        ))
    elif not versioning.get("mfa_delete"):
        # Detect only. Enabling MFA delete requires the account root user with
        # an MFA token, which is a credential this tool must never ask for or
        # hold. CIS marks the control Manual for the same reason.
        warnings.append(_warning(
            INFO,
            "Versioning is on, but deleting a version does not require a second "
            "factor. Someone who obtains working credentials could erase the "
            "file history as well as the files. Turning this on has to be done "
            "by hand with the account's root login and an authenticator code, "
            "so this tool reports it rather than offering to fix it.",
            _target(bucket, "mfa_delete"),
            control="S3_MFA_DELETE",
        ))

    # ---- Access logging ------------------------------------------------------
    if "logging_enabled" in unreadable:
        pass
    elif not settings.get("logging_enabled"):
        warnings.append(_warning(
            INFO,
            "Access logging is off, so there is no record of who read or "
            "changed these files. Without it you cannot tell what was taken if "
            "something goes wrong later.",
            _target(bucket, "logging"),
        ))

    return warnings
