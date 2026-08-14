"""Security rules for evaluating Azure storage accounts.

Contains pure Python evaluation logic with no external cloud dependencies.

The counterpart to `scanner/s3_rules.py`, and worth reading beside it. The two
clouds spell the same three questions differently - can the public read this,
is unencrypted transport refused, is anything watching - and the findings here
deliberately use the same words as the S3 ones where the question is the same.
A reader who has learned what "Block Public Access" means in one place should
not have to learn a second vocabulary for the other.

Ported from `check_storage_public_access` and `check_storage_https_only` on
`group/main`, which were correct and returned a shape aimed at being rendered
on its own rather than counted alongside anything else.

The container access level and shared key rules came the same way, from the
Streamlit frontend's `preflight.py` on `streamlit-gui-for-review`. Both ask
something the account-level settings do not: which containers anonymous access
is actually reaching, and whether the account key is still a working
credential.

One difference from S3 is real rather than cosmetic and is called out in the
findings: AWS has blocked public access on every new bucket since April 2023,
so that rule cannot fire on a bucket made today. Azure has no such default -
`allow_blob_public_access` is a switch somebody sets, and it can be on for a
container created this morning.
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

# When an unrotated account key stops being ordinary and starts being worth
# saying out loud. Prowler uses ninety and so does most Azure guidance; it is
# a convention, not a measurement, and the finding says so rather than
# implying something changes on the ninety-first day.
KEY_ROTATION_DAYS = 90


def _target(account_name, setting):
    return {
        "rule_id": f"{account_name}:{setting}",
        "resource_id": account_name,
        "setting": setting,
    }


def check_storage_account(settings):
    """Evaluates one storage account and returns detected risks.

    Expects the shape produced by az.storage.read_account_for_scanning():
        {
          "account_name": str,
          "resource_group": str,
          "location": str,
          "allow_blob_public_access": bool | None,
          "supports_https_traffic_only": bool | None,
          "minimum_tls_version": str | None,
          "public_network_access": str | None,
          "unreadable": {setting: reason},
        }

    Anything in "unreadable" is reported as an unchecked setting and then
    skipped, exactly as `s3_rules` does. Silence would imply the setting is
    fine; a normal finding would assert something the scan never observed.
    """
    if not settings:
        return []

    name = settings.get("account_name", "this storage account")
    unreadable = settings.get("unreadable") or {}
    warnings = []

    for setting, reason in unreadable.items():
        warnings.append(_warning(
            WARNING,
            f"Could not check {setting} on '{name}': {reason}. This part of "
            "the audit did not run, so an absence of findings below is not a "
            "clean result.",
            _target(name, f"unreadable_{setting}"),
        ))

    # ---- Public read access --------------------------------------------------
    if "allow_blob_public_access" not in unreadable:
        if settings.get("allow_blob_public_access") is True:
            warnings.append(_warning(
                CRITICAL,
                f"Containers in '{name}' can be opened to anonymous readers. "
                "Anyone who learns or guesses a container's address can read "
                "what is in it, with no sign-in and no record of who they "
                "were. Unlike AWS, which has blocked this by default on new "
                "storage since April 2023, Azure leaves it to whoever created "
                "the account - so this is a switch somebody set, not a "
                "historical accident.",
                _target(name, "public_blob_access"),
                fix={
                    "action": "disable_public_blob_access",
                    "label": "Stop containers being readable anonymously",
                },
            ))

    # ---- Plain HTTP ----------------------------------------------------------
    if "supports_https_traffic_only" not in unreadable:
        if settings.get("supports_https_traffic_only") is False:
            warnings.append(_warning(
                CRITICAL,
                f"'{name}' accepts unencrypted connections. Anything sent to "
                "or from it can be read by whoever carries the traffic - a "
                "network operator, anyone on the same wireless network, "
                "anyone between. That includes the access key used to "
                "authenticate, which is worth more than the file being "
                "fetched.",
                _target(name, "http_allowed"),
                fix={
                    "action": "require_https",
                    "label": "Refuse unencrypted connections",
                },
            ))

    # ---- How old a TLS version is accepted -----------------------------------
    tls = settings.get("minimum_tls_version")
    if tls and tls.upper().replace("_", "") not in ("TLS12", "TLS13"):
        warnings.append(_warning(
            WARNING,
            f"'{name}' still accepts {tls}, which has known weaknesses and is "
            "no longer accepted by most of the industry. Requiring TLS 1.2 "
            "costs nothing unless something very old is still connecting, and "
            "if something very old is still connecting that is worth knowing "
            "on its own.",
            _target(name, "old_tls"),
            fix={
                "action": "require_modern_tls",
                "label": "Require TLS 1.2 or better",
            },
        ))

    # ---- Which containers are actually public --------------------------------
    #
    # Distinct from the account switch above, and worth saying separately. The
    # account setting says whether a container may be opened to anonymous
    # readers; this says which ones are. Somebody who turned the account switch
    # on months ago needs the second answer to know what it currently exposes,
    # and turning the switch back off is only safe once they do.
    if "containers" not in unreadable:
        for container in settings.get("containers") or []:
            level = str(container.get("public_access") or "").lower()
            if level not in ("blob", "container"):
                continue

            listing = (
                " Anyone can also list everything in it, so the addresses do "
                "not have to be guessed."
                if level == "container" else
                " The names have to be known or guessed to fetch them, which "
                "is not a protection."
            )
            warnings.append(_warning(
                CRITICAL,
                f"Container '{container.get('name')}' in '{name}' is served to "
                "anyone on the internet with no sign-in, and nothing records "
                f"who read what.{listing} Whether the account permits this is a "
                "separate setting; this container is using it.",
                _target(name, f"public_container_{container.get('name')}"),
            ))

    # ---- Whether the account key is still a working credential ---------------
    #
    # Not a way in by itself - somebody still has to hold the key - which is
    # why this is a warning rather than critical. It matters because of how the
    # key behaves once it does leak: it never expires, it grants everything,
    # and nothing records which person used it.
    if settings.get("allow_shared_key_access"):
        warnings.append(_warning(
            WARNING,
            f"'{name}' still accepts its account key as a credential. That key "
            "never expires, cannot be scoped down, grants full control of "
            "every container, and identifies nobody - so a leaked key is "
            "indistinguishable from ordinary use in the logs. Keys reach "
            "config files, screenshots and chat messages far more often than "
            "anyone intends. Authorizing with Entra ID identities instead "
            "gives each person their own access, revocable on its own.",
            _target(name, "shared_key_allowed"),
        ))

    # ---- How old the key is, which is a different question from whether it
    # ---- works --------------------------------------------------------------
    #
    # The rule above says the account key is still accepted. This says nobody
    # has changed it. They are worth reporting separately because the remedy
    # differs: one is a switch, the other is a rotation somebody has to
    # schedule and then actually do.
    #
    # Ninety days is Prowler's threshold and the one most Azure guidance
    # repeats. It is a convention rather than a measurement, and it is stated
    # as one - a key at 91 days is not dangerous in a way it was not at 89.
    # What the number is for is making "nobody has ever rotated this" visible
    # before it is measured in years.
    if "key_age_days" not in unreadable:
        age = settings.get("key_age_days")
        if age is not None and age > KEY_ROTATION_DAYS:
            warnings.append(_warning(
                WARNING,
                f"The account keys for '{name}' were created {age} days ago "
                f"and have not been changed since. A key that never rotates "
                "is a password that never expires: everyone who has ever held "
                "it still holds it, including people who have left and laptops "
                "that were replaced. Rotating both keys invalidates every copy "
                "that escaped, which is the only way to take one back.",
                _target(name, "stale_account_key"),
            ))

    # ---- Whether a deleted blob can be got back ------------------------------
    #
    # The only rule here that is not about exposure, and it is here for the
    # reason the key vault rules are: some settings decide whether a mistake
    # can be undone. An accidental delete, a script with a wrong prefix and a
    # ransomware run all look the same to storage, and soft delete is what
    # separates "restore it" from "it is gone".
    #
    # A warning rather than critical because nothing is reachable that should
    # not be. Severity here means exposure, and this is not that.
    # Containers first, because it is the larger loss and the less obvious of
    # the two: deleting a container takes everything inside it, and the blob
    # retention setting people do know about does not cover that at all.
    if "container_soft_delete" not in unreadable:
        if settings.get("container_soft_delete") is False:
            warnings.append(_warning(
                WARNING,
                f"Deleting a container in '{name}' destroys it and everything "
                "in it immediately, with no way back. The setting that keeps "
                "deleted *blobs* recoverable does not cover containers - they "
                "are separate, and this one is off. One mistyped name in a "
                "cleanup script is the whole container.",
                _target(name, "no_container_soft_delete"),
            ))

    if "blob_soft_delete" not in unreadable:
        if settings.get("blob_soft_delete") is False:
            warnings.append(_warning(
                WARNING,
                f"Deleting a blob in '{name}' destroys it immediately, with "
                "no way back. Soft delete keeps deleted blobs for a set "
                "number of days so an accident, a bad script or somebody "
                "else's ransomware can be undone. It is off, which is Azure's "
                "default rather than a decision somebody made.",
                _target(name, "no_blob_soft_delete"),
            ))

    # ---- Reachable from anywhere ---------------------------------------------
    access = str(settings.get("public_network_access") or "").lower()
    if access == "enabled":
        warnings.append(_warning(
            INFO,
            f"'{name}' can be reached from any network. That is the default "
            "and is not a fault by itself - the keys still have to be right - "
            "but restricting it to your own network removes a whole class of "
            "attempt before authentication is even involved.",
            _target(name, "reachable_from_anywhere"),
        ))

    return warnings


def check_storage_spec(spec):
    """Scans the settings a storage account would have if created this way.

    Builds the shape the reader would produce, so the warnings somebody sees
    before creating match the ones they see afterwards.
    """
    if not spec:
        return []

    secure = spec.get("secure_by_default", True)
    return check_storage_account({
        "account_name": spec.get("name") or "this storage account",
        "allow_blob_public_access": not secure,
        "supports_https_traffic_only": secure,
        "minimum_tls_version": "TLS1_2" if secure else "TLS1_0",
        "public_network_access": "Enabled",
        # An account being made now has no containers yet, and Azure permits
        # the account key unless it is turned off. Saying so before creation
        # matches what the reader would report the moment it exists.
        "containers": [],
        "allow_shared_key_access": True,
        "unreadable": {},
    })
