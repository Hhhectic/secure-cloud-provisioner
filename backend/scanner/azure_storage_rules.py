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
        "unreadable": {},
    })
