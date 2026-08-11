"""Security rules for evaluating Azure key vaults.

Contains pure Python evaluation logic with no external cloud dependencies.

Ported from `check_key_vault_governance` and the two `AZURE_KEY_VAULT_*`
entries in `security_messages.py` on `group/feature/key-vault`, which were
correct and returned a shape aimed at being rendered on its own. The rewrite is
not a criticism of them: two scanners returning two shapes is fine until
something has to count both, and `api/app.py` counts. Their wording is kept
where it was already right.

**A vault is judged differently from everything else here, and deliberately.**
Every other rule in this package asks who can reach a thing. These ask two
questions instead - can what is in here be destroyed beyond recovery, and can
anybody tell who holds access - because that is where the danger actually is.
A vault holds the keys other resources' data is encrypted with, so destroying
one can destroy data that was never in it, and access granted by a vault's own
policy list appears in no role audit anywhere in the subscription.

Nothing here carries a CIS citation, for the reason `scanner/controls.py`
gives: CIS AWS Foundations is an AWS benchmark, the CIS Microsoft Azure
Foundations Benchmark is a separate document nobody here has read, and
inventing IDs from it would be the fabricated citation that file warns about.
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


def _target(vault_name, setting):
    return {
        "rule_id": f"{vault_name}:{setting}",
        "resource_id": vault_name,
        "setting": setting,
    }


def check_key_vault(settings):
    """Evaluates one key vault and returns detected risks.

    Expects the shape produced by az.keyvault.read_vault_for_scanning():
        {
          "vault_name": str,
          "soft_delete_enabled": bool | None,
          "purge_protection_enabled": bool | None,
          "rbac_authorization": bool | None,
          "soft_delete_retention_days": int | None,
          "access_policy_count": int,
          "public_network_access": str | None,
          "network_default_action": str | None,
          "unreadable": {setting: reason},
        }
    """
    if not settings:
        return []

    name = settings.get("vault_name", "this key vault")
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

    # ---- Whether a deletion can be undone ------------------------------------
    #
    # Critical rather than a warning, and it is the one finding here that is
    # about the vault ceasing to exist rather than about who can open it. A
    # vault without soft delete is one mistyped command away from taking every
    # key in it permanently, and the data those keys unlock goes with them.
    #
    # Azure made soft delete mandatory in 2020 and no longer permits a vault
    # without it, so this cannot fire on anything created since. It stays for
    # the same reason the two S3 rules that AWS closed off stay: older vaults
    # exist, they are exactly the ones nobody has looked at in years, and a
    # rule that silently stopped being checked would be worse than one that
    # rarely fires.
    if "soft_delete_enabled" not in unreadable:
        if settings.get("soft_delete_enabled") is False:
            warnings.append(_warning(
                CRITICAL,
                f"Deleting '{name}' would destroy everything in it "
                "immediately, with no way back. That includes the keys other "
                "services use to encrypt their own data, so the damage is not "
                "limited to this vault - anything encrypted with a key stored "
                "here becomes unreadable too. Azure has required recoverable "
                "deletion on new vaults since 2020, so this vault predates "
                "that and has never been changed.",
                _target(name, "no_soft_delete"),
            ))

    # ---- Whether somebody can force the deletion through anyway --------------
    #
    # A warning rather than critical: recovery still exists, and purging takes
    # a specific permission that ordinary access does not carry. It is real
    # because the retention window is precisely when somebody who wanted this
    # gone would act, and because the usual reason it is off is that nobody
    # wanted to accept a setting they can never reverse - which is a decision
    # worth surfacing rather than a mistake worth scolding.
    if "purge_protection_enabled" not in unreadable:
        if settings.get("purge_protection_enabled") is not True:
            days = settings.get("soft_delete_retention_days")
            window = f"{days} days" if days else "the retention period"
            warnings.append(_warning(
                WARNING,
                f"A deleted '{name}' can be permanently destroyed during "
                f"{window} rather than waiting to be recoverable. Recovery is "
                "the thing standing between a mistake and permanent loss, and "
                "this leaves a door open in exactly the window where somebody "
                "who wanted the vault gone would use it. Turning purge "
                "protection on is a one-way decision - it can never be "
                "switched off again - which is the honest reason it is often "
                "left like this.",
                _target(name, "no_purge_protection"),
            ))

    # ---- Whether anyone can tell who holds access ---------------------------
    #
    # The finding this file exists for, and the one with no counterpart in the
    # ported original. Access granted by a vault's own policy list is invisible
    # to every role and policy scan in this tool and in the portal's own access
    # review - `scanner/role_rules.py` can read an identity's entire permission
    # set and still not know it can open this vault. That is the same shape as
    # `grants_account_wide_iam_read`: not a way in by itself, but the thing
    # that makes a way in impossible to see.
    if settings.get("rbac_authorization") is not True:
        held_by = settings.get("access_policy_count") or 0
        if held_by:
            warnings.append(_warning(
                WARNING,
                f"Access to '{name}' is granted by the vault's own list rather "
                f"than by roles, and {held_by} "
                f"{'identity holds' if held_by == 1 else 'identities hold'} "
                "access that way. Nothing outside this vault can see that: an "
                "audit of who can do what in this subscription will read every "
                "role and still not report a single one of them. Switching to "
                "role-based access makes the same permissions visible to the "
                "same review as everything else - but it revokes every entry "
                "on the existing list the moment it takes effect, so read the "
                "list first.",
                _target(name, "access_policies_not_roles"),
            ))
        else:
            warnings.append(_warning(
                INFO,
                f"'{name}' uses its own access list rather than roles, and "
                "nothing is on it. Nobody can open this vault, which is "
                "harmless now and is the state somebody is about to fix by "
                "adding an entry that no permission audit will ever show.",
                _target(name, "access_policies_empty"),
            ))

    # ---- Reachable from anywhere --------------------------------------------
    #
    # A note rather than a fault, in the same words and for the same reason as
    # the storage rule: it is Azure's default, the credentials still have to be
    # right, and restricting it removes a class of attempt before
    # authentication is involved at all.
    access = str(settings.get("public_network_access") or "").lower()
    default_action = str(settings.get("network_default_action") or "").lower()
    if access == "enabled" or default_action == "allow":
        warnings.append(_warning(
            INFO,
            f"'{name}' can be reached from any network. That is the default "
            "and is not a fault by itself - a caller still has to hold "
            "permission - but restricting it to your own network means a "
            "stolen credential is not enough on its own.",
            _target(name, "reachable_from_anywhere"),
        ))

    return warnings


def check_key_vault_spec(spec):
    """Scans the settings a vault would have if created this way.

    Builds the shape the reader would produce, so the warnings somebody sees
    before creating match the ones they see afterwards.

    Soft delete is True on both sides of the switch because Azure will not
    create a vault without it, and `create_vault` states it as True regardless.
    Reporting the deliberately-weak option as having recoverable deletion off
    would be describing a vault Azure would refuse to build.
    """
    if not spec:
        return []

    secure = spec.get("secure_by_default", True)
    return check_key_vault({
        "vault_name": spec.get("name") or "this key vault",
        "soft_delete_enabled": True,
        "purge_protection_enabled": secure,
        "rbac_authorization": secure,
        "soft_delete_retention_days": 90 if secure else 7,
        # A vault being made now has nobody on its access list yet, whichever
        # way it authorizes.
        "access_policy_count": 0,
        "public_network_access": "Enabled",
        "network_default_action": None,
        "unreadable": {},
    })
