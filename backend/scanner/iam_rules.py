"""Security rules for evaluating an account's IAM configuration.

Contains pure Python evaluation logic with no external AWS dependencies.

Everything else this tool scans is a resource: a bucket, a machine, a network.
These findings are about the account itself, so there is one "resource" and the
things that go wrong belong to people rather than to infrastructure. That
changes what a finding has to say. Nobody is confused about which bucket a
bucket finding is about, but "an access key is 400 days old" is useless without
a name attached, so every per-person finding names the user in its message and
carries it in the rule.

None of these findings is fixable and the reason is in aws/iam.py: every
remediation here is a credential change that can lock a real person out of a
real account, with no undo.

The severity split is deliberate. Critical is reserved for the ways an account
is taken over whole - the root user's own credentials, and a console login
without a second step. Everything else is a warning or a note, because a
scanner that calls twenty things critical has said nothing about any of them.
"""

from scanner.escalation import (
    direct_escalations,
    grants_everything,
    reads_every_identity,
    role_passing_paths,
    statements_from,
)
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

UNUSED_CREDENTIAL_DAYS = 45
KEY_ROTATION_DAYS = 90
RECENT_ROOT_USE_DAYS = 30
MINIMUM_PASSWORD_LENGTH = 14
MINIMUM_PASSWORDS_REMEMBERED = 24

# What each unread check would have told us, in the words the finding uses.
CHECK_LABELS = {
    "summary": "whether the root user has access keys or a second login step",
    "password_policy": "the rules for how strong passwords have to be",
    "users": "who has an account and how they get their permissions",
    "admin_policies": "whether anyone has been granted unrestricted access",
    "enumeration_policies": "whether anyone can read every identity in the "
                            "account",
    "expired_certificates": "whether expired certificates are still stored",
    "analyzer_count": "whether anything watches for resources shared outside "
                      "the account",
    "support_role_exists": "whether anyone can raise a support case",
    "cloudshell_full_access": "who can use the browser-based shell",
    "root_hardware_mfa": "whether the root user's second login step is a "
                         "physical device",
    "credential_report": "passwords, keys and when they were last used",
}


def _target(account_id, setting, user=None):
    """Builds the finding target. The user rides in the rule, not the id.

    resource_id stays the account for every finding, because the account is
    what was scanned and what the caller asked about. A finding that named the
    user there would not resolve to anything the read or fix routes accept.
    """
    rule_id = f"{account_id}:{user}:{setting}" if user \
        else f"{account_id}:{setting}"
    return {
        "rule_id": rule_id,
        "resource_id": account_id,
        "setting": setting,
        "user": user,
    }


def _plural(count, singular, plural=None):
    return singular if count == 1 else (plural or singular + "s")


def check_account(settings):
    """Evaluates one account's IAM posture and returns detected risks.

    Expects the shape produced by aws.iam.read_account_for_scanning().
    """
    if not settings:
        return []

    account = settings.get("account_id", "this account")
    unreadable = settings.get("unreadable") or {}
    warnings = []

    # ---- Checks that did not happen ------------------------------------------
    #
    # First, and as warnings rather than notes. A skipped check is the one place
    # a clean-looking scan can be actively misleading, and the person reading it
    # needs to know before the absence of findings below reassures them.
    for name, permission in unreadable.items():
        label = CHECK_LABELS.get(name, name)
        warnings.append(_warning(
            WARNING,
            f"Could not check {label}. The login this tool is using was "
            f"refused {permission}, so this part of the audit did not run. "
            "A finding did not appear here because nothing was looked at, "
            "which is not the same as nothing being wrong.",
            _target(account, f"unreadable_{name}"),
        ))

    warnings.extend(_check_root(settings, account, unreadable))
    warnings.extend(_check_password_policy(settings, account, unreadable))
    warnings.extend(_check_users(settings, account))
    warnings.extend(_check_account_wide(settings, account))

    return warnings


# ------------------------------------------------------------------- Root user


def _check_root(settings, account, unreadable):
    """The root user's own credentials. CIS 1.3 to 1.6."""
    warnings = []
    summary = settings.get("summary") or {}
    report = settings.get("root_report") or {}

    if "summary" not in unreadable:
        # ---- Root access keys. CIS 1.3 ---------------------------------------
        keys = summary.get("root_access_keys", 0)
        if keys:
            warnings.append(_warning(
                CRITICAL,
                f"The root user has {keys} access "
                f"{_plural(keys, 'key')}. Root can do anything in this "
                "account, including closing it and removing the records of "
                "what happened, and an access key is a long string that works "
                "from anywhere with no second step and no expiry. There is no "
                "task that needs one: anything a program has to do can be done "
                "by a user or a role created for it. Delete "
                f"{'it' if keys == 1 else 'them'}.",
                _target(account, "root_access_key"),
                control="ROOT_ACCESS_KEY",
            ))

        # ---- Root MFA. CIS 1.4 -----------------------------------------------
        if not summary.get("root_mfa_enabled"):
            warnings.append(_warning(
                CRITICAL,
                "Signing in as the root user needs only the email address and "
                "password. Anyone who learns or guesses that password has "
                "complete control of the account from a browser, and root can "
                "undo anything done to stop it. Turn on a second step at "
                "login, so a password on its own is not enough.",
                _target(account, "root_mfa"),
                control="ROOT_MFA",
            ))

    # ---- Hardware MFA. CIS 1.5 ----------------------------------------------
    #
    # Only asked once the second step is known to exist. Reported as a note:
    # this is the difference between good and slightly better, and saying so in
    # the same tone as "root has no protection at all" would flatten both.
    if settings.get("root_hardware_mfa") is False:
        warnings.append(_warning(
            INFO,
            "The root user's second login step is an app on a phone rather "
            "than a separate physical device. That is much better than "
            "nothing. A physical device is better still, because it cannot be "
            "copied off a phone that has been compromised, and the root user "
            "is the one login where that difference is worth the cost.",
            _target(account, "root_hardware_mfa"),
            control="ROOT_HARDWARE_MFA",
        ))

    # ---- Root used recently. CIS 1.6 ----------------------------------------
    #
    # Only from the credential report: the account summary says whether root
    # has credentials, not whether anyone signed in with them.
    used = [d for d in (report.get("password_last_used_days"),
                        *(k.get("last_used_days") for k in
                          report.get("access_keys") or []))
            if d is not None]

    if used and min(used) <= RECENT_ROOT_USE_DAYS:
        days = min(used)
        when = "today" if days == 0 else \
            f"{days} {_plural(days, 'day')} ago"
        warnings.append(_warning(
            WARNING,
            f"The root user was last used {when}. Root should be locked away "
            "after setup and used only for the handful of tasks that genuinely "
            "require it. Day-to-day work done as root cannot be attributed to "
            "a person, cannot be limited to what that person needs, and cannot "
            "be revoked without changing the account's own password.",
            _target(account, "root_recently_used"),
            control="ROOT_DAILY_USE",
        ))

    return warnings


# ------------------------------------------------------------- Password policy


def _check_password_policy(settings, account, unreadable):
    """How strong passwords have to be. CIS 1.7 and 1.8."""
    if "password_policy" in unreadable:
        return []

    policy = settings.get("password_policy")

    if not policy:
        return [_warning(
            WARNING,
            "This account has no password rules of its own, so it accepts "
            "AWS's defaults. Those allow passwords shorter than fourteen "
            "characters and let an old password be set again, both of which "
            "make guessing and credential-stuffing attacks meaningfully "
            "easier. Set a password policy.",
            _target(account, "no_password_policy"),
            control="PASSWORD_LENGTH",
        )]

    warnings = []
    length = policy.get("minimum_length")

    if length is None or length < MINIMUM_PASSWORD_LENGTH:
        warnings.append(_warning(
            WARNING,
            f"Passwords in this account can be as short as {length or 'six'} "
            f"characters. Short passwords fall to an automated guessing attack "
            f"in a practical amount of time; {MINIMUM_PASSWORD_LENGTH} "
            "characters is the length at which that stops being worth "
            "attempting.",
            _target(account, "password_length"),
            control="PASSWORD_LENGTH",
        ))

    remembered = policy.get("passwords_remembered")

    if not remembered or remembered < MINIMUM_PASSWORDS_REMEMBERED:
        warnings.append(_warning(
            WARNING,
            "Someone changing their password here can set one they have used "
            "before, which means a password that has already leaked can come "
            "back into use. Remembering the last "
            f"{MINIMUM_PASSWORDS_REMEMBERED} prevents cycling back to it.",
            _target(account, "password_reuse"),
            control="PASSWORD_REUSE",
        ))

    return warnings


# ----------------------------------------------------------------------- Users


def _check_users(settings, account):
    """Per-person credential findings. CIS 1.9, 1.11, 1.12, 1.13 and 1.14."""
    users = settings.get("users")
    if not users:
        return []

    admin_policy_names = {p["name"] for p in settings.get("admin_policies") or []}
    warnings = []

    for user in users:
        name = user.get("user_name", "an unnamed user")

        # ---- Where this person could get to from here ------------------------
        warnings.extend(_check_escalation(user, name, account))

        # ---- MFA on console logins. CIS 1.9 ----------------------------------
        if user.get("password_enabled") and not user.get("mfa_enabled"):
            warnings.append(_warning(
                CRITICAL,
                f"{name} can sign in to the AWS website with just a password "
                "and no second step. This is the single most common way an "
                "account is taken over: the password is reused from somewhere "
                "that has been breached, or is handed over to a convincing "
                "email, and there is nothing else in the way.",
                _target(account, "user_mfa", user=name),
                control="USER_MFA",
            ))

        # ---- Credentials nobody is using. CIS 1.11 ---------------------------
        warnings.extend(_check_unused(user, name, account))

        # ---- Access keys. CIS 1.12 and 1.13 ----------------------------------
        keys = user.get("access_keys") or []
        active = [k for k in keys if k.get("active")]

        if len(active) > 1:
            warnings.append(_warning(
                WARNING,
                f"{name} has {len(active)} access keys in use at once. Two "
                "working keys means two things to steal and two to remember to "
                "replace, and nobody can tell from the outside whether both are "
                "still needed. The exception is the few minutes during a "
                "planned swap, which is what the second slot is for.",
                _target(account, "multiple_access_keys", user=name),
                control="ONE_ACTIVE_KEY",
            ))

        for key in active:
            age = key.get("age_days")
            if age is not None and age > KEY_ROTATION_DAYS:
                warnings.append(_warning(
                    WARNING,
                    f"An access key belonging to {name} was created {age} days "
                    "ago and has not been replaced since. A key that never "
                    "changes is a password that never expires: every copy ever "
                    "made of it - in a config file, a log, an old laptop, a "
                    "chat message - still works today.",
                    _target(account, f"key_age_{key.get('slot')}", user=name),
                    control="KEY_ROTATION",
                ))

        # ---- Permissions pinned to a person. CIS 1.14 ------------------------
        attached = user.get("attached_policies") or []
        inline = user.get("inline_policies") or []

        if attached or inline:
            granted_admin = admin_policy_names.intersection(attached)
            detail = "unrestricted access to everything in the account" if \
                granted_admin else "permissions"
            warnings.append(_warning(
                WARNING if granted_admin else INFO,
                f"{name} has {detail} granted directly rather than through a "
                "group. Permissions attached to one person have to be found "
                "and changed one person at a time, so they drift: someone "
                "changes role, the group membership is updated, and the "
                "direct grant stays behind. Move these to a group and put "
                f"{name} in it.",
                _target(account, "direct_permissions", user=name),
                control="PERMISSIONS_VIA_GROUPS",
            ))

    return warnings


def _check_escalation(user, name, account):
    """Whether this person could end up with more than they were given.

    The same engine the role scanner uses, pointed at a user. Roles were built
    first because the benchmark said "role to something", and re-running one
    CloudGoat scenario afterwards showed the other end of every chain: in
    `iam_privesc_by_ec2` the tool named the AdministratorAccess role sitting on
    a machine and said nothing about the user who could put it there, because
    the escalation was in that user's inline policy and nothing read it.

    Policies inherited through a group count. Arriving that way is the
    recommended arrangement, so an escalation assembled there is if anything
    more likely than one pinned to a person.
    """
    policies = user.get("policies")
    if not policies:
        return []

    warnings = []

    unread = [p["name"] for p in policies if p.get("document") is None]
    if unread:
        warnings.append(_warning(
            WARNING,
            f"{len(unread)} of the policies reaching {name} could not be read "
            f"({', '.join(unread[:3])}), so what they permit is unknown. They "
            "are not counted as harmless below.",
            _target(account, "unreadable_policies", user=name),
        ))

    statements = statements_from(policies)
    if not statements:
        return warnings

    if grants_everything(statements):
        warnings.append(_warning(
            CRITICAL,
            f"{name} can do anything in this account. Whoever holds these "
            "credentials can grant themselves more, read everything, and "
            "delete the record of having done so. Give a person the "
            "permissions their work needs; the ones nobody uses are the ones "
            "an attacker gets for free.",
            _target(account, "user_full_admin", user=name),
            control="NO_FULL_ADMIN_POLICY",
        ))
        # Full admin implies every path below. Listing them too would report
        # one fact fourteen times.
        return warnings

    launchers = role_passing_paths(statements)
    if launchers:
        warnings.append(_warning(
            CRITICAL,
            f"{name} can hand any role in this account to something they "
            f"start, and can {launchers[0]}. That is a way up: pick the most "
            "powerful role in the account, start something carrying it, and "
            "take its credentials from the inside. Neither permission looks "
            "alarming on its own, which is what makes the pair worth naming.",
            _target(account, "user_pass_role_to_compute", user=name),
        ))
    elif launchers is not None:
        warnings.append(_warning(
            WARNING,
            f"{name} can hand any role in this account to a service. On its "
            "own that grants nothing, but paired with permission to start "
            "almost anything it becomes a way to acquire a more powerful "
            "role. Limit which roles they may pass.",
            _target(account, "user_pass_any_role", user=name),
        ))

    for key, consequence in direct_escalations(statements):
        warnings.append(_warning(
            CRITICAL,
            f"{name} can {consequence}. This is a way for them to end up with "
            "more than they were given, without anything looking unusual: the "
            "permission itself is ordinary administration, and the escalation "
            "is what it allows rather than what it is.",
            _target(account, f"user_escalation_{key}", user=name),
        ))

    if reads_every_identity(statements):
        warnings.append(_warning(
            WARNING,
            f"{name} can read every user, role and policy in this account. "
            "That is how somebody who has got in works out where to go next, "
            "and it leaves almost no trace because it is all reads.",
            _target(account, "user_reads_every_identity", user=name),
        ))

    return warnings


def _check_unused(user, name, account):
    """Credentials that exist and have not been used in a long time. CIS 1.11.

    Split out because "unused" has three separate shapes - a password never
    used, a password not used lately, and a key not used lately - and they read
    as one rule only if each says which it is.
    """
    warnings = []
    created = user.get("created_days")

    if user.get("password_enabled"):
        last_used = user.get("password_last_used_days")

        if last_used is None and created is not None \
                and created > UNUSED_CREDENTIAL_DAYS:
            warnings.append(_warning(
                WARNING,
                f"{name} has been able to sign in to the AWS website for "
                f"{created} days and never has. Either this login was set up "
                "for someone who did not need it, or it was set up for someone "
                "who has gone. Both leave a working password on the account "
                "with nobody watching whether it is used.",
                _target(account, "password_never_used", user=name),
                control="UNUSED_CREDENTIALS",
            ))
        elif last_used is not None and last_used > UNUSED_CREDENTIAL_DAYS:
            warnings.append(_warning(
                WARNING,
                f"{name} last signed in {last_used} days ago but can still "
                "sign in today. A login nobody uses is a login nobody would "
                "notice being used by someone else. Remove the password if "
                "this person no longer needs access.",
                _target(account, "password_unused", user=name),
                control="UNUSED_CREDENTIALS",
            ))

    for key in user.get("access_keys") or []:
        if not key.get("active"):
            continue

        last_used = key.get("last_used_days")
        age = key.get("age_days")
        slot = key.get("slot")

        if last_used is None and age is not None \
                and age > UNUSED_CREDENTIAL_DAYS:
            warnings.append(_warning(
                WARNING,
                f"An access key belonging to {name} was created {age} days ago "
                "and has never been used. It was made for something that did "
                "not happen, and it still works. Delete it.",
                _target(account, f"key_never_used_{slot}", user=name),
                control="UNUSED_CREDENTIALS",
            ))
        elif last_used is not None and last_used > UNUSED_CREDENTIAL_DAYS:
            warnings.append(_warning(
                WARNING,
                f"An access key belonging to {name} was last used "
                f"{last_used} days ago and is still enabled. Whatever it was "
                "for has stopped needing it, but anyone holding a copy can "
                "still use it.",
                _target(account, f"key_unused_{slot}", user=name),
                control="UNUSED_CREDENTIALS",
            ))

    return warnings


# ---------------------------------------------------------------- Account-wide


def _check_account_wide(settings, account):
    """Findings about the account's arrangements rather than a person.

    CIS 1.15, 1.16, 1.18, 1.19 and 1.21.
    """
    warnings = []

    # ---- Reading every identity in the account. Uncited ----------------------
    #
    # Not a CIS control, and not full admin either, which is why it is
    # separate from 1.15 below. Found by deploying CloudGoat's
    # iam_enum_basics against a real account: the scenario turns on a user
    # holding IAMReadOnlyAccess, this tool said nothing about it, and being
    # able to read every user, role and policy is how somebody works out
    # where the way up is. It leaves no trace worth the name, because it is
    # all reads.
    for policy in settings.get("enumeration_policies") or []:
        holders = policy.get("attached_count", 0)
        warnings.append(_warning(
            WARNING,
            f"'{policy['name']}' lets its holder read every user, role and "
            f"permission set in this account, and {holders} "
            f"{_plural(holders, 'identity', 'identities')} "
            f"{_plural(holders, 'has', 'have')} it. That is less than full "
            "control and it is the first thing somebody does with a stolen "
            "credential: reading the whole arrangement shows them which "
            "account to take next, and asking questions leaves nothing behind "
            "to notice. An auditor may need this, in which case say so; a "
            "program almost never does.",
            _target(account, f"enumeration_{policy['name']}"),
        ))

    # ---- Unrestricted access granted to anyone. CIS 1.15 ---------------------
    for policy in settings.get("admin_policies") or []:
        holders = policy.get("attached_count", 0)
        warnings.append(_warning(
            WARNING,
            f"The permission set '{policy['name']}' allows every action on "
            f"every resource, and {holders} "
            f"{_plural(holders, 'identity', 'identities')} "
            f"{_plural(holders, 'has', 'have')} it. Anyone holding this can do "
            "anything in the account, including granting themselves more and "
            "deleting the record of it. Grant the permissions actually needed "
            "instead; the ones nobody uses are the ones an attacker gets for "
            "free.",
            _target(account, f"full_admin_policy_{policy['name']}"),
            control="NO_FULL_ADMIN_POLICY",
        ))

    # ---- Somebody who can raise a support case. CIS 1.16 --------------------
    if settings.get("support_role_exists") is False:
        warnings.append(_warning(
            INFO,
            "Nobody in this account has been given permission to open a "
            "support case with AWS. During an incident that permission is "
            "needed at the moment it is hardest to arrange, and the person "
            "who can grant it may be the person whose access has just been "
            "lost. Grant it to someone in advance.",
            _target(account, "support_role"),
            control="SUPPORT_ROLE",
        ))

    # ---- Expired certificates. CIS 1.18 -------------------------------------
    for cert in settings.get("expired_certificates") or []:
        warnings.append(_warning(
            WARNING,
            f"The certificate '{cert['name']}' expired {cert['expired_days']} "
            "days ago and is still stored in this account. An expired "
            "certificate cannot secure anything, so if something is still "
            "pointed at it, that thing is either broken or showing visitors a "
            "warning. Leaving it also invites it to be attached to something "
            "new by mistake.",
            _target(account, f"expired_certificate_{cert['name']}"),
            control="EXPIRED_CERTIFICATES",
        ))

    # ---- Watching for things shared outside the account. CIS 1.19 -----------
    if settings.get("analyzer_count") == 0:
        region = settings.get("region", "this region")
        warnings.append(_warning(
            INFO,
            f"Nothing in {region} is watching for resources that have been "
            "shared outside this account. Access Analyzer reports storage, "
            "keys and roles reachable by other accounts or by the public, "
            "which is the class of mistake nobody discovers by looking. It is "
            "free. Note that this tool checked one region, and the "
            "recommendation is to enable it in all of them.",
            _target(account, "access_analyzer"),
            control="ACCESS_ANALYZER",
        ))

    # ---- The browser shell. CIS 1.21 ----------------------------------------
    if settings.get("cloudshell_full_access") is True:
        warnings.append(_warning(
            INFO,
            "Someone here has full access to AWS CloudShell, a terminal that "
            "runs inside the AWS website. It is genuinely useful, and it is "
            "also a way to move files out of the account that does not look "
            "like the ways people usually watch for. Give it only to those who "
            "need it.",
            _target(account, "cloudshell_full_access"),
            control="CLOUDSHELL_FULL_ACCESS",
        ))

    return warnings
