"""What a role can reach, and who can become it.

Contains pure Python evaluation logic with no external AWS dependencies.

Every other scanner here judges a setting: this port is open, that disk is not
encrypted. This one judges a *route* - given that somebody holds this role,
where can they get to - and that is a different kind of question, because the
danger is rarely in one permission. It is in a pair. `iam:PassRole` grants
nothing on its own and neither does `ec2:RunInstances`; together they let the
holder start a machine carrying a role more powerful than their own and take
its credentials from the metadata service. That is CloudGoat's
`iam_privesc_by_ec2` in one sentence, and the reason this file is about
combinations rather than about actions.

Benchmarking is what produced it. Against 13 CloudGoat scenarios the tool named
the planted vulnerability in three; of the eight it missed, most were a chain
of role to something, and it reported that an instance profile was attached
without ever saying what the role behind it granted. It saw the first link and
none of the corridor. `docs/benchmark.md` has the breakdown.

Two deliberate limits, both of which keep this honest rather than thorough:

Only unconditional Allow statements count. A statement carrying a Condition
might still permit escalation, but deciding whether a given condition closes a
given path means evaluating IAM's policy language against a request context
that does not exist yet, which is a different program. `grants_full_admin` in
`aws/iam.py` already draws the line here and this follows it.

Nothing below is cited except full administrative access, which is CIS 1.15.
CIS has no control covering privilege-escalation paths, and inventing one would
be exactly the fabricated citation `scanner/controls.py` warns about.
"""

from fnmatch import fnmatchcase

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

EVERY_RESOURCE = "*"

# Actions that hand an existing role to something that will run with it. On
# their own they are inert; paired with a way to start that something, they are
# the most common escalation in AWS.
PASS_ROLE = "iam:PassRole"

# Things that can be started carrying a passed role. Each is a real escalation
# path with a CloudGoat scenario behind it.
COMPUTE_THAT_CARRIES_A_ROLE = {
    "ec2:RunInstances": "start a machine",
    "lambda:CreateFunction": "create a function",
    "glue:CreateDevEndpoint": "create a development endpoint",
    "sagemaker:CreateNotebookInstance": "create a notebook",
    "cloudformation:CreateStack": "create a stack",
    "datapipeline:CreatePipeline": "create a pipeline",
}

# Ways to grant yourself more without passing a role anywhere. Each entry is
# (actions that together do it, what the holder ends up able to do).
ESCALATION_PATHS = [
    (
        ("iam:AttachUserPolicy",),
        "attach any policy, including AdministratorAccess, to a user",
    ),
    (
        ("iam:AttachRolePolicy",),
        "attach any policy, including AdministratorAccess, to a role",
    ),
    (
        ("iam:AttachGroupPolicy",),
        "attach any policy, including AdministratorAccess, to a group",
    ),
    (
        ("iam:PutUserPolicy",),
        "write a new policy directly onto a user",
    ),
    (
        ("iam:PutRolePolicy",),
        "write a new policy directly onto a role",
    ),
    (
        ("iam:PutGroupPolicy",),
        "write a new policy directly onto a group",
    ),
    (
        ("iam:CreatePolicyVersion",),
        "rewrite a policy that is already attached to somebody, without "
        "attaching anything",
    ),
    (
        ("iam:SetDefaultPolicyVersion",),
        "roll a policy back to an older version that granted more",
    ),
    (
        ("iam:UpdateAssumeRolePolicy",),
        "change who is allowed to assume a role, including making it "
        "assumable by themselves",
    ),
    (
        ("iam:CreateAccessKey",),
        "create a permanent access key for another user and use it as them",
    ),
    (
        ("iam:CreateLoginProfile",),
        "set a console password on a user who had none and sign in as them",
    ),
    (
        ("iam:UpdateLoginProfile",),
        "change another user's console password and sign in as them",
    ),
    (
        ("iam:AddUserToGroup",),
        "add themselves to a group that has more permissions",
    ),
]

# Reading everything is its own finding, reported by iam_rules for policies.
# Repeated here because a role is where it usually sits.
IAM_ENUMERATION_WILDCARDS = ("iam:*", "iam:get*", "iam:list*")

# Wildcards that read the account's data rather than its identities.
DATA_READ_WILDCARDS = ("s3:*", "s3:get*", "s3:list*")


def _target(role_name, setting):
    return {
        "rule_id": f"{role_name}:{setting}",
        "resource_id": role_name,
        "setting": setting,
    }


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _allow_statements(document):
    """Unconditional Allow statements from one policy document.

    NotAction is skipped rather than inverted. A NotAction statement can be
    equivalent to a very broad Allow, and working out which requires knowing
    every action AWS has - a list that changes weekly and that being wrong
    about produces confident nonsense.
    """
    if not isinstance(document, dict):
        return []

    out = []
    for statement in _as_list(document.get("Statement")):
        if not isinstance(statement, dict):
            continue
        if statement.get("Effect") != "Allow" or statement.get("Condition"):
            continue
        if statement.get("NotAction") or statement.get("NotResource"):
            continue
        out.append(statement)
    return out


def _permits(statements, wanted_action):
    """Whether these statements allow an action on every resource.

    Matching is by IAM's own wildcard rules, so `iam:*` permits
    `iam:PassRole` and `*` permits everything. Resource is required to be `*`:
    a policy that can pass one named role is a deliberate arrangement, and
    treating it the same as one that can pass any role would flag most
    correctly-built infrastructure.
    """
    wanted = wanted_action.lower()

    for statement in statements:
        if EVERY_RESOURCE not in _as_list(statement.get("Resource")):
            continue
        for action in _as_list(statement.get("Action")):
            if fnmatchcase(wanted, str(action).lower()):
                return True
    return False


def _granted_actions(policies):
    """Every unconditional Allow statement across every readable policy.

    Flattened deliberately. What a role can reach is the union of what its
    policies permit, and an escalation built from one action in an inline
    policy and another in an attached one is exactly as effective as one built
    from a single statement.
    """
    statements = []
    for policy in policies or []:
        statements.extend(_allow_statements(policy.get("document")))
    return statements


def check_role(settings):
    """Evaluates one role and returns detected risks.

    Expects the shape produced by aws.roles.read_role_for_scanning().
    """
    if not settings:
        return []

    name = settings.get("role_name", "this role")
    unreadable = settings.get("unreadable") or {}
    warnings = []

    for check, permission in unreadable.items():
        warnings.append(_warning(
            WARNING,
            f"Could not read {check} for {name}: the login this tool uses was "
            f"refused {permission}. Nothing below covers that part, so an "
            "absence of findings here is not a clean result.",
            _target(name, f"unreadable_{check}"),
        ))

    policies = settings.get("policies")
    if policies is not None:
        unread = [p["name"] for p in policies if p.get("document") is None]
        if unread:
            warnings.append(_warning(
                WARNING,
                f"{name} has {len(unread)} policy document(s) this tool could "
                f"not read ({', '.join(unread)}), so what they permit is "
                "unknown. They are not counted as harmless below.",
                _target(name, "unreadable_policy_documents"),
            ))

    warnings.extend(_check_what_it_grants(settings, name))
    warnings.extend(_check_who_can_assume(settings, name))

    return warnings


# --------------------------------------------------------- What it can reach


def _check_what_it_grants(settings, name):
    policies = settings.get("policies")
    if not policies:
        return []

    statements = _granted_actions(policies)
    if not statements:
        return []

    warnings = []
    reachable = _where_it_can_be_reached_from(settings)

    # ---- Full administrative access. CIS 1.15 -------------------------------
    if _permits(statements, "*"):
        warnings.append(_warning(
            CRITICAL,
            f"{name} can do anything in this account. {reachable} Anyone who "
            "obtains it can grant themselves more, read everything, and delete "
            "the record of having done so. A role like this should exist only "
            "if a person deliberately decided it should, and should be "
            "assumable by as few things as possible.",
            _target(name, "full_admin"),
            control="NO_FULL_ADMIN_POLICY",
        ))
        # Everything below is implied by full admin. Listing the individual
        # escalation paths as well would report the same fact fourteen times
        # and bury the one line that matters.
        return warnings

    # ---- Passing a role to something that will run with it ------------------
    if _permits(statements, PASS_ROLE):
        launchers = [what for action, what
                     in COMPUTE_THAT_CARRIES_A_ROLE.items()
                     if _permits(statements, action)]

        if launchers:
            warnings.append(_warning(
                CRITICAL,
                f"{name} can hand any role in this account to something it "
                f"starts, and can {launchers[0]}. {reachable} That is a way "
                "up: pick the most powerful role in the account, start "
                "something carrying it, and take its credentials from the "
                "inside. Nothing about the role itself looks wrong, which is "
                "why this is worth saying out loud.",
                _target(name, "pass_role_to_compute"),
            ))
        else:
            warnings.append(_warning(
                WARNING,
                f"{name} can hand any role in this account to a service. "
                f"{reachable} On its own that grants nothing, but paired with "
                "permission to start almost anything it becomes a way to "
                "acquire a more powerful role. Limit which roles it may pass.",
                _target(name, "pass_any_role"),
            ))

    # ---- Granting itself more, directly -------------------------------------
    for actions, consequence in ESCALATION_PATHS:
        if all(_permits(statements, a) for a in actions):
            warnings.append(_warning(
                CRITICAL,
                f"{name} can {consequence}. {reachable} This is a way for "
                "whoever holds it to end up with more than they were given, "
                "without anything looking unusual: the permission itself is "
                "ordinary administration, and the escalation is what it "
                "allows rather than what it is.",
                _target(name, f"escalation_{actions[0].split(':')[1].lower()}"),
            ))

    # ---- Reading every identity ---------------------------------------------
    if any(_permits(statements, w) for w in IAM_ENUMERATION_WILDCARDS):
        warnings.append(_warning(
            WARNING,
            f"{name} can read every user, role and policy in this account. "
            f"{reachable} That is how somebody who has got in works out where "
            "to go next, and it leaves almost no trace because it is all "
            "reads. A policy that names the reads it needs individually is "
            "fine; a wildcard is not.",
            _target(name, "reads_every_identity"),
        ))

    # ---- Reading all the data ------------------------------------------------
    if any(_permits(statements, w) for w in DATA_READ_WILDCARDS):
        warnings.append(_warning(
            WARNING,
            f"{name} can read every storage bucket in this account. "
            f"{reachable} If this role is meant to work with one bucket, name "
            "it: the difference between one bucket and all of them is the "
            "difference between a contained mistake and an account-wide one.",
            _target(name, "reads_every_bucket"),
        ))

    return warnings


def _where_it_can_be_reached_from(settings):
    """A sentence about how somebody would come to be holding this role.

    Present in every finding above rather than reported once on its own,
    because "this role can become administrator" and "this role can become
    administrator and is sitting on a machine that answers HTTP requests" are
    not the same finding, and a reader who sees them in two places has to join
    them up themselves.
    """
    machines = settings.get("machines")
    profiles = settings.get("instance_profiles") or []

    if machines:
        count = len(machines)
        return (f"It is attached to {count} running "
                f"{'machine' if count == 1 else 'machines'} "
                f"({', '.join(machines[:3])}"
                f"{', and others' if count > 3 else ''}), and anything that can "
                "make that machine fetch a URL can read its credentials from "
                "the metadata service.")

    if machines is None and profiles:
        return ("It can be attached to machines, and this tool could not check "
                "whether any currently hold it.")

    if profiles:
        return ("It is set up to be attached to machines, so anything running "
                "on one would hold it.")

    return ""


# -------------------------------------------------------- Who can become it


def _check_who_can_assume(settings, name):
    """The trust policy: the door rather than the corridor."""
    trust = settings.get("trust_policy")
    if not isinstance(trust, dict):
        return []

    warnings = []
    this_account = settings.get("account_id")

    for statement in _allow_statements(trust):
        principals = statement.get("Principal")
        if not isinstance(principals, dict):
            if principals == EVERY_RESOURCE:
                warnings.append(_anyone_can_assume(name))
            continue

        aws = [str(p) for p in _as_list(principals.get("AWS"))]

        if EVERY_RESOURCE in aws:
            warnings.append(_anyone_can_assume(name))
            continue

        for principal in aws:
            other = _foreign_account(principal, this_account)
            if other:
                warnings.append(_warning(
                    WARNING,
                    f"{name} can be assumed by AWS account {other}, which is "
                    "not this one. That may be exactly right - it is how "
                    "third-party tools are given access - but it is a door "
                    "into this account that does not belong to anybody here, "
                    "and it should be one somebody chose. A trust like this "
                    "is usually meant to carry an external ID as well, so a "
                    "third party cannot be talked into using it on somebody "
                    "else's behalf.",
                    _target(name, f"trusted_account_{other}"),
                ))

    return warnings


def _anyone_can_assume(name):
    return _warning(
        CRITICAL,
        f"{name} can be assumed by anyone with any AWS account. That is not a "
        "misconfiguration of degree - it is the role being available to the "
        "entire internet, and whatever it grants is granted to whoever asks. "
        "Name the accounts or services that should be able to assume it.",
        _target(name, "assumable_by_anyone"),
    )


def _foreign_account(principal, this_account):
    """The account number in a principal ARN, if it is not this account."""
    if not this_account or ":" not in principal:
        return None
    parts = principal.split(":")
    if len(parts) < 5:
        return None
    account = parts[4]
    if account and account != this_account and account.isdigit():
        return account
    return None
