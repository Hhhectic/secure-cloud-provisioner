"""Whether a set of policies lets its holder end up with more than it was given.

Contains pure Python evaluation logic with no external AWS dependencies.

This started inside `role_rules.py`, because the benchmark that produced it
said "role to something" and roles were what got built first. Re-running one
CloudGoat scenario afterwards showed the other half: in `iam_privesc_by_ec2`
the tool named the `AdministratorAccess` role sitting on a machine and said
nothing about the *user* who could put it there, because the escalation
permissions were on the user and nothing looked at those. The chain has two
ends and this file is the part both share.

Nothing here knows what an identity is. It takes policy statements and answers
questions about them, so a user, a role, and a group whose members inherit its
permissions are all the same question asked three times.

Two deliberate limits, which keep this honest rather than thorough:

Only unconditional Allow statements count. A statement carrying a Condition
might still permit the escalation, but deciding whether a given condition
closes a given path means evaluating IAM's policy language against a request
context that does not exist yet. `grants_full_admin` in `aws/iam.py` drew that
line first and this follows it. One consequence is visible in CloudGoat's own
`iam_privesc_by_ec2`: its `cg_ec2_management_role` carries a `StringNotEquals`
condition and is correctly not reported, because with the condition in force it
is not the escalation.

NotAction is skipped rather than inverted. A NotAction statement can be
equivalent to a very broad Allow, and working out which needs every action AWS
has - a list that changes weekly, and being wrong about it produces confident
nonsense.
"""

from fnmatch import fnmatchcase

EVERY_RESOURCE = "*"

# Handing an existing role to something that will run with it. Inert alone;
# paired with a way to start that something, it is the most common escalation
# in AWS and the one CloudGoat teaches first.
PASS_ROLE = "iam:PassRole"

# Things that can be started carrying a passed role.
COMPUTE_THAT_CARRIES_A_ROLE = {
    "ec2:RunInstances": "start a machine",
    "lambda:CreateFunction": "create a function",
    "glue:CreateDevEndpoint": "create a development endpoint",
    "sagemaker:CreateNotebookInstance": "create a notebook",
    "cloudformation:CreateStack": "create a stack",
    "datapipeline:CreatePipeline": "create a pipeline",
}

# Ways to acquire more without passing a role anywhere. Each is (the actions
# that together do it, what the holder ends up able to do).
ESCALATION_PATHS = [
    (("iam:AttachUserPolicy",),
     "attach any policy, including AdministratorAccess, to a user"),
    (("iam:AttachRolePolicy",),
     "attach any policy, including AdministratorAccess, to a role"),
    (("iam:AttachGroupPolicy",),
     "attach any policy, including AdministratorAccess, to a group"),
    (("iam:PutUserPolicy",), "write a new policy directly onto a user"),
    (("iam:PutRolePolicy",), "write a new policy directly onto a role"),
    (("iam:PutGroupPolicy",), "write a new policy directly onto a group"),
    (("iam:CreatePolicyVersion",),
     "rewrite a policy that is already attached to somebody, without "
     "attaching anything"),
    (("iam:SetDefaultPolicyVersion",),
     "roll a policy back to an older version that granted more"),
    (("iam:UpdateAssumeRolePolicy",),
     "change who is allowed to assume a role, including making it assumable "
     "by themselves"),
    (("iam:CreateAccessKey",),
     "create a permanent access key for another user and use it as them"),
    (("iam:CreateLoginProfile",),
     "set a console password on a user who had none and sign in as them"),
    (("iam:UpdateLoginProfile",),
     "change another user's console password and sign in as them"),
    (("iam:AddUserToGroup",),
     "add themselves to a group that has more permissions"),
]

# Wildcards that read the account's identities, or its data.
IAM_ENUMERATION_WILDCARDS = ("iam:*", "iam:get*", "iam:list*")
DATA_READ_WILDCARDS = ("s3:*", "s3:get*", "s3:list*")


def as_list(value):
    """Policy documents write a single item either bare or in a list."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def allow_statements(document):
    """Unconditional Allow statements from one policy document."""
    if not isinstance(document, dict):
        return []

    out = []
    for statement in as_list(document.get("Statement")):
        if not isinstance(statement, dict):
            continue
        if statement.get("Effect") != "Allow" or statement.get("Condition"):
            continue
        if statement.get("NotAction") or statement.get("NotResource"):
            continue
        out.append(statement)
    return out


def statements_from(policies):
    """Every unconditional Allow across every readable policy in a list.

    Flattened deliberately. What an identity can reach is the union of what its
    policies permit, and an escalation assembled from one action in an inline
    policy and another in an attached one works exactly as well as one written
    in a single statement. For a user this includes the policies reaching them
    through a group, which is how permissions are supposed to arrive.
    """
    statements = []
    for policy in policies or []:
        statements.extend(allow_statements(policy.get("document")))
    return statements


def _unrestricted(resource):
    """Whether one Resource entry names everything rather than something.

    `*` obviously. Also `arn:aws:iam::123456789012:role/*`, which is every role
    in the account and is how the console writes it - and which this required
    to be a bare `*`, so `iam:PassRole` on a wildcard role ARN reported nothing
    at all. That is not "one named role is a deliberate arrangement", the case
    the rule was written for; it is every role, spelled the ordinary way.

    Two things deliberately left out, both to avoid trading a false negative
    for a false positive:

    A prefix - `role/build-*` - is a family somebody chose the shape of, and
    reporting it would put a finding on a common, reasonable arrangement.

    Only IAM ARNs are read this way. `arn:aws:s3:::mybucket/*` is every object
    in *one* bucket, so treating a trailing `/*` as "everything" everywhere
    would report an ordinary bucket policy as unrestricted access to all data.
    Narrow on purpose: the escalation paths this module matches are IAM ones.
    """
    text = str(resource or "").strip()
    if text == EVERY_RESOURCE:
        return True
    if not text.lower().startswith("arn:aws:iam:"):
        return False
    return text.endswith("/*") or text.endswith(":*")


def permits(statements, wanted_action):
    """Whether these statements allow an action on every resource.

    Matching follows IAM's own wildcard rules, so `iam:*` permits
    `iam:PassRole` and `*` permits everything. What counts as every resource is
    `_unrestricted` above: passing one named role is a deliberate arrangement
    and stays unreported, passing any of them is reported however the ARN is
    written.
    """
    wanted = wanted_action.lower()

    for statement in statements:
        if not any(_unrestricted(r) for r in as_list(statement.get("Resource"))):
            continue
        for action in as_list(statement.get("Action")):
            if fnmatchcase(wanted, str(action).lower()):
                return True
    return False


def grants_everything(statements):
    """Full administrative access: every action on every resource."""
    return permits(statements, "*")


def role_passing_paths(statements):
    """What the holder could start while carrying somebody else's role.

    Empty when it cannot pass a role at all. A holder that can pass a role but
    start nothing is reported separately by the callers, because on its own
    that grants nothing.
    """
    if not permits(statements, PASS_ROLE):
        return None
    return [what for action, what in COMPUTE_THAT_CARRIES_A_ROLE.items()
            if permits(statements, action)]


def direct_escalations(statements):
    """The named ways to acquire more without passing a role.

    Returns (key, consequence) pairs. The key is stable and derived from the
    first action, so a finding keeps the same rule_id across runs.
    """
    found = []
    for actions, consequence in ESCALATION_PATHS:
        if all(permits(statements, a) for a in actions):
            found.append((actions[0].split(":")[1].lower(), consequence))
    return found


def reads_every_identity(statements):
    return any(permits(statements, w) for w in IAM_ENUMERATION_WILDCARDS)


def reads_every_bucket(statements):
    return any(permits(statements, w) for w in DATA_READ_WILDCARDS)
