"""IAM roles: who may become one, and what it can do once they have.

This module exists because of a gap both benchmarks found from opposite ends.
Prowler's `s3_bucket_cross_account_access` asks who can reach into a resource;
CloudGoat's privilege-escalation scenarios ask what an identity can reach out
to. They are the same question about the corridor between two things, and this
tool could previously answer neither: it reported that an instance profile was
attached and never what it granted, so it saw the first link of every chain and
none of the rest.

Unlike `aws/iam.py`, this module makes no judgements at all. It fetches policy
documents and hands them over intact, and `scanner/role_rules.py` decides what
they mean. That split is deliberate and is the one this project's layout asks
for: deciding whether a policy permits privilege escalation is pure reasoning
over a JSON document, and pure reasoning belongs where it can be tested without
an AWS account. `grants_full_admin` living in `aws/iam.py` is the older
arrangement and the weaker one.

Everything here is a read. Roles are audited, never created or changed - a tool
that offered to edit a trust policy on someone's behalf would be offering to
change who can enter the account.
"""

import boto3
from botocore.exceptions import BotoCoreError, ClientError

# Raised here too, so one HTTP handler turns a missing permission into a 403
# for every resource type.
from aws.s3_buckets import PermissionDenied
from aws.iam import client_region

_DENIED = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
           "NotAuthorized"}

_NOT_FOUND = {"NoSuchEntity", "NoSuchEntityException", "ValidationError"}

# Roles AWS creates and controls. They are excluded from listing because an
# account has dozens, nobody chose their contents, and nobody can change them -
# so a finding about one is noise that buries the roles somebody did write.
AWS_SERVICE_ROLE_PATHS = ("/aws-service-role/", "/service-role/")


def get_client(region="us-east-1"):
    """Initializes and returns an IAM client that remembers its region."""
    from aws.iam import get_client as iam_client
    return iam_client(region)


def _denied(e, permission):
    if e.response["Error"]["Code"] in _DENIED:
        raise PermissionDenied(permission, e.response["Error"]["Message"]) from e
    raise


def _is_aws_managed(role):
    """Whether AWS owns this role rather than somebody in the account."""
    path = role.get("Path") or "/"
    return any(path.startswith(p) for p in AWS_SERVICE_ROLE_PATHS)


# ------------------------------------------------------------------------ Read


def list_roles(iam, only_ours=False):
    """Returns the roles somebody in this account wrote.

    only_ours is honoured as "not AWS's own service roles" rather than by tag.
    Nothing here creates roles, so a tag would match nothing; the useful
    distinction is between roles a person chose the contents of and the ones a
    service created for itself.
    """
    try:
        pages = iam.get_paginator("list_roles").paginate()
        found = [r for page in pages for r in page.get("Roles", [])]
    except ClientError as e:
        _denied(e, "iam:ListRoles")

    if only_ours:
        found = [r for r in found if not _is_aws_managed(r)]
    return found


def read_policies_for_role(iam, role_name):
    """Every policy that applies to this role, with its document intact.

    Inline and attached are gathered into one list because the distinction
    matters to whoever maintains the role and not at all to the question this
    module exists to answer. What a role can reach is the union of both.
    """
    policies = []

    try:
        inline_names = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
    except ClientError as e:
        _denied(e, "iam:ListRolePolicies")

    for name in inline_names:
        try:
            document = iam.get_role_policy(
                RoleName=role_name, PolicyName=name)["PolicyDocument"]
        except ClientError as e:
            _denied(e, "iam:GetRolePolicy")
        policies.append({"name": name, "source": "inline", "arn": None,
                         "document": document})

    try:
        attached = iam.list_attached_role_policies(
            RoleName=role_name)["AttachedPolicies"]
    except ClientError as e:
        _denied(e, "iam:ListAttachedRolePolicies")

    for policy in attached:
        document = _managed_policy_document(iam, policy["PolicyArn"])
        policies.append({
            "name": policy["PolicyName"],
            "source": "attached",
            "arn": policy["PolicyArn"],
            "document": document,
        })

    return policies


def _managed_policy_document(iam, policy_arn):
    """The current version of a managed policy, or None if it cannot be read.

    None rather than an empty document: an empty one reads as "grants nothing",
    which is the reassuring answer and would be a lie. The scanner reports a
    policy it could not read rather than scoring it as harmless.
    """
    try:
        version_id = iam.get_policy(PolicyArn=policy_arn)["Policy"][
            "DefaultVersionId"]
        return iam.get_policy_version(
            PolicyArn=policy_arn, VersionId=version_id)["PolicyVersion"]["Document"]
    except ClientError as e:
        if e.response["Error"]["Code"] in _DENIED:
            return None
        if e.response["Error"]["Code"] in _NOT_FOUND:
            return None
        raise


def read_instance_profiles(iam, role_name):
    """The instance profiles this role can be handed out through.

    A role in an instance profile is one the metadata service will give to
    anything running on the machine, which is why CIS 5.7 and this module meet.
    """
    try:
        profiles = iam.list_instance_profiles_for_role(
            RoleName=role_name)["InstanceProfiles"]
    except ClientError as e:
        _denied(e, "iam:ListInstanceProfilesForRole")

    return [p["InstanceProfileName"] for p in profiles]


def read_machines_holding(iam, profile_names):
    """Machines currently running with one of these instance profiles.

    The difference between "this role could be handed to a machine" and "this
    role is on a machine right now", which is the difference between a design
    note and a live exposure. Returns None if it could not be established,
    which the scanner reports as unchecked rather than as none.
    """
    if not profile_names:
        return []

    ec2 = boto3.client("ec2", region_name=client_region(iam))
    holding = []

    try:
        pages = ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "instance-state-name",
                      "Values": ["pending", "running", "stopping", "stopped"]}])
        for page in pages:
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    arn = (instance.get("IamInstanceProfile") or {}).get("Arn", "")
                    if any(arn.endswith(f"/{name}") for name in profile_names):
                        holding.append(instance["InstanceId"])
    except (ClientError, BotoCoreError):
        return None

    return holding


def read_role_for_scanning(iam, role_name):
    """Retrieves one role's settings formatted for scanner processing.

    Returns None when there is no such role. Each read is attempted
    independently and a failure is recorded in "unreadable" rather than
    aborting: a role whose trust policy is readable and whose attached
    policies are not still produces the finding about who can assume it.
    """
    try:
        role = iam.get_role(RoleName=role_name)["Role"]
    except ClientError as e:
        if e.response["Error"]["Code"] in _NOT_FOUND:
            return None
        _denied(e, "iam:GetRole")

    settings = {
        "role_name": role["RoleName"],
        "arn": role.get("Arn"),
        "path": role.get("Path"),
        "description": role.get("Description"),
        "aws_managed": _is_aws_managed(role),
        "trust_policy": role.get("AssumeRolePolicyDocument"),
        "account_id": (role.get("Arn") or "::::").split(":")[4],
    }
    unreadable = {}

    def attempt(name, permission, reader):
        try:
            settings[name] = reader()
        except PermissionDenied as e:
            settings[name] = None
            unreadable[name] = e.permission
        except (ClientError, BotoCoreError):
            settings[name] = None
            unreadable[name] = permission

    attempt("policies", "iam:ListRolePolicies",
            lambda: read_policies_for_role(iam, role_name))
    attempt("instance_profiles", "iam:ListInstanceProfilesForRole",
            lambda: read_instance_profiles(iam, role_name))

    profiles = settings.get("instance_profiles") or []
    attempt("machines", "ec2:DescribeInstances",
            lambda: read_machines_holding(iam, profiles))

    settings["unreadable"] = unreadable
    return settings


def describe_role(settings):
    """What the role is, as opposed to what is wrong with it."""
    if not settings:
        return None

    policies = settings.get("policies") or []
    return {
        "role_name": settings.get("role_name"),
        "arn": settings.get("arn"),
        "description": settings.get("description"),
        "aws_managed": settings.get("aws_managed"),
        "policy_count": len(policies),
        "policy_names": [p["name"] for p in policies],
        "instance_profiles": settings.get("instance_profiles") or [],
        "machines": settings.get("machines"),
        "checks_skipped": sorted(settings.get("unreadable") or {}),
    }


# ------------------------------------------------------------------------- Fix


def apply_fix(iam, role_name, warning):
    """Role findings are never fixed automatically.

    Every remediation here changes who can enter the account or what they can
    do once inside. Detaching a policy from a role breaks whatever was relying
    on it, and narrowing a trust policy can lock out the automation that
    assumes it - neither failure is visible until something stops working, and
    both are worse than the finding.
    """
    return False, (
        "Role findings are reported, not fixed. Changing what a role grants, "
        "or who is allowed to assume it, breaks whatever was relying on the "
        "old answer, and nothing here can tell what that is. Each finding says "
        "what to change and where."
    )
