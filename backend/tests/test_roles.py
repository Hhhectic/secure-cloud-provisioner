"""Tests for role reachability.

The cases below are not invented. They are the shapes of the CloudGoat
scenarios this tool failed to detect, written out as the policy documents that
produced them, so a regression here is a regression against a measured result
rather than against somebody's idea of what a bad policy looks like.
`docs/benchmark.md` records the run: 13 scenarios, the planted vulnerability
named in three.

Each test named for a scenario asserts the thing the tool previously missed -
not merely that some finding fired, because the old behaviour was that findings
fired. `iam_privesc_by_attachment` produced IMDSv1 and an unencrypted disk,
both true and neither the point.
"""

import json

import boto3
import pytest
from moto import mock_aws

from api import registry
from aws import roles
from scanner.common import CRITICAL, WARNING, INFO, cited, fixable
from scanner.role_rules import check_role

REGION = "us-east-1"
ACCOUNT = "123456789012"
OTHER_ACCOUNT = "999988887777"

EC2_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow",
                   "Principal": {"Service": "ec2.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}


@pytest.fixture
def iam():
    with mock_aws():
        yield roles.get_client(REGION)


def _policy(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def _allow(actions, resource="*", **extra):
    statement = {"Effect": "Allow", "Action": actions, "Resource": resource}
    statement.update(extra)
    return statement


def _settings(*documents, **overrides):
    base = {
        "role_name": "app-role",
        "arn": f"arn:aws:iam::{ACCOUNT}:role/app-role",
        "account_id": ACCOUNT,
        "aws_managed": False,
        "trust_policy": EC2_TRUST,
        "policies": [{"name": f"p{i}", "source": "inline", "arn": None,
                      "document": d} for i, d in enumerate(documents)],
        "instance_profiles": [],
        "machines": [],
        "unreadable": {},
    }
    base.update(overrides)
    return base


def _settings_of(warnings):
    return {w["rule"]["setting"] for w in warnings}


def _find(warnings, setting):
    matches = [w for w in warnings if w["rule"]["setting"] == setting]
    assert len(matches) == 1, f"expected one {setting}, got {len(matches)}"
    return matches[0]


# ============================================ The scenarios that defeated it


def test_iam_privesc_by_ec2_is_named_rather_than_its_flow_logs():
    """Pass a role to EC2 and inherit it. The tool previously reported flow
    logs and a subnet setting - both true, neither the escalation."""
    found = _find(check_role(_settings(_policy(
        _allow(["iam:PassRole", "ec2:RunInstances"])))),
        "pass_role_to_compute")

    assert found["level"] == CRITICAL
    assert "start a machine" in found["message"]


def test_iam_privesc_by_attachment_is_named_rather_than_imdsv1():
    """A role that can attach a policy to a role and then assume it. The tool
    previously reported IMDSv1 and an unencrypted disk on the instance."""
    found = _find(check_role(_settings(_policy(
        _allow(["iam:AttachRolePolicy", "sts:AssumeRole"])))),
        "escalation_attachrolepolicy")

    assert found["level"] == CRITICAL
    assert "AdministratorAccess" in found["message"]


def test_lambda_privesc_is_named():
    found = _find(check_role(_settings(_policy(
        _allow(["iam:PassRole", "lambda:CreateFunction",
                "lambda:InvokeFunction"])))),
        "pass_role_to_compute")
    assert found["level"] == CRITICAL


def test_a_policy_rollback_path_is_named():
    """iam_privesc_by_rollback: set a policy back to a version that granted
    more. Nothing is attached and nothing is created, so nothing about the
    account's shape changes - which is what makes it hard to spot."""
    found = _find(check_role(_settings(_policy(
        _allow("iam:SetDefaultPolicyVersion")))),
        "escalation_setdefaultpolicyversion")
    assert "older version" in found["message"]


def test_rewriting_an_attached_policy_is_named():
    found = _find(check_role(_settings(_policy(
        _allow("iam:CreatePolicyVersion")))),
        "escalation_createpolicyversion")
    assert found["level"] == CRITICAL


@pytest.mark.parametrize("action,setting", [
    ("iam:AttachUserPolicy", "escalation_attachuserpolicy"),
    ("iam:PutUserPolicy", "escalation_putuserpolicy"),
    ("iam:UpdateAssumeRolePolicy", "escalation_updateassumerolepolicy"),
    ("iam:CreateAccessKey", "escalation_createaccesskey"),
    ("iam:CreateLoginProfile", "escalation_createloginprofile"),
    ("iam:UpdateLoginProfile", "escalation_updateloginprofile"),
    ("iam:AddUserToGroup", "escalation_addusertogroup"),
])
def test_every_named_escalation_primitive_is_reported(action, setting):
    assert _find(check_role(_settings(_policy(_allow(action)))),
                 setting)["level"] == CRITICAL


# ================================================= How the escalation is built


def test_an_escalation_split_across_two_policies_is_still_found():
    """The union of what a role's policies permit is what it can do. An
    escalation assembled from an inline policy and an attached one works
    exactly as well as one written in a single statement."""
    found = check_role(_settings(
        _policy(_allow("iam:PassRole")),
        _policy(_allow("ec2:RunInstances")),
    ))
    assert "pass_role_to_compute" in _settings_of(found)


def test_passing_a_role_with_nothing_to_start_is_only_a_warning():
    """PassRole alone grants nothing. Reporting it as critical would put a
    red finding on most correctly-built infrastructure."""
    found = _find(check_role(_settings(_policy(_allow("iam:PassRole")))),
                  "pass_any_role")
    assert found["level"] == WARNING


def test_starting_things_without_being_able_to_pass_a_role_says_nothing():
    assert check_role(_settings(_policy(_allow("ec2:RunInstances")))) == []


def test_passing_one_named_role_is_not_passing_any_role():
    """A policy that can pass a single named role is a deliberate
    arrangement. Treating it the same as a wildcard would flag the correct
    way to build this."""
    warnings = check_role(_settings(_policy(
        _allow("iam:PassRole", resource=f"arn:aws:iam::{ACCOUNT}:role/known"),
        _allow("ec2:RunInstances"))))
    assert warnings == []


def test_a_wildcard_action_matches_the_primitive_underneath_it():
    """iam:* permits iam:PassRole. Matching by IAM's own wildcard rules rather
    than by string equality is the difference between catching this and not."""
    found = check_role(_settings(_policy(
        _allow(["iam:*", "ec2:RunInstances"]))))
    assert "pass_role_to_compute" in _settings_of(found)


def test_a_conditioned_statement_is_not_counted():
    """A condition might still permit the escalation, but deciding that means
    evaluating IAM's policy language against a request that does not exist.
    aws/iam.py draws the line here and this follows it."""
    assert check_role(_settings(_policy(
        _allow(["iam:PassRole", "ec2:RunInstances"],
               Condition={"StringEquals": {"aws:RequestedRegion": "eu-west-2"}})
    ))) == []


def test_a_deny_is_not_an_allow():
    assert check_role(_settings({"Statement": [
        {"Effect": "Deny", "Action": "*", "Resource": "*"}]})) == []


def test_not_action_is_skipped_rather_than_inverted():
    """A NotAction statement can be equivalent to a very broad Allow, and
    working out which needs every action AWS has - a list that changes weekly
    and that being wrong about produces confident nonsense."""
    assert check_role(_settings(_policy(
        {"Effect": "Allow", "NotAction": "s3:*", "Resource": "*"}))) == []


# ====================================================== Full administrative


def test_full_admin_is_critical_and_cites_1_15():
    found = _find(check_role(_settings(_policy(_allow("*")))), "full_admin")
    assert found["level"] == CRITICAL
    assert found["control"]["id"] == "1.15"


def test_full_admin_does_not_also_list_every_escalation_it_implies():
    """Full admin permits all fourteen primitives. Listing them as well would
    report one fact fourteen times and bury the line that matters."""
    warnings = check_role(_settings(_policy(_allow("*"))))
    settings = _settings_of(warnings)
    assert settings == {"full_admin"}


# ============================================================== Broad reads


def test_reading_every_identity_is_reported():
    found = _find(check_role(_settings(_policy(_allow("iam:List*")))),
                  "reads_every_identity")
    assert found["level"] == WARNING
    assert "almost no trace" in found["message"]


def test_reading_every_bucket_is_reported():
    found = _find(check_role(_settings(_policy(_allow("s3:Get*")))),
                  "reads_every_bucket")
    assert found["level"] == WARNING


def test_one_named_read_action_on_every_bucket_is_not_the_wildcard_finding():
    """s3:GetObject on * is broad, but the finding is about a policy that
    reaches for a wildcard rather than one that names what it needs. Naming
    one action across all buckets is a different, narrower decision."""
    assert "reads_every_bucket" not in _settings_of(
        check_role(_settings(_policy(_allow("s3:GetObject")))))


def test_a_role_naming_the_bucket_it_needs_says_nothing():
    assert check_role(_settings(_policy(
        _allow("s3:GetObject", resource="arn:aws:s3:::one-bucket/*")))) == []


# ============================================ Where the role can be reached


def test_a_role_on_a_running_machine_says_so_in_the_finding():
    """"This role can become administrator" and "this role can become
    administrator and is sitting on a machine that answers HTTP requests" are
    not the same finding."""
    found = _find(check_role(_settings(
        _policy(_allow("*")), machines=["i-0abc", "i-0def"],
        instance_profiles=["app-profile"])), "full_admin")

    assert "2 running machines" in found["message"]
    assert "i-0abc" in found["message"]
    assert "metadata service" in found["message"]


def test_a_role_that_could_be_on_a_machine_is_worded_more_carefully():
    found = _find(check_role(_settings(
        _policy(_allow("*")), machines=[],
        instance_profiles=["app-profile"])), "full_admin")
    assert "set up to be attached" in found["message"]


def test_an_unchecked_machine_list_is_not_reported_as_none():
    found = _find(check_role(_settings(
        _policy(_allow("*")), machines=None,
        instance_profiles=["app-profile"])), "full_admin")
    assert "could not check" in found["message"]


def test_a_role_no_machine_can_hold_gets_no_such_sentence():
    found = _find(check_role(_settings(_policy(_allow("*")))), "full_admin")
    assert "machine" not in found["message"]


# ================================================== Who can assume the role


def test_a_role_anyone_can_assume_is_critical():
    trust = _policy({"Effect": "Allow", "Principal": {"AWS": "*"},
                     "Action": "sts:AssumeRole"})
    found = _find(check_role(_settings(trust_policy=trust)),
                  "assumable_by_anyone")
    assert found["level"] == CRITICAL
    assert "entire internet" in found["message"]


def test_a_bare_wildcard_principal_is_also_caught():
    trust = _policy({"Effect": "Allow", "Principal": "*",
                     "Action": "sts:AssumeRole"})
    assert "assumable_by_anyone" in _settings_of(
        check_role(_settings(trust_policy=trust)))


def test_a_role_another_account_can_assume_is_a_warning_naming_it():
    trust = _policy({"Effect": "Allow",
                     "Principal": {"AWS": f"arn:aws:iam::{OTHER_ACCOUNT}:root"},
                     "Action": "sts:AssumeRole"})
    found = _find(check_role(_settings(trust_policy=trust)),
                  f"trusted_account_{OTHER_ACCOUNT}")
    assert found["level"] == WARNING
    assert "external ID" in found["message"]


def test_this_account_trusting_itself_is_not_a_foreign_account():
    trust = _policy({"Effect": "Allow",
                     "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
                     "Action": "sts:AssumeRole"})
    assert check_role(_settings(trust_policy=trust)) == []


def test_a_service_trust_is_the_ordinary_case_and_says_nothing():
    assert check_role(_settings()) == []


# ================================================ Checks that did not happen


def test_a_policy_document_that_could_not_be_read_is_not_counted_harmless():
    settings = _settings()
    settings["policies"] = [{"name": "opaque", "source": "attached",
                             "arn": "arn:aws:iam::aws:policy/Opaque",
                             "document": None}]
    found = _find(check_role(settings), "unreadable_policy_documents")
    assert found["level"] == WARNING
    assert "not counted as harmless" in found["message"]


def test_an_unreadable_check_is_reported_before_the_findings():
    settings = _settings(_policy(_allow("*")),
                         unreadable={"policies": "iam:ListRolePolicies"})
    assert check_role(settings)[0]["rule"]["setting"] == "unreadable_policies"


def test_the_scanner_tolerates_a_role_that_is_not_there():
    assert check_role(None) == []
    assert check_role({}) == []


def test_nothing_here_is_offered_as_an_automatic_fix():
    warnings = check_role(_settings(_policy(_allow("*")), machines=["i-1"]))
    assert warnings
    assert fixable(warnings) == []


def test_only_full_admin_claims_a_published_control():
    """CIS has no control covering privilege-escalation paths, and inventing
    one would be the fabricated citation controls.py warns about."""
    warnings = check_role(_settings(_policy(
        _allow(["iam:PassRole", "ec2:RunInstances", "iam:List*"]))))
    assert warnings
    assert cited(warnings) == []


# ================================================== Against a real IAM API


def test_a_role_reads_back_with_its_policies_and_profiles(iam):
    iam.create_role(RoleName="app", AssumeRolePolicyDocument=json.dumps(EC2_TRUST))
    iam.put_role_policy(RoleName="app", PolicyName="inline",
                        PolicyDocument=json.dumps(_policy(
                            _allow(["iam:PassRole", "ec2:RunInstances"]))))
    iam.create_instance_profile(InstanceProfileName="app-profile")
    iam.add_role_to_instance_profile(InstanceProfileName="app-profile",
                                     RoleName="app")

    settings = roles.read_role_for_scanning(iam, "app")

    assert settings["role_name"] == "app"
    assert [p["name"] for p in settings["policies"]] == ["inline"]
    assert settings["instance_profiles"] == ["app-profile"]
    assert "pass_role_to_compute" in _settings_of(check_role(settings))


def test_an_attached_managed_policy_is_read_too(iam):
    created = iam.create_policy(PolicyName="escalate", PolicyDocument=json.dumps(
        _policy(_allow("iam:CreateAccessKey"))))["Policy"]
    iam.create_role(RoleName="app", AssumeRolePolicyDocument=json.dumps(EC2_TRUST))
    iam.attach_role_policy(RoleName="app", PolicyArn=created["Arn"])

    settings = roles.read_role_for_scanning(iam, "app")

    assert [p["source"] for p in settings["policies"]] == ["attached"]
    assert "escalation_createaccesskey" in _settings_of(check_role(settings))


def test_a_role_that_is_not_there_reads_as_none(iam):
    assert roles.read_role_for_scanning(iam, "no-such-role") is None


def test_aws_service_roles_are_left_out_of_the_listing(iam):
    iam.create_role(RoleName="mine",
                    AssumeRolePolicyDocument=json.dumps(EC2_TRUST))
    iam.create_role(RoleName="theirs", Path="/aws-service-role/",
                    AssumeRolePolicyDocument=json.dumps(EC2_TRUST))

    ours = [r["id"] for r in registry.ROLE.list_all(iam, only_ours=True)]
    everything = [r["id"] for r in registry.ROLE.list_all(iam, only_ours=False)]

    assert ours == ["mine"]
    assert set(everything) == {"mine", "theirs"}


def test_roles_are_registered_as_audit_only():
    assert registry.get("role") is registry.ROLE
    assert registry.ROLE.read_only is True
    for operation in (registry.ROLE.create, registry.ROLE.delete,
                      registry.ROLE.cleanup):
        with pytest.raises(NotImplementedError):
            operation(None, None)


def test_describing_a_role_does_not_restate_its_policy_documents(iam):
    iam.create_role(RoleName="app", AssumeRolePolicyDocument=json.dumps(EC2_TRUST))
    iam.put_role_policy(RoleName="app", PolicyName="inline",
                        PolicyDocument=json.dumps(_policy(_allow("*"))))

    described = registry.ROLE.describe(roles.read_role_for_scanning(iam, "app"))

    assert described["policy_count"] == 1
    assert described["policy_names"] == ["inline"]
    assert "policies" not in described
