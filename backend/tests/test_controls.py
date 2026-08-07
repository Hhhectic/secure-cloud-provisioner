"""Tests for benchmark control citation.

Two things are being protected here.

The first is that citations are accurate. A finding claiming CIS backing it does
not have is worse than an uncited finding, because it borrows authority under
false pretences and a marker or auditor can check.

The second is that citation stays optional. Several rules in this tool are
ordinary good practice that no published benchmark covers, and the design
depends on being able to say so by leaving the field empty.
"""

import boto3
import pytest
from moto import mock_aws

from scanner import controls
from scanner.rules import (
    check_firewall_rules,
    check_group_usage,
    check_default_group,
)
from scanner.s3_rules import check_bucket_settings
from scanner.common import CRITICAL, WARNING, INFO, cited, fixable
from aws import s3_buckets

REGION = "us-east-1"
WORLD = "0.0.0.0/0"
WORLD_V6 = "::/0"
BUCKET = "scp-controls-test"


def _rule(port, source=WORLD, **extra):
    base = {
        "rule_id": f"sgr-{port}", "group_id": "sg-test", "protocol": "tcp",
        "from_port": port, "to_port": port, "source": source,
        "direction": "inbound",
    }
    base.update(extra)
    return base


def _one(warnings, setting):
    return next(w for w in warnings if w["rule_id"].endswith(f":{setting}"))


# ------------------------------------------------------------- The registry


def test_no_scanner_falls_over_on_a_resource_that_is_not_there():
    """Asked of all five together, because four had the guard and one did not.

    A reader returns None when the thing does not exist, and that None reaches
    the scanner. The S3 checker was missing its guard, so the failure surfaced
    as an AttributeError several layers below the question that caused it.
    """
    from scanner.s3_rules import check_bucket_settings
    from scanner.key_pair_rules import check_key_pair
    from scanner.instance_rules import check_instance
    from scanner.vpc_rules import check_vpc

    for checker in (check_bucket_settings, check_key_pair, check_instance,
                    check_vpc):
        assert checker(None) == [], f"{checker.__name__} should tolerate None"

    # The firewall scanner takes a list of rules rather than a settings dict,
    # so its equivalent is an empty list; _sg_check guards the None case.
    assert check_firewall_rules([]) == []


def test_every_control_is_fully_described():
    for name, c in controls.CONTROLS.items():
        assert c.id, name
        assert c.title, name
        assert c.level in (1, 2), name
        assert c.framework and c.version, name


def test_a_finding_on_something_not_yet_created_offers_no_fix_button(capsys):
    """Printed output used to advertise a fix followed by "(None)".

    A rule typed into a form has no ID because it does not exist, so there is
    nothing to fix. The remedy at that stage is to change the answer, and
    saying "can fix" invites someone to look for a button that cannot exist.
    """
    from scanner.common import print_warnings

    proposed = check_firewall_rules([{
        "protocol": "tcp", "from_port": 22, "to_port": 22, "source": WORLD,
        "direction": "inbound",
    }])
    assert proposed[0]["rule_id"] is None

    print_warnings(proposed)
    printed = capsys.readouterr().out

    assert "(None)" not in printed
    assert "change this before creating it" in printed


def test_a_finding_on_a_real_rule_still_names_it(capsys):
    from scanner.common import print_warnings

    print_warnings(check_firewall_rules([_rule(22)]))
    printed = capsys.readouterr().out

    assert "can fix" in printed
    assert "sgr-22" in printed


def test_unknown_control_names_do_not_raise():
    """A typo in a rule should cost a citation, not crash a security scan."""
    assert controls.control("NO_SUCH_CONTROL") is None


def test_citation_reads_the_way_a_write_up_would_quote_it():
    c = controls.CONTROLS["SG_ADMIN_PORTS_V4"]
    assert c.citation == "CIS AWS Foundations Benchmark v5.0.0 §5.3"


def test_non_cis_controls_are_not_labelled_cis():
    """ACCT.09 is AWS guidance, not a benchmark control. Say so."""
    c = controls.CONTROLS["UNUSED_SECURITY_GROUPS"]
    assert c.framework == controls.SSB
    assert "CIS" not in c.framework


# ------------------------------------------------- Security group citations


def test_open_ssh_cites_cis_5_3():
    w = check_firewall_rules([_rule(22)])[0]
    assert w["control"]["id"] == "5.3"
    assert w["control"]["version"] == "5.0.0"
    assert w["control"]["level"] == 1


def test_open_rdp_cites_cis_5_3():
    assert check_firewall_rules([_rule(3389)])[0]["control"]["id"] == "5.3"


def test_ipv6_admin_port_cites_cis_5_4_not_5_3():
    """CIS splits this control by address family; the citation has to follow."""
    w = check_firewall_rules([_rule(22, source=WORLD_V6)])[0]
    assert w["control"]["id"] == "5.4"


def test_exposed_database_is_critical_but_uncited():
    """An open MySQL port is serious and CIS 5.3 does not cover it.

    5.3 names remote server administration ports. Stretching it to cover
    databases would be a fabricated citation on a real finding.
    """
    w = check_firewall_rules([_rule(3306)])[0]
    assert w["level"] == CRITICAL
    assert w["control"] is None


def test_wide_range_cites_only_when_it_covers_an_admin_port():
    covering = check_firewall_rules([_rule(None, from_port=1, to_port=9000)])[0]
    assert covering["control"]["id"] == "5.3"

    missing = check_firewall_rules([_rule(None, from_port=8000, to_port=9000)])[0]
    assert missing["control"] is None


def test_all_ports_open_cites_the_admin_port_control():
    w = check_firewall_rules([
        _rule(None, protocol="-1", from_port=None, to_port=None)
    ])[0]
    assert w["control"]["id"] == "5.3"


# ------------------------------------------------------------------- Egress


def test_open_outbound_is_informational_not_a_fault():
    """It is the default on every new group. Flagging it hard trains people to
    ignore the tool."""
    warnings = check_firewall_rules([
        _rule(None, protocol="-1", from_port=None, to_port=None,
              direction="outbound")
    ])
    assert len(warnings) == 1
    assert warnings[0]["level"] == INFO
    assert warnings[0]["fix"] is None
    assert warnings[0]["control"] is None


def test_restricted_outbound_says_nothing():
    assert check_firewall_rules([
        _rule(443, source="10.0.0.0/8", direction="outbound")
    ]) == []


def test_inbound_and_outbound_are_judged_differently():
    """The same rule shape is critical inbound and unremarkable outbound."""
    inbound = check_firewall_rules([_rule(22)])
    outbound = check_firewall_rules([_rule(22, direction="outbound")])

    assert inbound[0]["level"] == CRITICAL
    assert outbound == []


# ------------------------------------------------------------ Unused groups


def test_unused_group_is_reported_and_cited_to_the_baseline():
    warnings = check_group_usage({
        "group_id": "sg-1", "group_name": "leftover",
        "in_use": False, "is_default": False,
    })
    assert len(warnings) == 1
    assert warnings[0]["level"] == INFO
    assert warnings[0]["control"]["id"] == "ACCT.09"
    assert warnings[0]["control"]["framework"] == controls.SSB


def test_group_in_use_says_nothing():
    assert check_group_usage({
        "group_id": "sg-1", "group_name": "live", "in_use": True,
        "is_default": False,
    }) == []


def test_the_default_group_is_never_reported_as_unused():
    """It cannot be deleted, so the warning would be permanent and unactionable."""
    assert check_group_usage({
        "group_id": "sg-1", "group_name": "default", "in_use": False,
        "is_default": True,
    }) == []


# ------------------------------------------------------ Default group, CIS 5.5


DEFAULT_GROUP = {"group_id": "sg-1", "group_name": "default",
                 "in_use": False, "is_default": True}
NAMED_GROUP = {"group_id": "sg-2", "group_name": "web",
               "in_use": True, "is_default": False}


def test_default_group_with_rules_cites_cis_5_5():
    w = check_default_group(DEFAULT_GROUP, [_rule(22)])[0]
    assert w["control"]["id"] == "5.5"
    assert w["control"]["level"] == 2
    assert w["level"] == WARNING


def test_an_empty_default_group_is_compliant():
    assert check_default_group(DEFAULT_GROUP, []) == []


def test_default_group_counts_outbound_rules_too():
    """CIS 5.5 asks for all traffic restricted, both directions."""
    w = check_default_group(DEFAULT_GROUP, [_rule(None, direction="outbound")])[0]
    assert "1 outbound" in w["message"]


def test_a_named_group_is_not_judged_against_5_5():
    """Rules on a group someone chose deliberately are the entire point of it."""
    assert check_default_group(NAMED_GROUP, [_rule(22)]) == []


def test_default_group_finding_offers_no_fix():
    """Emptying the default group can break running workloads that rely on it.

    Deleting rules the user did not ask about is a bigger action than this tool
    should take unprompted, so it reports and explains instead.
    """
    w = check_default_group(DEFAULT_GROUP, [_rule(22)])[0]
    assert w["fix"] is None
    assert "cannot be deleted" in w["message"]


# ---------------------------------------------------------- Bucket citations


def _settings(**overrides):
    base = {
        "bucket": BUCKET,
        "public_access_block": dict(s3_buckets.ALL_BLOCKS_ON),
        "encryption": {"enabled": True, "algorithm": "aws:kms"},
        "versioning": {"enabled": True, "mfa_delete": True},
        "public_acl_grants": [],
        "policy_is_public": False,
        "policy_denies_http": True,
        "logging_enabled": True,
        "unreadable": {},
    }
    base.update(overrides)
    return base


def test_a_fully_hardened_bucket_is_clean():
    assert check_bucket_settings(_settings()) == []


def test_block_public_access_cites_cis_2_1_4():
    w = check_bucket_settings(_settings(public_access_block=None))[0]
    assert w["control"]["id"] == "2.1.4"
    assert w["control"]["level"] == 1


def test_plain_http_allowed_cites_cis_2_1_1():
    w = _one(check_bucket_settings(_settings(policy_denies_http=False)),
             "deny_http")
    assert w["control"]["id"] == "2.1.1"
    assert w["fix"]["action"] == "enforce_https"


def test_mfa_delete_cites_cis_2_1_2_and_offers_no_fix():
    """CIS marks it Manual because it needs root plus an MFA token.

    A fix button here would either fail every time or require this tool to hold
    root credentials. Reporting it is the correct behaviour.
    """
    w = _one(check_bucket_settings(_settings(
        versioning={"enabled": True, "mfa_delete": False}
    )), "mfa_delete")

    assert w["control"]["id"] == "2.1.2"
    assert w["control"]["automated"] is False
    assert w["fix"] is None


def test_versioning_off_reports_versioning_not_mfa_delete():
    """MFA delete is meaningless without versioning; two warnings would be noise."""
    warnings = check_bucket_settings(_settings(
        versioning={"enabled": False, "mfa_delete": False}
    ))
    assert len(warnings) == 1
    assert warnings[0]["rule_id"].endswith(":versioning")


def test_encryption_findings_are_uncited():
    """CIS v5.0.0 has no S3 encryption control; AWS made it non-optional."""
    off = check_bucket_settings(_settings(
        encryption={"enabled": False, "algorithm": None}
    ))[0]
    aes = check_bucket_settings(_settings(
        encryption={"enabled": True, "algorithm": "AES256"}
    ))[0]

    assert off["control"] is None
    assert aes["control"] is None
    assert aes["level"] == INFO


def test_cited_filters_to_findings_with_a_published_backing():
    warnings = check_bucket_settings(_settings(
        public_access_block=None,
        encryption={"enabled": False, "algorithm": None},
    ))
    assert len(warnings) == 2
    assert len(cited(warnings)) == 1


# ------------------------------------- Deny-HTTP detection and fix, on moto


@pytest.fixture
def s3():
    with mock_aws():
        yield boto3.client("s3", region_name=REGION)


def test_a_fresh_bucket_allows_plain_http(s3):
    s3.create_bucket(Bucket=BUCKET)
    assert s3_buckets.policy_denies_http(s3, BUCKET) is False


def test_enforce_https_makes_the_check_pass(s3):
    s3.create_bucket(Bucket=BUCKET)

    ok, msg = s3_buckets.enforce_https(s3, BUCKET)
    assert ok, msg
    assert s3_buckets.policy_denies_http(s3, BUCKET) is True


def test_enforce_https_keeps_the_existing_policy(s3):
    """A security fix that removes access will be reverted and never reapplied."""
    import json

    s3.create_bucket(Bucket=BUCKET)
    s3.put_bucket_policy(Bucket=BUCKET, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "SomethingImportant",
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{BUCKET}/*",
        }],
    }))

    ok, msg = s3_buckets.enforce_https(s3, BUCKET)
    assert ok, msg

    after = s3_buckets.get_bucket_policy_document(s3, BUCKET)
    sids = {s.get("Sid") for s in after["Statement"]}
    assert "SomethingImportant" in sids
    assert s3_buckets.DENY_HTTP_SID in sids


def test_enforce_https_twice_does_not_duplicate_the_statement(s3):
    s3.create_bucket(Bucket=BUCKET)
    s3_buckets.enforce_https(s3, BUCKET)
    s3_buckets.enforce_https(s3, BUCKET)

    document = s3_buckets.get_bucket_policy_document(s3, BUCKET)
    denies = [s for s in document["Statement"]
              if s.get("Sid") == s3_buckets.DENY_HTTP_SID]
    assert len(denies) == 1


def test_an_equivalent_policy_written_differently_is_recognised(s3):
    """Someone else's deny statement counts. Only the effect matters."""
    import json

    s3.create_bucket(Bucket=BUCKET)
    s3.put_bucket_policy(Bucket=BUCKET, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "WrittenByHand",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": f"arn:aws:s3:::{BUCKET}/*",
            "Condition": {"BoolIfExists": {"aws:SecureTransport": False}},
        }],
    }))

    assert s3_buckets.policy_denies_http(s3, BUCKET) is True


def test_secure_by_default_bucket_refuses_plain_http(s3):
    ok, name, problems = s3_buckets.create_bucket(s3, BUCKET, region=REGION)
    assert ok
    assert problems == []

    settings = s3_buckets.read_bucket_for_scanning(s3, name)
    assert settings["policy_denies_http"] is True

    # 2.1.2 survives because MFA delete cannot be enabled through the API at
    # all. Everything the tool is capable of setting is set.
    remaining = {w["control"]["id"] for w in cited(check_bucket_settings(settings))}
    assert remaining == {"2.1.2"}


def test_weak_bucket_can_be_fixed_through_the_scanner(s3):
    """Every cited finding on a weak bucket is fixable except the manual one."""
    ok, name, _ = s3_buckets.create_bucket(s3, BUCKET, region=REGION,
                                           secure_by_default=False)
    assert ok

    before = check_bucket_settings(s3_buckets.read_bucket_for_scanning(s3, name))
    assert {w["control"]["id"] for w in cited(before)} == {"2.1.1", "2.1.4"}

    for w in fixable(before):
        applied, msg = s3_buckets.apply_fix(s3, name, w)
        assert applied, msg

    # Only the manual control is left. Every automated one has been dealt with,
    # and 2.1.2 appears now precisely because turning versioning on is what
    # makes MFA delete meaningful to ask about.
    after = check_bucket_settings(s3_buckets.read_bucket_for_scanning(s3, name))
    assert {w["control"]["id"] for w in cited(after)} == {"2.1.2"}
    assert not any(w["control"]["automated"] for w in cited(after))
