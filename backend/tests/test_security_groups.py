"""Tests for the firewall rules engine and security group CRUD.

The rules tests touch no cloud. The CRUD tests run against moto.

The fix path gets the most attention here because it is the one operation that
changes live network access. Everything else in this tool either creates a thing
or reads a thing; narrow_rule_to_ip reaches into a running configuration and
edits it, and the failure modes are asymmetric. Failing to narrow a rule leaves
you exposed. Failing halfway through leaves you locked out.
"""

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from scanner.rules import check_firewall_rules, RISKY_PORTS
from scanner.common import CRITICAL, WARNING, INFO, fixable, summarize
from aws import security_groups as sg

REGION = "us-east-1"
WORLD = "0.0.0.0/0"
WORLD_V6 = "::/0"
MY_IP = "203.0.113.25/32"


def _rule(port, source=WORLD, protocol="tcp", **extra):
    base = {
        "rule_id": f"sgr-{port}",
        "resource_id": "sg-test",
        "protocol": protocol,
        "from_port": port,
        "to_port": port,
        "source": source,
        "direction": "inbound",
    }
    base.update(extra)
    return base


def _ids(warnings):
    return {w["rule_id"] for w in warnings}


# ------------------------------------------------------- Rules: no AWS involved


def test_ssh_open_to_world_is_critical_and_narrowable():
    warnings = check_firewall_rules([_rule(22)])
    assert len(warnings) == 1
    assert warnings[0]["level"] == CRITICAL
    assert warnings[0]["fix"]["action"] == "narrow_to_my_ip"
    assert warnings[0]["rule_id"] == "sgr-22"


def test_ssh_restricted_to_one_address_is_clean():
    assert check_firewall_rules([_rule(22, source=MY_IP)]) == []


def test_every_risky_port_is_detected():
    for port in RISKY_PORTS:
        warnings = check_firewall_rules([_rule(port)])
        assert warnings, f"port {port} produced no warning"
        assert warnings[0]["level"] == CRITICAL


def test_all_protocols_open_is_critical_and_removable():
    """Protocol -1 means every port. Narrowing the source is not enough."""
    warnings = check_firewall_rules([
        _rule(None, protocol="-1", from_port=None, to_port=None)
    ])
    assert warnings[0]["level"] == CRITICAL
    assert warnings[0]["fix"]["action"] == "remove"


def test_wide_port_range_is_critical():
    warnings = check_firewall_rules([_rule(None, from_port=1, to_port=9000)])
    assert warnings[0]["level"] == CRITICAL
    assert warnings[0]["fix"]["action"] == "remove"


def test_a_risky_port_inside_a_range_is_caught():
    """Ports 20-25 opens SSH without ever naming port 22."""
    warnings = check_firewall_rules([_rule(None, from_port=20, to_port=25)])
    assert any("22" in w["message"] for w in warnings)


def test_ipv6_open_is_flagged_and_says_so():
    warnings = check_firewall_rules([_rule(22, source=WORLD_V6)])
    assert warnings[0]["level"] == CRITICAL
    assert "IPv6" in warnings[0]["message"]


def test_port_443_open_to_world_is_clean():
    """HTTPS open to everyone is the normal case, not a finding."""
    assert check_firewall_rules([_rule(443)]) == []


def test_port_80_open_to_world_is_informational():
    warnings = check_firewall_rules([_rule(80)])
    assert len(warnings) == 1
    assert warnings[0]["level"] == INFO
    assert warnings[0]["fix"] is None


def test_unrecognised_open_port_is_a_warning():
    warnings = check_firewall_rules([_rule(8080)])
    assert warnings[0]["level"] == WARNING
    assert warnings[0]["fix"]["action"] == "narrow_to_my_ip"


def test_half_the_internet_is_not_a_private_range():
    """`0.0.0.0/0` was tested by string equality, which is the shape of check
    somebody writes a backdoor around.

    `0.0.0.0/1` and `128.0.0.0/1` are two rules covering every address there
    is, and both produced no finding at all - on either cloud. So did
    `0.0.0.0/4` and `::/1`. The branch that swallowed them was reasoning about
    *private* ranges: "there is nothing to say about port 443 from a private
    range". A broad public one is not that.
    """
    for source, addresses in [
        ("0.0.0.0/1", "2,147,483,648"),
        ("128.0.0.0/1", "2,147,483,648"),
        ("0.0.0.0/4", "268,435,456"),
        ("8.0.0.0/9", "8,388,608"),
    ]:
        warnings = check_firewall_rules([_rule(22, source=source)])
        assert warnings, f"{source} produced no warning at all"
        assert warnings[0]["level"] == CRITICAL, source
        # Named, and counted. Nobody reads /9 as eight million.
        assert source in warnings[0]["message"], source
        assert addresses in warnings[0]["message"], source


def test_a_broad_ipv6_range_is_caught_the_same_way():
    warnings = check_firewall_rules([_rule(22, source="::/1")])
    assert warnings and warnings[0]["level"] == CRITICAL
    assert "::/1" in warnings[0]["message"]


def test_the_ipv6_threshold_sits_between_a_provider_and_a_site():
    """Where BROAD_PREFIX_V6 actually falls, probed with routable space.

    The obvious range to test this with is 2001:db8::/32, and it proves
    nothing: that is the documentation range, is_global excludes it before the
    prefix is looked at, and the assertion passes for the wrong reason. It has
    to be real space.

    A provider is given a /32 and a site a /48, which is why the line is drawn
    between them rather than at some count of addresses - a /48 is 2^80 hosts
    and is still one organisation.
    """
    provider = check_firewall_rules([_rule(22, source="2606:4700::/32")])
    assert provider and provider[0]["level"] == CRITICAL, \
        "an entire provider allocation is not an allowlist"

    site = check_firewall_rules([_rule(22, source="2606:4700:4700::/48")])
    assert site == [], "one organisation's allocation is a choice somebody made"

    assert check_firewall_rules(
        [_rule(22, source="2606:4700:4700::1111/128")]) == []

    assert check_firewall_rules([_rule(22, source="2001:db8::/32")]) == [], \
        "documentation space is excluded before the prefix matters"


def test_broad_ranges_are_judged_by_what_they_open():
    """The threshold's real justification, which is not the one first written.

    Ranges broader than /16 are published and legitimately named in real
    allowlists - Cloudflare's 104.16.0.0/12 among them - so "nothing real is
    this big" was simply false. What makes firing correct is the port: the
    architecture that trusts a whole CDN is an origin lock on 443, and 443
    returns silently whatever the source. The same range on 22 is somebody
    trusting every host that can rent space behind that CDN.
    """
    cdn = "104.16.0.0/12"

    assert check_firewall_rules([_rule(443, source=cdn)]) == [], \
        "an origin lock is the reason a range this size is ever named"

    admin = check_firewall_rules([_rule(22, source=cdn)])
    assert admin and admin[0]["level"] == CRITICAL, \
        "and the same range on an admin port is not that"

    ordinary = check_firewall_rules([_rule(8080, source=cdn)])
    assert ordinary and ordinary[0]["level"] == WARNING


def test_an_allowlist_is_still_an_allowlist():
    """The other half, and the one that decides whether this is usable. A real
    allowlist is an office, a VPN endpoint or one machine; reporting those
    would put a critical on every correctly configured group in existence."""
    for source in ["203.0.113.25/32", "8.8.8.0/24", "198.51.100.0/22"]:
        assert check_firewall_rules([_rule(22, source=source)]) == [], source


def test_private_space_stays_silent_however_large():
    """10.0.0.0/8 is sixteen million addresses and not one of them is a
    stranger. The size threshold applies to public space only - judging by
    prefix length alone would report every VPC-internal rule as critical."""
    for source in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                   "100.64.0.0/10"]:
        assert check_firewall_rules([_rule(22, source=source)]) == [], source


def test_a_rule_with_no_ports_does_not_report_a_port_called_none():
    """It rendered as "Port None is open to the entire internet", which reads
    as a bug rather than a finding."""
    warnings = check_firewall_rules(
        [_rule(22, from_port=None, to_port=None)])
    assert warnings
    assert "None" not in warnings[0]["message"]
    assert "names no port range" in warnings[0]["message"]


def test_private_source_is_never_flagged():
    for source in ("10.0.0.0/8", "192.168.1.0/24", "172.16.0.0/12", MY_IP):
        assert check_firewall_rules([_rule(22, source=source)]) == []


def test_every_warning_carries_the_rule_id_that_caused_it():
    """Without this the fix button has nothing to aim at."""
    warnings = check_firewall_rules([_rule(22), _rule(3389), _rule(8080)])
    assert _ids(warnings) == {"sgr-22", "sgr-3389", "sgr-8080"}
    for w in warnings:
        assert set(w) == {"level", "message", "rule_id", "resource_id", "rule",
                          "fix", "control"}


# ------------------------------------------------------------ Shape translation


def test_to_scanner_shape_reads_ipv4_ipv6_and_group_sources():
    aws_rules = [
        {"SecurityGroupRuleId": "sgr-1", "GroupId": "sg-1", "IpProtocol": "tcp",
         "FromPort": 22, "ToPort": 22, "CidrIpv4": WORLD, "IsEgress": False},
        {"SecurityGroupRuleId": "sgr-2", "GroupId": "sg-1", "IpProtocol": "tcp",
         "FromPort": 22, "ToPort": 22, "CidrIpv6": WORLD_V6, "IsEgress": False},
        {"SecurityGroupRuleId": "sgr-3", "GroupId": "sg-1", "IpProtocol": "tcp",
         "FromPort": 443, "ToPort": 443,
         "ReferencedGroupInfo": {"GroupId": "sg-other"}, "IsEgress": False},
    ]
    shaped = sg.to_scanner_shape(aws_rules)
    assert [r["source"] for r in shaped] == [WORLD, WORLD_V6, "sg:sg-other"]
    assert all(r["direction"] == "inbound" for r in shaped)


def test_to_scanner_shape_drops_outbound_by_default():
    """Outbound open to the world is the AWS default and not a finding."""
    aws_rules = [
        {"SecurityGroupRuleId": "sgr-1", "GroupId": "sg-1", "IpProtocol": "-1",
         "CidrIpv4": WORLD, "IsEgress": True},
    ]
    assert sg.to_scanner_shape(aws_rules) == []
    assert len(sg.to_scanner_shape(aws_rules, include_outbound=True)) == 1


def test_a_group_source_on_an_admin_port_is_recognised_as_correct():
    """The bastion pattern, reported rather than passed over in silence.

    An empty result is ambiguous: it could mean nothing reaches this port, or
    that the scanner did not look. Saying what the answer is removes the doubt,
    and it is the only place this tool tells someone they got something right.
    """
    warnings = check_firewall_rules([_rule(22, source="sg:sg-bastion")])

    assert len(warnings) == 1
    assert warnings[0]["level"] == INFO
    assert warnings[0]["fix"] is None
    assert "sg-bastion" in warnings[0]["message"]
    assert "stronger arrangement" in warnings[0]["message"]


def test_the_group_source_message_says_to_check_that_group_too():
    """The private instance is only as safe as whatever the bastion allows."""
    w = check_firewall_rules([_rule(22, source="sg:sg-bastion")])[0]
    assert "worth checking too" in w["message"]


def test_a_group_source_on_an_ordinary_port_stays_silent():
    """Only admin ports. Otherwise a busy account produces pages of praise."""
    assert check_firewall_rules([_rule(443, source="sg:sg-web")]) == []
    assert check_firewall_rules([_rule(8080, source="sg:sg-web")]) == []


def test_a_group_source_is_never_treated_as_public():
    """sg: contains a colon, and the IPv6 check looks for a colon."""
    warnings = check_firewall_rules([_rule(22, source="sg:sg-bastion")])
    assert all(w["level"] != CRITICAL for w in warnings)


def test_to_ip_permission_puts_a_group_source_in_the_right_field():
    """Not IpRanges. AWS rejects an ID there with an unhelpful message."""
    entry = sg.to_ip_permission({
        "protocol": "tcp", "from_port": 22, "to_port": 22,
        "source": "sg:sg-0123456789abcdef0",
    })

    assert entry["UserIdGroupPairs"][0]["GroupId"] == "sg-0123456789abcdef0"
    assert "IpRanges" not in entry
    assert "Ipv6Ranges" not in entry


def test_to_ip_permission_splits_ipv4_from_ipv6():
    """CidrIp accepts an IPv6 string and then AWS rejects it unhelpfully."""
    v4 = sg.to_ip_permission({"protocol": "tcp", "from_port": 22, "to_port": 22,
                              "source": WORLD})
    v6 = sg.to_ip_permission({"protocol": "tcp", "from_port": 22, "to_port": 22,
                              "source": WORLD_V6})
    assert v4["IpRanges"][0]["CidrIp"] == WORLD
    assert "Ipv6Ranges" not in v4
    assert v6["Ipv6Ranges"][0]["CidrIpv6"] == WORLD_V6
    assert "IpRanges" not in v6


# ------------------------------------------------------------ CRUD against moto


@pytest.fixture
def ec2():
    with mock_aws():
        client = boto3.client("ec2", region_name=REGION)
        yield client


@pytest.fixture
def vpc_id(ec2):
    found, err = sg.get_default_vpc(ec2)
    assert err is None, err
    return found


def _make(ec2, vpc_id, rules=None, name="test-sg"):
    ok, sg_id, problems = sg.create_security_group(
        ec2, name, "created by tests", vpc_id, rules
    )
    assert ok, sg_id
    return sg_id, problems


def test_one_repeated_rule_does_not_discard_the_others(ec2, vpc_id):
    """AWS rejects the whole request if a permission appears twice in it.

    Found in a live session: five rules submitted, one of them a repeat, and
    the group was created with none of them. The failure is silent apart from
    a line of error text, and an empty group is far worse than the duplicate
    would have been - it looks configured and permits nothing.
    """
    sg_id, _ = _make(ec2, vpc_id, [
        _rule(22, source=WORLD),
        _rule(22, source=WORLD),
        _rule(3389, source=WORLD),
        _rule(443, source=MY_IP),
    ])

    live = sg.read_group_for_scanning(ec2, sg_id)
    ports = sorted(r["from_port"] for r in live)

    assert ports == [22, 443, 3389], "every distinct rule should have landed"


def test_the_duplicate_is_reported_rather_than_swallowed(ec2, vpc_id):
    ok, message = sg.add_rules(ec2, _make(ec2, vpc_id)[0], [
        _rule(22, source=WORLD),
        _rule(22, source=WORLD),
    ])

    assert ok
    assert "1 repeated rule" in message


def test_rules_differing_only_by_source_are_not_duplicates(ec2, vpc_id):
    """Same port, two different addresses, is an ordinary thing to want."""
    sg_id, _ = _make(ec2, vpc_id, [
        _rule(22, source=MY_IP),
        _rule(22, source="198.51.100.9/32"),
    ])

    sources = {r["source"] for r in sg.read_group_for_scanning(ec2, sg_id)}
    assert sources == {MY_IP, "198.51.100.9/32"}


def test_created_group_is_tagged_and_findable(ec2, vpc_id):
    sg_id, problems = _make(ec2, vpc_id)
    assert problems == []

    ours = [g["GroupId"] for g in sg.list_security_groups(ec2, only_ours=True)]
    assert ours == [sg_id]

    everything = sg.list_security_groups(ec2)
    assert len(everything) > 1, "the VPC default group should also be present"


def test_a_listed_group_can_be_fed_straight_to_the_reader(ec2, vpc_id):
    """The two functions a script composes first, composed.

    list_security_groups returns AWS's own dicts and everything downstream is
    documented as taking an ID, so the obvious loop handed a dict to a filter
    value and botocore rejected it as a malformed parameter - naming the
    parameter, not the mistake. The page never hit it because the registry's
    list adapter reshapes first; anything reaching for the two directly did.
    """
    sg_id, _ = _make(ec2, vpc_id, [_rule(22, source="0.0.0.0/0")])

    for group in sg.list_security_groups(ec2, only_ours=True):
        rules = sg.read_group_for_scanning(ec2, group)
        assert [r["source"] for r in rules] == ["0.0.0.0/0"]


def test_every_spelling_of_a_group_id_reaches_the_same_group(ec2, vpc_id):
    """Three shapes are in circulation and all three have to work.

    GroupId comes off the API, group_id out of read_group_usage, and id out of
    the registry's list adapter. A caller holding any of them is holding a
    security group, and which spelling it happens to carry is an accident of
    where it came from.
    """
    sg_id, _ = _make(ec2, vpc_id, [_rule(22, source="0.0.0.0/0")])

    for shape in ({"GroupId": sg_id}, {"group_id": sg_id}, {"id": sg_id}, sg_id):
        assert sg.group_id_of(shape) == sg_id
        assert len(sg.read_group_for_scanning(ec2, shape)) == 1


def test_a_dict_carrying_no_group_id_is_a_caller_error_not_a_missing_group(ec2):
    """Refuse loudly rather than resolving to "no such group".

    Returning None here would send a dict somebody built wrong down the same
    path as a group that does not exist, and answer 404 about a group that is
    sitting there.
    """
    with pytest.raises(ValueError) as raised:
        sg.group_id_of({"VpcId": "vpc-1", "GroupName": "web"})

    assert "GroupId" in str(raised.value)


def test_create_reports_rule_failure_without_losing_the_group(ec2, vpc_id):
    """The bug this replaces: a rule failure reported the group as not created.

    The group exists either way. Calling that a failure means the user never
    goes looking for it, and it sits in the account untracked.
    """
    def refuse(*args, **kwargs):
        raise ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "denied"}},
            "AuthorizeSecurityGroupIngress",
        )

    ec2.authorize_security_group_ingress = refuse

    ok, sg_id, problems = sg.create_security_group(
        ec2, "half-made", "created by tests", vpc_id, [_rule(22)]
    )
    assert ok
    assert sg_id.startswith("sg-")
    assert any("rules were not applied" in p for p in problems)


def test_duplicate_name_reuses_the_group_and_says_so(ec2, vpc_id):
    first, _ = _make(ec2, vpc_id)
    ok, second, problems = sg.create_security_group(
        ec2, "test-sg", "created by tests", vpc_id, None
    )
    assert ok
    assert second == first
    assert any("already existed" in p for p in problems)


def test_the_bastion_pattern_can_be_built_and_read_back(ec2, vpc_id):
    """End to end: a private group that trusts a bastion group, not an address.

    This is the architecture the lab teaches, created by the tool rather than
    by hand, then read back and recognised by the scanner.
    """
    bastion_id, _ = _make(ec2, vpc_id, [_rule(22, source=MY_IP)],
                          name="bastion-sg")
    private_id, _ = _make(ec2, vpc_id, [_rule(22, source=f"sg:{bastion_id}")],
                          name="private-sg")

    bastion_rules = sg.read_group_for_scanning(ec2, bastion_id)
    assert [r["source"] for r in bastion_rules] == [MY_IP]
    assert check_firewall_rules(bastion_rules) == []

    private_rules = sg.read_group_for_scanning(ec2, private_id)
    assert [r["source"] for r in private_rules] == [f"sg:{bastion_id}"]

    findings = check_firewall_rules(private_rules)
    assert [w["level"] for w in findings] == [INFO]
    assert bastion_id in findings[0]["message"]


def test_a_bastion_group_open_to_the_world_is_still_critical(ec2, vpc_id):
    """The pattern is only as good as what the bastion itself accepts.

    A private group trusting a bastion is sound. A bastion accepting SSH from
    the entire internet makes the whole arrangement decorative, and the tool
    has to say so about the bastion even though the private group looks fine.
    """
    bastion_id, _ = _make(ec2, vpc_id, [_rule(22)], name="bastion-sg")
    private_id, _ = _make(ec2, vpc_id, [_rule(22, source=f"sg:{bastion_id}")],
                          name="private-sg")

    bastion = check_firewall_rules(sg.read_group_for_scanning(ec2, bastion_id))
    private = check_firewall_rules(sg.read_group_for_scanning(ec2, private_id))

    assert summarize(bastion)[CRITICAL] == 1
    assert summarize(private)[CRITICAL] == 0


def test_round_trip_open_ssh_is_flagged_when_read_back(ec2, vpc_id):
    """The full read path: create, fetch live rules, scan what is actually there."""
    sg_id, _ = _make(ec2, vpc_id, [_rule(22)])

    live = sg.read_group_for_scanning(ec2, sg_id)
    assert any(r["source"] == WORLD for r in live)

    warnings = check_firewall_rules(live)
    assert summarize(warnings)[CRITICAL] == 1
    assert fixable(warnings)


def test_rules_come_back_with_ids_attached(ec2, vpc_id):
    """No rule ID means no fix button. This is the load-bearing assertion."""
    sg_id, _ = _make(ec2, vpc_id, [_rule(22), _rule(3389)])

    live = sg.read_group_for_scanning(ec2, sg_id)
    assert len(live) == 2
    for r in live:
        assert r["rule_id"], r
        assert r["rule_id"].startswith("sgr-")
        assert r["resource_id"] == sg_id


def test_a_firewall_finding_says_which_group_it_came_from(ec2, vpc_id):
    """Without this the finding names a rule but not the group holding it.

    Harmless while a page shows one group at a time and wrong the moment an
    account-wide view lists findings from several together.
    """
    sg_id, _ = _make(ec2, vpc_id, [_rule(22)])

    warnings = check_firewall_rules(sg.read_group_for_scanning(ec2, sg_id))
    assert warnings
    for w in warnings:
        assert w["resource_id"] == sg_id, w


# ---------------------------------------------------------------- The fix path


def test_remove_rule_actually_removes_it(ec2, vpc_id):
    sg_id, _ = _make(ec2, vpc_id, [_rule(22)])
    live = sg.read_group_for_scanning(ec2, sg_id)

    ok, msg = sg.remove_rule(ec2, sg_id, live[0]["rule_id"])
    assert ok, msg
    assert sg.read_group_for_scanning(ec2, sg_id) == []


def test_narrowing_closes_the_world_and_opens_one_address(ec2, vpc_id):
    """The demo moment, verified end to end rather than assumed."""
    sg_id, _ = _make(ec2, vpc_id, [_rule(22)])

    before = sg.read_group_for_scanning(ec2, sg_id)
    warning = check_firewall_rules(before)[0]

    ok, msg = sg.apply_fix(ec2, sg_id, warning, new_cidr=MY_IP)
    assert ok, msg

    after = sg.read_group_for_scanning(ec2, sg_id)
    sources = [r["source"] for r in after]
    assert WORLD not in sources
    assert MY_IP in sources
    assert check_firewall_rules(after) == []


def test_narrowing_leaves_the_port_and_protocol_alone(ec2, vpc_id):
    """Narrowing the source must not quietly change what the rule allows."""
    sg_id, _ = _make(ec2, vpc_id, [_rule(22)])
    warning = check_firewall_rules(sg.read_group_for_scanning(ec2, sg_id))[0]

    ok, msg = sg.apply_fix(ec2, sg_id, warning, new_cidr=MY_IP)
    assert ok, msg

    after = sg.read_group_for_scanning(ec2, sg_id)[0]
    assert after["from_port"] == 22
    assert after["to_port"] == 22
    assert after["protocol"] == "tcp"


def test_narrowing_one_rule_leaves_the_others_untouched(ec2, vpc_id):
    sg_id, _ = _make(ec2, vpc_id, [_rule(22), _rule(443), _rule(3389)])
    live = sg.read_group_for_scanning(ec2, sg_id)

    ssh = next(r for r in live if r["from_port"] == 22)
    warning = next(
        w for w in check_firewall_rules(live) if w["rule_id"] == ssh["rule_id"]
    )

    ok, msg = sg.apply_fix(ec2, sg_id, warning, new_cidr=MY_IP)
    assert ok, msg

    after = {r["from_port"]: r["source"]
             for r in sg.read_group_for_scanning(ec2, sg_id)}
    assert after[22] == MY_IP
    assert after[443] == WORLD
    assert after[3389] == WORLD


def test_fixing_every_finding_clears_the_scan(ec2, vpc_id):
    """Create bad, scan, fix everything, re-scan clean."""
    sg_id, _ = _make(ec2, vpc_id, [_rule(22), _rule(3389), _rule(3306)])

    before = check_firewall_rules(sg.read_group_for_scanning(ec2, sg_id))
    assert summarize(before)[CRITICAL] == 3

    for w in fixable(before):
        ok, msg = sg.apply_fix(ec2, sg_id, w, new_cidr=MY_IP)
        assert ok, msg

    after = check_firewall_rules(sg.read_group_for_scanning(ec2, sg_id))
    assert after == []


def test_remove_fix_deletes_the_rule_rather_than_narrowing_it(ec2, vpc_id):
    """A rule opening every port cannot be made safe by narrowing its source."""
    sg_id, _ = _make(ec2, vpc_id)
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": WORLD}]}],
    )

    warnings = check_firewall_rules(sg.read_group_for_scanning(ec2, sg_id))
    assert warnings[0]["fix"]["action"] == "remove"

    ok, msg = sg.apply_fix(ec2, sg_id, warnings[0])
    assert ok, msg
    assert sg.read_group_for_scanning(ec2, sg_id) == []


def test_ipv6_rule_refuses_an_ipv4_narrow_with_an_explanation(ec2, vpc_id):
    """AWS rejects a family switch with a message that explains nothing."""
    rule = _rule(22, source=WORLD_V6)
    ok, msg = sg.narrow_rule_to_ip(ec2, "sg-test", rule, new_cidr=MY_IP)
    assert not ok
    assert "IPv4" in msg and "IPv6" in msg


def test_narrowing_uses_the_detected_public_ip_when_none_is_given(monkeypatch):
    """The default path calls out to the network, so it needs to be swappable."""
    monkeypatch.setattr(sg, "my_public_ip", lambda: "198.51.100.7")

    captured = {}

    class FakeEc2:
        def modify_security_group_rules(self, **kwargs):
            captured.update(kwargs)

    ok, msg = sg.narrow_rule_to_ip(FakeEc2(), "sg-test", _rule(22))
    assert ok
    assert "198.51.100.7/32" in msg
    sent = captured["SecurityGroupRules"][0]["SecurityGroupRule"]
    assert sent["CidrIpv4"] == "198.51.100.7/32"
    assert sent["FromPort"] == 22


def test_apply_fix_rejects_a_warning_with_nothing_to_do():
    ok, msg = sg.apply_fix(None, "sg-test", {"level": CRITICAL, "message": "x"})
    assert not ok
    assert "Nothing to fix" in msg


# --------------------------------------------------------------------- Teardown


def test_cleanup_removes_only_managed_groups(ec2, vpc_id):
    _make(ec2, vpc_id, name="ours-1")
    _make(ec2, vpc_id, name="ours-2")
    ec2.create_security_group(
        GroupName="not-ours", Description="left alone", VpcId=vpc_id
    )

    results = sg.cleanup_all_managed_groups(ec2)
    assert len(results) == 2
    assert all(ok for _, ok, _ in results)

    remaining = [g["GroupName"] for g in sg.list_security_groups(ec2)]
    assert "not-ours" in remaining
    assert "ours-1" not in remaining
    assert "ours-2" not in remaining


def test_cleanup_on_an_empty_account_is_not_an_error(ec2):
    assert sg.cleanup_all_managed_groups(ec2) == []
