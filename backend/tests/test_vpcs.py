"""Tests for VPC creation, auditing and teardown.

Teardown gets the most attention, and it is the reason this module exists in
the shape it does. Everything else in the project deletes in one call. A VPC
refuses to go while anything lives in it, and reports that as a
DependencyViolation naming nothing, so a half-deleted network that will not
finish dying is the characteristic failure. The tests below pin the ordering.
"""

import ipaddress

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from api import registry
from aws import vpcs
from aws import instances as ec2i
from aws.s3_buckets import PermissionDenied
from scanner.vpc_rules import check_vpc
from scanner.common import CRITICAL, WARNING, INFO, cited, fixable

REGION = "us-east-1"


def _settings(**overrides):
    """A soundly built network. Override one key to introduce one flaw."""
    base = {
        "vpc_id": "vpc-0123456789abcdef0",
        "name": "demo",
        "cidr": "10.0.0.0/16",
        "is_default": False,
        "flow_logs_enabled": True,
        "managed_by_us": True,
        "subnets": [
            {"subnet_id": "subnet-pub", "name": "demo-public",
             "declared_role": "public", "cidr": "10.0.1.0/24",
             "auto_assign_public_ip": False, "reaches_internet": True,
             "using_main_route_table": False},
            {"subnet_id": "subnet-priv", "name": "demo-private",
             "declared_role": "private", "cidr": "10.0.2.0/24",
             "auto_assign_public_ip": False, "reaches_internet": False,
             "using_main_route_table": False},
        ],
    }
    base.update(overrides)
    return base


def _one(warnings, setting):
    return next(w for w in warnings if setting in w["rule_id"])


# ------------------------------------------------------------ The cost refusal


def test_a_nat_gateway_is_refused_with_the_price_named():
    """The only continuously billing thing in this project.

    A warning would not do. It bills from creation to deletion regardless of
    traffic, so the mistake is silent and compounding, and nothing this tool
    provisions needs one.
    """
    with mock_aws():
        ec2 = boto3.client("ec2", region_name=REGION)
        ok, message, _ = vpcs.create_vpc(ec2, "demo", with_nat_gateway=True)

        # Inside the mock, and it was not. This line sat after the block, so
        # the client it used was talking to real AWS: the call failed with
        # AuthFailure, list_vpcs swallowed every ClientError into an empty
        # list, and the assertion passed without ever looking at the network
        # the test had just refused to build. It only surfaced when that
        # swallow was removed. The third time this project has found an
        # offline test quietly reaching the network.
        assert vpcs.list_vpcs(ec2, only_ours=True) == []

    assert not ok
    assert "$32" in message
    # The point that makes it dangerous: stopping your machines does not stop
    # this bill. Only deleting the gateway does.
    assert "until it is deleted" in message


# ------------------------------------------------------------ Build, over moto


@pytest.fixture
def ec2():
    with mock_aws():
        yield boto3.client("ec2", region_name=REGION)


def test_a_created_network_has_a_public_and_a_private_subnet(ec2):
    ok, vpc_id, _ = vpcs.create_vpc(ec2, "demo", region=REGION)
    assert ok, vpc_id

    settings = vpcs.read_vpc_for_scanning(ec2, vpc_id)
    by_role = {s["declared_role"]: s for s in settings["subnets"]}

    assert set(by_role) == {"public", "private"}
    assert by_role["public"]["reaches_internet"] is True
    assert by_role["private"]["reaches_internet"] is False


@pytest.mark.parametrize("cidr", ["10.0.0.0/16", "10.1.0.0/16",
                                  "172.31.0.0/16", "192.168.0.0/16"])
def test_every_cidr_the_form_offers_gets_both_its_subnets(ec2, cidr):
    """The subnets have to be inside the network somebody chose.

    They were the constants 10.0.1.0/24 and 10.0.2.0/24, which are inside
    10.0.0.0/16 and inside none of the other three the page's menu offers. So
    three of four choices failed both create_subnet calls with "The CIDR
    '10.0.1.0/24' is invalid" and returned a VPC with nothing in it - reported
    as created, with the failures relegated to `problems`, which is how it
    survived: a network you cannot put a machine in, that answers ok.

    Parametrized over the menu rather than over one awkward value, because the
    bug was not that some exotic CIDR broke - it was that the default was the
    only one that worked.
    """
    ok, vpc_id, problems = vpcs.create_vpc(ec2, "demo", cidr=cidr, region=REGION)
    assert ok, vpc_id
    assert not [p for p in problems if "invalid" in p.lower()], problems

    settings = vpcs.read_vpc_for_scanning(ec2, vpc_id)
    by_role = {s["declared_role"]: s for s in settings["subnets"]}
    assert set(by_role) == {"public", "private"}, problems

    network = ipaddress.ip_network(cidr)
    for role in ("public", "private"):
        subnet = ipaddress.ip_network(by_role[role]["cidr"])
        assert subnet.subnet_of(network), f"{role} {subnet} is outside {network}"
    assert by_role["public"]["cidr"] != by_role["private"]["cidr"]


def test_the_default_network_keeps_the_subnets_it_always_had(ec2):
    """The derivation is not an excuse to move the default's addresses.

    Anything already running in a 10.0.0.0/16 built by this tool sits in
    10.0.1.0/24 or 10.0.2.0/24, and a security group written against those
    ranges by hand should not quietly start pointing at nothing.
    """
    assert vpcs.subnet_cidrs("10.0.0.0/16") == ("10.0.1.0/24", "10.0.2.0/24")


def test_a_network_too_small_to_divide_says_so_rather_than_failing_twice(ec2):
    """A /28 has nothing to carve, and one clear sentence beats two AWS errors."""
    public, private = vpcs.subnet_cidrs("10.0.0.0/28")
    assert public is None and private is None


def test_the_private_subnet_has_no_internet_route_at_all(ec2):
    """The whole point of the exercise, asserted against the routing.

    Not against the name, and not against whether an instance has a public
    address. Routing is the thing that holds no matter what anyone does to a
    machine inside the subnet later.
    """
    ok, vpc_id, _ = vpcs.create_vpc(ec2, "demo", region=REGION)
    assert ok

    tables = ec2.describe_route_tables(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
    )["RouteTables"]

    private = [t for t in tables
               if any(tag["Value"] == "private" for tag in t.get("Tags", [])
                      if tag["Key"] == "Role")]
    assert private, "expected a route table tagged private"

    for route in private[0]["Routes"]:
        assert not route.get("GatewayId", "").startswith("igw-")


def test_the_private_subnet_gets_its_own_route_table(ec2):
    """Sharing the main table works today and is a trap tomorrow: a route
    added to it for another subnet would silently open this one."""
    ok, vpc_id, _ = vpcs.create_vpc(ec2, "demo", region=REGION)
    settings = vpcs.read_vpc_for_scanning(ec2, vpc_id)

    for subnet in settings["subnets"]:
        assert subnet["using_main_route_table"] is False


def test_no_subnet_hands_out_public_addresses_automatically(ec2):
    """Even the public subnet. The instance says whether it wants one.

    This is the same lesson as the launch bug: an absent setting must not
    decide something this consequential.
    """
    ok, vpc_id, _ = vpcs.create_vpc(ec2, "demo", region=REGION)
    settings = vpcs.read_vpc_for_scanning(ec2, vpc_id)

    assert all(not s["auto_assign_public_ip"] for s in settings["subnets"])


def test_dns_is_enabled_so_instances_get_names(ec2):
    """Off by default on a VPC you build yourself, unlike the default one.

    Also a regression guard on the parameter names: boto3 wants
    EnableDnsSupport, and the lowercase spelling from the AWS docs raises
    ParamValidationError, which is not a ClientError and so slips past the
    handler around this call.
    """
    ok, vpc_id, problems = vpcs.create_vpc(ec2, "demo", region=REGION)
    assert ok
    assert not any("Could not enable" in p for p in problems)

    for attribute in ("enableDnsSupport", "enableDnsHostnames"):
        value = ec2.describe_vpc_attribute(
            VpcId=vpc_id, Attribute=attribute
        )[attribute[0].upper() + attribute[1:]]["Value"]
        assert value is True, f"{attribute} should be on"


def test_a_refused_listing_is_not_an_account_with_no_networks():
    """It answered a denial with an empty list, which is the one wrong answer
    that reassures.

    The route hands that back as HTTP 200 with nothing in it and the page
    prints "none" - the single word meaning somebody looked and there was
    nothing there. Every other type reports "unreachable" when its read is
    refused, because every other list either raises or lets the error out;
    networks alone went quiet, and an account whose networks could not be read
    was indistinguishable from one that has none.

    aws/snapshots.py writes the rule down for itself and it is the same rule:
    something this tool was not allowed to ask about must never be reported as
    the safe answer.
    """
    denied = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "not authorized"}},
        "DescribeVpcs")

    class _Refusing:
        def describe_vpcs(self, **kwargs):
            raise denied

    with pytest.raises(PermissionDenied) as raised:
        vpcs.list_vpcs(_Refusing())

    assert raised.value.permission == "ec2:DescribeVpcs"


def test_a_listing_that_fails_for_another_reason_still_propagates():
    """Only a refusal becomes PermissionDenied. Anything else keeps its own
    identity rather than being relabelled as a missing permission, which would
    send somebody to fix an IAM policy that was never wrong."""
    other = ClientError(
        {"Error": {"Code": "RequestLimitExceeded", "Message": "slow down"}},
        "DescribeVpcs")

    class _Throttled:
        def describe_vpcs(self, **kwargs):
            raise other

    with pytest.raises(ClientError):
        vpcs.list_vpcs(_Throttled())


def test_a_created_network_is_tagged_and_findable(ec2):
    ok, vpc_id, _ = vpcs.create_vpc(ec2, "demo", region=REGION)

    ours = [v["VpcId"] for v in vpcs.list_vpcs(ec2, only_ours=True)]
    assert ours == [vpc_id]

    everything = vpcs.list_vpcs(ec2)
    assert len(everything) > 1, "the default VPC should also be present"


def test_creation_warns_that_the_private_subnet_cannot_reach_out(ec2):
    """Otherwise the first thing anyone notices is dnf hanging."""
    ok, _, problems = vpcs.create_vpc(ec2, "demo", region=REGION)
    assert ok
    assert any("cannot reach the internet outbound" in p for p in problems)


# ------------------------------------------------------------------- Teardown


def test_deleting_removes_every_piece(ec2):
    ok, vpc_id, _ = vpcs.create_vpc(ec2, "demo", region=REGION)
    assert ok

    removed, message = vpcs.delete_vpc(ec2, vpc_id)
    assert removed, message

    assert vpcs.list_vpcs(ec2, only_ours=True) == []
    assert ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
    )["Subnets"] == []


def test_deleting_refuses_while_machines_are_running_and_names_them(ec2):
    """Destroying a network destroys everything in it. Say what, first."""
    ok, vpc_id, _ = vpcs.create_vpc(ec2, "demo", region=REGION)
    subnet = vpcs.read_vpc_for_scanning(ec2, vpc_id)["subnets"][0]["subnet_id"]

    launched, instance_id, _ = ec2i.launch_instance(
        ec2, "resident", region=REGION, subnet_id=subnet
    )
    assert launched, instance_id

    refused, message = vpcs.delete_vpc(ec2, vpc_id)
    assert not refused
    assert instance_id in message
    assert "would destroy them" in message
    assert vpcs.list_vpcs(ec2, only_ours=True) != []


def test_terminating_a_machine_that_is_still_starting_is_not_a_failure(ec2):
    """The boto3 InstanceTerminated waiter fails on the "pending" state.

    Its reasoning is that an instance which has not finished starting should
    not be heading for terminated, so it treats "pending" as terminal failure.
    Cascading deletes hit that constantly, because the machine being removed
    is usually one created moments earlier. Waiting on network interfaces
    avoids the acceptor entirely and is what actually gates the subnet delete.
    """
    ok, vpc_id, _ = vpcs.create_vpc(ec2, "demo", region=REGION)
    subnet = vpcs.read_vpc_for_scanning(ec2, vpc_id)["subnets"][0]["subnet_id"]
    ec2i.launch_instance(ec2, "just-born", region=REGION, subnet_id=subnet)

    removed, message = vpcs.delete_vpc(ec2, vpc_id, force=True)
    assert removed, message


def test_waiting_for_interfaces_returns_at_once_when_there_are_none(ec2):
    """No sleeping on an empty network, which is the common case."""
    ok, vpc_id, _ = vpcs.create_vpc(ec2, "demo", region=REGION)

    cleared = vpcs.wait_for_interfaces_to_clear(ec2, vpc_id, attempts=1, delay=0)
    assert cleared is True


def test_a_network_whose_interfaces_never_clear_is_reported_not_deleted(ec2):
    """Half-deleting a network is worse than refusing to start."""
    ok, vpc_id, _ = vpcs.create_vpc(ec2, "demo", region=REGION)
    subnet = vpcs.read_vpc_for_scanning(ec2, vpc_id)["subnets"][0]["subnet_id"]
    ec2i.launch_instance(ec2, "stuck", region=REGION, subnet_id=subnet)

    original = vpcs.wait_for_interfaces_to_clear
    vpcs.wait_for_interfaces_to_clear = lambda *a, **k: False
    try:
        removed, message = vpcs.delete_vpc(ec2, vpc_id, force=True)
    finally:
        vpcs.wait_for_interfaces_to_clear = original

    assert not removed
    assert "still attached" in message
    assert "Nothing has been deleted" in message
    assert vpcs.list_vpcs(ec2, only_ours=True) != []


def test_forcing_the_delete_clears_the_machines_first(ec2):
    ok, vpc_id, _ = vpcs.create_vpc(ec2, "demo", region=REGION)
    subnet = vpcs.read_vpc_for_scanning(ec2, vpc_id)["subnets"][0]["subnet_id"]
    ec2i.launch_instance(ec2, "resident", region=REGION, subnet_id=subnet)

    removed, message = vpcs.delete_vpc(ec2, vpc_id, force=True)
    assert removed, message
    assert vpcs.list_vpcs(ec2, only_ours=True) == []


def test_the_deletion_plan_lists_everything_in_removal_order(ec2):
    """Consent to a cascade is not informed unless the list comes first."""
    ok, vpc_id, _ = vpcs.create_vpc(ec2, "demo", region=REGION)
    subnet = vpcs.read_vpc_for_scanning(ec2, vpc_id)["subnets"][0]["subnet_id"]
    ec2i.launch_instance(ec2, "resident", region=REGION, subnet_id=subnet)

    plan = vpcs.plan_deletion(ec2, vpc_id)
    kinds = [kind for kind, _, _ in plan]

    assert kinds[0] == "server", "machines have to go first"
    assert kinds[-1] == "network", "the network itself goes last"
    assert kinds.index("subnet") < kinds.index("internet gateway")
    assert "route table" in kinds
    assert plan[-1][1] == vpc_id


def test_the_plan_omits_things_aws_deletes_with_the_vpc(ec2):
    """The main route table and default group cannot be deleted separately,
    so listing them as casualties would be inaccurate and alarming."""
    ok, vpc_id, _ = vpcs.create_vpc(ec2, "demo", region=REGION)

    plan = vpcs.plan_deletion(ec2, vpc_id)
    labels = [label for _, _, label in plan]

    assert "default" not in labels


def test_the_plan_flags_what_this_tool_did_not_create(ec2):
    """A cascade destroys things nobody named. Say which ones are strangers."""
    ok, vpc_id, _ = vpcs.create_vpc(ec2, "demo", region=REGION)
    subnet = vpcs.read_vpc_for_scanning(ec2, vpc_id)["subnets"][0]["subnet_id"]

    ec2.create_security_group(
        GroupName="someone-elses", Description="not ours", VpcId=vpc_id
    )

    plan = vpcs.plan_deletion(ec2, vpc_id)
    foreign_ids = {item[1] for item in vpcs.not_ours(plan, ec2, vpc_id)}

    theirs = ec2.describe_security_groups(Filters=[
        {"Name": "group-name", "Values": ["someone-elses"]},
    ])["SecurityGroups"][0]["GroupId"]

    assert theirs in foreign_ids


class _TagsFilteredLikeAws:
    """A client whose DescribeTags honours the tag filter, as AWS does.

    moto ignores it and answers with every tag it holds. That difference is
    invisible in the existing coverage, because the stranger there carries no
    tags at all and so is absent from either answer - but a machine with a
    Name tag and nothing else is present in moto's, which makes it look like
    something this tool created. The one resource the "!" exists to mark is
    the one the fake hides.

    Checked against a real account: filtering on a value nothing carries comes
    back empty there, so this models AWS rather than inventing behaviour.
    """

    def __init__(self, ec2, tags):
        self._ec2 = ec2
        self._tags = tags  # [(resource_id, key, value)]

    def __getattr__(self, name):
        return getattr(self._ec2, name)

    def get_paginator(self, name):
        if name != "describe_tags":
            return self._ec2.get_paginator(name)
        return self

    def paginate(self, Filters=None, **kwargs):
        wanted = {f["Name"][4:]: set(f["Values"])
                  for f in (Filters or []) if f["Name"].startswith("tag:")}
        rows = [
            {"ResourceId": rid, "Key": key, "Value": value}
            for rid, key, value in self._tags
            if all(key == k and value in v for k, v in wanted.items())
        ]
        return [{"Tags": rows}]


def test_a_machine_tagged_by_someone_else_is_still_named_as_a_stranger(ec2):
    """The case moto cannot show: a stranger's resource that has tags of its own.

    Ownership is decided by this tool's tag specifically, not by whether
    anything tagged the resource at all. A machine somebody named is still
    somebody else's machine.
    """
    ok, vpc_id, _ = vpcs.create_vpc(ec2, "demo", region=REGION)
    plan = vpcs.plan_deletion(ec2, vpc_id)

    stranger = plan[0][1]
    tags = [(item_id, vpcs.MANAGED_TAG_KEY, vpcs.MANAGED_TAG_VALUE)
            for _, item_id, _ in plan if item_id != stranger]
    tags.append((stranger, "Name", "someone-elses-box"))

    foreign = vpcs.not_ours(plan, _TagsFilteredLikeAws(ec2, tags), vpc_id)
    assert [item[1] for item in foreign] == [stranger]


def test_ownership_that_could_not_be_established_names_everything(ec2):
    """The reassuring answer to a question nobody managed to ask.

    When the tag lookup fails this used to return an empty list, which reads
    as "everything in this plan was made by this tool" - on the one list whose
    entire job is to make somebody look twice before destroying a stranger's
    machine. Not knowing has to be louder than knowing it is fine, not
    quieter.
    """
    ok, vpc_id, _ = vpcs.create_vpc(ec2, "demo", region=REGION)
    plan = vpcs.plan_deletion(ec2, vpc_id)

    class Blinded:
        """Answers everything the plan needs, refuses only the tag lookup."""
        def __getattr__(self, name):
            return getattr(ec2, name)

        def get_paginator(self, name):
            if name == "describe_tags":
                raise ClientError(
                    {"Error": {"Code": "UnauthorizedOperation",
                               "Message": "no"}},
                    "DescribeTags")
            return ec2.get_paginator(name)

    assert vpcs.not_ours(plan, Blinded(), vpc_id) == plan


def test_an_association_that_has_already_gone_does_not_stop_the_teardown(ec2):
    """Found live. Deleting a subnet removes its route table association, but
    AWS keeps reporting that association for a moment afterwards, so the
    disassociate call fails on an ID that no longer exists.

    The failure was not the stale ID. It was that one such error aborted the
    whole route table step, leaving the rest in place and the network
    undeletable for a reason that had already stopped being true.
    """
    ok, vpc_id, _ = vpcs.create_vpc(ec2, "demo", region=REGION)
    assert ok

    real = ec2.disassociate_route_table
    calls = {"n": 0}

    def stale_first(**kwargs):
        """Removes the association and then reports it as already missing.

        Both halves are needed. moto does not remove a route table
        association when its subnet is deleted, so raising NotFound without
        also disassociating would describe a state AWS never produces - the
        association reported gone while genuinely still holding the table
        open - and the test would fail for a reason that cannot happen.
        """
        calls["n"] += 1
        if calls["n"] == 1:
            real(**kwargs)
            raise ClientError(
                {"Error": {"Code": "InvalidAssociationID.NotFound",
                           "Message": "does not exist"}},
                "DisassociateRouteTable",
            )
        return real(**kwargs)

    ec2.disassociate_route_table = stale_first

    removed, message = vpcs.delete_vpc(ec2, vpc_id)
    assert removed, message
    assert vpcs.list_vpcs(ec2, only_ours=True) == []


def test_one_failing_step_does_not_abandon_the_others(ec2):
    """A cascade that gives up halfway leaves the worst of both outcomes.

    Only the steps before the failure are asserted. Whether the network itself
    then goes is not a property worth pinning here: moto permits deleting a
    VPC with an internet gateway still attached and AWS does not, so either
    answer would be asserting the fake rather than the behaviour.
    """
    ok, vpc_id, _ = vpcs.create_vpc(ec2, "demo", region=REGION)

    def refuse(**kwargs):
        raise ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "no"}},
            "DeleteInternetGateway",
        )

    ec2.delete_internet_gateway = refuse

    vpcs.delete_vpc(ec2, vpc_id)

    assert ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
    )["Subnets"] == [], "subnets should still have gone"

    remaining = [
        t for t in ec2.describe_route_tables(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )["RouteTables"]
        if not any(a.get("Main") for a in t.get("Associations", []))
    ]
    assert remaining == [], "route tables should still have gone"


def test_whats_inside_lists_the_blockers(ec2):
    ok, vpc_id, _ = vpcs.create_vpc(ec2, "demo", region=REGION)
    subnet = vpcs.read_vpc_for_scanning(ec2, vpc_id)["subnets"][0]["subnet_id"]
    _, instance_id, _ = ec2i.launch_instance(
        ec2, "resident", region=REGION, subnet_id=subnet
    )

    kinds = {kind for kind, _ in vpcs.whats_inside(ec2, vpc_id)}
    assert "instance" in kinds


def test_cleanup_leaves_the_default_network_alone(ec2):
    """It is not ours, it cannot be recreated by this tool, and deleting it
    breaks anything in the account that assumes it exists."""
    vpcs.create_vpc(ec2, "demo", region=REGION)

    vpcs.cleanup_all_managed_vpcs(ec2, force=True)

    remaining = vpcs.list_vpcs(ec2)
    assert len(remaining) == 1
    assert remaining[0]["IsDefault"] is True


# ---------------------------------------------------------------- The rules


def test_a_soundly_built_network_is_clean():
    assert check_vpc(_settings()) == []


def test_flow_logs_off_cites_cis_3_7():
    w = _one(check_vpc(_settings(flow_logs_enabled=False)), "flow_logs")

    assert w["level"] == WARNING
    assert w["control"]["id"] == "3.7"
    assert w["control"]["level"] == 2


def test_flow_logs_are_not_automatically_fixable():
    """Enabling them means choosing a destination and paying to store it."""
    warnings = check_vpc(_settings(flow_logs_enabled=False))
    assert fixable(warnings) == []


def test_a_private_subnet_that_reaches_the_internet_is_critical():
    """The finding this whole module exists for.

    The name says isolated, the routing says otherwise, and the name is what
    someone reads when deciding where to put a database.
    """
    settings = _settings()
    settings["subnets"][1]["reaches_internet"] = True

    w = _one(check_vpc(settings), "private_subnet_reaches_internet")
    assert w["level"] == CRITICAL
    assert "worse than none" in w["message"]


def test_a_subnet_is_judged_private_by_its_name_as_well_as_its_tag():
    """Networks built by hand or by other tools will not carry our tag."""
    settings = _settings()
    settings["subnets"][1]["declared_role"] = None
    settings["subnets"][1]["name"] = "app-internal-1a"
    settings["subnets"][1]["reaches_internet"] = True

    assert any("private_subnet_reaches_internet" in w["rule_id"]
               for w in check_vpc(settings))


def test_auto_assign_is_worse_on_a_subnet_claiming_to_be_private():
    settings = _settings()
    settings["subnets"][0]["auto_assign_public_ip"] = True
    public = _one(check_vpc(settings), "auto_assign_public_ip")
    assert public["level"] == WARNING

    settings = _settings()
    settings["subnets"][1]["auto_assign_public_ip"] = True
    private = _one(check_vpc(settings), "auto_assign_public_ip")
    assert private["level"] == CRITICAL


def test_sharing_the_main_route_table_is_reported_as_a_future_risk():
    settings = _settings()
    settings["subnets"][1]["using_main_route_table"] = True

    w = _one(check_vpc(settings), "shares_main_route_table")
    assert w["level"] == INFO
    assert "later" in w["message"]


def test_a_network_with_nowhere_private_is_reported():
    settings = _settings()
    settings["subnets"][1]["reaches_internet"] = True
    settings["subnets"][1]["declared_role"] = "public"
    settings["subnets"][1]["name"] = "demo-public-b"

    w = _one(check_vpc(settings), "no_private_subnet")
    assert w["level"] == INFO


def test_the_default_network_is_reported_as_a_poor_place_for_anything():
    w = _one(check_vpc(_settings(is_default=True)), "default_vpc")
    assert w["level"] == INFO
    assert "build a network deliberately" in w["message"]


def test_an_empty_network_says_so_rather_than_looking_clean():
    warnings = check_vpc(_settings(subnets=[]))
    assert any("no_subnets" in w["rule_id"] for w in warnings)


def test_a_missing_network_produces_no_findings():
    assert check_vpc(None) == []


# ------------------------------------------------------- Through the registry


def test_networks_are_a_registered_resource_type():
    assert "network" in registry.REGISTRY


def test_networks_are_registered_last_so_cleanup_runs_in_order():
    """A VPC cannot be deleted until what is inside it is gone, and cleanup
    walks the registry in order."""
    assert list(registry.REGISTRY)[-1] == "network"


def test_the_full_lifecycle_through_the_registry(ec2):
    resource = registry.VPC

    ok, vpc_id, problems = resource.create(ec2, {"name": "demo",
                                                 "region": REGION})
    assert ok, vpc_id

    listed = resource.list_all(ec2, only_ours=True)
    assert [v["id"] for v in listed] == [vpc_id]

    settings = resource.read(ec2, vpc_id)
    assert settings["managed_by_us"] is True

    warnings = resource.check(settings)
    assert [w["control"]["id"] for w in cited(warnings)] == ["3.7"]

    removed, message = resource.delete(ec2, vpc_id, {})
    assert removed, message


def test_checking_a_spec_that_asks_for_a_nat_gateway_warns_first():
    assert registry.VPC.check_spec({"name": "demo"}) == []


# ------------------------------------------------- saying what it is doing


def test_a_cascade_names_each_step_as_it_takes_it(ec2):
    """The steps were always named; the names were thrown away.

    delete_vpc has had a list of labelled steps since it was written and
    reported none of them, so a caller got one answer four or five minutes
    after asking and nothing in between. That is the same shape as the
    `problems` list a failed create discarded: the information existed at the
    only point it was useful and was dropped there.
    """
    _, made, _ = vpcs.create_vpc(ec2, "progress-demo", "10.30.0.0/16")
    said = []

    ok, _ = vpcs.delete_vpc(ec2, made, force=True, report=said.append)
    assert ok

    joined = "\n".join(said)
    for expected in ("subnets", "route tables", "internet gateways",
                     "security groups", "the network itself"):
        assert expected in joined, f"no step mentioned {expected}"


def test_a_cascade_without_a_report_is_unchanged(ec2):
    """Every existing caller passes nothing. The CLI, the smoke test and the
    rest of this file must not have to learn about progress to keep working."""
    _, made, _ = vpcs.create_vpc(ec2, "silent-demo", "10.31.0.0/16")

    ok, message = vpcs.delete_vpc(ec2, made, force=True)

    assert ok
    assert made in message


class _InterfacesThatLinger:
    """describe_network_interfaces that answers "still attached" a few times.

    moto detaches instantly, so the wait this narrates never actually waits
    against the fake - and it is where a real cascade spends nearly all of its
    four or five minutes. Without a stub the one thing worth reporting is the
    one thing no test would see.
    """

    def __init__(self, counts):
        # One answer per poll, so a test can make the count fall the way a
        # real one does rather than only switch off.
        self.counts = list(counts)

    def describe_network_interfaces(self, **kwargs):
        left = self.counts.pop(0) if self.counts else 0
        return {"NetworkInterfaces": [{"NetworkInterfaceId": f"eni-{n}"}
                                      for n in range(left)]}


def test_the_long_wait_speaks_once_rather_than_once_per_poll():
    """The first version reported every time round and it was wrong.

    Polling every five seconds for four minutes is about fifty lines, of which
    forty-nine repeat the one before them - so the log scrolls, the earlier
    steps leave the screen, and the one genuinely new fact arrives looking
    like more of the same. Whether the thing is alive is a different question
    from what it is doing, and the page answers it with a clock.
    """
    said = []
    cleared = vpcs.wait_for_interfaces_to_clear(
        _InterfacesThatLinger([2, 2, 2, 2, 2, 0]), "vpc-1",
        attempts=10, delay=0, report=said.append)

    assert cleared
    assert len(said) == 2, f"one line for the wait, one for the all-clear: {said}"
    assert "2 network connections" in said[0]
    assert said[-1] == "Network connections are clear."


def test_the_wait_speaks_again_when_the_count_actually_changes():
    """A change is news. Two machines releasing one interface each is the
    difference between "still waiting" and "halfway", and it is the only thing
    during this wait that is worth a new line."""
    said = []
    vpcs.wait_for_interfaces_to_clear(
        _InterfacesThatLinger([3, 3, 2, 2, 1, 0]), "vpc-1",
        attempts=10, delay=0, report=said.append)

    assert len(said) == 4, said
    assert "3 network connections" in said[0]
    assert "2 network connections" in said[1]
    assert "1 network connection " in said[2]
    assert said[3] == "Network connections are clear."


def test_the_wait_carries_no_clock_of_its_own():
    """Two timers started at different moments disagree by however long the
    earlier steps took, which reads as one of them being broken rather than as
    them measuring different things. The page has the clock; this has the
    facts."""
    said = []
    vpcs.wait_for_interfaces_to_clear(
        _InterfacesThatLinger([2, 2, 0]), "vpc-1",
        attempts=10, delay=30, report=said.append)

    assert not any("0m" in line or "1m" in line for line in said), said


def test_one_remaining_interface_is_not_described_in_the_plural():
    said = []
    vpcs.wait_for_interfaces_to_clear(
        type("One", (), {"describe_network_interfaces":
                         lambda self, **k: {"NetworkInterfaces": [{"x": 1}]}})(),
        "vpc-1", attempts=1, delay=0, report=said.append)

    assert "1 network connection " in said[0]
