"""Tests for launching and auditing EC2 instances.

Everything runs against moto. No real instance is ever started by this file,
which matters more here than elsewhere: this is the only resource in the
project that bills by the second.

The allowlist gets the most attention. It is the one piece of code standing
between a mistyped instance type and a bill, and unlike every other guardrail
here its failure mode is silent — a launch that succeeds and keeps succeeding.
"""

import boto3
import pytest
from botocore.exceptions import WaiterError
from moto import mock_aws

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from api import registry
from aws import instances as ec2i
from aws import key_pairs as kp
from aws import security_groups as sg
from aws import vpcs
from scanner.instance_rules import check_instance
from scanner.key_pair_rules import check_key_pair
from scanner.rules import check_firewall_rules
from scanner.common import CRITICAL, WARNING, INFO, fixable, cited

REGION = "us-east-1"
WORLD = "0.0.0.0/0"

ED25519 = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
    encoding=serialization.Encoding.OpenSSH,
    format=serialization.PublicFormat.OpenSSH,
).decode() + " user@example"


def _instance(**overrides):
    """A well configured instance. Override one key to introduce one flaw."""
    base = {
        "instance_id": "i-0123456789abcdef0",
        "name": "demo",
        "state": "running",
        "instance_type": "t3.micro",
        "public_ip": None,
        "private_ip": "10.0.0.5",
        "key_name": "demo-key",
        "imdsv2_required": True,
        "metadata_endpoint_enabled": True,
        "metadata_hop_limit": 1,
        "root_volume_encrypted": True,
        "security_group_ids": ["sg-1"],
        "has_instance_profile": False,
        "managed_by_us": True,
        "ssh_reachable": True,
    }
    base.update(overrides)
    return base


def _open_ssh_finding():
    return check_firewall_rules([{
        "rule_id": "sgr-1", "resource_id": "sg-1", "protocol": "tcp",
        "from_port": 22, "to_port": 22, "source": WORLD, "direction": "inbound",
    }])


# ------------------------------------------------------- The spending guardrail


def test_an_instance_type_off_the_allowlist_is_refused():
    """The single most important assertion in this file.

    Everything else here protects against a security mistake. This protects
    against a financial one, and it is the only guardrail whose absence would
    not be noticed until a bill arrived.
    """
    with mock_aws():
        ec2 = boto3.client("ec2", region_name=REGION)
        ok, message, _ = ec2i.launch_instance(
            ec2, "expensive", region=REGION, instance_type="p4d.24xlarge"
        )

    assert not ok
    assert "allowlist" in message
    assert "t3.micro" in message


def test_the_refusal_happens_before_any_aws_call():
    """Passing None as the client proves nothing was called.

    If the check ever moves after the API call, this raises AttributeError
    instead of returning cleanly, and the test fails.
    """
    ok, message, _ = ec2i.launch_instance(
        None, "expensive", region=REGION, instance_type="m5.24xlarge"
    )
    assert not ok
    assert "allowlist" in message


def test_every_allowed_type_is_small():
    """A cheap allowlist stops being a guardrail the moment something big
    is added to it without thinking."""
    for instance_type in ec2i.ALLOWED_INSTANCE_TYPES:
        family, size = instance_type.split(".")
        assert family.startswith("t"), f"{instance_type} is not burstable"
        assert size in ("nano", "micro", "small"), f"{instance_type} is large"


def test_the_default_type_is_on_the_allowlist():
    assert ec2i.DEFAULT_INSTANCE_TYPE in ec2i.ALLOWED_INSTANCE_TYPES


def test_graviton_types_ask_for_an_arm_image():
    """An x86 image on a t4g fails with an error that never says why."""
    assert ec2i.architecture_for("t4g.micro") == "arm64"
    assert ec2i.architecture_for("t3.micro") == "x86_64"


# ------------------------------------------------------------- Launch, on moto


@pytest.fixture
def ec2():
    with mock_aws():
        yield boto3.client("ec2", region_name=REGION)


def test_a_launched_instance_requires_imdsv2(ec2):
    """CIS 5.7 enforced at launch, not offered as an option."""
    ok, instance_id, _ = ec2i.launch_instance(ec2, "demo", region=REGION)
    assert ok, instance_id

    settings = ec2i.read_instance_for_scanning(ec2, instance_id)
    assert settings["imdsv2_required"] is True
    assert settings["metadata_hop_limit"] == 1


def test_a_launched_instance_is_tagged_and_findable(ec2):
    ok, instance_id, _ = ec2i.launch_instance(ec2, "demo", region=REGION)
    assert ok

    ours = [i["InstanceId"] for i in ec2i.list_instances(ec2, only_ours=True)]
    assert ours == [instance_id]


def test_a_launched_instance_has_no_public_address_by_default(ec2):
    """Every firewall mistake is survivable on a machine nothing can reach.

    This is not free. A default subnet sets MapPublicIpOnLaunch, so an instance
    launched into one gets a public address unless the request explicitly says
    not to. An earlier version left the field unset and let the subnet decide,
    which handed out public addresses while the tool reported the instance was
    private. Saying nothing is not the same as saying no.
    """
    ok, instance_id, _ = ec2i.launch_instance(ec2, "demo", region=REGION)
    assert ok
    assert ec2i.read_instance_for_scanning(ec2, instance_id)["public_ip"] is None


def test_the_subnet_default_does_not_decide_the_public_address(ec2):
    """Asserted against a subnet that would assign one, so it cannot pass by
    accident on a subnet that never would."""
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "default-for-az", "Values": ["true"]}]
    )["Subnets"]
    assert subnets, "expected a default subnet to test against"
    assert subnets[0]["MapPublicIpOnLaunch"] is True

    ok, private_id, _ = ec2i.launch_instance(
        ec2, "private", region=REGION, subnet_id=subnets[0]["SubnetId"]
    )
    ok_public, public_id, _ = ec2i.launch_instance(
        ec2, "public", region=REGION, subnet_id=subnets[0]["SubnetId"],
        assign_public_ip=True,
    )
    assert ok and ok_public

    assert ec2i.read_instance_for_scanning(ec2, private_id)["public_ip"] is None
    assert ec2i.read_instance_for_scanning(ec2, public_id)["public_ip"]


# ------------------------------------------------------ Which network it lands in


def test_a_launch_follows_its_security_groups_into_their_network(ec2):
    """The account default is not the answer when the request already implies one.

    A security group belongs to one network and cannot be attached to a machine
    in another. Falling back to the default VPC's subnet while holding a group
    from a network built here fails with InvalidParameterValue, which names
    neither the subnet nor the group and reads like the group itself is wrong.
    """
    ok, vpc_id, _ = vpcs.create_vpc(ec2, "elsewhere", region=REGION)
    assert ok, vpc_id

    created, group_id, _ = sg.create_security_group(
        ec2, "elsewhere-sg", "Managed by tests", vpc_id, []
    )
    assert created, group_id

    launched, instance_id, _ = ec2i.launch_instance(
        ec2, "follows-its-group", region=REGION, security_group_ids=[group_id]
    )
    assert launched, instance_id

    assert ec2i.read_instance_for_scanning(ec2, instance_id)["vpc_id"] == vpc_id


def test_a_subnet_is_never_borrowed_from_another_network(ec2):
    """Scoping to a VPC is a boundary, not a preference.

    Networks built by this tool have no default-for-az subnets, so the search
    always falls through to the second lookup. An unscoped fallback there
    returns whatever subnet the account happens to have, and the machine lands
    somewhere nobody asked for.
    """
    ok, vpc_id, _ = vpcs.create_vpc(ec2, "scoped", region=REGION)
    assert ok, vpc_id

    subnet_id, err = ec2i.default_subnet(ec2, vpc_id)
    assert not err, err

    ours = {s["SubnetId"] for s in ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
    )["Subnets"]}
    assert subnet_id in ours


def test_an_empty_network_is_an_error_rather_than_a_subnet_elsewhere(ec2):
    vpc_id = ec2.create_vpc(CidrBlock="10.9.0.0/16")["Vpc"]["VpcId"]

    subnet_id, err = ec2i.default_subnet(ec2, vpc_id)

    assert subnet_id is None
    assert "no subnets" in err


def test_groups_from_two_different_networks_decide_nothing(ec2):
    """Disagreement is not an answer, so the account default stands.

    AWS will reject the launch either way. The point is that a contradiction
    never gets resolved by picking one of the two at random.
    """
    other_vpc = ec2.create_vpc(CidrBlock="10.8.0.0/16")["Vpc"]["VpcId"]

    default_vpc, _ = sg.get_default_vpc(ec2)
    _, here, _ = sg.create_security_group(ec2, "here", "d", default_vpc, [])
    _, there, _ = sg.create_security_group(ec2, "there", "d", other_vpc, [])

    assert ec2i.vpc_of_groups(ec2, [here, there]) is None


def test_a_launched_instance_reports_where_it_landed(ec2):
    """Choosing a subnet is worth little if the tool cannot say which one it used."""
    ok, vpc_id, _ = vpcs.create_vpc(ec2, "reported", region=REGION)
    assert ok, vpc_id
    subnet = vpcs.read_vpc_for_scanning(ec2, vpc_id)["subnets"][0]["subnet_id"]

    launched, instance_id, _ = ec2i.launch_instance(
        ec2, "placed", region=REGION, subnet_id=subnet
    )
    assert launched, instance_id

    settings = ec2i.read_instance_for_scanning(ec2, instance_id)
    assert settings["subnet_id"] == subnet
    assert settings["vpc_id"] == vpc_id


def test_asking_for_a_public_address_says_what_that_means(ec2):
    ok, instance_id, problems = ec2i.launch_instance(
        ec2, "demo", region=REGION, assign_public_ip=True
    )
    assert ok, instance_id
    assert any("reachable from the internet" in p for p in problems)


def test_launching_without_a_key_pair_explains_the_consequence(ec2):
    ok, _, problems = ec2i.launch_instance(ec2, "demo", region=REGION)
    assert ok
    assert any("nobody can log in" in p for p in problems)


def test_a_launched_instance_scans_clean(ec2):
    ok, instance_id, _ = ec2i.launch_instance(ec2, "demo", region=REGION)
    assert ok

    settings = registry.INSTANCE.read(ec2, instance_id)
    warnings = registry.INSTANCE.check(settings)

    assert [w for w in warnings if w["level"] == CRITICAL] == []


def test_an_instance_is_readable_immediately_after_launching(ec2):
    """EC2 is eventually consistent and this used to fail against real AWS.

    RunInstances returns an ID that DescribeInstances cannot see for a second
    or two. The API's create endpoint reads the instance straight back to
    report what was actually made, so the race produced an intermittent 500
    claiming the instance did not exist.

    moto answers instantly and so cannot reproduce the race. This test only
    guards the shape - that launch returns something immediately readable. The
    live smoke test is what actually exercises the timing.
    """
    ok, instance_id, _ = ec2i.launch_instance(ec2, "demo", region=REGION)
    assert ok

    assert ec2i.read_instance_for_scanning(ec2, instance_id) is not None


def test_an_instance_that_never_becomes_visible_is_reported_as_billing(ec2):
    """If the wait times out the instance still exists and still costs money.

    Silence here would be the worst outcome: a running instance the tool
    created and then declined to mention.
    """
    class TimingOut:
        def wait(self, **kwargs):
            raise WaiterError(name="instance_exists", reason="timed out",
                              last_response={})

    real_get_waiter = ec2.get_waiter
    ec2.get_waiter = lambda name: (TimingOut() if name == "instance_exists"
                                   else real_get_waiter(name))

    ok, instance_id, problems = ec2i.launch_instance(ec2, "demo", region=REGION)

    assert ok
    assert any("running and billing" in p for p in problems)


def test_terminating_stops_the_billing_and_says_so(ec2):
    ok, instance_id, _ = ec2i.launch_instance(ec2, "demo", region=REGION)
    assert ok

    stopped, message = ec2i.terminate_instance(ec2, instance_id)
    assert stopped
    assert "Billing stops" in message


def test_cleanup_terminates_every_managed_instance(ec2):
    ec2i.launch_instance(ec2, "one", region=REGION)
    ec2i.launch_instance(ec2, "two", region=REGION)

    results = ec2i.cleanup_all_managed_instances(ec2)
    assert len(results) == 2
    assert all(ok for _, ok, _ in results)
    assert ec2i.list_instances(ec2, only_ours=True) == []


def test_terminated_instances_are_not_listed_as_present(ec2):
    """AWS keeps them visible for about an hour. Reporting them as present
    makes a cleanup screen untrustworthy."""
    ok, instance_id, _ = ec2i.launch_instance(ec2, "demo", region=REGION)
    ec2i.terminate_instance(ec2, instance_id)

    assert ec2i.list_instances(ec2, only_ours=True) == []
    assert len(ec2i.list_instances(ec2, only_ours=True,
                                   include_terminated=True)) == 1


# ------------------------------------------------------- The metadata service


def test_imdsv1_is_critical_and_cites_cis_5_7():
    w = check_instance(_instance(imdsv2_required=False))[0]

    assert w["level"] == CRITICAL
    assert w["control"]["id"] == "5.7"
    assert w["control"]["level"] == 1
    assert w["fix"]["action"] == "enforce_imdsv2"


def test_the_imdsv1_message_avoids_jargon():
    """It has to explain a subtle attack to someone who has not heard of it.

    "metadata" is deliberately not on this list. Acronyms and IP addresses are
    jargon: nobody can guess what IMDSv1 or 169.254.169.254 means, and printing
    them teaches nothing. "Metadata" is an ordinary English word and it is the
    actual name of the thing, so avoiding it entirely would make the message
    vaguer rather than clearer.
    """
    w = check_instance(_instance(imdsv2_required=False))[0]

    for jargon in ("imds", "imdsv1", "imdsv2", "169.254.169.254", "ssrf"):
        assert jargon not in w["message"].lower()
    assert "credentials" in w["message"]


def test_a_raised_hop_limit_is_flagged():
    """One extra hop is usually enough for a container to reach the host's
    credentials."""
    w = check_instance(_instance(metadata_hop_limit=2))[0]
    assert w["level"] == WARNING
    assert w["control"]["id"] == "5.7"


def test_the_metadata_service_switched_off_is_the_strongest_setting():
    w = check_instance(_instance(metadata_endpoint_enabled=False))[0]
    assert w["level"] == INFO
    assert w["fix"] is None


def test_a_correct_metadata_configuration_says_nothing():
    assert check_instance(_instance()) == []


# --------------------------------------------------------------- Reachability


def test_a_public_address_plus_open_ssh_is_exposure_not_risk():
    """The finding the whole composition exists for.

    Neither fact alone is alarming. A public IP with sound rules is normal, and
    an open rule on an unreachable machine is latent. Together they mean anyone
    can reach port 22 right now, and the reader should not have to work that out.
    """
    warnings = check_instance(
        _instance(public_ip="203.0.113.10"), _open_ssh_finding()
    )
    exposure = next(w for w in warnings
                    if w["rule_id"].endswith(":reachable_from_internet"))

    assert exposure["level"] == CRITICAL
    assert "203.0.113.10" in exposure["message"]
    assert "22" in exposure["message"]
    assert "it is exposure" in exposure["message"]


def test_open_rules_without_a_public_address_are_latent_not_urgent():
    warnings = check_instance(_instance(public_ip=None), _open_ssh_finding())
    latent = next(w for w in warnings
                  if w["rule_id"].endswith(":latent_exposure"))

    assert latent["level"] == INFO
    assert "nothing can reach it" in latent["message"]


def test_a_public_address_with_sound_rules_is_informational():
    warnings = check_instance(_instance(public_ip="203.0.113.10"), [])
    assert [w["level"] for w in warnings] == [INFO]


def test_a_private_instance_with_sound_rules_says_nothing():
    assert check_instance(_instance(), []) == []


# ----------------------------------------------------- Placement nobody chose


def _network_with_both_kinds(ec2):
    """A VPC with one routable subnet and one isolated one."""
    from aws import vpcs

    ok, vpc_id, _ = vpcs.create_vpc(ec2, "placement", region=REGION)
    assert ok, vpc_id

    layout = vpcs.read_vpc_for_scanning(ec2, vpc_id)
    by_role = {s["declared_role"]: s for s in layout["subnets"]}
    return vpc_id, by_role


def test_an_unnamed_subnet_prefers_the_one_with_no_route_out(ec2):
    """The two ways of being wrong here are not equally bad.

    A machine in an isolated subnet is unreachable, which is noticed at once
    and undone by relaunching. A machine in a routable subnet has quietly lost
    the stronger of its two protections and nobody finds out.
    """
    vpc_id, by_role = _network_with_both_kinds(ec2)

    chosen, err = ec2i.default_subnet(ec2, vpc_id)
    assert err is None
    assert chosen == by_role["private"]["subnet_id"]


def test_launching_without_a_subnet_lands_in_the_private_one(ec2):
    vpc_id, by_role = _network_with_both_kinds(ec2)
    ok, group_id, _ = sg.create_security_group(
        ec2, "placement-sg", "test", vpc_id, None
    )
    assert ok, group_id

    launched, instance_id, _ = ec2i.launch_instance(
        ec2, "unplaced", region=REGION, security_group_ids=[group_id]
    )
    assert launched, instance_id

    settings = ec2i.read_instance_for_scanning(ec2, instance_id)
    assert settings["subnet_id"] == by_role["private"]["subnet_id"]


def test_a_placement_nobody_chose_is_reported(ec2):
    """Choosing well is half of it. A decision nobody can see is the same
    silent assumption this tool exists to point out."""
    vpc_id, _ = _network_with_both_kinds(ec2)
    ok, group_id, _ = sg.create_security_group(
        ec2, "placement-sg", "test", vpc_id, None
    )

    launched, _, problems = ec2i.launch_instance(
        ec2, "unplaced", region=REGION, security_group_ids=[group_id]
    )
    assert launched

    note = next(p for p in problems if "No subnet was named" in p)
    assert "no route to the internet" in note
    assert "Name a subnet explicitly" in note


def test_naming_a_subnet_produces_no_placement_note(ec2):
    """Nothing was assumed, so there is nothing to disclose."""
    vpc_id, by_role = _network_with_both_kinds(ec2)

    launched, _, problems = ec2i.launch_instance(
        ec2, "placed", region=REGION,
        subnet_id=by_role["public"]["subnet_id"],
    )
    assert launched
    assert not any("No subnet was named" in p for p in problems)


def test_the_note_admits_when_no_isolated_subnet_was_available(ec2):
    """A network where everything is routable has no safer choice to offer.

    The network is built here rather than borrowing the account's default one,
    which is the obvious way to write this and does not work. moto does not
    give its default VPC an internet route, so offline that network looks
    isolated while in reality nothing in it is - the note would come out
    backwards and the test would pass anyway, asserting the wrong thing. The
    default-VPC case is covered live in scripts/smoke_test.py, where the note
    correctly reads "has a route to the internet".
    """
    vpc_id = ec2.create_vpc(CidrBlock="10.8.0.0/16")["Vpc"]["VpcId"]
    gateway = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=gateway, VpcId=vpc_id)

    table = ec2.create_route_table(VpcId=vpc_id)["RouteTable"]["RouteTableId"]
    ec2.create_route(RouteTableId=table, DestinationCidrBlock="0.0.0.0/0",
                     GatewayId=gateway)

    for cidr in ("10.8.1.0/24", "10.8.2.0/24"):
        subnet = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=cidr
        )["Subnet"]["SubnetId"]
        ec2.associate_route_table(RouteTableId=table, SubnetId=subnet)

    ok, group_id, _ = sg.create_security_group(
        ec2, "all-routable-sg", "test", vpc_id, None
    )
    assert ok, group_id

    launched, _, problems = ec2i.launch_instance(
        ec2, "unplaced", region=REGION, security_group_ids=[group_id]
    )
    assert launched

    note = next(p for p in problems if "No subnet was named" in p)
    assert "has a route to the internet" in note
    assert "only thing keeping it that way" in note


def test_a_network_with_one_subnet_needs_no_preference(ec2):
    """Nothing to choose between, so no route table lookups are wasted."""
    vpc_id = ec2.create_vpc(CidrBlock="10.9.0.0/16")["Vpc"]["VpcId"]
    only = ec2.create_subnet(VpcId=vpc_id,
                             CidrBlock="10.9.1.0/24")["Subnet"]["SubnetId"]

    chosen, err = ec2i.default_subnet(ec2, vpc_id)
    assert err is None
    assert chosen == only


# ---------------------------------------------------------------- Key pairs


def test_launching_with_a_key_that_does_not_exist_fails_before_creating(ec2):
    """A key pair cannot be attached after launch.

    Getting this wrong means terminating the instance and starting over, so
    the check has to happen before anything is created. AWS reports it only
    when the run request is made, and its message does not name the key.
    """
    ok, message, _ = ec2i.launch_instance(
        ec2, "demo", region=REGION, key_name="no-such-key"
    )

    assert not ok
    assert "no-such-key" in message
    assert "cannot be attached after" in message
    assert ec2i.list_instances(ec2, only_ours=True) == []


def test_launching_with_a_real_key_attaches_it(ec2):
    kp.import_key_pair(ec2, "demo-key", ED25519)

    ok, instance_id, problems = ec2i.launch_instance(
        ec2, "demo", region=REGION, key_name="demo-key"
    )
    assert ok, instance_id
    assert not any("nobody can log in" in p for p in problems)

    settings = ec2i.read_instance_for_scanning(ec2, instance_id)
    assert settings["key_name"] == "demo-key"


def test_attaching_a_key_clears_the_unused_key_finding(ec2):
    """The cross-resource loop, end to end.

    The key pair scanner reports an unused key. Attaching it to an instance
    should silence that, and only a real launch proves the two halves agree
    about what "in use" means.
    """
    kp.import_key_pair(ec2, "demo-key", ED25519)

    before = check_key_pair(kp.read_key_pair_for_scanning(ec2, "demo-key"))
    assert [w["rule_id"] for w in before] == ["demo-key:unused"]

    ec2i.launch_instance(ec2, "demo", region=REGION, key_name="demo-key")

    after = check_key_pair(kp.read_key_pair_for_scanning(ec2, "demo-key"))
    assert after == []


def test_terminating_the_instance_makes_the_key_unused_again(ec2):
    kp.import_key_pair(ec2, "demo-key", ED25519)
    _, instance_id, _ = ec2i.launch_instance(
        ec2, "demo", region=REGION, key_name="demo-key"
    )
    ec2i.terminate_instance(ec2, instance_id)

    findings = check_key_pair(kp.read_key_pair_for_scanning(ec2, "demo-key"))
    assert [w["rule_id"] for w in findings] == ["demo-key:unused"]


def test_a_key_on_a_private_instance_is_not_reported():
    """The recommended arrangement, so reporting it would teach the wrong fix.

    A key pair on a machine with no public address means access goes through a
    bastion or Session Manager. Warning about it would push people to add a
    public address purely to silence the tool.
    """
    assert check_instance(_instance(key_name="demo-key", public_ip=None)) == []


def test_a_key_and_an_address_but_no_ssh_rule_is_reported():
    w = next(w for w in check_instance(_instance(key_name="demo-key",
                                                 public_ip="203.0.113.10",
                                                 ssh_reachable=False))
             if w["rule_id"].endswith(":key_without_firewall_rule"))

    assert w["level"] == INFO
    assert "will not connect" in w["message"]


def test_a_correctly_reachable_instance_reports_no_access_problem():
    """Key, address, and a rule narrowed to one address. Nothing to say."""
    warnings = check_instance(
        _instance(key_name="demo-key", public_ip="203.0.113.10",
                  ssh_reachable=True),
        [],
    )
    access = [w for w in warnings if "key_without" in w["rule_id"]]
    assert access == []


# ------------------------------------------------------------------- Storage


def test_an_unencrypted_disk_is_a_warning_that_admits_it_cannot_be_fixed():
    w = next(w for w in check_instance(_instance(root_volume_encrypted=False))
             if w["rule_id"].endswith(":root_volume_encryption"))

    assert w["level"] == WARNING
    assert w["fix"] is None
    assert "cannot be changed on a running instance" in w["message"]


def test_an_unreadable_disk_is_reported_rather_than_assumed_safe():
    w = next(w for w in check_instance(_instance(root_volume_encrypted=None))
             if w["rule_id"].endswith(":root_volume_unknown"))

    assert w["level"] == INFO
    assert "DescribeVolumes" in w["message"]


def test_a_starting_machine_does_not_blame_the_iam_policy():
    """The disk is not attached yet, so there is nothing to read.

    The original wording named ec2:DescribeVolumes as the likely cause, which
    sent someone off to rewrite a policy that was correct. The common reason
    for this finding is impatience, not permissions.
    """
    w = next(w for w in check_instance(_instance(root_volume_encrypted=None,
                                                 state="pending"))
             if w["rule_id"].endswith(":root_volume_unknown"))

    assert "DescribeVolumes" not in w["message"]
    assert "still starting" in w["message"]


# ------------------------------------------------- Through the registry and API


def test_instances_are_a_registered_resource_type():
    assert "instance" in registry.REGISTRY


def test_checking_a_launch_request_warns_about_a_public_address():
    warnings = registry.INSTANCE.check_spec({
        "name": "demo", "assign_public_ip": True,
    })
    assert any("public address" in w["message"] for w in warnings)


def test_checking_a_private_launch_request_is_clean():
    assert registry.INSTANCE.check_spec({"name": "demo"}) == []


def test_a_missing_instance_produces_no_findings():
    assert check_instance(None) == []


# ------------------------------------------------- What the machine is doing

# The plain-language health half of KAN-12, ported from the CloudWatch
# harness. moto answers get_metric_statistics but never has any data points
# for it, so everything about a machine that *is* reporting numbers is tested
# through the rule directly. That is the point of keeping the rules free of
# boto3: a 400-day-old key and a machine at 90% CPU are both reachable without
# an account.


def _with_usage(average, peak=None, hours=3, **overrides):
    settings = {
        "instance_id": "i-demo",
        "name": "demo",
        "imdsv2_required": True,
        "metadata_endpoint_enabled": True,
        "metadata_hop_limit": 1,
        "public_ip": None,
        "root_volume_encrypted": True,
        "key_name": None,
        "security_group_ids": [],
        "ssh_reachable": False,
        "cpu_usage": None if average is None else {
            "hours": hours, "samples": 36,
            "average": average, "peak": peak if peak is not None else average,
        },
    }
    settings.update(overrides)
    return settings


def _workload_finding(settings):
    found = [w for w in check_instance(settings)
             if w["rule"]["setting"] in ("idle", "workload_normal",
                                         "workload_busy", "workload_saturated")]
    assert len(found) <= 1, "a machine has one workload, so it gets one verdict"
    return found[0] if found else None


def test_a_machine_doing_nothing_is_reported_as_costing_the_same_anyway():
    found = _workload_finding(_with_usage(1.2, peak=4.0))
    assert found["rule"]["setting"] == "idle"
    assert found["level"] == "info"
    assert "1.2%" in found["message"] and "4.0%" in found["message"]
    assert "stopping it is free money" in found["message"]


def test_an_idle_machine_is_a_note_rather_than_a_fault():
    """A standby is idle on purpose. This says what is true and leaves the
    decision alone."""
    assert _workload_finding(_with_usage(0.0))["level"] == "info"


def test_a_comfortable_machine_says_so():
    assert _workload_finding(_with_usage(20.0))["rule"]["setting"] == "workload_normal"


def test_a_hard_working_machine_is_still_only_a_note():
    found = _workload_finding(_with_usage(60.0))
    assert found["rule"]["setting"] == "workload_busy"
    assert found["level"] == "info"


def test_a_saturated_machine_is_a_warning_because_it_stops_answering():
    found = _workload_finding(_with_usage(92.0))
    assert found["rule"]["setting"] == "workload_saturated"
    assert found["level"] == "warning"
    assert "too small" in found["message"]


@pytest.mark.parametrize("average,expected", [
    (4.9, "idle"), (5.0, "workload_normal"),
    (39.9, "workload_normal"), (40.0, "workload_busy"),
    (74.9, "workload_busy"), (75.0, "workload_saturated"),
])
def test_the_band_edges_land_where_the_harness_put_them(average, expected):
    assert _workload_finding(_with_usage(average))["rule"]["setting"] == expected


def test_a_machine_with_no_readings_is_not_called_idle():
    """No data is not zero. A machine that launched two minutes ago has
    published nothing yet, and a stopped one never will; calling either idle
    would advise switching off something that may be busy."""
    assert _workload_finding(_with_usage(None)) is None


def test_a_reading_with_no_average_is_not_guessed_at():
    settings = _with_usage(0)
    settings["cpu_usage"] = {"hours": 3, "samples": 0, "average": None,
                             "peak": None}
    assert _workload_finding(settings) is None


def test_the_workload_note_does_not_displace_the_security_findings():
    """Cost is an addition to what this scanner says, not a replacement."""
    settings = _with_usage(1.0, public_ip="203.0.113.9", imdsv2_required=False)
    settings_of = {w["rule"]["setting"] for w in check_instance(settings)}
    assert "idle" in settings_of
    assert "imdsv2" in settings_of


def test_reading_cpu_usage_of_a_machine_with_no_metrics_is_none(ec2):
    """moto answers the call and has nothing to report, which is also what a
    just-launched machine looks like against real AWS."""
    ok, instance_id, _ = ec2i.launch_instance(ec2, "demo", region=REGION)
    assert ok
    assert ec2i.read_cpu_usage(ec2, instance_id) is None


def test_the_registry_read_carries_the_workload_alongside_the_settings(ec2):
    ok, instance_id, _ = ec2i.launch_instance(ec2, "demo", region=REGION)
    assert ok

    settings = registry.INSTANCE.read(ec2, instance_id)
    assert "cpu_usage" in settings["instance"]
