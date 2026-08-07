"""Virtual private clouds: the network the other resources live in.

A VPC is not one resource. Creating a usable one means a VPC, an internet
gateway, at least two subnets and two route tables, plus the associations
between them - six or seven API calls that only make sense together. That is
why this module has one create function rather than exposing each piece: a
half-built network is worse than none, because it looks finished.

Two things here differ from every other module in this project.

Teardown is ordered and it matters. AWS refuses to delete a VPC while anything
lives in it, and reports that as DependencyViolation without naming the
dependency. Worse, terminating an instance does not immediately free its
network interface, so a delete attempted straight afterwards fails for reasons
that have already stopped being true. The teardown below removes things in the
order AWS requires and waits where waiting is needed.

NAT gateways are refused. They are the one thing here with a running cost -
around $32 a month, billed from creation to deletion regardless of traffic -
and nothing this tool provisions needs one. A private instance that only
accepts SSH from a bastion has no reason to reach the internet outbound. If
that changes, the refusal is one deliberate edit away, which is the right
amount of friction for a recurring charge.
"""

import time

import boto3
from botocore.exceptions import ClientError, WaiterError

MANAGED_TAG_KEY = "ManagedBy"
MANAGED_TAG_VALUE = "secure-cloud-provisioner"

DEFAULT_CIDR = "10.0.0.0/16"
PUBLIC_SUBNET_CIDR = "10.0.1.0/24"
PRIVATE_SUBNET_CIDR = "10.0.2.0/24"

ANYWHERE = "0.0.0.0/0"


def get_client(region="us-east-1"):
    """Initializes and returns an EC2 client."""
    return boto3.client("ec2", region_name=region)


def _tags(name, resource_type, role=None):
    tags = [
        {"Key": "Name", "Value": name},
        {"Key": MANAGED_TAG_KEY, "Value": MANAGED_TAG_VALUE},
        {"Key": "Environment", "Value": "test"},
    ]
    if role:
        tags.append({"Key": "Role", "Value": role})
    return [{"ResourceType": resource_type, "Tags": tags}]


# ---------------------------------------------------------------------- Create


def create_vpc(ec2, name, cidr=DEFAULT_CIDR, region="us-east-1",
               with_nat_gateway=False):
    """Creates a VPC with one public and one private subnet.

    Returns (ok, vpc_id_or_error, problems).

    The two subnets differ in exactly one way that matters: the public one has
    a route to the internet gateway and the private one does not. Everything
    else about them is the same. That single routing difference is what makes
    the private subnet private, and it holds regardless of what anyone later
    does to an instance inside it - which is the advantage over relying on an
    instance simply not having a public address.
    """
    if with_nat_gateway:
        return False, (
            "This tool does not create NAT gateways. One costs about $32 a "
            "month from the moment it is created until it is deleted, whether "
            "or not any traffic passes through it, and it is not covered by "
            "the free tier. Nothing this tool provisions needs outbound "
            "internet from a private subnet. If you genuinely do, create it by "
            "hand so the decision is a deliberate one."
        ), []

    problems = []

    try:
        vpc_id = ec2.create_vpc(
            CidrBlock=cidr,
            TagSpecifications=_tags(name, "vpc"),
        )["Vpc"]["VpcId"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "VpcLimitExceeded":
            return False, ("This account has reached its limit on VPCs. "
                           "Delete an unused one first."), []
        return False, e.response["Error"]["Message"], []

    try:
        ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id])
    except WaiterError:
        problems.append(f"{vpc_id} was created but is slow to become "
                        "available. The pieces below may not have attached.")

    # Needed for instances to receive DNS names. Off by default on a VPC you
    # create yourself, unlike the default VPC, which is a common surprise.
    #
    # Support has to go on before Hostnames; AWS rejects the second while the
    # first is off. Note the capitalisation: boto3 wants EnableDnsSupport, and
    # the lowercase enableDnsSupport seen in AWS documentation is the raw API
    # spelling. Getting it wrong raises ParamValidationError, which is not a
    # ClientError and so escapes the handler below - which is exactly how this
    # went unnoticed until the tests ran.
    for attribute in ("EnableDnsSupport", "EnableDnsHostnames"):
        try:
            ec2.modify_vpc_attribute(VpcId=vpc_id, **{attribute: {"Value": True}})
        except ClientError as e:
            problems.append(f"Could not enable {attribute}: "
                            f"{e.response['Error']['Message']}")

    zones = _availability_zones(ec2)
    if not zones:
        problems.append("Could not list availability zones; subnets were not "
                        "created.")
        return True, vpc_id, problems

    # ---- Public side -----------------------------------------------------
    try:
        public_subnet = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=PUBLIC_SUBNET_CIDR,
            AvailabilityZone=zones[0],
            TagSpecifications=_tags(f"{name}-public", "subnet", role="public"),
        )["Subnet"]["SubnetId"]

        gateway = ec2.create_internet_gateway(
            TagSpecifications=_tags(f"{name}-igw", "internet-gateway"),
        )["InternetGateway"]["InternetGatewayId"]
        ec2.attach_internet_gateway(InternetGatewayId=gateway, VpcId=vpc_id)

        public_routes = ec2.create_route_table(
            VpcId=vpc_id,
            TagSpecifications=_tags(f"{name}-public-rt", "route-table",
                                    role="public"),
        )["RouteTable"]["RouteTableId"]
        ec2.create_route(RouteTableId=public_routes,
                         DestinationCidrBlock=ANYWHERE,
                         GatewayId=gateway)
        ec2.associate_route_table(RouteTableId=public_routes,
                                  SubnetId=public_subnet)
    except ClientError as e:
        problems.append("The public side is incomplete: "
                        f"{e.response['Error']['Message']}")

    # ---- Private side ----------------------------------------------------
    #
    # A route table with no route to the gateway. Created explicitly rather
    # than leaving the subnet on the VPC's main route table: both behave the
    # same today, but the main table is shared, and a route added to it later
    # for some other purpose would silently give this subnet a way out.
    try:
        private_subnet = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=PRIVATE_SUBNET_CIDR,
            AvailabilityZone=zones[1 % len(zones)],
            TagSpecifications=_tags(f"{name}-private", "subnet", role="private"),
        )["Subnet"]["SubnetId"]

        private_routes = ec2.create_route_table(
            VpcId=vpc_id,
            TagSpecifications=_tags(f"{name}-private-rt", "route-table",
                                    role="private"),
        )["RouteTable"]["RouteTableId"]
        ec2.associate_route_table(RouteTableId=private_routes,
                                  SubnetId=private_subnet)
    except ClientError as e:
        problems.append("The private side is incomplete: "
                        f"{e.response['Error']['Message']}")

    problems.append(
        "Machines in the private subnet cannot reach the internet outbound at "
        "all, including for software updates. That is the point of it, and it "
        "is worth knowing before you wonder why dnf hangs."
    )

    return True, vpc_id, problems


def _availability_zones(ec2):
    try:
        zones = ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
        return [z["ZoneName"] for z in zones]
    except ClientError:
        return []


# ------------------------------------------------------------------------ Read


def list_vpcs(ec2, only_ours=False):
    """Returns VPCs, optionally only ones this tool created."""
    filters = []
    if only_ours:
        filters.append({"Name": f"tag:{MANAGED_TAG_KEY}",
                        "Values": [MANAGED_TAG_VALUE]})
    try:
        return ec2.describe_vpcs(Filters=filters)["Vpcs"]
    except ClientError:
        return []


def _subnets(ec2, vpc_id):
    return ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
    )["Subnets"]


def _route_tables(ec2, vpc_id):
    return ec2.describe_route_tables(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
    )["RouteTables"]


def _has_internet_route(route_table):
    """Whether this table routes anywhere out through an internet gateway."""
    for route in route_table.get("Routes", []):
        if route.get("GatewayId", "").startswith("igw-"):
            if route.get("DestinationCidrBlock") == ANYWHERE:
                return True
            if route.get("DestinationIpv6CidrBlock") == "::/0":
                return True
    return False


def flow_logs_enabled(ec2, vpc_id):
    """Whether any flow log is recording traffic for this VPC. CIS 3.7."""
    try:
        logs = ec2.describe_flow_logs(
            Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
        )["FlowLogs"]
        return any(log.get("FlowLogStatus") == "ACTIVE" for log in logs)
    except ClientError:
        return False


def read_vpc_for_scanning(ec2, vpc_id):
    """Retrieves one VPC's layout formatted for scanner processing.

    Each subnet is reported with whether its route table reaches an internet
    gateway, because that - not its name or its tags - is what decides whether
    it is public.
    """
    try:
        found = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"]
    except ClientError as e:
        if e.response["Error"]["Code"] in ("InvalidVpcID.NotFound",
                                           "InvalidVpcID.Malformed"):
            return None
        raise

    if not found:
        return None

    vpc = found[0]
    tags = {t["Key"]: t["Value"] for t in vpc.get("Tags", [])}
    tables = _route_tables(ec2, vpc_id)

    by_subnet = {}
    main_table = None
    for table in tables:
        for association in table.get("Associations", []):
            if association.get("Main"):
                main_table = table
            elif association.get("SubnetId"):
                by_subnet[association["SubnetId"]] = table

    subnets = []
    for subnet in _subnets(ec2, vpc_id):
        subnet_tags = {t["Key"]: t["Value"] for t in subnet.get("Tags", [])}
        table = by_subnet.get(subnet["SubnetId"], main_table)
        subnets.append({
            "subnet_id": subnet["SubnetId"],
            "name": subnet_tags.get("Name", subnet["SubnetId"]),
            "declared_role": subnet_tags.get("Role"),
            "cidr": subnet.get("CidrBlock"),
            "availability_zone": subnet.get("AvailabilityZone"),
            "auto_assign_public_ip": subnet.get("MapPublicIpOnLaunch", False),
            "reaches_internet": _has_internet_route(table) if table else False,
            "using_main_route_table": (
                by_subnet.get(subnet["SubnetId"]) is None
            ),
        })

    return {
        "vpc_id": vpc_id,
        "name": tags.get("Name", vpc_id),
        "cidr": vpc.get("CidrBlock"),
        "is_default": vpc.get("IsDefault", False),
        "subnets": subnets,
        "flow_logs_enabled": flow_logs_enabled(ec2, vpc_id),
        "managed_by_us": tags.get(MANAGED_TAG_KEY) == MANAGED_TAG_VALUE,
    }


def plan_deletion(ec2, vpc_id):
    """Returns everything a cascading delete would destroy, in order.

    Separate from doing it, and deliberately so. A cascade that terminates
    machines is the most destructive operation in this tool, and the only
    honest way to ask for consent is to show the whole list first. "Delete this
    network and everything in it?" is not informed consent when the answer
    includes three servers someone else is using.

    Returns a list of (kind, id, label) in the order they would be removed.
    Anything AWS creates and manages itself - the main route table, the default
    security group - is left out, because it goes with the VPC and cannot be
    deleted separately.
    """
    plan = []

    try:
        reservations = ec2.describe_instances(Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "instance-state-name",
             "Values": ["pending", "running", "stopping", "stopped"]},
        ])["Reservations"]
        for reservation in reservations:
            for instance in reservation.get("Instances", []):
                tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
                plan.append((
                    "server", instance["InstanceId"],
                    f"{tags.get('Name', 'unnamed')} "
                    f"({instance.get('InstanceType')}, "
                    f"{instance.get('State', {}).get('Name')})"
                ))
    except ClientError:
        pass

    try:
        for subnet in _subnets(ec2, vpc_id):
            tags = {t["Key"]: t["Value"] for t in subnet.get("Tags", [])}
            plan.append((
                "subnet", subnet["SubnetId"],
                f"{tags.get('Name', 'unnamed')} ({subnet.get('CidrBlock')})"
            ))
    except ClientError:
        pass

    try:
        for table in _route_tables(ec2, vpc_id):
            if any(a.get("Main") for a in table.get("Associations", [])):
                continue
            tags = {t["Key"]: t["Value"] for t in table.get("Tags", [])}
            plan.append(("route table", table["RouteTableId"],
                         tags.get("Name", "unnamed")))
    except ClientError:
        pass

    try:
        gateways = ec2.describe_internet_gateways(Filters=[
            {"Name": "attachment.vpc-id", "Values": [vpc_id]},
        ])["InternetGateways"]
        for gateway in gateways:
            plan.append(("internet gateway", gateway["InternetGatewayId"],
                         "the network's way out"))
    except ClientError:
        pass

    try:
        groups = ec2.describe_security_groups(Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
        ])["SecurityGroups"]
        for group in groups:
            if group["GroupName"] == "default":
                continue
            plan.append(("security group", group["GroupId"],
                         group["GroupName"]))
    except ClientError:
        pass

    plan.append(("network", vpc_id, "the network itself"))
    return plan


def not_ours(plan, ec2, vpc_id):
    """Returns the items in a deletion plan this tool did not create.

    The thing worth being loudest about. A network built by hand, or by a
    teammate, can contain machines nobody expected this tool to touch, and the
    cascade does not distinguish. Naming them separately gives someone the
    chance to stop.
    """
    managed = set()

    try:
        # Paginated because describe_tags stops at a thousand and an account
        # this tool has been used in for a while will pass that. A truncated
        # answer marks things this tool did create as somebody else's, which
        # is the harmless direction but still wrong.
        paginator = ec2.get_paginator("describe_tags")
        for page in paginator.paginate(Filters=[
            {"Name": "tag:" + MANAGED_TAG_KEY, "Values": [MANAGED_TAG_VALUE]},
        ]):
            managed.update(t["ResourceId"] for t in page.get("Tags", []))
    except ClientError:
        # Returning [] here used to say "everything in this plan was made by
        # this tool" - the reassuring answer to a question nobody managed to
        # ask, on the one list whose entire job is to make someone look twice
        # before destroying a stranger's machine. Ownership that could not be
        # established is reported as not established, which here means naming
        # all of it.
        return list(plan)

    return [item for item in plan if item[1] not in managed]


def whats_inside(ec2, vpc_id):
    """Lists what would block deletion, so the refusal can say what to do."""
    blockers = []

    try:
        reservations = ec2.describe_instances(Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "instance-state-name",
             "Values": ["pending", "running", "stopping", "stopped"]},
        ])["Reservations"]
        for reservation in reservations:
            for instance in reservation.get("Instances", []):
                blockers.append(("instance", instance["InstanceId"]))
    except ClientError:
        pass

    try:
        interfaces = ec2.describe_network_interfaces(Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
        ])["NetworkInterfaces"]
        for interface in interfaces:
            blockers.append(("network interface",
                             interface["NetworkInterfaceId"]))
    except ClientError:
        pass

    return blockers


# ---------------------------------------------------------------------- Delete


# Eight minutes. Generous because the slow case is specific and common here:
# an instance terminated while still starting has to finish starting first, so
# pending -> running -> shutting-down -> terminated can take five minutes on
# its own. Three minutes timed out and then succeeded seconds later, which is
# the worst way to be wrong - it reports failure for something that worked.
INTERFACE_WAIT_ATTEMPTS = 96
INTERFACE_WAIT_SECONDS = 5


def wait_for_interfaces_to_clear(ec2, vpc_id,
                                 attempts=INTERFACE_WAIT_ATTEMPTS,
                                 delay=INTERFACE_WAIT_SECONDS):
    """Waits until no network interfaces are left in the VPC.

    Deliberately not the instance_terminated waiter. That waiter treats the
    "pending" state as a terminal failure - the reasoning being that an
    instance which has not finished starting should not be on its way to
    terminated - so terminating a machine mid-launch makes it fail immediately
    and report a failure for something proceeding normally. Cascading deletes
    hit that constantly, because the machine you are removing is often one you
    created moments ago.

    Waiting on interfaces is also more accurate. An interface is what actually
    blocks a subnet from being deleted; instance state is a proxy for it, and
    the two do not disappear at the same moment.

    Checks before sleeping, so a VPC that is already clear returns at once.
    """
    for attempt in range(attempts):
        try:
            interfaces = ec2.describe_network_interfaces(Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
            ])["NetworkInterfaces"]
        except ClientError:
            # Cannot see them, so cannot wait for them. Let the delete attempt
            # report the real problem rather than stalling here.
            return True

        if not interfaces:
            return True

        if attempt < attempts - 1:
            time.sleep(delay)

    return False


def delete_vpc(ec2, vpc_id, force=False):
    """Deletes a VPC and everything this tool put in it.

    AWS demands a specific order and reports failure as DependencyViolation
    without saying which dependency, so the order is spelled out below. The
    awkward step is the wait: terminating an instance returns immediately but
    its network interface lingers for another half minute, and a subnet cannot
    be deleted while an interface is in it.

    Without force, this refuses and names what is in the way rather than
    destroying running machines because someone typed a VPC ID.
    """
    blockers = whats_inside(ec2, vpc_id)
    instances = [b[1] for b in blockers if b[0] == "instance"]

    if instances and not force:
        listed = ", ".join(instances)
        return False, (
            f"{vpc_id} still contains running machines ({listed}). Deleting "
            "the network would destroy them. Terminate them first, or use the "
            "force option if that is what you intend."
        )

    if instances:
        try:
            ec2.terminate_instances(InstanceIds=instances)
        except ClientError as e:
            return False, (f"Could not terminate the machines in {vpc_id}: "
                           f"{e.response['Error']['Message']}")

        if not wait_for_interfaces_to_clear(ec2, vpc_id):
            return False, (
                f"The machines in {vpc_id} were told to terminate, but their "
                "network connections are still attached after several minutes. "
                "Nothing has been deleted. Wait a little and try again; if it "
                "persists, something else is holding the network open."
            )

    steps = [
        ("subnets", lambda: _delete_subnets(ec2, vpc_id)),
        ("route tables", lambda: _delete_route_tables(ec2, vpc_id)),
        ("internet gateways", lambda: _delete_gateways(ec2, vpc_id)),
        ("security groups", lambda: _delete_security_groups(ec2, vpc_id)),
    ]

    failures = []
    for label, step in steps:
        error = step()
        if error:
            failures.append(f"{label}: {error}")

    # Retried, because DependencyViolation here is usually a dependency that
    # has already been removed and not yet stopped being reported. The
    # teardown that fails and then succeeds ten seconds later is the common
    # case; asking again costs a few seconds and saves someone deleting a
    # network by hand in the console.
    detail = None
    for attempt in range(4):
        try:
            ec2.delete_vpc(VpcId=vpc_id)
            return True, f"Deleted {vpc_id} and everything in it."
        except ClientError as e:
            detail = e.response["Error"]["Message"]
            if e.response["Error"]["Code"] != "DependencyViolation":
                break
            if attempt < 3:
                time.sleep(5)

    if failures:
        detail += " Earlier steps also failed: " + "; ".join(failures)
    return False, f"Could not delete {vpc_id}. {detail}"


# Codes meaning the thing being removed has already gone. During a cascade
# that is the ordinary case rather than an error: deleting a subnet takes its
# route table association with it, and AWS keeps reporting the association for
# a moment afterwards.
_ALREADY_GONE = {
    "InvalidAssociationID.NotFound",
    "InvalidRouteTableID.NotFound",
    "InvalidSubnetID.NotFound",
    "InvalidInternetGatewayID.NotFound",
    "InvalidGroup.NotFound",
    "Gateway.NotAttached",
}


def _forgive_missing(call, *args, **kwargs):
    """Runs a delete, treating "it was already gone" as success.

    Returns an error string, or None. Never raises, so one step failing cannot
    stop the steps after it: a cascade that abandons the remaining work leaves
    a network that will not delete for a reason which has already stopped
    being true.
    """
    try:
        call(*args, **kwargs)
        return None
    except ClientError as e:
        if e.response["Error"]["Code"] in _ALREADY_GONE:
            return None
        return e.response["Error"]["Message"]


def _delete_subnets(ec2, vpc_id):
    try:
        subnets = _subnets(ec2, vpc_id)
    except ClientError as e:
        return e.response["Error"]["Message"]

    failures = [
        error for error in (
            _forgive_missing(ec2.delete_subnet, SubnetId=s["SubnetId"])
            for s in subnets
        ) if error
    ]
    return "; ".join(failures) if failures else None


def _delete_route_tables(ec2, vpc_id):
    """Deletes every route table except the main one, which cannot be deleted.

    Subnets are removed before this runs, and removing a subnet also removes
    its route table association. AWS is eventually consistent about that: it
    will hand back an association here and then refuse to disassociate it
    because it no longer exists. That refusal is the work already being done.
    """
    try:
        tables = _route_tables(ec2, vpc_id)
    except ClientError as e:
        return e.response["Error"]["Message"]

    failures = []

    for table in tables:
        if any(a.get("Main") for a in table.get("Associations", [])):
            continue

        for association in table.get("Associations", []):
            association_id = association.get("RouteTableAssociationId")
            if not association_id:
                continue
            error = _forgive_missing(ec2.disassociate_route_table,
                                     AssociationId=association_id)
            if error:
                failures.append(f"{association_id}: {error}")

        error = _forgive_missing(ec2.delete_route_table,
                                 RouteTableId=table["RouteTableId"])
        if error:
            failures.append(f"{table['RouteTableId']}: {error}")

    return "; ".join(failures) if failures else None


def _delete_gateways(ec2, vpc_id):
    """Detaches before deleting. AWS refuses to delete an attached gateway."""
    try:
        gateways = ec2.describe_internet_gateways(Filters=[
            {"Name": "attachment.vpc-id", "Values": [vpc_id]},
        ])["InternetGateways"]
    except ClientError as e:
        return e.response["Error"]["Message"]

    failures = []

    for gateway in gateways:
        gateway_id = gateway["InternetGatewayId"]

        error = _forgive_missing(ec2.detach_internet_gateway,
                                 InternetGatewayId=gateway_id, VpcId=vpc_id)
        if error:
            failures.append(f"{gateway_id}: {error}")

        error = _forgive_missing(ec2.delete_internet_gateway,
                                 InternetGatewayId=gateway_id)
        if error:
            failures.append(f"{gateway_id}: {error}")

    return "; ".join(failures) if failures else None


def _delete_security_groups(ec2, vpc_id):
    """Deletes every group except default, which cannot be deleted.

    Groups are removed after subnets because a group referenced by another
    group's rules cannot be deleted, and clearing the subnets first removes
    most of what was using them.
    """
    try:
        groups = ec2.describe_security_groups(Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
        ])["SecurityGroups"]

        remaining = [g for g in groups if g["GroupName"] != "default"]

        # Two passes: a group referenced by another cannot go first, and
        # sorting that out properly means building a dependency graph for
        # something two attempts resolves.
        for _ in range(2):
            still_there = []
            for group in remaining:
                try:
                    ec2.delete_security_group(GroupId=group["GroupId"])
                except ClientError:
                    still_there.append(group)
            remaining = still_there
            if not remaining:
                break

        if remaining:
            names = ", ".join(g["GroupId"] for g in remaining)
            return f"could not delete {names}, likely still referenced"
    except ClientError as e:
        return e.response["Error"]["Message"]


def cleanup_all_managed_vpcs(ec2, force=False):
    """Deletes every VPC this tool created."""
    results = []
    for vpc in list_vpcs(ec2, only_ours=True):
        ok, message = delete_vpc(ec2, vpc["VpcId"], force=force)
        results.append((vpc["VpcId"], ok, message))
    return results


# ------------------------------------------------------------------------- Fix


def apply_fix(ec2, vpc_id, warning):
    """VPC findings are reported rather than corrected.

    Removing a route or a subnet changes what an entire network can reach. The
    blast radius is every machine inside it, and unlike a firewall rule the
    damage is not obvious from the thing that was changed. This tool explains
    and leaves the decision alone.
    """
    return False, (
        "Network layout has to be changed by hand. Altering routing affects "
        "every machine in the network at once, so this tool will not do it "
        "for you."
    )
