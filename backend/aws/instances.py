"""EC2 instances: launching, auditing and terminating.

This is the first resource in the tool that costs money. Everything else is a
configuration object that is free to leave lying around; an instance bills by
the second from the moment it starts and keeps billing until someone stops it.
That difference shapes the whole module.

Three guardrails, in descending order of how much they matter.

ALLOWED_INSTANCE_TYPES is an allowlist, not a warning. The tool physically
cannot launch anything outside it. A GPU instance is roughly a thousand times
the hourly cost of a t3.micro, and the distance between the two is one typo.
A confirmation prompt would not survive that typo; a refusal does.

Every instance is tagged at launch, in the same call that creates it. Tagging
afterwards leaves a window where a crash orphans an untracked, running,
billing instance. RunInstances takes TagSpecifications precisely so that window
does not exist.

IMDSv2 is required at launch rather than checked afterwards. It costs nothing,
it cannot break a new instance, and it closes the hole behind the 2019 Capital
One breach, where a request forgery bug was used to read instance credentials
from the metadata service. CIS 5.7 asks for it; this tool does not offer the
alternative.
"""

from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import ClientError, WaiterError

MANAGED_TAG_KEY = "ManagedBy"
MANAGED_TAG_VALUE = "secure-cloud-provisioner"

# Cheap, burstable, free-tier eligible. Anything absent from this set is
# refused outright rather than warned about. Widen it deliberately if you ever
# genuinely need to, and understand the hourly cost before you do.
ALLOWED_INSTANCE_TYPES = {
    "t2.nano", "t2.micro", "t2.small",
    "t3.nano", "t3.micro", "t3.small",
    "t3a.nano", "t3a.micro", "t3a.small",
    "t4g.nano", "t4g.micro", "t4g.small",
}

DEFAULT_INSTANCE_TYPE = "t3.micro"

# How far back to look when asking what a machine has been doing. Three hours
# is long enough that a single burst does not decide the answer, and short
# enough that the answer is about now rather than about last week.
CPU_WINDOW_HOURS = 3

# Looked up rather than hardcoded: AMI IDs differ per region and are replaced
# whenever the image is patched, so any literal ID is wrong somewhere and stale
# everywhere within a month.
AMI_PARAMETERS = {
    "x86_64": "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64",
    "arm64": "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64",
}

# The metadata service settings CIS 5.7 asks for. HttpTokens required is IMDSv2.
# A hop limit of 1 stops a container on the instance reaching the metadata
# service through the host's network stack, which is the usual way a
# containerised application ends up with the host's IAM credentials.
SECURE_METADATA = {
    "HttpTokens": "required",
    "HttpEndpoint": "enabled",
    "HttpPutResponseHopLimit": 1,
}

RUNNING_STATES = ["pending", "running", "stopping", "stopped"]

ANYWHERE_V4 = "0.0.0.0/0"
ANYWHERE_V6 = "::/0"


class InstanceTypeNotAllowed(ValueError):
    """A refusal rather than a warning. See ALLOWED_INSTANCE_TYPES."""


def get_client(region="us-east-1"):
    """Initializes and returns an EC2 client."""
    return boto3.client("ec2", region_name=region)


def architecture_for(instance_type):
    """Returns the CPU architecture a given instance type needs.

    The t4g family is Graviton, which is ARM. Booting an x86 image on it fails
    with a message that does not mention architecture at all.
    """
    return "arm64" if instance_type.startswith("t4g") else "x86_64"


def latest_ami(region, architecture="x86_64"):
    """Looks up the current Amazon Linux 2023 image for this region."""
    ssm = boto3.client("ssm", region_name=region)
    parameter = AMI_PARAMETERS.get(architecture)
    if not parameter:
        return None, f"No image is configured for {architecture}."

    try:
        return ssm.get_parameter(Name=parameter)["Parameter"]["Value"], None
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDeniedException":
            return None, ("This login cannot look up machine images "
                          "(needs ssm:GetParameter).")
        return None, e.response["Error"]["Message"]


def key_pair_exists(ec2, key_name):
    """Returns (exists, explanation) for a key pair name.

    A key pair cannot be attached to an instance after launch. Getting this
    wrong means terminating the instance and starting again, so it is worth
    one extra API call to fail before anything is created rather than after.
    """
    try:
        found = ec2.describe_key_pairs(KeyNames=[key_name])["KeyPairs"]
        if found:
            return True, None
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidKeyPair.NotFound":
            return False, e.response["Error"]["Message"]

    return False, (
        f"There is no key pair called '{key_name}' in this region. Import one "
        "first: a key pair cannot be attached after the instance is running, "
        "so launching without it would mean starting over."
    )


def _subnet_reaches_internet(ec2, subnet):
    """Whether traffic from this subnet can leave through an internet gateway.

    The subnet's own route table if it has one, otherwise the network's main
    table, which is what AWS applies when nothing else is associated.
    """
    subnet_id = subnet["SubnetId"]
    vpc_id = subnet.get("VpcId")

    try:
        tables = ec2.describe_route_tables(Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
        ])["RouteTables"]
    except ClientError:
        # Unknown. Treated as reaching the internet, because guessing the safe
        # answer here would mean claiming isolation this has not verified.
        return True

    own = None
    main = None
    for table in tables:
        for association in table.get("Associations", []):
            if association.get("SubnetId") == subnet_id:
                own = table
            elif association.get("Main"):
                main = table

    table = own or main
    if not table:
        return True

    for route in table.get("Routes", []):
        if route.get("GatewayId", "").startswith("igw-"):
            if route.get("DestinationCidrBlock") == ANYWHERE_V4:
                return True
            if route.get("DestinationIpv6CidrBlock") == ANYWHERE_V6:
                return True

    return False


def default_subnet(ec2, vpc_id=None):
    """Finds a subnet to launch into. Returns (subnet_id, error).

    Only reached when nobody said where the machine should go. The CLI always
    asks and the blueprint always states it, so this is the API being called
    without a subnet_id, or a script.

    Where the network offers a choice, the one with no route to the internet
    wins. The two ways of being wrong here are not equally bad: a machine in an
    isolated subnet is unreachable, which is noticed within a minute and undone
    by relaunching, while a machine in a routable subnet has quietly lost the
    stronger of its two protections and nobody finds out. The caller is told
    which subnet was chosen so anyone who wanted the other one learns at launch
    rather than at a demonstration.

    A vpc_id is a boundary, not a preference. Every fallback below stays inside
    it: a subnet from some other network is never a better answer than an error
    saying this one has nowhere to put the machine.
    """
    scope = [{"Name": "vpc-id", "Values": [vpc_id]}] if vpc_id else []

    try:
        subnets = ec2.describe_subnets(Filters=scope)["Subnets"]
    except ClientError as e:
        return None, e.response["Error"]["Message"]

    if not subnets:
        if vpc_id:
            return None, (f"{vpc_id} has no subnets, so there is nowhere in it "
                          "to launch a machine.")
        return None, "No subnet was found to launch into."

    if len(subnets) == 1:
        return subnets[0]["SubnetId"], None

    isolated = [s for s in subnets if not _subnet_reaches_internet(ec2, s)]
    if isolated:
        return isolated[0]["SubnetId"], None

    # Every subnet reaches the internet, so there is no safer choice to make.
    # The account's default network looks like this, and so does any network
    # built without somewhere private in it.
    return subnets[0]["SubnetId"], None


def _placement_note(ec2, subnet_id):
    """Explains where a machine went when the caller did not say."""
    try:
        subnets = ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"]
    except ClientError:
        return f"No subnet was named, so this went into {subnet_id}."

    if not subnets:
        return f"No subnet was named, so this went into {subnet_id}."

    tags = {t["Key"]: t["Value"] for t in subnets[0].get("Tags", [])}
    label = tags.get("Name", subnet_id)

    if _subnet_reaches_internet(ec2, subnets[0]):
        return (
            f"No subnet was named, so this went into {label} ({subnet_id}), "
            "which has a route to the internet. Nothing can reach the machine "
            "while it has no public address, but that address is the only "
            "thing keeping it that way. Name a subnet with no route out if you "
            "wanted the stronger arrangement."
        )

    return (
        f"No subnet was named, so this went into {label} ({subnet_id}), which "
        "has no route to the internet. Nothing outside can reach it and it "
        "cannot reach out, including for software updates. Name a subnet "
        "explicitly if you wanted it reachable."
    )


def vpc_of_groups(ec2, security_group_ids):
    """Returns the VPC the given security groups live in, or None.

    None means the question has no single answer - the groups disagree, or the
    lookup failed - and the caller should not pretend otherwise.
    """
    if not security_group_ids:
        return None

    try:
        groups = ec2.describe_security_groups(
            GroupIds=list(security_group_ids)
        )["SecurityGroups"]
    except ClientError:
        return None

    found = {g.get("VpcId") for g in groups if g.get("VpcId")}
    return found.pop() if len(found) == 1 else None


# ---------------------------------------------------------------------- Launch


DEFAULT_ROOT_VOLUME_GB = 8


def launch_instance(ec2, name, region="us-east-1", instance_type=None,
                    key_name=None, security_group_ids=None, subnet_id=None,
                    assign_public_ip=False, encrypt_root=True,
                    root_volume_gb=DEFAULT_ROOT_VOLUME_GB):
    """Launches one instance. Returns (ok, instance_id_or_error, problems).

    Refuses instance types outside ALLOWED_INSTANCE_TYPES. That refusal is the
    single most important line in this file: it is the difference between a
    mistake that costs pennies and one that costs hundreds.

    assign_public_ip defaults to False. An instance with no public address is
    not reachable from the internet at all, which makes every firewall mistake
    survivable. Turning it on is a deliberate act.
    """
    instance_type = instance_type or DEFAULT_INSTANCE_TYPE
    problems = []

    if instance_type not in ALLOWED_INSTANCE_TYPES:
        allowed = ", ".join(sorted(ALLOWED_INSTANCE_TYPES))
        return False, (
            f"'{instance_type}' is not on this tool's allowlist, so it will not "
            f"be launched. Permitted types are: {allowed}. These are the cheap "
            "burstable sizes; the allowlist exists so a mistyped instance type "
            "cannot quietly cost a large amount of money."
        ), []

    architecture = architecture_for(instance_type)
    image_id, err = latest_ami(region, architecture)
    if err:
        return False, err, []

    if not subnet_id:
        # A security group belongs to exactly one network and cannot be
        # attached to a machine in another. Reaching for the default VPC's
        # subnet while holding a group from somewhere else fails with
        # InvalidParameterValue, which mentions neither the subnet nor the
        # group; where the groups agree on a network, they are saying which
        # one was meant, so believe them rather than the account default.
        subnet_id, err = default_subnet(ec2, vpc_of_groups(ec2, security_group_ids))
        if err:
            return False, err, []

        # Choosing well is only half of it. A placement decision nobody made
        # and nobody can see is the same silent assumption this tool exists to
        # point out, so it says which subnet and what that means.
        problems.append(_placement_note(ec2, subnet_id))

    if key_name:
        # Checked before launching rather than after. AWS reports a missing key
        # as InvalidKeyPair.NotFound only once the run request is made, by
        # which point the image lookup and subnet lookup have already happened
        # and the message does not say which name it could not find.
        exists, detail = key_pair_exists(ec2, key_name)
        if not exists:
            return False, detail, []
    else:
        problems.append(
            "No key pair was given, so nobody can log in over SSH. That is "
            "often what you want. Use EC2 Instance Connect or Session Manager "
            "if you need a shell without managing keys."
        )

    request = {
        "ImageId": image_id,
        "InstanceType": instance_type,
        "MinCount": 1,
        "MaxCount": 1,
        # The public address is always stated outright, never left to the
        # subnet to decide. Default subnets have MapPublicIpOnLaunch set, so
        # saying nothing here gets a public address assigned anyway - and this
        # tool would then report that the instance is private while it sits on
        # the open internet. Being explicit costs one field and removes an
        # entire class of quietly wrong answer.
        "NetworkInterfaces": [{
            "DeviceIndex": 0,
            "SubnetId": subnet_id,
            "AssociatePublicIpAddress": assign_public_ip,
            "DeleteOnTermination": True,
            **({"Groups": security_group_ids} if security_group_ids else {}),
        }],
        "MetadataOptions": dict(SECURE_METADATA),
        # Overriding the image's own disk settings to force encryption means
        # AWS stops supplying the defaults that came with the image, so the
        # size has to be given explicitly. Omitting it fails with "the request
        # must contain the parameter size or snapshotId", which does not
        # mention that specifying a mapping at all is what caused it.
        # 8 GiB is the Amazon Linux 2023 default; free tier includes 30 GiB.
        "BlockDeviceMappings": [{
            "DeviceName": "/dev/xvda",
            "Ebs": {
                "VolumeSize": root_volume_gb,
                "Encrypted": encrypt_root,
                "DeleteOnTermination": True,
                "VolumeType": "gp3",
            },
        }],
        "TagSpecifications": [
            {
                "ResourceType": resource,
                "Tags": [
                    {"Key": "Name", "Value": name},
                    {"Key": MANAGED_TAG_KEY, "Value": MANAGED_TAG_VALUE},
                    {"Key": "Environment", "Value": "test"},
                ],
            }
            # The volume is tagged too. An untagged volume left behind by a
            # failed termination is invisible to cleanup and still bills.
            for resource in ("instance", "volume")
        ],
    }

    # SubnetId and SecurityGroupIds are set inside the network interface above,
    # not at the top level. AWS rejects a request that specifies both.
    if key_name:
        request["KeyName"] = key_name

    if assign_public_ip:
        problems.append(
            "This instance is getting a public address, so it is reachable "
            "from the internet and its firewall rules are the only thing "
            "standing in the way."
        )

    try:
        resp = ec2.run_instances(**request)
        instance_id = resp["Instances"][0]["InstanceId"]

        # EC2 is eventually consistent: RunInstances returns an ID that
        # DescribeInstances cannot see yet, for a second or two. Anything that
        # reads the instance straight back - the API's create endpoint does
        # exactly that, to report what was actually made - fails with
        # InvalidInstanceID.NotFound saying the instance does not exist, which
        # is alarming and wrong. Waiting here fixes it once for every caller
        # rather than leaving each one to discover the race.
        try:
            ec2.get_waiter("instance_exists").wait(
                InstanceIds=[instance_id],
                WaiterConfig={"Delay": 2, "MaxAttempts": 20},
            )
        except WaiterError:
            problems.append(
                f"{instance_id} was created but has not become visible yet. "
                "It is running and billing; give it a moment and scan again."
            )

        return True, instance_id, problems
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "UnauthorizedOperation":
            return False, ("This login lacks permission to launch instances "
                           "(needs ec2:RunInstances)."), []
        if code == "InstanceLimitExceeded":
            return False, ("This account has reached its limit on running "
                           "instances. Terminate something first."), []
        if code == "VcpuLimitExceeded":
            return False, ("This account's vCPU quota is used up. Terminate "
                           "an instance or request a quota increase."), []
        return False, e.response["Error"]["Message"], []


# ------------------------------------------------------------------------ Read


def list_instances(ec2, only_ours=False, include_terminated=False):
    """Returns instances, optionally only ones this tool launched.

    Terminated instances are excluded by default. AWS keeps them visible for
    about an hour after termination, and reporting something as present when it
    is already gone makes a cleanup screen untrustworthy.
    """
    filters = []
    if only_ours:
        filters.append({"Name": f"tag:{MANAGED_TAG_KEY}",
                        "Values": [MANAGED_TAG_VALUE]})
    if not include_terminated:
        filters.append({"Name": "instance-state-name", "Values": RUNNING_STATES})

    found = []
    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate(Filters=filters):
        for reservation in page.get("Reservations", []):
            found.extend(reservation.get("Instances", []))
    return found


def _root_volume_encrypted(ec2, instance):
    """Returns whether the root volume is encrypted, or None if unknowable."""
    root_name = instance.get("RootDeviceName")
    volume_id = None

    for mapping in instance.get("BlockDeviceMappings", []):
        if mapping.get("DeviceName") == root_name:
            volume_id = mapping.get("Ebs", {}).get("VolumeId")
            break

    if not volume_id:
        return None

    try:
        volumes = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"]
        return volumes[0].get("Encrypted") if volumes else None
    except ClientError:
        return None


def read_cpu_usage(ec2, instance_id, hours=CPU_WINDOW_HOURS, now=None):
    """How hard this machine has been working, or None if nothing is known.

    A free read that creates nothing: AWS publishes basic EC2 metrics every
    five minutes whether or not anyone looks. It needs a CloudWatch client
    rather than the EC2 one, built here for the same region, because the
    registry hands readers a single client and the caller should not have to
    know that one fact about a machine lives in a different service.

    Returns None rather than zero when there are no data points. They are
    different: a machine reporting 0% is idle, and a machine reporting nothing
    has either just launched, or is stopped, or is not being measured. Scoring
    the second as idle would advise switching off something that may be busy.
    """
    now = now or datetime.now(timezone.utc)
    cloudwatch = boto3.client("cloudwatch", region_name=ec2.meta.region_name)

    try:
        points = cloudwatch.get_metric_statistics(
            Namespace="AWS/EC2",
            MetricName="CPUUtilization",
            Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
            StartTime=now - timedelta(hours=hours),
            EndTime=now,
            Period=300,
            Statistics=["Average", "Maximum"],
        )["Datapoints"]
    except ClientError:
        # Not fatal. Every other finding about this machine still stands, and
        # the rules treat an absent reading as "not known" rather than "idle".
        return None

    if not points:
        return None

    return {
        "hours": hours,
        "samples": len(points),
        "average": sum(p["Average"] for p in points) / len(points),
        "peak": max(p["Maximum"] for p in points),
    }


def read_instance_for_scanning(ec2, instance_id):
    """Retrieves one instance's settings formatted for scanner processing.

    Returns None when there is no such machine, rather than letting AWS's
    exception for that travel upwards as an error.
    """
    try:
        reservations = ec2.describe_instances(
            InstanceIds=[instance_id]
        )["Reservations"]
    except ClientError as e:
        if e.response["Error"]["Code"] in ("InvalidInstanceID.NotFound",
                                           "InvalidInstanceID.Malformed"):
            return None
        raise

    instances = [i for r in reservations for i in r.get("Instances", [])]
    if not instances:
        return None

    instance = instances[0]
    tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
    metadata = instance.get("MetadataOptions", {})

    return {
        "instance_id": instance["InstanceId"],
        "name": tags.get("Name", instance["InstanceId"]),
        "state": instance.get("State", {}).get("Name"),
        "instance_type": instance.get("InstanceType"),
        # Where it landed. Reported because it cannot be changed afterwards and
        # decides more about exposure than any setting below it.
        "vpc_id": instance.get("VpcId"),
        "subnet_id": instance.get("SubnetId"),
        "public_ip": instance.get("PublicIpAddress"),
        "private_ip": instance.get("PrivateIpAddress"),
        "key_name": instance.get("KeyName"),
        "imdsv2_required": metadata.get("HttpTokens") == "required",
        "metadata_endpoint_enabled": metadata.get("HttpEndpoint") == "enabled",
        "metadata_hop_limit": metadata.get("HttpPutResponseHopLimit"),
        "root_volume_encrypted": _root_volume_encrypted(ec2, instance),
        "security_group_ids": [g["GroupId"]
                               for g in instance.get("SecurityGroups", [])],
        "has_instance_profile": bool(instance.get("IamInstanceProfile")),
        "managed_by_us": tags.get(MANAGED_TAG_KEY) == MANAGED_TAG_VALUE,
    }


# ------------------------------------------------------------------- Terminate


def terminate_instance(ec2, instance_id):
    """Terminates an instance. This is permanent and it stops the billing."""
    try:
        ec2.terminate_instances(InstanceIds=[instance_id])
        return True, (
            f"Terminating {instance_id}. Billing stops as it shuts down. This "
            "cannot be undone: the instance and its root disk are destroyed."
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "UnauthorizedOperation":
            return False, ("This login lacks permission to terminate instances "
                           "(needs ec2:TerminateInstances).")
        return False, e.response["Error"]["Message"]


def cleanup_all_managed_instances(ec2):
    """Terminates every instance this tool launched.

    The one piece of teardown in this project that saves money rather than
    tidiness. Worth running even when you think nothing is left.
    """
    results = []
    for instance in list_instances(ec2, only_ours=True):
        ok, message = terminate_instance(ec2, instance["InstanceId"])
        results.append((instance["InstanceId"], ok, message))
    return results


# ------------------------------------------------------------------------- Fix


def enforce_imdsv2(ec2, instance_id):
    """Switches a running instance to IMDSv2 only. CIS 5.7.

    Safe on a running instance: it changes how the metadata service answers,
    not the instance itself. Software still using IMDSv1 will start getting
    401s, which is the point, but it is worth knowing before clicking.
    """
    try:
        ec2.modify_instance_metadata_options(
            InstanceId=instance_id,
            HttpTokens="required",
            HttpEndpoint="enabled",
            HttpPutResponseHopLimit=1,
        )
        return True, (
            "The metadata service now requires a session token. Anything on "
            "this instance still using the older method will stop being able "
            "to read instance credentials, which is the intent."
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "UnauthorizedOperation":
            return False, ("This login lacks permission to change metadata "
                           "options (needs ec2:ModifyInstanceMetadataOptions).")
        return False, e.response["Error"]["Message"]


_FIX_ACTIONS = {
    "enforce_imdsv2": enforce_imdsv2,
}


def apply_fix(ec2, instance_id, warning):
    """Executes remediation specified in warning objects."""
    fix = warning.get("fix")
    if not fix:
        return False, "Nothing to fix on this warning."

    handler = _FIX_ACTIONS.get(fix["action"])
    if not handler:
        return False, f"Unknown fix type: {fix['action']}"

    return handler(ec2, instance_id)
