"""One interface over every resource type the tool can provision.

The two AWS modules do the same seven things with different signatures, because
a firewall and a bucket genuinely differ: one takes ports and address ranges,
the other takes a globally unique name and three on/off switches. Rather than
push that difference up into the HTTP routes, each resource registers a set of
small adapter functions here that present a single shape:

    create(client, spec)              -> (ok, id_or_error, problems)
    list_all(client, only_ours)       -> [{"id": str, "name": str, ...}]
    read(client, resource_id)         -> settings the scanner understands
    check(settings)                   -> warnings
    check_spec(spec)                  -> warnings for something not created yet
    fix(client, resource_id, w, opts) -> (ok, message)
    delete(client, resource_id, opts) -> (ok, message)
    cleanup(client, opts)             -> [(id, ok, message)]

Adding EC2 instances, or Azure, means writing one of these blocks and adding a
line to REGISTRY. No route changes.
"""

from dataclasses import dataclass
from typing import Any, Callable, Optional

from botocore.exceptions import ClientError

from aws import security_groups as sg
from aws import s3_buckets as s3
from aws import key_pairs as kp
from aws import instances as ec2i
from aws import vpcs
from aws import alarms
from aws import iam
from aws import snapshots
from scanner.rules import (
    check_firewall_rules,
    check_group_usage,
    check_default_group,
    RISKY_PORTS,
    OPEN_TO_WORLD_V4,
    OPEN_TO_WORLD_V6,
)
from scanner.s3_rules import check_bucket_settings
from scanner.key_pair_rules import check_key_pair
from scanner.instance_rules import check_instance, BUSY_PERCENT
from scanner.vpc_rules import check_vpc
from scanner.iam_rules import check_account
from scanner.alarm_rules import check_alarm, check_alarm_spec
from scanner.snapshot_rules import check_snapshot

DEFAULT_REGION = "us-east-1"

# Ports a form should offer, which is not the same list as the ports the
# scanner warns about. RISKY_PORTS exists to describe what is dangerous;
# 80 and 443 belong in a menu of things people open on purpose and would be
# wrong in that one, because everything in it produces a finding. The
# descriptions are taken from the scanner wherever it has them, so the words a
# user picks from are the words the warning will use back at them.
FORM_PORTS = [22, 80, 443, 3389, 3306, 5432, 6379, 9200, 27017, 5900]

EXTRA_PORT_LABELS = {
    80: "HTTP, an unencrypted web server",
    443: "HTTPS, an encrypted web server",
}


def _port_choices():
    choices = []
    for port in FORM_PORTS:
        what = RISKY_PORTS.get(port) or EXTRA_PORT_LABELS.get(port, "")
        choices.append({"value": str(port),
                        "label": f"{port} — {what}" if what else str(port)})
    return choices


def _protocol_choices():
    return [
        {"value": "tcp", "label": "TCP"},
        {"value": "udp", "label": "UDP"},
        {"value": "icmp", "label": "ICMP (ping)"},
        {"value": "-1", "label": "All protocols"},
    ]


def _source_choices():
    return [
        {"value": OPEN_TO_WORLD_V4,
         "label": f"{OPEN_TO_WORLD_V4} — the entire internet"},
        {"value": OPEN_TO_WORLD_V6,
         "label": f"{OPEN_TO_WORLD_V6} — the entire internet, IPv6"},
        {"value": "10.0.0.0/8", "label": "10.0.0.0/8 — private networks only"},
        {"value": "172.16.0.0/12", "label": "172.16.0.0/12 — private networks only"},
        {"value": "192.168.0.0/16", "label": "192.168.0.0/16 — private networks only"},
    ]


def _name_tag(resource, fallback="unnamed"):
    """The Name tag off a raw AWS object, for labelling a menu entry."""
    tags = {t["Key"]: t["Value"] for t in resource.get("Tags", [])}
    return tags.get("Name", fallback)


def _as_read(settings):
    """The default description: whatever read() returned.

    Correct for every resource whose read is already a flat description of the
    thing. Only the two that wrap extra material for the scanner need to
    override it.
    """
    return settings


def _cannot_create(*args, **kwargs):
    raise NotImplementedError("this resource type is audited, not provisioned")


@dataclass(frozen=True)
class ResourceType:
    key: str
    label: str
    id_label: str
    get_client: Callable[[str], Any]
    list_all: Callable
    read: Callable
    check: Callable
    check_spec: Callable
    fix: Callable

    # Not every resource is one this tool makes.
    #
    # An account's IAM configuration, or the snapshots lying around in it, can
    # be audited but not provisioned - there is no sensible "create an IAM
    # posture" operation, and a tool that offered to delete access keys or
    # snapshots on someone's behalf would be dangerous in a way none of the
    # rest of this is. Those types set read_only and leave the three
    # destructive callables alone.
    #
    # The alternative was a create() that returns an error string, which would
    # let /docs advertise an endpoint that always refuses. Saying a type cannot
    # be created is more honest than pretending it can and declining.
    read_only: bool = False
    create: Callable = _cannot_create
    delete: Callable = _cannot_create
    cleanup: Callable = _cannot_create

    # The choices a form should offer for this type, as
    # {field: [{"value", "label"}]}.
    #
    # Here rather than in the page because every one of them is already known
    # on this side and knowing it twice is how the two drift: the instance
    # allowlist is enforced in aws/instances.py, the port descriptions are the
    # scanner's own words, and the networks a group can be placed in are a
    # live account lookup. A menu hardcoded in JavaScript would be a second
    # copy of all three, wrong at a different time from the first.
    #
    # A choice may carry "when": {other_field: value}, meaning it only applies
    # while that field holds that value. An alarm's threshold is the case that
    # forced it — dollars against CPUUtilization is not untidy, it is wrong:
    # "$20" offered next to Server CPU reads as money and creates an alarm at
    # 20%, which fires on an idle machine and gets muted within a week.
    #
    # None means this type has nothing to offer and the form is plain text.
    options: Optional[Callable] = None

    # What a forced delete would destroy, in the order it would go.
    #
    # Only networks have one, because only a network's delete reaches things
    # that are not it: a VPC cascade terminates machines, and a machine might
    # be doing something for somebody who has never heard of this tool. The
    # CLI has shown this list and demanded a typed ID since it was written;
    # this field is what lets the HTTP routes do the same, rather than being
    # the one interface where the destructive path is also the quiet one.
    #
    # None means no preview exists for this type. The route says so rather
    # than returning an empty list, which would read as "this destroys
    # nothing else" - the wrong answer for a bucket, whose forced delete
    # empties it first.
    plan_deletion: Optional[Callable] = None

    # What the resource looks like, as opposed to what is wrong with it.
    #
    # read() returns whatever check() needs, which for two resources is a
    # wrapper holding the thing plus material gathered alongside it. That
    # wrapper is this module's internal arrangement; the API should not hand it
    # to a browser and call it the resource. describe() unwraps where needed
    # and is the identity everywhere else.
    describe: Callable = _as_read


# ------------------------------------------------------------- Security groups


def _sg_create(client, spec):
    vpc_id = spec.get("vpc_id")
    if not vpc_id:
        vpc_id, err = sg.get_default_vpc(client)
        if err:
            return False, err, []

    return sg.create_security_group(
        client,
        spec["name"],
        spec.get("description") or "Managed by secure-cloud-provisioner",
        vpc_id,
        spec.get("rules"),
    )


def _sg_list(client, only_ours):
    return [
        {"id": g["GroupId"], "name": g["GroupName"], "vpc_id": g.get("VpcId")}
        for g in sg.list_security_groups(client, only_ours=only_ours)
    ]


def _sg_read(client, group_id, include_outbound=False):
    """Reads a group's rules plus whether anything is using it.

    Usage is not a rule, so it rides alongside the rule list rather than in it.
    _sg_check unpacks the pair.

    Outbound is off by default. Every new security group allows all outbound,
    so including it would put a finding on essentially every group in every
    account — precisely the noise that gets a scanner ignored. It is available
    on request for anyone who wants the fuller picture.
    """
    try:
        groups = client.describe_security_groups(
            GroupIds=[group_id]
        )["SecurityGroups"]
    except ClientError as e:
        if e.response["Error"]["Code"] in ("InvalidGroup.NotFound",
                                           "InvalidGroupId.Malformed"):
            return None
        raise

    if not groups:
        return None

    return {
        "rules": sg.read_group_for_scanning(client, group_id,
                                            include_outbound=include_outbound),
        "usage": sg.read_group_usage(client, groups[0]),
    }


def _sg_describe(settings):
    """Rules and whether anything uses the group. Both are facts about it."""
    if not settings:
        return None
    usage = settings.get("usage") or {}
    return {
        "group_id": usage.get("group_id"),
        "name": usage.get("group_name"),
        "is_default": usage.get("is_default"),
        "in_use": usage.get("in_use"),
        "rules": settings.get("rules") or [],
    }


def _sg_check(settings):
    if not settings:
        return []
    warnings = check_firewall_rules(settings["rules"])
    usage = settings.get("usage")
    if usage:
        warnings.extend(check_group_usage(usage))
        warnings.extend(check_default_group(usage, settings["rules"]))
    return warnings


def _sg_check_spec(spec):
    """Scans rules the user has typed but not yet submitted.

    These have no rule IDs because they do not exist yet, so the warnings come
    back unfixable. That is correct: the remedy for a bad rule in a form is to
    edit the form, not to call AWS.
    """
    return check_firewall_rules(spec.get("rules") or [])


def _networks_for_menu(client):
    """Every network, labelled. Shared by the forms that must place something.

    Placement is asked for and never assumed, which only works if the asking
    is answerable - a text box wanting a vpc- identifier is a question most
    people cannot answer without leaving the page.
    """
    try:
        return [{"value": v["id"], "label": v["name"]}
                for v in _vpc_list(client, False)]
    except ClientError:
        return []


def _sg_options(client):
    return {
        "vpc_id": _networks_for_menu(client),
        "protocol": _protocol_choices(),
        "port": _port_choices(),
        "source": _source_choices(),
    }


def _sg_fix(client, resource_id, warning, options):
    return sg.apply_fix(client, resource_id, warning,
                        new_cidr=options.get("new_cidr"))


def _sg_delete(client, resource_id, options):
    return sg.delete_security_group(client, resource_id)


def _sg_cleanup(client, options):
    return sg.cleanup_all_managed_groups(client)


SECURITY_GROUP = ResourceType(
    key="security-group",
    label="Security group",
    id_label="Group ID",
    get_client=sg.get_client,
    create=_sg_create,
    list_all=_sg_list,
    read=_sg_read,
    check=_sg_check,
    describe=_sg_describe,
    check_spec=_sg_check_spec,
    fix=_sg_fix,
    options=_sg_options,
    delete=_sg_delete,
    cleanup=_sg_cleanup,
)


# ------------------------------------------------------------------ S3 buckets


def _bucket_create(client, spec):
    return s3.create_bucket(
        client,
        spec["name"],
        region=spec.get("region") or DEFAULT_REGION,
        secure_by_default=spec.get("secure_by_default", True),
    )


def _bucket_list(client, only_ours):
    return [
        {"id": b["Name"], "name": b["Name"]}
        for b in s3.list_buckets(client, only_ours=only_ours)
    ]


def _bucket_check_spec(spec):
    """Scans the settings a bucket would have if created with this form.

    Builds the same settings dict read_bucket_for_scanning would produce, so the
    warnings the user sees before creating match the ones they see after.
    """
    secure = spec.get("secure_by_default", True)
    return check_bucket_settings({
        "bucket": spec.get("name") or "this bucket",
        "public_access_block": dict(s3.ALL_BLOCKS_ON) if secure else None,
        "encryption": {
            "enabled": secure,
            "algorithm": "AES256" if secure else None,
        },
        "versioning": {"enabled": secure, "mfa_delete": False},
        "public_acl_grants": [],
        "policy_is_public": False,
        "policy_denies_http": secure,
        "logging_enabled": False,
        "unreadable": {},
    })


def _bucket_fix(client, resource_id, warning, options):
    return s3.apply_fix(client, resource_id, warning)


def _bucket_delete(client, resource_id, options):
    return s3.delete_bucket(client, resource_id, force=options.get("force", False))


def _bucket_cleanup(client, options):
    return s3.cleanup_all_managed_buckets(client, force=options.get("force", False))


BUCKET = ResourceType(
    key="bucket",
    label="Storage bucket",
    id_label="Bucket name",
    get_client=s3.get_client,
    create=_bucket_create,
    list_all=_bucket_list,
    read=s3.read_bucket_for_scanning,
    check=check_bucket_settings,
    check_spec=_bucket_check_spec,
    fix=_bucket_fix,
    delete=_bucket_delete,
    cleanup=_bucket_cleanup,
)


# ------------------------------------------------------------------ Key pairs


def _key_pair_create(client, spec):
    """Imports a public key. Never generates one.

    The spec carries public_key because that is all this tool will accept. See
    aws/key_pairs.py for why create_key_pair is not used anywhere.
    """
    material = spec.get("public_key")
    if not material:
        return False, (
            "No public key was provided. Generate a key pair on your own "
            "machine and send the public half; this tool does not create "
            "private keys."
        ), []

    return kp.import_key_pair(client, spec["name"], material)


def _key_pair_list(client, only_ours):
    return [
        {"id": k["KeyName"], "name": k["KeyName"]}
        for k in kp.list_key_pairs(client, only_ours=only_ours)
    ]


def _key_pair_check_spec(spec):
    """Scans a key before it is imported.

    The only thing knowable in advance is the type, which the public key
    itself declares. Validation failures are raised at import rather than
    reported here, because a malformed key is not a security finding.
    """
    material = spec.get("public_key")
    if not material:
        return []

    try:
        key_type = kp.validate_public_key(material)
    except kp.InvalidPublicKey:
        return []

    return check_key_pair({
        "key_name": spec.get("name") or "this key",
        "key_type": key_type,
        # Nothing can be using a key that has not been imported yet, and
        # reporting that as a finding before creation would be noise.
        "in_use": True,
    })


def _key_pair_fix(client, resource_id, warning, options):
    return kp.apply_fix(client, resource_id, warning)


def _key_pair_delete(client, resource_id, options):
    return kp.delete_key_pair(client, resource_id)


def _key_pair_cleanup(client, options):
    return kp.cleanup_all_managed_key_pairs(client)


KEY_PAIR = ResourceType(
    key="key-pair",
    label="Key pair",
    id_label="Key name",
    get_client=kp.get_client,
    create=_key_pair_create,
    list_all=_key_pair_list,
    read=kp.read_key_pair_for_scanning,
    check=check_key_pair,
    check_spec=_key_pair_check_spec,
    fix=_key_pair_fix,
    delete=_key_pair_delete,
    cleanup=_key_pair_cleanup,
)


# ------------------------------------------------------------------- Instances


def _instance_create(client, spec):
    return ec2i.launch_instance(
        client,
        name=spec["name"],
        region=spec.get("region") or DEFAULT_REGION,
        instance_type=spec.get("instance_type"),
        key_name=spec.get("key_name"),
        security_group_ids=spec.get("security_group_ids"),
        subnet_id=spec.get("subnet_id"),
        assign_public_ip=spec.get("assign_public_ip", False),
    )


def _instance_list(client, only_ours):
    out = []
    for i in ec2i.list_instances(client, only_ours=only_ours):
        tags = {t["Key"]: t["Value"] for t in i.get("Tags", [])}
        out.append({
            "id": i["InstanceId"],
            "name": tags.get("Name", i["InstanceId"]),
        })
    return out


def _instance_read(client, instance_id):
    """Reads the instance and the findings from the groups attached to it.

    The firewall findings are fetched here rather than in the rules, because
    the rules must stay free of AWS calls. check_instance turns them into a
    statement about the machine.
    """
    settings = ec2i.read_instance_for_scanning(client, instance_id)
    if not settings:
        return None

    # What the machine has been doing, which lives in CloudWatch rather than
    # EC2. Fetched here for the same reason the firewall findings are: the
    # rules cannot make a cloud call, and a caller asking about a machine
    # should not have to know its workload is kept in a different service.
    settings["cpu_usage"] = ec2i.read_cpu_usage(client, instance_id)

    firewall = []
    rules = []
    rules = []
    for group_id in settings.get("security_group_ids", []):
        group_rules = sg.read_group_for_scanning(client, group_id)
        rules.extend(group_rules)
        firewall.extend(check_firewall_rules(group_rules))

    # Whether SSH is permitted at all, from anywhere. Distinct from whether it
    # is permitted from the whole internet: a rule narrowed to one address is
    # not a finding, but it is still the difference between being able to log
    # in and not. The scanner cannot work this out from the warnings alone,
    # because a correctly narrowed rule produces no warning.
    settings["ssh_reachable"] = any(
        r.get("direction") != "outbound"
        and r.get("from_port") is not None
        and r["from_port"] <= 22 <= r["to_port"]
        for r in rules
    ) or any(r.get("protocol") == "-1" and r.get("direction") != "outbound"
             for r in rules)

    return {"instance": settings, "firewall": firewall}


def _instance_describe(settings):
    """The machine itself. The firewall findings alongside it are already
    reported as warnings, so repeating them here would say the same thing
    twice in two shapes."""
    return settings["instance"] if settings else None


def _instance_check(settings):
    if not settings:
        return []
    return check_instance(settings["instance"], settings["firewall"])


def _instance_check_spec(spec):
    """Scans a launch request before anything is created.

    Only the settings this tool controls at launch are knowable in advance, and
    it always sets the metadata options securely, so the useful finding here is
    about the public address.
    """
    return check_instance({
        "instance_id": spec.get("name") or "this instance",
        "name": spec.get("name") or "this instance",
        "imdsv2_required": True,
        "metadata_endpoint_enabled": True,
        "metadata_hop_limit": 1,
        "public_ip": "an address will be assigned"
                     if spec.get("assign_public_ip") else None,
        "root_volume_encrypted": True,
        "key_name": spec.get("key_name"),
        "security_group_ids": spec.get("security_group_ids") or [],
        # Unknowable before launch without reading the groups, and claiming
        # SSH is unreachable when it is would be worse than staying quiet.
        "ssh_reachable": True,
    })


def _instance_options(client):
    """The allowlist, plus whatever this account actually has to attach.

    instance_type comes from aws/instances rather than a list typed here, so
    the menu cannot offer something the tool would then refuse - the refusal
    is the guardrail and a menu that disagreed with it would look like a bug.
    """
    def _safe(fn):
        try:
            return fn()
        except ClientError:
            return []

    subnets = _safe(lambda: [
        {"value": s["SubnetId"],
         "label": f"{_name_tag(s)} ({s.get('CidrBlock')}, {s.get('AvailabilityZone')})"}
        for s in client.describe_subnets()["Subnets"]
    ])

    groups = _safe(lambda: [
        {"value": g["id"], "label": f"{g['name']} ({g.get('vpc_id') or 'no network'})"}
        for g in _sg_list(client, False)
    ])

    keys = _safe(lambda: [{"value": k["id"], "label": k["name"]}
                          for k in _key_pair_list(client, False)])

    return {
        "instance_type": [
            {"value": t, "label": t + (" (default)"
                                       if t == ec2i.DEFAULT_INSTANCE_TYPE else "")}
            for t in sorted(ec2i.ALLOWED_INSTANCE_TYPES)
        ],
        "key_name": keys,
        "security_group_ids": groups,
        "subnet_id": subnets,
    }


def _instance_fix(client, resource_id, warning, options):
    return ec2i.apply_fix(client, resource_id, warning)


def _instance_delete(client, resource_id, options):
    return ec2i.terminate_instance(client, resource_id)


def _instance_cleanup(client, options):
    return ec2i.cleanup_all_managed_instances(client)


INSTANCE = ResourceType(
    key="instance",
    label="Server",
    id_label="Instance ID",
    get_client=ec2i.get_client,
    create=_instance_create,
    list_all=_instance_list,
    read=_instance_read,
    check=_instance_check,
    describe=_instance_describe,
    check_spec=_instance_check_spec,
    fix=_instance_fix,
    options=_instance_options,
    delete=_instance_delete,
    cleanup=_instance_cleanup,
)


# ----------------------------------------------------------------------- VPCs


def _vpc_create(client, spec):
    return vpcs.create_vpc(
        client,
        name=spec["name"],
        cidr=spec.get("cidr") or vpcs.DEFAULT_CIDR,
        region=spec.get("region") or DEFAULT_REGION,
        with_nat_gateway=spec.get("with_nat_gateway", False),
    )


def _vpc_list(client, only_ours):
    out = []
    for v in vpcs.list_vpcs(client, only_ours=only_ours):
        tags = {t["Key"]: t["Value"] for t in v.get("Tags", [])}
        label = tags.get("Name", v["VpcId"])
        if v.get("IsDefault"):
            label += " (default)"
        out.append({"id": v["VpcId"], "name": label})
    return out


def _vpc_check_spec(spec):
    """Scans a network before it is created.

    The layout this tool builds is fixed, so the only thing worth checking in
    advance is whether a NAT gateway was asked for. That refusal comes from
    the AWS layer at creation; reporting it here as well means the form can
    say so before the button is pressed.
    """
    if spec.get("with_nat_gateway"):
        return check_vpc({
            "vpc_id": spec.get("name") or "this network",
            "name": spec.get("name") or "this network",
            "flow_logs_enabled": True,
            "subnets": [],
        })
    return []


def _vpc_options(client):
    """Sizes rather than a free-text CIDR.

    The tool carves a /16 into two /24s, so the sensible answers are a small
    set and the interesting decision is not the number.
    """
    return {
        "cidr": [
            {"value": vpcs.DEFAULT_CIDR, "label": f"{vpcs.DEFAULT_CIDR} (default)"},
            {"value": "10.1.0.0/16", "label": "10.1.0.0/16"},
            {"value": "172.31.0.0/16", "label": "172.31.0.0/16"},
            {"value": "192.168.0.0/16", "label": "192.168.0.0/16"},
        ],
    }


def _vpc_plan_deletion(client, resource_id):
    """The cascade, flattened for the API, with ownership marked per item.

    vpcs.plan_deletion returns tuples in deletion order and vpcs.not_ours says
    which of them this tool did not create. The CLI prints the second as a "!"
    against the first; over HTTP they have to travel together, because a
    caller cannot mark up a list it was given no marks for.
    """
    plan = vpcs.plan_deletion(client, resource_id)
    foreign = {item[1] for item in vpcs.not_ours(plan, client, resource_id)}

    return [
        {
            "kind": kind,
            "id": item_id,
            "label": label,
            "created_by_this_tool": item_id not in foreign,
        }
        for kind, item_id, label in plan
    ]


def _vpc_fix(client, resource_id, warning, options):
    return vpcs.apply_fix(client, resource_id, warning)


def _vpc_delete(client, resource_id, options):
    return vpcs.delete_vpc(client, resource_id, force=options.get("force", False))


def _vpc_cleanup(client, options):
    return vpcs.cleanup_all_managed_vpcs(client, force=options.get("force", False))


VPC = ResourceType(
    key="network",
    label="Network",
    id_label="VPC ID",
    get_client=vpcs.get_client,
    create=_vpc_create,
    list_all=_vpc_list,
    read=vpcs.read_vpc_for_scanning,
    check=check_vpc,
    check_spec=_vpc_check_spec,
    fix=_vpc_fix,
    options=_vpc_options,
    delete=_vpc_delete,
    cleanup=_vpc_cleanup,
    plan_deletion=_vpc_plan_deletion,
)


# ------------------------------------------------------------------------- IAM


def _iam_list(client, only_ours):
    """One row: the account itself.

    Every other type lists many things of one kind. There is exactly one IAM
    configuration per account, and the alternative - listing users as the
    resources - would leave the root user, the password policy and the account's
    analyzers with nowhere to be reported, which is most of what CIS section 1
    is about.

    only_ours is meaningless here and is ignored rather than made to mean
    something. Nothing tags an account, and this tool did not create it.
    """
    account = iam.account_id(client)
    alias = iam.account_alias(client)
    return [{"id": account, "name": f"{alias} ({account})" if alias else account}]


def _iam_check_spec(spec):
    """Nothing to check: there is no form that creates an IAM posture.

    Returning an empty list rather than raising keeps POST /check working
    generically for every type, which is what lets the route stay one route.
    """
    return []


def _iam_fix(client, resource_id, warning, options):
    return iam.apply_fix(client, resource_id, warning)


IAM = ResourceType(
    key="iam",
    label="Account access",
    id_label="Account ID",
    get_client=iam.get_client,
    list_all=_iam_list,
    read=iam.read_account_for_scanning,
    check=check_account,
    describe=iam.describe_account,
    check_spec=_iam_check_spec,
    fix=_iam_fix,
    # Audited, never provisioned. create, delete and cleanup stay unimplemented
    # and the routes answer 405 with a sentence about why.
    read_only=True,
)


# ------------------------------------------------------------------- Snapshots


def _snapshot_list(client, only_ours):
    """Snapshots this account owns.

    only_ours means "tagged by this tool", which for snapshots can only be
    something scripts/make_vulnerable.py left behind - nothing here creates
    one. It is honoured rather than ignored so the demo resources can be
    picked out, which is the one case where the distinction exists.
    """
    out = []
    for s in snapshots.list_snapshots(client, only_ours=only_ours):
        tags = {t["Key"]: t["Value"] for t in s.get("Tags", [])}
        out.append({
            "id": s["SnapshotId"],
            "name": tags.get("Name") or s.get("Description") or s["SnapshotId"],
        })
    return out


def _snapshot_check_spec(spec):
    """Nothing to check: no form here creates a snapshot.

    Same reasoning as _iam_check_spec. Returning an empty list rather than
    raising is what lets POST /check stay one route for every type.
    """
    return []


def _snapshot_fix(client, resource_id, warning, options):
    return snapshots.apply_fix(client, resource_id, warning)


SNAPSHOT = ResourceType(
    key="snapshot",
    label="Disk backup",
    id_label="Snapshot ID",
    get_client=snapshots.get_client,
    list_all=_snapshot_list,
    read=snapshots.read_snapshot_for_scanning,
    check=check_snapshot,
    check_spec=_snapshot_check_spec,
    fix=_snapshot_fix,
    # Audited, never provisioned. A snapshot is somebody's backup; deleting one
    # on their behalf is the most destructive thing this tool could offer, and
    # creating one is not a security operation at all.
    read_only=True,
)


# --------------------------------------------------------------------- Alarms


def _alarm_create(client, spec):
    return alarms.create_alarm(
        client,
        name=spec["name"],
        namespace=spec.get("namespace") or alarms.BILLING_NAMESPACE,
        metric_name=spec.get("metric_name") or alarms.BILLING_METRIC,
        threshold=spec.get("threshold"),
        region=spec.get("region"),
        period=spec.get("period"),
        evaluation_periods=spec.get("evaluation_periods", 2),
        treat_missing_data=spec.get("treat_missing_data"),
        dimensions=spec.get("dimensions"),
        notify=spec.get("notify", True),
        email=spec.get("email"),
        description=spec.get("description"),
    )


def _alarm_list(client, only_ours):
    return [
        {"id": a["AlarmName"], "name": a["AlarmName"]}
        for a in alarms.list_alarms(client, only_ours=only_ours)
    ]


def _alarm_options(client):
    """What the form should offer.

    The two metrics here are the two this tool has an opinion about. Anything
    else CloudWatch can watch is still reachable by typing a namespace and a
    metric name; these are the ones where the defaults, the period and the
    missing-data handling are all decided for you and decided correctly.
    """
    return {
        "namespace": [
            {"value": alarms.BILLING_NAMESPACE,
             "label": "Account spending — tells you before the bill does"},
            {"value": alarms.CPU_NAMESPACE,
             "label": "Server CPU — tells you a machine is working hard"},
        ],
        # A threshold means nothing without the metric it belongs to. These
        # carry "when", so the form shows only the ones that make sense for
        # whatever is being watched: offering dollars against CPUUtilization
        # is not merely untidy, it reads as $20 and creates an alarm at 20%
        # that fires on an idle machine and gets muted within a week.
        "threshold": [
            {"value": "5", "label": "$5 — a free-tier project has slipped",
             "when": {"namespace": alarms.BILLING_NAMESPACE}},
            {"value": "20", "label": "$20",
             "when": {"namespace": alarms.BILLING_NAMESPACE}},
            {"value": "50", "label": "$50",
             "when": {"namespace": alarms.BILLING_NAMESPACE}},

            # The scanner's own bands, so the number somebody picks here is
            # the number it will use back at them when it describes the
            # machine.
            {"value": str(BUSY_PERCENT),
             "label": f"{BUSY_PERCENT}% — the band this tool calls working hard",
             "when": {"namespace": alarms.CPU_NAMESPACE}},
            {"value": "85", "label": "85%",
             "when": {"namespace": alarms.CPU_NAMESPACE}},
            {"value": "95", "label": "95% — saturated, work is queueing",
             "when": {"namespace": alarms.CPU_NAMESPACE}},
        ],
    }


def _alarm_fix(client, resource_id, warning, options):
    return alarms.apply_fix(client, resource_id, warning)


def _alarm_delete(client, resource_id, options):
    return alarms.delete_alarm(client, resource_id)


def _alarm_cleanup(client, options):
    return alarms.cleanup_all_managed_alarms(client)


ALARM = ResourceType(
    key="alarm",
    label="Alarm",
    id_label="Alarm name",
    get_client=alarms.get_client,
    create=_alarm_create,
    list_all=_alarm_list,
    read=alarms.read_alarm_for_scanning,
    check=check_alarm,
    check_spec=check_alarm_spec,
    options=_alarm_options,
    fix=_alarm_fix,
    delete=_alarm_delete,
    cleanup=_alarm_cleanup,
)


# Networks last: cleanup runs in registry order, and a VPC cannot be deleted
# until the things inside it are gone. IAM sits before them rather than at the
# end, because it creates and deletes nothing and so has no place in a cleanup
# ordering at all - putting it last would suggest it did.
REGISTRY = {r.key: r for r in (SECURITY_GROUP, BUCKET, KEY_PAIR, INSTANCE, IAM,
                               SNAPSHOT, ALARM, VPC)}


def get(resource_type):
    """Returns the registered resource, or None if the key is unknown."""
    return REGISTRY.get(resource_type)
