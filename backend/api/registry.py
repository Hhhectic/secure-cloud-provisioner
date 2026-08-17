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

from aws.common import ClientError

from aws import security_groups as sg
from aws import s3_buckets as s3
from aws import key_pairs as kp
from aws import instances as ec2i
from aws import vpcs
from aws import alarms
from aws import iam
from aws import snapshots
from aws import roles
from az import nsg as az_nsg
from az import storage as az_storage
from az import keyvault as az_keyvault
from az import vnet as az_vnet
from az import vm as az_vm
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
from scanner.role_rules import check_role
from scanner.azure_nsg_rules import check_nsg, check_nsg_spec
from scanner.azure_storage_rules import (check_storage_account,
                                         check_storage_spec)
from scanner.azure_keyvault_rules import check_key_vault, check_key_vault_spec
from scanner.azure_vnet_rules import check_vnet, check_vnet_spec
from scanner.azure_vm_rules import check_vm, check_vm_spec

DEFAULT_REGION = "us-east-1"

# Azure's equivalent, used when a spec names no location. Separate from
# DEFAULT_REGION because "us-east-1" is not a place Azure has heard of.
DEFAULT_AZURE_LOCATION = "eastus"


def _az_location(spec):
    """Where an Azure resource goes, in one place for all five types.

    Two spellings because two callers: the CLI and the smoke test have always
    sent `region`, and the page's forms ask for `location`, which is the word
    Azure uses. Three adapters already tried both and two read only `region`,
    so the same form field worked or did not depending on which type it was -
    except that `location` reached none of them, because ResourceSpec did not
    declare it until now and pydantic drops what it does not declare.
    """
    return spec.get("region") or spec.get("location") or DEFAULT_AZURE_LOCATION


def _az_created(result):
    """Reduces a created Azure resource's id to the name the routes accept.

    Azure answers a create with the full ARM path, which carries eight slashes;
    a route takes an id as ONE path segment. So every follow-up call on the id
    a create had just handed back - read, scan, fix, the deletion plan, delete -
    matched no route and 404'd before any Azure code ran. A resource built from
    the page could not then be deleted from the page, which is how three live
    resources were stranded in a real subscription and had to be removed by
    typing their names in by hand.

    The list adapters were fixed for this and the create adapters were not,
    which is why nothing caught it: a list-then-act flow works and a
    create-then-act flow does not. `A row's id is whatever the routes accept`
    is the rule, and for Azure that is the name.
    """
    ok, value, problems = result
    if ok and isinstance(value, str) and "/" in value:
        value = value.rsplit("/", 1)[-1]
    return ok, value, problems

# Ports a form should offer, which is not the same list as the ports the
# scanner warns about. RISKY_PORTS exists to describe what is dangerous;
# 80 and 443 belong in a menu of things people open on purpose and would be
# wrong in that one, because everything in it produces a finding. The
# descriptions are taken from the scanner wherever it has them, so the words a
# user picks from are the words the warning will use back at them.
FORM_PORTS = [22, 80, 443, 3389, 3306, 5432, 6379, 9200, 27017, 5900]

# What a port is, in a few words, for a menu.
#
# Deliberately not RISKY_PORTS. That is the scanner's prose and it belongs in
# a finding, where there is a whole sentence to be read and "the remote login
# door for Windows servers" is exactly the right amount of explanation for
# somebody who does not know what 3389 is. In a dropdown it is 63 characters
# in a 133px control: measured, the longest of them overflowed by 280px, so
# the closed menu showed "3389 — Remote Desktop, the remo…" and a chosen port
# could not be read back at all.
#
# Short enough to fit, long enough to still answer "what is this port". The
# names people actually say - SSH, RDP, MySQL - rather than a description of
# them.
PORT_MENU_LABELS = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    3389: "Remote Desktop",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
    5900: "VNC",
}


def _port_choices():
    choices = []
    for port in FORM_PORTS:
        what = PORT_MENU_LABELS.get(port, "")
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
    # "the entire internet" stays: an address is jargon by this project's own
    # style rule, and 0.0.0.0/0 is the one entry here where the words are the
    # whole warning. "private networks only" shortens to "private" without
    # losing anything - the address beside it already says which.
    return [
        {"value": OPEN_TO_WORLD_V4,
         "label": f"{OPEN_TO_WORLD_V4} — the entire internet"},
        {"value": OPEN_TO_WORLD_V6,
         "label": f"{OPEN_TO_WORLD_V6} — all of it, IPv6"},
        {"value": "10.0.0.0/8", "label": "10.0.0.0/8 — private"},
        {"value": "172.16.0.0/12", "label": "172.16.0.0/12 — private"},
        {"value": "192.168.0.0/16", "label": "192.168.0.0/16 — private"},
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
    # A choice may carry anything else the form needs alongside its value and
    # label; the page reads the whole object. An alarm's metric carries the
    # unit its threshold is measured in, because a bare number is meaningless
    # without it: 20 is twenty dollars under billing and twenty percent under
    # CPU, and offering the wrong one is not untidy but wrong — those amounts
    # are valid for CPUUtilization, so "$20" would create an alarm at 20% that
    # fires on an idle machine.
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

    # What the checkbox that narrows the list should say, or None if this
    # type has no meaningful way to narrow it.
    #
    # The page used to infer this from read_only: audited types got the box
    # disabled, on the reasoning that nothing tags an account. That held while
    # the audited types were IAM and snapshots, and broke the moment roles
    # arrived - a role filter is meaningful, it just means "written by somebody
    # here" rather than "made by this tool", and the page had no way to say so.
    # Snapshots were caught by the same rule despite genuinely honouring the
    # tag, so make_vulnerable's demo snapshots could not be picked out either.
    #
    # The default suits every type that filters by this tool's own tag.
    only_ours_label: Optional[str] = "only ones this tool made"

    # Which cloud this lives in, so a caller can group by it.
    #
    # The page needs the split to offer one cloud at a time rather than
    # fourteen tabs in a row, and the only other way to get it is to match on
    # the "azure-" key prefix - the page inferring a provider from a naming
    # convention nothing guarantees - and one that goes wrong the first time
    # somebody registers "aks" or "s3-glacier". Declared here instead, next to
    # the adapters that actually talk to that cloud, so a third provider is one
    # more value rather than another prefix rule in JavaScript.
    #
    # Defaulted to aws because eight of the nine AWS types predate the second
    # cloud and none of them should have to say so.
    provider: str = "aws"

    # The label again, for somewhere the cloud is already established.
    #
    # Every Azure label starts with the word Azure because the CLI lists all
    # fourteen types together and "Storage account" beside "Storage bucket"
    # would be a guess. A page showing one cloud at a time has already said
    # which, so the prefix is a word repeated in every row of a 212px column.
    # None means the label was already short enough.
    short_label: Optional[str] = None

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
    """Creates a group in the network the caller named, and only there.

    This used to fall back to the account's default VPC when a spec omitted
    vpc_id. That contradicted the rule the rest of this program is built on -
    placement is asked for, never assumed - and it was only ever reachable over
    HTTP, because the CLI and the page both ask. So the one caller who could
    hit it was a script, which is the caller least likely to notice that its
    group went somewhere it did not choose.

    A network cannot be changed after creation and it decides more about a
    group's reach than any rule in it, so guessing is the expensive kind of
    wrong. The menu is served by _sg_options; a caller with no vpc_id in hand
    can read it from GET /resources/security-group/options.
    """
    vpc_id = spec.get("vpc_id")
    if not vpc_id:
        return False, (
            "Which network this group belongs to has to be chosen, because it "
            "cannot be changed afterwards and it decides what the group can "
            "reach. Pass vpc_id; GET /resources/security-group/options lists "
            "the networks in this account."
        ), []

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
    # report travels in options rather than as a parameter on ResourceType.
    # delete, because thirteen other adapters would otherwise have to grow an
    # argument they ignore. A delete that has nothing to say simply never
    # calls it, which is every type but this one so far.
    return vpcs.delete_vpc(client, resource_id,
                           force=options.get("force", False),
                           report=options.get("report"))


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
    # One account. There is nothing to narrow it to.
    only_ours_label=None,
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


def _metric_for(namespace):
    """The metric that goes with a namespace, since the menu chooses both.

    The form offers one control - "Account spending ($)" or "CPU usage (%)" -
    whose value is a namespace. The metric was then read from the spec with an
    unconditional `or BILLING_METRIC` fallback, and no caller of the web form
    can send a metric because there is no field for one. So picking CPU built
    an alarm on AWS/EC2 + EstimatedCharges: a pair that has no data, which
    CloudWatch accepts without complaint and which then sits in
    INSUFFICIENT_DATA forever.

    That is exactly the silence `scanner/alarm_rules.py` exists to catch, and
    it could not: no rule reads metric_name, so the pre-flight and the
    read-back scan both called it clean. backend/main.py has always paired the
    two correctly; this is the same pairing, in the half the page uses.

    A mapping and not an `if`, returning None for anything unlisted. The first
    version of this fix ended `return alarms.BILLING_METRIC`, which pairs any
    third namespace with EstimatedCharges and rebuilds the same
    never-fires-forever alarm the moment one is added - the defect reproduced
    by its own repair. The caller refuses instead, because a wrong pairing is
    silent and a refusal is not.
    """
    return {
        alarms.BILLING_NAMESPACE: alarms.BILLING_METRIC,
        alarms.CPU_NAMESPACE: alarms.CPU_METRIC,
    }.get(namespace)


def _alarm_create(client, spec):
    namespace = spec.get("namespace") or alarms.BILLING_NAMESPACE
    # An explicit metric still wins: the CLI and the smoke test send one.
    metric_name = spec.get("metric_name") or _metric_for(namespace)
    if not metric_name:
        return False, (
            f"'{namespace}' is not a namespace this tool knows the metric for, "
            f"and none was named. Send metric_name as well, or use one of "
            f"{alarms.BILLING_NAMESPACE} or {alarms.CPU_NAMESPACE}. Guessing "
            f"here builds an alarm on a pair with no data, which CloudWatch "
            f"accepts and then leaves silent forever."
        ), []

    return alarms.create_alarm(
        client,
        name=spec["name"],
        namespace=namespace,
        metric_name=metric_name,
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
    # The unit is in the label because that is where it is already being read.
    #
    # It has been in three places now. A menu of dollar amounts, which offered
    # "$20" while CPU was selected and would have created an alarm at 20
    # percent. Then a sentence under the box, which was a line of prose to say
    # one character. "Account spending ($)" is shorter than both and cannot
    # drift from the thing it describes, because it is the same string.
    return {
        "namespace": [
            {"value": alarms.BILLING_NAMESPACE,
             "label": "Account spending ($)"},
            {"value": alarms.CPU_NAMESPACE,
             "label": "CPU usage (%)"},
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
# ---------------------------------------------------------------------- Roles


def _role_list(client, only_ours):
    """Roles somebody in this account wrote.

    only_ours excludes the roles AWS creates for its own services. An account
    has dozens, nobody chose their contents and nobody can change them, so
    including them by default would bury the handful a person actually wrote.
    """
    return [
        {"id": r["RoleName"], "name": r["RoleName"]}
        for r in roles.list_roles(client, only_ours=only_ours)
    ]


def _role_check_spec(spec):
    """Nothing to check: this tool does not create roles."""
    return []


def _role_fix(client, resource_id, warning, options):
    return roles.apply_fix(client, resource_id, warning)


ROLE = ResourceType(
    key="role",
    label="Role",
    id_label="Role name",
    get_client=roles.get_client,
    list_all=_role_list,
    read=roles.read_role_for_scanning,
    check=check_role,
    describe=roles.describe_role,
    check_spec=_role_check_spec,
    fix=_role_fix,
    # Not by tag: this tool creates no roles. The useful distinction is
    # between roles somebody chose the contents of and the dozens AWS makes
    # for its own services, which cannot be changed and bury the rest.
    only_ours_label="only ones somebody here wrote",
    # Audited, never provisioned. Creating a role is not a security operation,
    # and changing one decides who can enter the account.
    read_only=True,
)


# ---------------------------------------------------------------- Azure
#
# The second provider, and the first evidence that the warning contract in
# scanner/common.py is what it has claimed to be since the first commit. Two
# entries here, no changes to api/app.py, no changes to scanner/common.py -
# which is the whole argument for having built it this way, finally testable
# rather than asserted.
#
# All five types provision now. That used to read "storage provisions; network
# security groups still do not", because an Azure firewall rule carries a
# priority deciding which of several overlapping rules wins and nothing here
# read the ordered set. scanner/azure_nsg_effective.py reads it, which is what
# unblocked creating a group, fixing a rule, and the two types built on top.


def _az_summary(resources):
    """List rows for the routes, keyed by name rather than by ARM path.

    `id` here means the identifier every per-resource route accepts, and a
    route takes it as one path segment: /resources/azure-storage/{id}. This
    used to hand back the full ARM path, which is nine segments separated by
    the one character a path parameter cannot carry - so the request never
    matched the route at all and 404'd before any Azure code ran. The readers
    themselves take either form quite happily, which is what made this hard to
    see from the inside: every offline test that called one directly passed.

    What it cost was the page. It passes a row's id straight to scan, fix and
    delete, so creating an Azure resource worked and then the detail panel said
    "Not Found" about the thing it had just built, no fix buttons appeared, and
    the delete modal opened empty with its button disabled forever.

    The name is unique per resource group rather than per subscription for
    every type but storage, so this is the same ambiguity the routes already
    had by taking a name at all; it is not introduced here.

    Which is why the resource group and the location travel alongside it. The
    readers have always known both, and dropping them here left the page
    printing the name in both of its two columns - a table saying one thing
    twice. They are also the two facts that make the name legible: a group
    called `web` means nothing on its own, and two of them in different
    resource groups are two different firewalls.
    """
    return [{"id": r["name"], "name": r["name"],
             "resource_group": r.get("resource_group"),
             "location": r.get("location")}
            for r in resources]


def _az_nsg_list(client, only_ours):
    return _az_summary(az_nsg.list_nsgs(client, only_ours=only_ours))


def _az_nsg_fix(client, resource_id, warning, options):
    return az_nsg.apply_fix(client, resource_id, warning)


def _az_nsg_create(client, spec):
    """Creates one security group, in a resource group the spec has to name.

    The same refusal the other two Azure types make, for the same reason: a
    resource group has no AWS equivalent to default from.
    """
    group = spec.get("resource_group")
    if not group:
        return False, (
            "Azure puts every resource in a resource group, and this one names "
            "none. Give a resource group; it will be created if it does not "
            "already exist."
        ), []

    return _az_created(az_nsg.create_nsg(
        client,
        spec.get("name"),
        group,
        location=_az_location(spec),
        # azure_rules, not rules: the AWS field carries a different shape, and
        # check_nsg_spec reads the same key for the same reason.
        rules=spec.get("azure_rules") or [],
    ))


def _az_nsg_delete(client, resource_id, options):
    return az_nsg.delete_nsg(
        client, resource_id, force=options.get("force", False))


def _az_nsg_cleanup(client, options):
    return az_nsg.cleanup_all_managed_nsgs(
        client, force=options.get("force", False))


def _az_nsg_options(client):
    """What a firewall form may offer, per field of one rule.

    The ports and the sources are the AWS lists, for the reason
    `_az_vm_options` gives: a port is the same port on either cloud and the
    scanner describes it in the same words. Only "everyone" differs - Azure
    writes `*` where AWS writes 0.0.0.0/0, and offering the AWS spelling
    produces a rule Azure accepts and treats as one address, which is the
    quietest possible way to build a firewall that does not do what it says.

    There is no priority here on purpose. `az/nsg._priorities_for` assigns one
    per rule from the list order, ten apart, and refuses a set where some
    rules name a priority and some do not. A field for it would let somebody
    submit two rules with the same priority - which Azure rejects - or an
    order whose effect is not the order the list reads as, which Azure accepts
    and nobody notices. The list is the precedence, and that is the only
    arrangement where what was typed and what Azure does are the same thing.
    """
    # Every label here has to fit a control about 133px wide, because an Azure
    # rule row carries six fields where a security group's carries three. A
    # label that overflows is not merely untidy: the closed menu truncates it,
    # so the thing somebody just chose cannot be read back.
    #
    # What survives shortening is whatever the bare value does not already
    # say. "Inbound" and "Allow" are ordinary words under captions that read
    # "direction" and "allow or deny", so the explanation was the same word
    # twice; "*" and "VirtualNetwork" say nothing on their own and keep theirs.
    return {
        "rule_direction": [
            {"value": "Inbound", "label": "Inbound"},
            {"value": "Outbound", "label": "Outbound"},
        ],
        # The field with no AWS counterpart, and the reason the AWS rules
        # widget cannot be reused as it stands. A security group has no deny;
        # every rule in one is an allow. An Azure rule set is read in order
        # until something matches, so a Deny above an Allow is what closes a
        # port the Allow below would open - and a form that submitted
        # everything as Allow would silently build a different firewall.
        "rule_access": [
            {"value": "Allow", "label": "Allow"},
            {"value": "Deny", "label": "Deny"},
        ],
        "rule_protocol": [
            {"value": "Tcp", "label": "TCP"},
            {"value": "Udp", "label": "UDP"},
            {"value": "Icmp", "label": "ICMP (ping)"},
            {"value": "*", "label": "All protocols"},
        ],
        "rule_port": _port_choices(),
        "rule_source": [
            {"value": "*", "label": "* — everywhere"},
            {"value": "VirtualNetwork", "label": "This network"},
            {"value": "AzureLoadBalancer", "label": "Azure load balancer"},
            {"value": "10.0.0.0/8", "label": "10.0.0.0/8 — private"},
            {"value": "192.168.0.0/16", "label": "192.168.0.0/16 — private"},
        ],
    }


AZURE_NSG = ResourceType(
    key="azure-nsg",
    provider="azure",
    short_label="Network security group",
    label="Azure network security group",
    id_label="Group name",
    get_client=az_nsg.get_client,
    create=_az_nsg_create,
    list_all=_az_nsg_list,
    read=az_nsg.read_nsg_for_scanning,
    check=check_nsg,
    describe=az_nsg.describe_nsg,
    check_spec=check_nsg_spec,
    fix=_az_nsg_fix,
    delete=_az_nsg_delete,
    cleanup=_az_nsg_cleanup,
    options=_az_nsg_options,
    # This type creates resources now, so the tag means something and the box
    # is worth offering. It did not until create_nsg arrived.
    only_ours_label="only ones this tool made",
    # The one Azure type with a deletion preview, and the reason is the reverse
    # of the reason the other two have none: deleting a group destroys nothing
    # inside it and exposes everything attached to it, which is a list this can
    # actually produce.
    plan_deletion=az_nsg.plan_deletion,
)


def _az_storage_list(client, only_ours):
    return _az_summary(az_storage.list_accounts(client, only_ours=only_ours))


def _az_storage_fix(client, resource_id, warning, options):
    return az_storage.apply_fix(client, resource_id, warning)


def _az_storage_create(client, spec):
    """Creates one storage account, in a resource group the spec has to name.

    The refusal is here rather than in the model because a missing resource
    group is only a problem for Azure, and ResourceSpec is shared with eight
    AWS types that have never heard of one. A default would have to be
    invented - there is no equivalent of the account's default VPC to fall
    back on - and inventing a place to put somebody's storage is the kind of
    quiet decision `_sg_create` is still on the Not-done list for making.
    """
    group = spec.get("resource_group")
    if not group:
        return False, (
            "Azure puts every resource in a resource group, and this one names "
            "none. Give a resource group; it will be created if it does not "
            "already exist."
        ), []

    return _az_created(az_storage.create_account(
        client,
        spec["name"],
        group,
        location=_az_location(spec),
        secure_by_default=spec.get("secure_by_default", True),
    ))


def _az_storage_delete(client, resource_id, options):
    return az_storage.delete_account(
        client, resource_id, force=options.get("force", False))


def _az_storage_cleanup(client, options):
    return az_storage.cleanup_all_managed_accounts(
        client, force=options.get("force", False))


AZURE_STORAGE = ResourceType(
    key="azure-storage",
    provider="azure",
    short_label="Storage account",
    label="Azure storage account",
    id_label="Account name",
    get_client=az_storage.get_client,
    create=_az_storage_create,
    list_all=_az_storage_list,
    read=az_storage.read_account_for_scanning,
    check=check_storage_account,
    describe=az_storage.describe_account,
    check_spec=check_storage_spec,
    fix=_az_storage_fix,
    delete=_az_storage_delete,
    cleanup=_az_storage_cleanup,
    # No plan_deletion, for the reason a bucket has none: deleting an account
    # takes every container and blob with it, and "nothing else would be
    # destroyed" is the one answer that must not appear in front of this
    # button. The route says there is no preview instead.
)


# ------------------------------------------------------------ Azure key vaults


def _az_keyvault_list(client, only_ours):
    return _az_summary(az_keyvault.list_vaults(client, only_ours=only_ours))


def _az_keyvault_fix(client, resource_id, warning, options):
    return az_keyvault.apply_fix(client, resource_id, warning)


def _az_keyvault_create(client, spec):
    """Creates one key vault, in a resource group the spec has to name.

    The same refusal _az_storage_create makes, for the same reason: a resource
    group has no AWS equivalent to default from.
    """
    group = spec.get("resource_group")
    if not group:
        return False, (
            "Azure puts every resource in a resource group, and this one names "
            "none. Give a resource group; it will be created if it does not "
            "already exist."
        ), []

    return _az_created(az_keyvault.create_vault(
        client,
        spec["name"],
        group,
        location=_az_location(spec),
        secure_by_default=spec.get("secure_by_default", True),
    ))


def _az_keyvault_delete(client, resource_id, options):
    return az_keyvault.delete_vault(
        client, resource_id, force=options.get("force", False))


def _az_keyvault_cleanup(client, options):
    return az_keyvault.cleanup_all_managed_vaults(
        client, force=options.get("force", False))


AZURE_KEYVAULT = ResourceType(
    key="azure-keyvault",
    provider="azure",
    short_label="Key vault",
    label="Azure key vault",
    id_label="Vault name",
    get_client=az_keyvault.get_client,
    create=_az_keyvault_create,
    list_all=_az_keyvault_list,
    read=az_keyvault.read_vault_for_scanning,
    check=check_key_vault,
    describe=az_keyvault.describe_vault,
    check_spec=check_key_vault_spec,
    fix=_az_keyvault_fix,
    delete=_az_keyvault_delete,
    cleanup=_az_keyvault_cleanup,
    # No plan_deletion. A vault's delete reaches further than any inventory
    # this tool could print - what breaks is whatever was encrypted with the
    # keys inside, which lives in resources this tool has never read. An empty
    # preview in front of that would be the most misleading thing here.
)


# --------------------------------------------------------- Azure virtual networks


def _az_vnet_list(client, only_ours):
    return _az_summary(az_vnet.list_vnets(client, only_ours=only_ours))


def _az_vnet_fix(client, resource_id, warning, options):
    return az_vnet.apply_fix(client, resource_id, warning)


def _az_vnet_create(client, spec):
    group = spec.get("resource_group")
    if not group:
        return False, (
            "Azure puts every resource in a resource group, and this one names "
            "none. Give a resource group; it will be created if it does not "
            "already exist."
        ), []

    return _az_created(az_vnet.create_vnet(
        client,
        spec.get("name"),
        group,
        location=_az_location(spec),
        address_prefixes=spec.get("address_prefixes"),
        subnets=spec.get("subnets"),
    ))


def _az_vnet_delete(client, resource_id, options):
    return az_vnet.delete_vnet(
        client, resource_id, force=options.get("force", False))


def _az_vnet_cleanup(client, options):
    return az_vnet.cleanup_all_managed_vnets(
        client, force=options.get("force", False))


AZURE_VNET = ResourceType(
    key="azure-vnet",
    provider="azure",
    short_label="Virtual network",
    label="Azure virtual network",
    id_label="Network name",
    get_client=az_vnet.get_client,
    create=_az_vnet_create,
    list_all=_az_vnet_list,
    read=az_vnet.read_vnet_for_scanning,
    check=check_vnet,
    describe=az_vnet.describe_vnet,
    check_spec=check_vnet_spec,
    fix=_az_vnet_fix,
    delete=_az_vnet_delete,
    cleanup=_az_vnet_cleanup,
    only_ours_label="only ones this tool made",
    plan_deletion=az_vnet.plan_deletion,
)


# ------------------------------------------------------- Azure virtual machines


def _az_vm_list(client, only_ours):
    return _az_summary(az_vm.list_vms(client, only_ours=only_ours))


def _az_vm_fix(client, resource_id, warning, options):
    return az_vm.apply_fix(client, resource_id, warning)


def _az_vm_create(client, spec):
    group = spec.get("resource_group")
    if not group:
        return False, (
            "Azure puts every resource in a resource group, and this one names "
            "none. Give a resource group; it will be created if it does not "
            "already exist."
        ), []

    return _az_created(az_vm.create_vm(
        client,
        spec.get("name"),
        group,
        location=_az_location(spec),
        vm_size=spec.get("vm_size"),
        admin_username=spec.get("admin_username") or "azureuser",
        # public_key, matching the AWS key-pair field. There is deliberately no
        # private key field anywhere in this project; see CLAUDE.md.
        ssh_public_key=spec.get("public_key") or spec.get("ssh_public_key"),
        vnet_name=spec.get("vnet_name"),
        subnet_name=spec.get("subnet_name") or "default",
        nsg_name=spec.get("nsg_name"),
        assign_public_ip=bool(spec.get("assign_public_ip")),
        open_ports=spec.get("open_ports"),
        allowed_source=spec.get("allowed_source"),
        encryption_at_host=bool(spec.get("encryption_at_host")),
    ))


def _az_vm_delete(client, resource_id, options):
    return az_vm.delete_vm(
        client, resource_id, force=options.get("force", False))


def _az_vm_cleanup(client, options):
    return az_vm.cleanup_all_managed_vms(
        client, force=options.get("force", False))


def _size_choices(offered, allowlist):
    """A machine size menu that says what each size is.

    `offered` carries vCPU and memory from resource_skus; the fallback is the
    bare allowlist, used when that call could not be made. A size with no
    numbers is labelled with its name alone rather than with a guess - the
    menu being less helpful is better than it being wrong about how big a
    machine is.
    """
    if not offered:
        return [{"value": name, "label": name} for name in sorted(allowlist)]

    choices = []
    for size in offered:
        vcpus, memory = size.get("vcpus"), size.get("memory_gb")
        if vcpus and memory:
            core = "core" if vcpus == 1 else "cores"
            label = f"{size['name']} — {vcpus} {core}, {memory} GB memory"
        else:
            label = size["name"]
        choices.append({"value": size["name"], "label": label})
    return choices


def _az_vm_options(client):
    """What a machine form may offer.

    Here rather than in the page for the reason every other options callable
    is: the allowlist is enforced in az/vm.py, and a menu hardcoded in
    JavaScript would be a second copy of it that goes wrong at a different
    time.

    The ports and the sources are the same lists the AWS forms offer, and
    deliberately so - a port is the same port on either cloud and the scanner
    describes it in the same words. Only the "everyone" value differs: Azure
    writes `*` where AWS writes 0.0.0.0/0, and offering the AWS spelling would
    produce a rule Azure accepts and treats as a single address.
    """
    # Only the sizes this subscription can actually start, not the whole
    # allowlist. Azure restricts sizes per subscription as well as per region
    # and reports both as SkuNotAvailable, so a menu built from ALLOWED_VM_SIZES
    # offered fourteen sizes here of which nine could never launch - and the
    # three Standard_B1* entries a person reaches for first were all among
    # them. az/vm.py already had available_sizes and already used it to explain
    # a refusal; the form was still offering the unfiltered list, so the page
    # led people into exactly the failure that function exists to prevent.
    #
    # Location is the account default because the form's own location field is
    # free text that may be empty when the menus are built. A size list for the
    # wrong region is a worse menu than this, but an empty one is worse still,
    # so an unanswerable lookup falls back to the allowlist rather than
    # offering nothing.
    startable = az_vm.offered_sizes(client, DEFAULT_AZURE_LOCATION)

    return {
        # Labelled with what the machine is, not only what Azure calls it.
        #
        # The name is jargon of the purest kind - family, generation, memory
        # ratio and feature letters, all of which have to be already known to
        # be read - and this project's own style note says findings are aimed
        # at somebody who does not know the jargon. The port menu two lines
        # down says "22 - SSH, the remote login door for Linux servers"; the
        # size menu was saying "Standard_F1als_v7" twice.
        #
        # The numbers arrive on the same call that decides which sizes are
        # offered at all, so this costs nothing extra.
        "vm_size": _size_choices(startable, az_vm.ALLOWED_VM_SIZES),
        "open_ports": _port_choices(),
        "allowed_source": [
            {"value": "*", "label": "* — the entire internet"},
            {"value": "VirtualNetwork",
             "label": "VirtualNetwork — only this network"},
            {"value": "10.0.0.0/8", "label": "10.0.0.0/8 — private networks only"},
            {"value": "192.168.0.0/16",
             "label": "192.168.0.0/16 — private networks only"},
        ],
    }


AZURE_VM = ResourceType(
    key="azure-vm",
    provider="azure",
    short_label="Virtual machine",
    label="Azure virtual machine",
    id_label="Machine name",
    get_client=az_vm.get_client,
    create=_az_vm_create,
    list_all=_az_vm_list,
    read=az_vm.read_vm_for_scanning,
    check=check_vm,
    describe=az_vm.describe_vm,
    check_spec=check_vm_spec,
    fix=_az_vm_fix,
    delete=_az_vm_delete,
    cleanup=_az_vm_cleanup,
    options=_az_vm_options,
    only_ours_label="only ones this tool made",
    plan_deletion=az_vm.plan_deletion,
)


REGISTRY = {r.key: r for r in (SECURITY_GROUP, BUCKET, KEY_PAIR, INSTANCE, IAM,
                               ROLE, AZURE_NSG, AZURE_STORAGE, AZURE_KEYVAULT,
                               AZURE_VNET, AZURE_VM, SNAPSHOT, ALARM, VPC)}


def get(resource_type):
    """Returns the registered resource, or None if the key is unknown."""
    return REGISTRY.get(resource_type)
