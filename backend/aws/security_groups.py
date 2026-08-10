"""Reading, creating, updating, and deleting EC2 security groups.

Handles all boto3 AWS interactions.
"""

import urllib.request
from aws.common import client as _client, ClientError

MANAGED_TAG_KEY = "ManagedBy"
MANAGED_TAG_VALUE = "secure-cloud-provisioner"


def get_client(region="us-east-1"):
    """Initializes and returns an EC2 client."""
    return _client("ec2", region)


def get_default_vpc(ec2):
    """Retrieves the default VPC ID for the current AWS account."""
    try:
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "is-default", "Values": ["true"]}])["Vpcs"]
        if not vpcs:
            return None, "No default VPC found."
        return vpcs[0]["VpcId"], None
    except ClientError as e:
        return None, e.response["Error"]["Message"]


# ---------------------------------------------------------------- CRUD Operations


def to_ip_permission(rule):
    """Converts one flat rule dict into the IpPermissions entry AWS expects.

    Three kinds of source, in three different fields.

    An address range goes in IpRanges or Ipv6Ranges depending on family.
    Putting "::/0" into CidrIp is accepted by botocore and then rejected by AWS
    with a message that does not mention address families, so the split happens
    here rather than at the call site.

    A source written "sg:sg-0123..." means another security group, and goes in
    UserIdGroupPairs. This is the shape that makes a bastion architecture work:
    the private machines trust the bastion's group rather than any address, so
    the bastion's address can change, and nothing else on the internet can
    impersonate it by arriving from the right IP.
    """
    source = rule["source"]
    entry = {"IpProtocol": rule["protocol"]}
    described = {"Description": "Added by provisioner"}

    # Checked before the IPv6 test, because "sg:" contains a colon.
    if source.startswith("sg:"):
        entry["UserIdGroupPairs"] = [dict(described, GroupId=source[3:])]
    elif ":" in source:
        entry["Ipv6Ranges"] = [dict(described, CidrIpv6=source)]
    else:
        entry["IpRanges"] = [dict(described, CidrIp=source)]

    if rule.get("from_port") is not None:
        entry["FromPort"] = rule["from_port"]
        entry["ToPort"] = rule["to_port"]

    return entry


def _without_duplicates(rules):
    """Returns (unique rules, how many were dropped).

    AWS rejects the entire authorize call if the same permission appears twice
    in it - "The same permission must not appear multiple times" - and rejects
    it wholesale, so one repeated rule loses every other rule in the request.
    A group then exists with nothing in it, which is a far worse outcome than
    the duplicate would have been, and the only clue is one line of error text.

    A repeat is not a mistake worth failing over. Asking for the same opening
    twice means wanting it once.
    """
    seen = set()
    unique = []

    for rule in rules:
        identity = (
            rule.get("protocol"),
            rule.get("from_port"),
            rule.get("to_port"),
            rule.get("source"),
        )
        if identity in seen:
            continue
        seen.add(identity)
        unique.append(rule)

    return unique, len(rules) - len(unique)


def add_rules(ec2, group_id, rules):
    """Authorizes ingress rules on an existing group."""
    if not rules:
        return True, "No rules to add."

    rules, dropped = _without_duplicates(rules)
    repeated = (f" {dropped} repeated rule(s) were asked for once instead."
                if dropped else "")

    try:
        ec2.authorize_security_group_ingress(
            GroupId=group_id,
            IpPermissions=[to_ip_permission(r) for r in rules],
        )
        return True, f"Added {len(rules)} rule(s).{repeated}"
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "InvalidPermission.Duplicate":
            return True, "Those rules were already there."
        if code == "UnauthorizedOperation":
            return False, (
                "The group was created but its rules were not applied: this "
                "login lacks ec2:AuthorizeSecurityGroupIngress."
            )
        return False, f"The group was created but its rules were not applied: {e.response['Error']['Message']}"


def create_security_group(ec2, group_name, description, vpc_id, rules=None):
    """Creates a tagged security group and authorizes initial ingress rules.

    Returns (ok, group_id_or_error, problems), matching create_bucket.

    The third element exists because creating the group and authorizing its
    rules are two calls behind two different permissions. The previous version
    returned False when the second one failed, which left a real group sitting
    in the account described to the user as a failure. A group that exists is a
    success with a problem attached, not a failure.
    """
    problems = []

    try:
        resp = ec2.create_security_group(
            GroupName=group_name,
            Description=description,
            VpcId=vpc_id,
            TagSpecifications=[{
                "ResourceType": "security-group",
                "Tags": [
                    {"Key": MANAGED_TAG_KEY, "Value": MANAGED_TAG_VALUE},
                    {"Key": "Environment", "Value": "test"},
                ]
            }]
        )
        sg_id = resp["GroupId"]
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidGroup.Duplicate":
            return False, e.response["Error"]["Message"], []

        found = ec2.describe_security_groups(
            Filters=[{"Name": "group-name", "Values": [group_name]},
                     {"Name": "vpc-id", "Values": [vpc_id]}]
        )["SecurityGroups"]
        if not found:
            return False, (
                f"A group named '{group_name}' exists but could not be read back."
            ), []
        sg_id = found[0]["GroupId"]
        problems.append(
            "A group with this name already existed in this network, so nothing "
            "new was created. Any rules you asked for were added to it."
        )

    ok, msg = add_rules(ec2, sg_id, rules)
    if not ok:
        problems.append(msg)

    return True, sg_id, problems


def list_security_groups(ec2, only_ours=False, vpc_id=None):
    """Returns raw security groups with pagination support."""
    filters = []
    if only_ours:
        filters.append({"Name": f"tag:{MANAGED_TAG_KEY}", "Values": [MANAGED_TAG_VALUE]})
    if vpc_id:
        filters.append({"Name": "vpc-id", "Values": [vpc_id]})

    groups = []
    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate(Filters=filters):
        groups.extend(page["SecurityGroups"])
    return groups


def list_rules(ec2, group_id):
    """Returns each rule with its SecurityGroupRuleId for targeted remediation."""
    rules = []
    paginator = ec2.get_paginator("describe_security_group_rules")
    for page in paginator.paginate(
        Filters=[{"Name": "group-id", "Values": [group_id]}]
    ):
        rules.extend(page["SecurityGroupRules"])
    return rules


def delete_security_group(ec2, group_id):
    """Deletes a specific security group by ID."""
    try:
        ec2.delete_security_group(GroupId=group_id)
        return True, f"Deleted {group_id}"
    except ClientError as e:
        return False, e.response["Error"]["Message"]


def cleanup_all_managed_groups(ec2):
    """Purges all security groups managed by this tool."""
    groups = list_security_groups(ec2, only_ours=True)
    results = []
    for sg in groups:
        success, msg = delete_security_group(ec2, sg["GroupId"])
        results.append((sg["GroupId"], success, msg))
    return results


# ----------------------------------------------------------- Data Transformation


def to_scanner_shape(aws_rules, include_outbound=False):
    """Transforms AWS rule objects into flat dicts expected by scanner/rules.py."""
    translated = []

    for r in aws_rules:
        if r.get("IsEgress") and not include_outbound:
            continue

        if r.get("CidrIpv4"):
            source = r["CidrIpv4"]
        elif r.get("CidrIpv6"):
            source = r["CidrIpv6"]
        elif r.get("ReferencedGroupInfo"):
            source = "sg:" + r["ReferencedGroupInfo"].get("GroupId", "unknown")
        elif r.get("PrefixListId"):
            source = "prefix-list:" + r["PrefixListId"]
        else:
            source = "unknown"

        translated.append({
            "rule_id": r.get("SecurityGroupRuleId"),
            # resource_id, not group_id: common.warning reads this key to say
            # which thing a finding came from, and it is the name every other
            # scanner's rule dict uses. A firewall-specific spelling here left
            # every firewall finding with resource_id: null, which is invisible
            # while a page shows one group and wrong the moment one lists an
            # account's findings together.
            "resource_id": r.get("GroupId"),
            "protocol": r.get("IpProtocol"),
            "from_port": r.get("FromPort"),
            "to_port": r.get("ToPort"),
            "source": source,
            "description": r.get("Description", ""),
            "direction": "outbound" if r.get("IsEgress") else "inbound",
        })

    return translated


def read_group_for_scanning(ec2, group_id, include_outbound=False):
    """Retrieves security group rules formatted for scanner processing."""
    return to_scanner_shape(list_rules(ec2, group_id),
                            include_outbound=include_outbound)


def groups_in_use(ec2):
    """Returns the IDs of every security group attached to something.

    Attachment is visible through network interfaces rather than instances,
    because a group can be attached to a load balancer, an RDS instance, a
    Lambda function in a VPC or an endpoint, none of which are EC2 instances.
    Every one of those has an interface, so asking about interfaces catches all
    of them where asking about instances would report live groups as unused.
    """
    in_use = set()
    paginator = ec2.get_paginator("describe_network_interfaces")

    for page in paginator.paginate():
        for interface in page.get("NetworkInterfaces", []):
            for group in interface.get("Groups", []):
                in_use.add(group["GroupId"])

    return in_use


def read_group_usage(ec2, group, in_use=None):
    """Describes one group's attachment state for the usage checker.

    Pass in_use when checking several groups so the interface listing happens
    once rather than per group.
    """
    if in_use is None:
        in_use = groups_in_use(ec2)

    return {
        "group_id": group["GroupId"],
        "group_name": group.get("GroupName"),
        "is_default": group.get("GroupName") == "default",
        "in_use": group["GroupId"] in in_use,
    }


# ----------------------------------------------------------------- Fix Operations


def my_public_ip():
    """Fetches public IP address via AWS endpoint."""
    with urllib.request.urlopen("https://checkip.amazonaws.com", timeout=5) as resp:
        return resp.read().decode().strip()


def remove_rule(ec2, group_id, rule_id, direction="inbound", dry_run=False):
    """Deletes one rule by ID, supporting both inbound and outbound rules."""
    try:
        if direction == "outbound":
            ec2.revoke_security_group_egress(
                GroupId=group_id,
                SecurityGroupRuleIds=[rule_id],
                DryRun=dry_run,
            )
        else:
            ec2.revoke_security_group_ingress(
                GroupId=group_id,
                SecurityGroupRuleIds=[rule_id],
                DryRun=dry_run,
            )
        return True, "Rule removed."
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "DryRunOperation":
            return True, "Allowed (dry run, nothing changed)."
        if code == "UnauthorizedOperation":
            return False, "This login lacks permission to change rules."
        return False, e.response["Error"]["Message"]


def narrow_rule_to_ip(ec2, group_id, rule, new_cidr=None):
    """Modifies rule CIDR scope to target a single IP address.

    A rule cannot change address family, so an IPv6 rule cannot be narrowed to
    an IPv4 address. That case is reported rather than attempted, because the
    error AWS returns for it does not explain itself.

    Falls back to revoke-then-authorize where modify_security_group_rules is
    unavailable. The fallback is safe in the direction that matters: if the
    revoke succeeds and the authorize fails, the result is no access rather than
    the original wide-open access.
    """
    is_ipv6_rule = ":" in (rule.get("source") or "")

    if new_cidr is None:
        if is_ipv6_rule:
            return False, (
                "This rule allows IPv6 addresses, which cannot be narrowed to an "
                "IPv4 address. Remove the rule instead, or replace it with one "
                "naming your own IPv6 address."
            )
        new_cidr = my_public_ip() + "/32"

    if is_ipv6_rule != (":" in new_cidr):
        return False, (
            "A rule cannot be switched between IPv4 and IPv6. Remove this rule "
            "and add a new one instead."
        )

    field = "CidrIpv6" if is_ipv6_rule else "CidrIpv4"
    replacement = {
        "IpProtocol": rule["protocol"],
        field: new_cidr,
        "Description": "Narrowed by secure-cloud-provisioner",
    }
    if rule.get("from_port") is not None:
        replacement["FromPort"] = rule["from_port"]
        replacement["ToPort"] = rule["to_port"]

    try:
        ec2.modify_security_group_rules(
            GroupId=group_id,
            SecurityGroupRules=[{
                "SecurityGroupRuleId": rule["rule_id"],
                "SecurityGroupRule": replacement,
            }],
        )
        return True, f"Rule now only allows {new_cidr}."
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "UnauthorizedOperation":
            return False, "This login lacks permission to change rules."
        if code not in ("InvalidParameterValue", "UnsupportedOperation"):
            return False, e.response["Error"]["Message"]
    except (AttributeError, NotImplementedError):
        pass

    return _narrow_by_replacing(ec2, group_id, rule, new_cidr)


def _narrow_by_replacing(ec2, group_id, rule, new_cidr):
    """Revokes the wide rule and authorizes a narrow one in its place.

    Used where modify_security_group_rules is not available. Note the new rule
    gets a new SecurityGroupRuleId, so anything holding the old ID must re-read
    the group afterwards.
    """
    removed, msg = remove_rule(ec2, group_id, rule["rule_id"],
                               direction=rule.get("direction", "inbound"))
    if not removed:
        return False, msg

    narrowed = dict(rule)
    narrowed["source"] = new_cidr
    added, msg = add_rules(ec2, group_id, [narrowed])
    if not added:
        return False, (
            f"The wide-open rule was removed, but the replacement allowing "
            f"{new_cidr} could not be added: {msg} Nothing can reach this port "
            "now. Add the rule you want manually."
        )

    return True, f"Rule now only allows {new_cidr}."


def apply_fix(ec2, group_id, warning, new_cidr=None):
    """Executes remediation logic specified in warning objects."""
    fix = warning.get("fix")
    if not fix:
        return False, "Nothing to fix on this warning."

    if fix["action"] == "remove":
        direction = warning.get("rule", {}).get("direction", "inbound")
        return remove_rule(ec2, group_id, warning["rule_id"], direction=direction)

    if fix["action"] == "narrow_to_my_ip":
        return narrow_rule_to_ip(ec2, group_id, warning["rule"], new_cidr)

    return False, f"Unknown fix type: {fix['action']}"