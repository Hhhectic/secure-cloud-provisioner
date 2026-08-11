"""Pre-flight security scan for the provisioning forms.

    from preflight import scan_config

Called with the flat dictionary a Streamlit form produces, before anything is
sent to a cloud provider. Named preflight rather than scanner because `scanner`
is the backend's rule package; see backend_path.py.

The AWS rules are not written here. backend/scanner/ already evaluates buckets,
firewalls and instances, its rules are free of boto3 so they run without an
account, and they carry citations to published controls. This module builds the
settings snapshot each of those rules expects and calls them. Only the Azure
rules live here, because backend/ has no Azure in it.

Everything comes back in the one warning shape defined by
backend/scanner/common.py, so the UI has a single thing to render:

    {"level": critical|warning|info, "message": str, "rule_id", "resource_id",
     "rule", "fix", "control"}

Two additions to that shape, both ignored by anything that does not look for
them:

    blocking   True on a finding that makes the request invalid rather than
               insecure - a malformed bucket name, a private key in the public
               key box. The UI refuses to deploy these and does not offer the
               acknowledgement checkbox, because the provider would reject the
               call anyway.
    title      A short heading. The Azure findings carry one because they are
               rendered as a block with a remediation line under it.
"""

import ipaddress
import re
from typing import Any, Dict, List

import backend_path  # noqa: F401 - must precede the aws/scanner imports below

from aws.s3_buckets import ALL_BLOCKS_ON
from scanner.common import (
    CRITICAL,
    INFO,
    WARNING,
    summarize,
    warning as _warning,
    worst_level,
)
from scanner.instance_rules import check_instance
from scanner.rules import check_firewall_rules
from scanner.s3_rules import check_bucket_settings

from security_messages import GET_SECURITY_MESSAGE

ALL_USERS_URI = "http://acs.amazonaws.com/groups/global/AllUsers"

WORLD_CIDRS = {"0.0.0.0/0", "*", "internet", "any", "::/0"}

RESERVED_ADMIN_USERNAMES = {"admin", "administrator", "root", "user", "test", "guest"}

SSH_PUBLIC_KEY_PREFIXES = ("ssh-rsa", "ssh-ed25519", "ecdsa-sha2-", "ssh-dss")

# The Azure catalogue in security_messages.py predates the shared contract and
# grades findings on a five-step ladder. Three of those steps mean "this is a
# way in or a way data gets out", which is what critical means here.
_AZURE_LEVELS = {
    "BLOCKER": CRITICAL,
    "CRITICAL": CRITICAL,
    "HIGH": CRITICAL,
    "MEDIUM": WARNING,
    "LOW": INFO,
}


# ----------------------------------------------------------------------
# Building findings
# ----------------------------------------------------------------------
def _blocker(message: str, field: str, title: str) -> Dict[str, Any]:
    """A configuration the provider would reject. Not acknowledgeable."""
    found = _warning(CRITICAL, message, rule={"rule_id": field, "resource_id": field})
    found["blocking"] = True
    found["title"] = title
    return found


def _azure_finding(rule_id: str, field: str = "", detail: str = "") -> Dict[str, Any]:
    """Renders an entry from the Azure catalogue in the shared warning shape."""
    entry = GET_SECURITY_MESSAGE(rule_id)
    message = entry.get("description", "")
    if detail:
        message = f"{message} ({detail})"
    if entry.get("impact"):
        message = f"{message} {entry['impact']}"

    found = _warning(
        _AZURE_LEVELS.get(entry.get("severity", "MEDIUM"), WARNING),
        message,
        rule={"rule_id": rule_id, "resource_id": field},
    )
    found["title"] = entry.get("title", "Security risk")
    found["remediation"] = entry.get("remediation", "")
    return found


def _is_world_open(cidr: str) -> bool:
    return str(cidr).strip().lower() in WORLD_CIDRS


def _strip_aws_specifics(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Removes the AWS-only parts of a finding raised against an Azure resource.

    check_firewall_rules is reused for Azure NSGs because a port opened to 0.0.0.0/0 is the same
    fault whoever is hosting it, and the rule reads nothing but ports and address ranges. Two
    things it attaches do not carry over:

      control  cites the CIS AWS Foundations Benchmark, which does not govern Azure network
               security groups. Repeating it here would be a fabricated citation, and an empty
               one is better than that.
      fix      names a remediation aws/security_groups.py performs. There is no Azure equivalent
               wired up, so offering it would describe a button that does not exist.
    """
    for found in findings:
        found["control"] = None
        found["fix"] = None
    return findings


# ----------------------------------------------------------------------
# Blocking validation
# ----------------------------------------------------------------------
def _check_bucket_name(name: str) -> List[Dict[str, Any]]:
    if not name:
        return [_blocker("A bucket name is required.", "bucket_name", "Name is missing")]
    valid = (
        re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", name)
        and ".." not in name
        and not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", name)
        and not name.startswith("xn--")
        and not name.endswith("-s3alias")
    )
    if not valid:
        return [_blocker(
            f"'{name}' is not a valid S3 bucket name. Names are 3-63 characters of "
            "lowercase letters, numbers, hyphens and dots, must start and end with a "
            "letter or number, and cannot look like an IP address. AWS rejects the "
            "request outright, so nothing would be created.",
            "bucket_name", "Invalid bucket name",
        )]
    return []


def _check_storage_account_name(name: str) -> List[Dict[str, Any]]:
    if not name:
        return [_blocker("A storage account name is required.", "account_name", "Name is missing")]
    if not re.fullmatch(r"[a-z0-9]{3,24}", name):
        return [_blocker(
            f"'{name}' is not a valid storage account name. Azure requires 3-24 "
            "characters of lowercase letters and numbers only, globally unique.",
            "account_name", "Invalid storage account name",
        )]
    return []


def _check_container_name(name: str) -> List[Dict[str, Any]]:
    if not name:
        return []
    if not re.fullmatch(r"[a-z0-9]([a-z0-9-]{1,61}[a-z0-9])?", name) or "--" in name:
        return [_blocker(
            f"'{name}' is not a valid container name. Containers are 3-63 characters "
            "of lowercase letters, numbers and single hyphens, starting and ending "
            "with a letter or number.",
            "container_name", "Invalid container name",
        )]
    return []


def _check_resource_group(name: str) -> List[Dict[str, Any]]:
    if not name:
        return [_blocker("A resource group name is required.", "resource_group", "Name is missing")]
    if not re.fullmatch(r"[A-Za-z0-9._\-()]{1,90}", name) or name.endswith("."):
        return [_blocker(
            f"'{name}' is not a valid resource group name. Use letters, numbers, "
            "underscores, hyphens, periods and parentheses, not ending in a period.",
            "resource_group", "Invalid resource group name",
        )]
    return []


def _check_vm_name(name: str) -> List[Dict[str, Any]]:
    if not name:
        return [_blocker("A name for the machine is required.", "vm_name", "Name is missing")]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,63}", name):
        return [_blocker(
            f"'{name}' is not a valid machine name. Use letters, numbers and hyphens, "
            "starting with a letter or number.",
            "vm_name", "Invalid machine name",
        )]
    return []


def _check_ssh_public_key(key: str) -> List[Dict[str, Any]]:
    key = (key or "").strip()
    if "PRIVATE KEY" in key.upper():
        return [_blocker(
            "That is a PRIVATE key. A private key must never leave your machine - "
            "uploading one compromises every host that trusts it. Rotate this key "
            "pair now, then paste the matching .pub public key instead.",
            "ssh_public_key", "Private key pasted into the public key box",
        )]
    if not key.startswith(SSH_PUBLIC_KEY_PREFIXES) or len(key.split()) < 2:
        return [_blocker(
            "SSH key authentication needs a public key, and this is not one. Paste "
            "the contents of your .pub file; it starts with ssh-ed25519, ssh-rsa or "
            "ecdsa-sha2-. Without it the machine would launch with no way to log in.",
            "ssh_public_key", "SSH public key missing or malformed",
        )]
    return []


def _check_cidr(cidr: str) -> List[Dict[str, Any]]:
    cidr = (cidr or "").strip()
    if not cidr:
        return [_blocker("A source address range is required.", "allowed_cidr", "Source range is missing")]
    try:
        ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return [_blocker(
            f"'{cidr}' is not a valid CIDR block. Use something like 203.0.113.10/32 "
            "for a single address, or 0.0.0.0/0 to deliberately allow the internet.",
            "allowed_cidr", "Invalid source range",
        )]
    return []


# ----------------------------------------------------------------------
# Translating a form into what the backend rules expect
# ----------------------------------------------------------------------
def firewall_rules_from_form(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Turns the port checkboxes and CIDR box into security group rules.

    This is the same shape aws/security_groups.py reads back off a live group,
    which is what lets the warnings shown before creation match the ones shown
    after it.
    """
    source = str(config.get("allowed_cidr", "0.0.0.0/0")).strip()
    if _is_world_open(source):
        source = "0.0.0.0/0"

    rules = []
    for port in config.get("open_ports", []) or []:
        if str(port).lower() in {"all", "*", "any"}:
            rules.append({
                "direction": "inbound",
                "protocol": "-1",
                "from_port": None,
                "to_port": None,
                "source": source,
            })
            continue
        try:
            number = int(port)
        except (TypeError, ValueError):
            continue
        rules.append({
            "direction": "inbound",
            "protocol": "tcp",
            "from_port": number,
            "to_port": number,
            "source": source,
        })
    return rules


def bucket_settings_from_form(config: Dict[str, Any]) -> Dict[str, Any]:
    """Builds the settings snapshot check_bucket_settings expects.

    registry._bucket_check_spec does the same thing from a single
    secure_by_default flag. This form exposes the four hardening steps
    separately, so each one is answered on its own rather than as a group.
    """
    blocked = bool(config.get("block_public_access", True))
    encrypted = bool(config.get("enable_encryption", True))
    versioned = bool(config.get("enable_versioning", True))
    acl = str(config.get("acl", "private")).strip().lower()

    grants = []
    if acl in {"public-read", "public-read-write"}:
        grants.append({"uri": ALL_USERS_URI, "permission": "READ"})
    if acl == "public-read-write":
        grants.append({"uri": ALL_USERS_URI, "permission": "WRITE"})

    return {
        "bucket": config.get("bucket_name") or "this bucket",
        "public_access_block": dict(ALL_BLOCKS_ON) if blocked else None,
        "encryption": {
            "enabled": encrypted,
            "algorithm": "AES256" if encrypted else None,
        },
        "versioning": {"enabled": versioned, "mfa_delete": False},
        "public_acl_grants": grants,
        "policy_is_public": False,
        "policy_denies_http": bool(config.get("enforce_tls", True)),
        "logging_enabled": False,
        "unreadable": {},
    }


def instance_settings_from_form(config: Dict[str, Any]) -> Dict[str, Any]:
    """Builds the settings snapshot check_instance expects.

    registry._instance_check_spec hardcodes the metadata and encryption answers
    because its own launch path always sets them securely. This form lets the
    user turn both off, so the real answers are passed through instead.
    """
    name = config.get("vm_name") or "this machine"
    return {
        "instance_id": name,
        "name": name,
        "imdsv2_required": bool(config.get("require_imdsv2", True)),
        "metadata_endpoint_enabled": True,
        "metadata_hop_limit": 1,
        "public_ip": "an address will be assigned" if config.get("assign_public_ip") else None,
        "root_volume_encrypted": bool(config.get("encrypt_os_disk", True)),
        "key_name": str(config.get("key_pair_name", "")).strip() or None,
        "security_group_ids": [],
        # Whether SSH is permitted at all, from anywhere - not the same question
        # as whether it is open to the world, which the firewall rules answer.
        "ssh_reachable": any(
            str(p).lower() in {"all", "*", "any"} or str(p) == "22"
            for p in config.get("open_ports", []) or []
        ),
    }


# ----------------------------------------------------------------------
# Per-resource scans
# ----------------------------------------------------------------------
def _scan_aws_vm(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = _check_vm_name(str(config.get("vm_name", "")).strip())
    findings += _check_cidr(config.get("allowed_cidr", ""))

    firewall = check_firewall_rules(firewall_rules_from_form(config))
    findings += firewall
    findings += check_instance(instance_settings_from_form(config), firewall)
    return findings


def _scan_aws_storage(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = _check_bucket_name(str(config.get("bucket_name", "")).strip())
    findings += check_bucket_settings(bucket_settings_from_form(config))
    return findings


def _scan_azure_vm(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = _check_vm_name(str(config.get("vm_name", "")).strip())
    findings += _check_resource_group(str(config.get("resource_group", "")).strip())
    findings += _check_cidr(config.get("allowed_cidr", ""))

    # Azure NSG rules are the same shape of question as an AWS security group, and the rules in
    # backend/scanner/rules.py read nothing but ports and address ranges. Reusing them keeps one
    # answer to "what is wrong with this opening" across both providers; _strip_aws_specifics
    # removes the two parts of the result that do not carry over.
    findings += _strip_aws_specifics(check_firewall_rules(firewall_rules_from_form(config)))

    admin_username = str(config.get("admin_username", "")).strip()
    if not admin_username:
        findings.append(_blocker(
            "An administrator username is required.", "admin_username", "Username is missing"))
    elif admin_username.lower() in RESERVED_ADMIN_USERNAMES:
        findings.append(_azure_finding(
            "AZURE_VM_ADMIN_USERNAME_RESERVED", "admin_username", f"'{admin_username}'"))

    if config.get("auth_type", "ssh_key") == "password":
        findings.append(_azure_finding("AZURE_VM_PASSWORD_AUTH", "auth_type"))
    else:
        findings += _check_ssh_public_key(config.get("ssh_public_key", ""))

    if config.get("assign_public_ip"):
        findings.append(_azure_finding("AZURE_VM_PUBLIC_IP", "assign_public_ip"))
    if not config.get("encrypt_os_disk", True):
        findings.append(_azure_finding("AZURE_VM_DISK_ENCRYPTION_DISABLED", "encrypt_os_disk"))

    return findings


def _scan_azure_storage(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    account_name = str(config.get("account_name", "")).strip()
    container_name = str(config.get("container_name", "")).strip()

    findings = _check_storage_account_name(account_name)
    findings += _check_resource_group(str(config.get("resource_group", "")).strip())
    findings += _check_container_name(container_name)

    if config.get("allow_blob_public_access", False):
        findings.append(_azure_finding("AZURE_STORAGE_PUBLIC_ACCESS_ENABLED", account_name))
    if not config.get("supports_https_traffic_only", True):
        findings.append(_azure_finding("AZURE_STORAGE_HTTPS_DISABLED", account_name))

    minimum_tls = str(config.get("minimum_tls_version", "TLS1_2")).strip()
    if minimum_tls not in {"TLS1_2", "TLS1_3"}:
        findings.append(_azure_finding("AZURE_STORAGE_WEAK_TLS", "minimum_tls_version", minimum_tls))

    container_access = str(config.get("container_public_access", "private")).strip().lower()
    if container_name and container_access in {"blob", "container"}:
        findings.append(_azure_finding(
            "AZURE_STORAGE_CONTAINER_PUBLIC", "container_public_access",
            f"'{container_name}' is set to '{container_access}'"))
    if config.get("allow_shared_key_access", True):
        findings.append(_azure_finding("AZURE_STORAGE_SHARED_KEY_ENABLED", "allow_shared_key_access"))

    return findings


_SCANNERS = {
    ("aws", "vm"): _scan_aws_vm,
    ("aws", "storage"): _scan_aws_storage,
    ("azure", "vm"): _scan_azure_vm,
    ("azure", "storage"): _scan_azure_storage,
}


# ----------------------------------------------------------------------
# Public entry point
# ----------------------------------------------------------------------
def scan_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """Scans a provisioning form before anything is created.

    Returns:
        {
            "provider", "resource_type",
            "blockers": [...],   # invalid: the UI must refuse to deploy
            "warnings": [...],   # insecure but deployable: acknowledgeable
            "counts": {"critical": n, "warning": n, "info": n, ...},
            "worst": "critical" | "warning" | "info" | None,
            "passed": bool,      # nothing found at all
            "blocked": bool,     # at least one blocker
            "needs_acknowledgement": bool,
        }

    needs_acknowledgement is false when the only findings are info. The AWS rules report context
    as well as faults - that a hardened bucket uses AWS-managed keys rather than KMS, that access
    logging is off - so a bucket with every hardening step applied still comes back with notes.
    Making someone tick "I acknowledge the security risk" to deploy that is how a risk
    acknowledgement becomes a reflex, which is the one thing it must never become.
    """
    provider = str(config.get("provider", "")).strip().lower()
    resource_type = str(config.get("resource_type", "")).strip().lower()

    scan = _SCANNERS.get((provider, resource_type))
    if scan is None:
        raise ValueError(
            f"No scanner registered for provider='{provider}', resource_type='{resource_type}'")

    findings = scan(config)
    blockers = [f for f in findings if f.get("blocking")]
    warnings = [f for f in findings if not f.get("blocking")]
    worst = worst_level(warnings)

    return {
        "provider": provider,
        "resource_type": resource_type,
        "blockers": blockers,
        "warnings": warnings,
        "counts": summarize(warnings),
        "worst": worst,
        "passed": not findings,
        "blocked": bool(blockers),
        "needs_acknowledgement": worst in (CRITICAL, WARNING),
    }
