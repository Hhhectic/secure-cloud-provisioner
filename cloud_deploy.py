"""
cloud_deploy.py
Deployment functions the Streamlit GUI imports directly - no REST layer in between:

    from cloud_deploy import deploy_aws_vm, deploy_aws_bucket, deploy_azure_vm, deploy_azure_storage

Every function takes the flat config dictionary the pre-flight scan validated, plus an optional
`status_callback(text)` used by the GUI to stream progress into `st.status()`.

The AWS functions are thin. backend/aws/ already creates buckets, security groups and instances,
tags them so cleanup can find them again, refuses instance types outside its allowlist and forces
IMDSv2 and root-volume encryption. These wrappers translate a form into those calls and translate
the (ok, id_or_error, problems) results back; they do not talk to boto3 themselves. The Azure
functions do the provisioning directly, because backend/ has no Azure in it.

Each function honours `config["dry_run"]`. In dry-run mode nothing touches a cloud API: the function
returns the ordered list of calls it *would* make, which makes the app fully demonstrable without
credentials. Set dry_run to False to provision for real.
"""

import os
from typing import Any, Callable, Dict, List, Optional

from dotenv import load_dotenv

import backend_path  # noqa: F401 - must precede the aws.* imports below

load_dotenv()

StatusCallback = Optional[Callable[[str], None]]

# Ubuntu 22.04 LTS gen2 - the image reference used for Azure Linux VMs. The AWS side does not need
# an equivalent: aws/instances.py resolves the current Amazon Linux 2023 AMI for the architecture.
AZURE_VM_IMAGE = {
    "publisher": "Canonical",
    "offer": "0001-com-ubuntu-server-jammy",
    "sku": "22_04-lts-gen2",
    "version": "latest",
}


class DeploymentError(Exception):
    """Raised when a deployment cannot start or fails part way through."""


def _report(status_callback: StatusCallback, message: str) -> None:
    if status_callback:
        status_callback(message)


def allowed_instance_types() -> List[str]:
    """The instance sizes the backend will actually launch.

    Read from aws/instances.py rather than listed in the form, so the menu cannot offer something
    the launch path would then refuse - the refusal is the cost guardrail, and a menu that
    disagreed with it would look like a bug.
    """
    try:
        from aws.instances import ALLOWED_INSTANCE_TYPES
    except ImportError:
        # boto3 is not installed, so nothing can be launched anyway. The form still needs
        # something to show; these are the allowlist's own values as of writing.
        return ["t2.micro", "t3.micro", "t3.small", "t4g.micro"]

    return sorted(ALLOWED_INSTANCE_TYPES)


# ----------------------------------------------------------------------
# Credential discovery (used by the sidebar status panel)
# ----------------------------------------------------------------------
def aws_credentials_available() -> bool:
    if os.getenv("AWS_ACCESS_KEY_ID") and os.getenv("AWS_SECRET_ACCESS_KEY"):
        return True
    return os.path.exists(os.path.expanduser("~/.aws/credentials"))


def azure_credentials_available() -> bool:
    required = ("AZURE_SUBSCRIPTION_ID", "AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET")
    return all(os.getenv(name) for name in required)


def credential_status(provider: str) -> Dict[str, Any]:
    """Returns {'ready': bool, 'detail': str} for the sidebar indicator."""
    if provider.lower() == "aws":
        ready = aws_credentials_available()
        return {
            "ready": ready,
            "detail": "AWS credentials detected" if ready else "No AWS credentials found (.env or ~/.aws/credentials)",
        }
    ready = azure_credentials_available()
    return {
        "ready": ready,
        "detail": "Azure service principal detected" if ready else "Missing AZURE_* variables in .env",
    }


# ----------------------------------------------------------------------
# Dry-run planning
# ----------------------------------------------------------------------
def _dry_run_result(resource: str, name: str, steps: List[str], config: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "status": "DRY_RUN",
        "mode": "SIMULATED",
        "resource": resource,
        "name": name,
        "planned_steps": steps,
        "effective_config": {k: v for k, v in config.items() if k != "ssh_public_key"},
        "message": "Dry run only - no cloud API calls were made.",
    }


# ======================================================================
# AWS - wrappers over backend/aws
# ======================================================================
def _require_aws():
    if not aws_credentials_available():
        raise DeploymentError(
            "No AWS credentials found. Put AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in .env, "
            "or configure ~/.aws/credentials."
        )
    try:
        from aws import instances, s3_buckets, security_groups  # noqa: F401
    except ImportError as exc:  # pragma: no cover - depends on local install
        raise DeploymentError(
            "The AWS backend could not be imported. Run: pip install -r requirements.txt"
        ) from exc


def deploy_aws_bucket(config: Dict[str, Any], status_callback: StatusCallback = None) -> Dict[str, Any]:
    """Creates an S3 bucket, then applies the hardening steps the form selected.

    aws/s3_buckets.py exposes the four hardening steps individually as well as together, so the
    form's four toggles map onto them one for one. secure_by_default is left off and the selected
    steps applied by name, which is the same work create_bucket does when all four are wanted.
    """
    bucket = str(config.get("bucket_name", "")).strip()
    region = str(config.get("region", "us-east-1")).strip()
    acl = str(config.get("acl", "private")).strip().lower()

    steps_wanted = [
        ("block_public_access", "Block all public access"),
        ("enable_encryption", "Default AES-256 encryption"),
        ("enable_versioning", "Object versioning"),
        ("enforce_tls", "Bucket policy denying plain HTTP"),
    ]
    selected = [label for key, label in steps_wanted if config.get(key, True)]

    if config.get("dry_run", True):
        planned = [f"create_bucket('{bucket}', region={region})"]
        planned += [f"apply: {label}" for label in selected]
        skipped = [label for key, label in steps_wanted if not config.get(key, True)]
        planned += [f"SKIP: {label}" for label in skipped]
        if acl != "private":
            planned.append(f"NOT APPLIED: '{acl}' ACL - this tool has no path that publishes a bucket")
        return _dry_run_result("S3 Bucket", bucket, planned, config)

    _require_aws()
    from aws import s3_buckets as s3

    try:
        client = s3.get_client(region)

        _report(status_callback, f"Creating bucket '{bucket}' in {region}...")
        ok, result, problems = s3.create_bucket(client, bucket, region=region, secure_by_default=False)
        if not ok:
            raise DeploymentError(result)

        hardening = {
            "block_public_access": s3.block_public_access,
            "enable_encryption": s3.enable_encryption,
            "enable_versioning": s3.enable_versioning,
            "enforce_tls": s3.enforce_https,
        }
        for key, label in steps_wanted:
            if not config.get(key, True):
                continue
            _report(status_callback, f"Applying: {label}...")
            step_ok, message = hardening[key](client, bucket)
            if not step_ok:
                problems.append(message)

        if acl != "private":
            # aws/s3_buckets.py has no function that grants public access, deliberately. Saying so
            # is better than quietly creating a private bucket and reporting success.
            problems.append(
                f"The '{acl}' ACL was NOT applied. This tool has no code path that publishes a "
                "bucket to the internet. The bucket was created without it; use "
                "backend/scripts/make_vulnerable.py if you need a deliberately weak bucket for a demo."
            )

        return {
            "status": "SUCCESS",
            "mode": "PROVISIONED_IN_AWS",
            "resource": "S3 Bucket",
            "name": bucket,
            "region": region,
            "arn": f"arn:aws:s3:::{bucket}",
            "hardening_applied": selected,
            "problems": problems,
        }
    except DeploymentError:
        raise
    except Exception as exc:
        raise DeploymentError(f"S3 provisioning failed: {exc}") from exc


def deploy_aws_vm(config: Dict[str, Any], status_callback: StatusCallback = None) -> Dict[str, Any]:
    """Creates a security group from the form's ports, then launches an instance into it.

    An instance and its firewall are two resources in AWS. The form asks about them together
    because that is how the question arises, but they are created in order and the group is
    reported back separately so it can be found and deleted.
    """
    from preflight import firewall_rules_from_form

    name = str(config.get("vm_name", "")).strip()
    region = str(config.get("region", "us-east-1")).strip()
    instance_type = str(config.get("instance_type", "t3.micro")).strip()
    key_name = str(config.get("key_pair_name", "")).strip() or None
    rules = firewall_rules_from_form(config)
    encrypt_root = bool(config.get("encrypt_os_disk", True))
    assign_public_ip = bool(config.get("assign_public_ip", False))

    if config.get("dry_run", True):
        opened = ", ".join(
            "all ports" if r["protocol"] == "-1" else str(r["from_port"]) for r in rules
        ) or "nothing"
        source = rules[0]["source"] if rules else "n/a"
        steps = [
            f"get_default_vpc() in {region}",
            f"create_security_group('{name}-sg', rules: {opened} from {source})",
            f"latest_ami({region}) - resolves the current Amazon Linux 2023 image",
            f"launch_instance('{name}', {instance_type}, key_name={key_name or 'none'}, "
            f"public IP: {'yes' if assign_public_ip else 'no'}, root encrypted: "
            f"{'yes' if encrypt_root else 'no'}, IMDSv2: always required)",
        ]
        return _dry_run_result("EC2 Instance", name, steps, config)

    _require_aws()
    from aws import instances as ec2i
    from aws import security_groups as sg

    # Checked before anything is created. launch_instance refuses a type outside the allowlist
    # too, but by then the security group exists and has to be reported as an orphan.
    if instance_type not in ec2i.ALLOWED_INSTANCE_TYPES:
        raise DeploymentError(
            f"'{instance_type}' is not on the backend's instance allowlist, so nothing was "
            f"created. Permitted types: {', '.join(sorted(ec2i.ALLOWED_INSTANCE_TYPES))}."
        )

    try:
        client = sg.get_client(region)

        _report(status_callback, "Looking up the default VPC...")
        vpc_id, err = sg.get_default_vpc(client)
        if err:
            raise DeploymentError(err)

        _report(status_callback, f"Creating security group '{name}-sg'...")
        ok, group_id, problems = sg.create_security_group(
            client,
            f"{name}-sg",
            f"Created by Secure Cloud Provisioner for {name}",
            vpc_id,
            rules,
        )
        if not ok:
            raise DeploymentError(group_id)

        _report(status_callback, f"Launching {instance_type} instance '{name}'...")
        ok, instance_id, launch_problems = ec2i.launch_instance(
            client,
            name=name,
            region=region,
            instance_type=instance_type,
            key_name=key_name,
            security_group_ids=[group_id],
            assign_public_ip=assign_public_ip,
            encrypt_root=encrypt_root,
        )
        problems.extend(launch_problems)
        if not ok:
            raise DeploymentError(
                f"The security group {group_id} was created, but the instance was not: {instance_id}"
            )

        return {
            "status": "SUCCESS",
            "mode": "PROVISIONED_IN_AWS",
            "resource": "EC2 Instance",
            "name": name,
            "instance_id": instance_id,
            "instance_type": instance_type,
            "region": region,
            "security_group_id": group_id,
            "public_ip_requested": assign_public_ip,
            "problems": problems,
        }
    except DeploymentError:
        raise
    except Exception as exc:
        raise DeploymentError(f"EC2 provisioning failed: {exc}") from exc


# ======================================================================
# Azure - provisioned here, because backend/ has no Azure in it
# ======================================================================
def _azure_credentials():
    """Reuses the credential helper already used by the FastAPI backend."""
    try:
        from azure_crud import get_azure_credentials
    except ImportError as exc:  # pragma: no cover - depends on local install
        raise DeploymentError("Azure SDK packages are not installed. Run: pip install -r requirements.txt") from exc
    try:
        return get_azure_credentials()
    except Exception as exc:
        raise DeploymentError("Azure authentication failed: check AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET.") from exc


def deploy_azure_storage(config: Dict[str, Any], status_callback: StatusCallback = None) -> Dict[str, Any]:
    """Provisions a resource group, storage account and (optionally) one blob container."""
    account_name = str(config.get("account_name", "")).strip()
    resource_group = str(config.get("resource_group", "")).strip()
    location = str(config.get("region", "eastus")).strip()
    container_name = str(config.get("container_name", "")).strip()
    container_access = str(config.get("container_public_access", "private")).strip().lower()

    if config.get("dry_run", True):
        steps = [
            f"Create or update resource group '{resource_group}' in {location}",
            f"Create storage account '{account_name}' (sku {config.get('sku', 'Standard_LRS')})",
            f"  allowBlobPublicAccess = {bool(config.get('allow_blob_public_access', False))}",
            f"  supportsHttpsTrafficOnly = {bool(config.get('supports_https_traffic_only', True))}",
            f"  minimumTlsVersion = {config.get('minimum_tls_version', 'TLS1_2')}",
            f"  allowSharedKeyAccess = {bool(config.get('allow_shared_key_access', True))}",
        ]
        if container_name:
            steps.append(f"Create container '{container_name}' with access level '{container_access}'")
        return _dry_run_result("Azure Storage Account", account_name, steps, config)

    if not azure_credentials_available():
        raise DeploymentError("Azure credentials are incomplete. Fill in the AZURE_* values in .env.")

    try:
        from azure_crud import create_resource_group, create_storage_account

        _report(status_callback, f"Creating resource group '{resource_group}'...")
        rg_result = create_resource_group(resource_group, location)

        _report(status_callback, f"Provisioning storage account '{account_name}'...")
        storage_config = {
            "sku": config.get("sku", "Standard_LRS"),
            "kind": "StorageV2",
            "supports_https_traffic_only": bool(config.get("supports_https_traffic_only", True)),
            "allow_blob_public_access": bool(config.get("allow_blob_public_access", False)),
            "minimum_tls_version": config.get("minimum_tls_version", "TLS1_2"),
            "allow_shared_key_access": bool(config.get("allow_shared_key_access", True)),
        }
        storage_result = create_storage_account(resource_group, location, account_name, storage_config)

        containers: List[str] = []
        if container_name:
            _report(status_callback, f"Creating container '{container_name}'...")
            from azure.storage.blob import BlobServiceClient

            credential, _ = _azure_credentials()
            blob_service = BlobServiceClient(
                f"https://{account_name}.blob.core.windows.net",
                credential=credential,
            )
            public_access = None if container_access == "private" else container_access
            blob_service.create_container(container_name, public_access=public_access)
            containers.append(container_name)

        return {
            "status": "SUCCESS",
            "mode": "PROVISIONED_IN_AZURE",
            "resource": "Azure Storage Account",
            "name": account_name,
            "resource_group": rg_result.get("name"),
            "location": storage_result.get("location"),
            "provisioning_state": storage_result.get("provisioning_state"),
            "endpoint": f"https://{account_name}.blob.core.windows.net",
            "containers": containers,
        }
    except DeploymentError:
        raise
    except Exception as exc:
        raise DeploymentError(f"Azure storage provisioning failed: {exc}") from exc


def deploy_azure_vm(config: Dict[str, Any], status_callback: StatusCallback = None) -> Dict[str, Any]:
    """Provisions a resource group, virtual network, NSG, NIC and Linux virtual machine."""
    vm_name = str(config.get("vm_name", "")).strip()
    resource_group = str(config.get("resource_group", "")).strip()
    location = str(config.get("region", "eastus")).strip()
    vm_size = str(config.get("vm_size", "Standard_B1s")).strip()
    admin_username = str(config.get("admin_username", "")).strip()
    ports = config.get("open_ports", []) or []
    cidr = str(config.get("allowed_cidr", "0.0.0.0/0")).strip()
    assign_public_ip = bool(config.get("assign_public_ip", False))

    if config.get("dry_run", True):
        steps = [
            f"Create or update resource group '{resource_group}' in {location}",
            f"Create virtual network '{vm_name}-vnet' (10.0.0.0/16) with subnet 'default' (10.0.0.0/24)",
            f"Create network security group '{vm_name}-nsg' allowing {ports or 'no'} inbound from {cidr}",
        ]
        if assign_public_ip:
            steps.append(f"Create public IP '{vm_name}-ip' (Standard, static)")
        steps += [
            f"Create network interface '{vm_name}-nic'",
            f"Create VM '{vm_name}' ({vm_size}, Ubuntu 22.04 LTS) as user '{admin_username}'"
            f" using {'SSH public key' if config.get('auth_type', 'ssh_key') == 'ssh_key' else 'PASSWORD'} authentication"
            f" (encryption at host: {'on' if config.get('encrypt_os_disk', True) else 'off'})",
        ]
        return _dry_run_result("Azure Virtual Machine", vm_name, steps, config)

    if not azure_credentials_available():
        raise DeploymentError("Azure credentials are incomplete. Fill in the AZURE_* values in .env.")

    auth_type = config.get("auth_type", "ssh_key")
    admin_password = os.getenv("AZURE_VM_ADMIN_PASSWORD")
    if auth_type == "password" and not admin_password:
        raise DeploymentError(
            "Password authentication was selected, but this tool never accepts passwords through the form. "
            "Set AZURE_VM_ADMIN_PASSWORD in your .env file, or switch to SSH key authentication (recommended)."
        )

    try:
        from azure.mgmt.compute import ComputeManagementClient
        from azure.mgmt.network import NetworkManagementClient

        from azure_crud import create_resource_group

        credential, subscription_id = _azure_credentials()
        network_client = NetworkManagementClient(credential, subscription_id)
        compute_client = ComputeManagementClient(credential, subscription_id)

        _report(status_callback, f"Creating resource group '{resource_group}'...")
        create_resource_group(resource_group, location)

        _report(status_callback, "Creating virtual network and subnet...")
        vnet_poller = network_client.virtual_networks.begin_create_or_update(
            resource_group,
            f"{vm_name}-vnet",
            {
                "location": location,
                "address_space": {"address_prefixes": ["10.0.0.0/16"]},
                "subnets": [{"name": "default", "address_prefix": "10.0.0.0/24"}],
            },
        )
        subnet_id = vnet_poller.result().subnets[0].id

        _report(status_callback, f"Creating network security group with rules for {ports} from {cidr}...")
        security_rules = []
        for index, port in enumerate(ports):
            is_all = str(port).lower() in {"all", "*"}
            security_rules.append({
                "name": f"allow-{'any' if is_all else port}",
                "protocol": "*" if is_all else "Tcp",
                "source_port_range": "*",
                "destination_port_range": "*" if is_all else str(port),
                "source_address_prefix": "*" if cidr == "0.0.0.0/0" else cidr,
                "destination_address_prefix": "*",
                "access": "Allow",
                "priority": 300 + index,
                "direction": "Inbound",
            })
        nsg_poller = network_client.network_security_groups.begin_create_or_update(
            resource_group,
            f"{vm_name}-nsg",
            {"location": location, "security_rules": security_rules},
        )
        nsg_id = nsg_poller.result().id

        public_ip_id = None
        public_ip_address = None
        if assign_public_ip:
            _report(status_callback, "Allocating public IP address...")
            ip_poller = network_client.public_ip_addresses.begin_create_or_update(
                resource_group,
                f"{vm_name}-ip",
                {
                    "location": location,
                    "sku": {"name": "Standard"},
                    "public_ip_allocation_method": "Static",
                    "public_ip_address_version": "IPv4",
                },
            )
            public_ip = ip_poller.result()
            public_ip_id = public_ip.id
            public_ip_address = public_ip.ip_address

        _report(status_callback, "Creating network interface...")
        ip_configuration: Dict[str, Any] = {
            "name": f"{vm_name}-ipcfg",
            "subnet": {"id": subnet_id},
        }
        if public_ip_id:
            ip_configuration["public_ip_address"] = {"id": public_ip_id}

        nic_poller = network_client.network_interfaces.begin_create_or_update(
            resource_group,
            f"{vm_name}-nic",
            {
                "location": location,
                "ip_configurations": [ip_configuration],
                "network_security_group": {"id": nsg_id},
            },
        )
        nic_id = nic_poller.result().id

        _report(status_callback, f"Creating virtual machine '{vm_name}' ({vm_size})...")
        os_profile: Dict[str, Any] = {
            "computer_name": vm_name,
            "admin_username": admin_username,
        }
        if auth_type == "password":
            os_profile["admin_password"] = admin_password
            os_profile["linux_configuration"] = {"disable_password_authentication": False}
        else:
            os_profile["linux_configuration"] = {
                "disable_password_authentication": True,
                "ssh": {
                    "public_keys": [{
                        "path": f"/home/{admin_username}/.ssh/authorized_keys",
                        "key_data": str(config.get("ssh_public_key", "")).strip(),
                    }]
                },
            }

        vm_parameters: Dict[str, Any] = {
            "location": location,
            "hardware_profile": {"vm_size": vm_size},
            "storage_profile": {
                "image_reference": AZURE_VM_IMAGE,
                "os_disk": {
                    "create_option": "FromImage",
                    "managed_disk": {"storage_account_type": "Premium_LRS"},
                    "delete_option": "Delete",
                },
            },
            "os_profile": os_profile,
            "network_profile": {"network_interfaces": [{"id": nic_id, "primary": True}]},
            "tags": {"ProvisionedBy": "secure-cloud-provisioner"},
        }
        if config.get("encrypt_os_disk", True):
            # Platform-managed keys always encrypt the disk at rest; encryption-at-host additionally
            # encrypts the temp disk and the caches on the physical host.
            vm_parameters["security_profile"] = {"encryption_at_host": True}

        vm_poller = compute_client.virtual_machines.begin_create_or_update(resource_group, vm_name, vm_parameters)
        vm_result = vm_poller.result()

        return {
            "status": "SUCCESS",
            "mode": "PROVISIONED_IN_AZURE",
            "resource": "Azure Virtual Machine",
            "name": vm_result.name,
            "resource_group": resource_group,
            "location": vm_result.location,
            "vm_size": vm_size,
            "provisioning_state": vm_result.provisioning_state,
            "public_ip": public_ip_address,
            "network_security_group": f"{vm_name}-nsg",
        }
    except DeploymentError:
        raise
    except Exception as exc:
        raise DeploymentError(f"Azure VM provisioning failed: {exc}") from exc


# ----------------------------------------------------------------------
# Dispatch helper used by the GUI
# ----------------------------------------------------------------------
DEPLOYERS = {
    ("aws", "vm"): deploy_aws_vm,
    ("aws", "storage"): deploy_aws_bucket,
    ("azure", "vm"): deploy_azure_vm,
    ("azure", "storage"): deploy_azure_storage,
}


def deploy(config: Dict[str, Any], status_callback: StatusCallback = None) -> Dict[str, Any]:
    """Routes a scanned config to the matching provider function."""
    key = (str(config.get("provider", "")).lower(), str(config.get("resource_type", "")).lower())
    deployer = DEPLOYERS.get(key)
    if deployer is None:
        raise DeploymentError(f"No deployment function registered for {key}.")
    return deployer(config, status_callback)
