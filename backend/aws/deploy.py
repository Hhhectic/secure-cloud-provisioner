"""
backend/aws/deploy.py — KAN-30: Enforced AWS Provisioning Gatekeeper

Re-runs the pre-flight scan using aws_scanner.py before allowing boto3 to provision resources.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Callable
from backend.aws.scanner.aws_scanner import scan_aws_resource


@dataclass
class DeployResult:
    status: str          # "BLOCKED" | "CREATED" | "FAILED"
    alerts: list[dict[str, Any]]
    resource_id: str | None = None
    error: str | None = None


def deploy_resource(
    resource_type: str,
    config: dict[str, Any],
    accept_risk: bool,
    creators: dict[str, Callable[[dict[str, Any]], str]],
) -> DeployResult:
    """
    Runs the scan unconditionally.
    Blocks deployment on CRITICAL findings unless accept_risk is True.
    """
    # 1. Unconditional Pre-flight Scan
    scan_result = scan_aws_resource(resource_type, config)
    
    if scan_result.get("status") == "ERROR":
        return DeployResult(
            status="FAILED",
            alerts=[],
            error=scan_result.get("message", "Invalid resource configuration")
        )

    alerts = scan_result.get("alerts", [])
    has_critical = any(a.get("severity") == "CRITICAL" for a in alerts)

    # 2. Enforcement Gate
    if has_critical and not accept_risk:
        return DeployResult(
            status="BLOCKED",
            alerts=alerts,
            error="Deployment blocked due to CRITICAL security findings. Set accept_risk=True to override."
        )

    # 3. Creator Lookup
    creator = creators.get(resource_type)
    if not creator:
        return DeployResult(
            status="FAILED",
            alerts=alerts,
            error=f"No creator logic registered for resource type '{resource_type}'"
        )

    # 4. Provision Resource via Boto3
    try:
        resource_id = creator(config)
        return DeployResult(status="CREATED", alerts=alerts, resource_id=resource_id)
    except Exception as exc:
        return DeployResult(status="FAILED", alerts=alerts, error=str(exc))


# ============================================================
# Boto3 Provisioning Creators (Only called if scan passes)
# ============================================================

def _create_security_group(session):
    def _inner(config: dict[str, Any]) -> str:
        ec2 = session.client("ec2")
        vpc_id = config["vpc_id"]
        group_name = config.get("group_name", "managed-security-group")
        description = config.get("description", "Provisioned via Secure Cloud Provisioner")

        resp = ec2.create_security_group(
            GroupName=group_name,
            Description=description,
            VpcId=vpc_id,
        )
        group_id = resp["GroupId"]

        ip_permissions = config.get("ip_permissions", [])
        if ip_permissions:
            formatted_permissions = []
            for perm in ip_permissions:
                formatted_permissions.append({
                    "IpProtocol": perm.get("protocol", "tcp"),
                    "FromPort": perm.get("from_port"),
                    "ToPort": perm.get("to_port"),
                    "IpRanges": [{"CidrIp": cidr} for cidr in perm.get("ip_ranges", [])]
                })
            ec2.authorize_security_group_ingress(GroupId=group_id, IpPermissions=formatted_permissions)

        return group_id
    return _inner


def _create_s3_bucket(session):
    def _inner(config: dict[str, Any]) -> str:
        s3 = session.client("s3")
        bucket_name = config["bucket_name"]
        
        s3.create_bucket(Bucket=bucket_name)

        pab = config.get("public_access_block", {})
        if pab:
            s3.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": pab.get("BlockPublicAcls", True),
                    "IgnorePublicAcls": pab.get("IgnorePublicAcls", True),
                    "BlockPublicPolicy": pab.get("BlockPublicPolicy", True),
                    "RestrictPublicBuckets": pab.get("RestrictPublicBuckets", True),
                },
            )

        if config.get("encryption_enabled", True):
            s3.put_bucket_encryption(
                Bucket=bucket_name,
                ServerSideEncryptionConfiguration={
                    "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
                },
            )
        return bucket_name
    return _inner


def build_creators(session) -> dict[str, Callable[[dict[str, Any]], str]]:
    return {
        "security_group": _create_security_group(session),
        "ec2_security_group": _create_security_group(session),
        "s3_bucket": _create_s3_bucket(session),
        "s3": _create_s3_bucket(session),
    }