import boto3
from botocore.exceptions import ClientError
from typing import Dict, Any


def fetch_security_group_config(group_id: str, region_name: str = "us-east-1") -> Dict[str, Any]:
    """
    Fetches real AWS Security Group configuration and maps it to scanner input shape.
    """
    ec2 = boto3.client("ec2", region_name=region_name)
    response = ec2.describe_security_groups(GroupIds=[group_id])
    sg = response["SecurityGroups"][0]

    ip_permissions = []
    for perm in sg.get("IpPermissions", []):
        ip_permissions.append({
            "from_port": perm.get("FromPort"),
            "to_port": perm.get("ToPort"),
            "ip_ranges": [r["CidrIp"] for r in perm.get("IpRanges", []) if "CidrIp" in r],
            "ipv6_ranges": [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", []) if "CidrIpv6" in r]
        })

    return {"ip_permissions": ip_permissions}


def fetch_s3_bucket_config(bucket_name: str, region_name: str = "us-east-1") -> Dict[str, Any]:
    """
    Fetches real AWS S3 Bucket configuration and maps it to scanner input shape.
    """
    s3 = boto3.client("s3", region_name=region_name)

    # 1. Check Public Access Block
    try:
        pab_response = s3.get_public_access_block(Bucket=bucket_name)
        pab = pab_response.get("PublicAccessBlockConfiguration", {})
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            pab = {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False
            }
        else:
            raise e

    # 2. Check Encryption
    encryption_enabled = False
    try:
        s3.get_bucket_encryption(Bucket=bucket_name)
        encryption_enabled = True
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
            encryption_enabled = False
        else:
            raise e

    return {
        "public_access_block": pab,
        "encryption_enabled": encryption_enabled
    }