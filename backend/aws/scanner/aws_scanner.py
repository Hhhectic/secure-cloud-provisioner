from typing import Dict, List, Any


def check_ec2_security_group(config: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Evaluates EC2 Security Group inbound rules for risky open ports.
    """
    alerts = []
    ip_permissions = config.get("ip_permissions", [])

    for permission in ip_permissions:
        from_port = permission.get("from_port")
        to_port = permission.get("to_port")
        ip_ranges = permission.get("ip_ranges", [])

        # Check if rule allows access from anywhere (0.0.0.0/0)
        is_open_to_world = any(cidr == "0.0.0.0/0" for cidr in ip_ranges)

        if is_open_to_world:
            # Check SSH (Port 22)
            if from_port <= 22 <= to_port:
                alerts.append({
                    "severity": "CRITICAL",
                    "message": "SSH (Port 22) is open to the entire internet (0.0.0.0/0).",
                    "remediation": "Restrict SSH ingress to your specific public IP address."
                })
            
            # Check RDP (Port 3389)
            if from_port <= 3389 <= to_port:
                alerts.append({
                    "severity": "CRITICAL",
                    "message": "RDP (Port 3389) is open to the entire internet (0.0.0.0/0).",
                    "remediation": "Restrict RDP ingress to a known management network IP."
                })

    return alerts


def check_s3_bucket(config: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Evaluates S3 Bucket configurations for public exposure and encryption.
    """
    alerts = []
    pab = config.get("public_access_block", {})

    # Check Public Access Block guardrails
    required_blocks = [
        "BlockPublicAcls",
        "IgnorePublicAcls",
        "BlockPublicPolicy",
        "RestrictPublicBuckets"
    ]

    missing_blocks = [block for block in required_blocks if not pab.get(block, False)]

    if missing_blocks:
        alerts.append({
            "severity": "CRITICAL",
            "message": f"S3 Public Access Block is incomplete. Missing: {', '.join(missing_blocks)}.",
            "remediation": "Enable all four Public Access Block settings to prevent public exposure."
        })

    # Check Server-Side Encryption
    if not config.get("encryption_enabled", False):
        alerts.append({
            "severity": "WARNING",
            "message": "Server-side encryption is disabled on this bucket.",
            "remediation": "Enable default SSE-S3 encryption to protect static data at rest."
        })

    return alerts


def scan_aws_resource(resource_type: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main router function to evaluate any AWS resource configuration payload.
    """
    resource_type_normalized = resource_type.lower().strip()

    if resource_type_normalized in ["ec2_security_group", "security_group", "sg"]:
        alerts = check_ec2_security_group(config)
    elif resource_type_normalized in ["s3_bucket", "s3", "bucket"]:
        alerts = check_s3_bucket(config)
    else:
        return {
            "status": "ERROR",
            "message": f"Unsupported resource type: '{resource_type}'",
            "alerts": []
        }

    has_critical = any(alert["severity"] == "CRITICAL" for alert in alerts)

    return {
        "status": "PASSED" if not alerts else ("BLOCKED" if has_critical else "WARNINGS"),
        "resource_type": resource_type_normalized,
        "alert_count": len(alerts),
        "alerts": alerts
    }


# =====================================================================
# Local Test Driver
# =====================================================================
if __name__ == "__main__":
    print("--- Testing Insecure S3 Bucket ---")
    insecure_s3 = {
        "public_access_block": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": False,  # Insecure
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True
        },
        "encryption_enabled": False
    }
    result = scan_aws_resource("s3_bucket", insecure_s3)
    print(f"Status: {result['status']}")
    for alert in result["alerts"]:
        print(f" [{alert['severity']}] {alert['message']}")
        print(f"  └─ Fix: {alert['remediation']}")

    print("\n--- Testing Insecure Security Group ---")
    insecure_sg = {
        "ip_permissions": [
            {
                "from_port": 22,
                "to_port": 22,
                "ip_ranges": ["0.0.0.0/0"]  # Insecure
            }
        ]
    }
    sg_result = scan_aws_resource("ec2_security_group", insecure_sg)
    print(f"Status: {sg_result['status']}")
    for alert in sg_result["alerts"]:
        print(f" [{alert['severity']}] {alert['message']}")
        print(f"  └─ Fix: {alert['remediation']}")