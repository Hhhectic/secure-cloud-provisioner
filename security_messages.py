"""
security_messages.py
Centralized dictionary store providing plain-language feedback and mitigation advice for security findings.
"""

SECURITY_MESSAGES = {
    "AZURE_NSG_OPEN_SSH": {
        "rule_id": "AZURE_NSG_OPEN_SSH",
        "severity": "HIGH",
        "title": "Management Port Exposed to Public Internet",
        "description": "Your Network Security Group rule allows unrestricted inbound traffic on port 22 (SSH) or 3389 (RDP) from all IP addresses.",
        "impact": "Exposing management ports to the open internet invites automated brute-force attacks and unauthorized access attempts.",
        "remediation": "Restrict the source address prefix to your specific administrative IP address or subnet (e.g., 192.168.1.50/32) instead of using '*' or '0.0.0.0/0'."
    },
    "AZURE_STORAGE_PUBLIC_ACCESS_ENABLED": {
        "rule_id": "AZURE_STORAGE_PUBLIC_ACCESS_ENABLED",
        "severity": "CRITICAL",
        "title": "Public Blob Access Allowed on Storage Account",
        "description": "The requested storage account configuration permits anonymous public read access to containers and blobs.",
        "impact": "Publicly accessible storage buckets are a leading cause of accidental cloud data leaks and credential exposure.",
        "remediation": "Disable anonymous public access by setting 'allow_blob_public_access' to False."
    },
    "AZURE_STORAGE_HTTPS_DISABLED": {
        "rule_id": "AZURE_STORAGE_HTTPS_DISABLED",
        "severity": "HIGH",
        "title": "Unencrypted HTTP Traffic Allowed on Storage Account",
        "description": "The requested storage account configuration allows plain-text HTTP connections rather than enforcing HTTPS encryption.",
        "impact": "Allowing unencrypted HTTP traffic exposes sensitive data in transit to potential man-in-the-middle eavesdropping or interception.",
        "remediation": "Enforce secure transit by setting 'supports_https_traffic_only' to True."
    }
}

def GET_SECURITY_MESSAGE(rule_id: str) -> dict:
    """
    Retrieves the plain-language message dictionary for a given rule_id with a fallback default.
    """
    return SECURITY_MESSAGES.get(rule_id, {
        "rule_id": rule_id,
        "severity": "MEDIUM",
        "title": "Security Configuration Warning",
        "description": "Potential security misconfiguration detected.",
        "impact": "May increase risk exposure depending on network placement.",
        "remediation": "Review configuration settings prior to deployment."
    })