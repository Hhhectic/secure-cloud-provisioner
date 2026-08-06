"""
security_messages.py
Central repository for plain-language security feedback messages.
Translates technical cloud rule IDs into clear explanations and actionable remediation steps.
"""

# Plain-language security advice dictionary
SECURITY_MESSAGES = {
    # Azure Network Rules
    "AZURE_NSG_OPEN_SSH": {
        "title": "Unrestricted SSH Access (Port 22)",
        "severity": "HIGH",
        "description": "Your Network Security Group allows inbound SSH traffic from any IP address on the internet (0.0.0.0/0).",
        "impact": "Attackers can continuously attempt to guess passwords or exploit SSH vulnerabilities to gain remote control of your server.",
        "remediation": "Restrict Port 22 access to specific, trusted IP addresses (like your home or work network)."
    },
    "AZURE_NSG_OPEN_RDP": {
        "title": "Unrestricted Remote Desktop Access (Port 3389)",
        "severity": "HIGH",
        "description": "Port 3389 (Windows Remote Desktop) is exposed to the entire internet.",
        "impact": "Exposing RDP directly to the internet makes your server a primary target for automated ransomware attacks.",
        "remediation": "Close Port 3389 to public traffic or require a VPN connection to access remote desktops."
    },
    
    # Azure Storage Rules
    "AZURE_STORAGE_PUBLIC_ACCESS": {
        "title": "Public Storage Blob Access Enabled",
        "severity": "MEDIUM",
        "description": "Public anonymous access is allowed on your Azure Storage Account containers.",
        "impact": "Anyone with the link can view or download files stored inside your containers without logging in.",
        "remediation": "Set container access permissions to Private to require authentication for all requests."
    },

    # AWS Network Rules
    "AWS_SG_OPEN_ALL_TRAFFIC": {
        "title": "Unrestricted Inbound Network Traffic",
        "severity": "CRITICAL",
        "description": "Your AWS Security Group permits all incoming protocols and ports from any source.",
        "impact": "Leaves all internal server ports wide open to internet scanning and intrusion.",
        "remediation": "Remove the all-traffic rule and explicitly permit only required ports (such as 80 or 443)."
    },

    # AWS Storage Rules
    "AWS_S3_PUBLIC_READ": {
        "title": "Public S3 Bucket Read Access",
        "severity": "HIGH",
        "description": "Your AWS S3 Bucket policy allows public read access to stored objects.",
        "impact": "Sensitive data or documents uploaded to this bucket can be indexed and exposed publicly.",
        "remediation": "Enable AWS 'Block Public Access' settings on the S3 bucket."
    }
}


def get_security_feedback(rule_id: str) -> dict:
    """
    Retrieves plain-language security advice for a given rule ID.
    If the rule ID is unknown, returns a generic fallback message.
    """
    return SECURITY_MESSAGES.get(
        rule_id,
        {
            "title": "Unknown Security Issue",
            "severity": "UNKNOWN",
            "description": f"Rule '{rule_id}' was triggered, but no plain-language advisory is available.",
            "impact": "Potential security misconfiguration detected.",
            "remediation": "Review cloud configuration manually against organizational standards."
        }
    )