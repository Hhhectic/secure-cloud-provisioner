"""
security_messages.py
Plain-language feedback and mitigation advice for the Azure security findings.

Azure only. The AWS wording lives with the AWS rules in backend/scanner/, which
also carries citations to published controls; duplicating any of it here is how
the two would drift apart. preflight.py renders these entries into the shared
warning contract from backend/scanner/common.py.

Severities here are the five-step ladder this catalogue was written with.
preflight._AZURE_LEVELS maps them onto the three levels the contract uses.
"""

SECURITY_MESSAGES = {
    # ------------------------------------------------------------------
    # Azure - network security groups
    # ------------------------------------------------------------------
    "AZURE_NSG_OPEN_SSH": {
        "rule_id": "AZURE_NSG_OPEN_SSH",
        "severity": "HIGH",
        "title": "Management Port Exposed to Public Internet",
        "description": "Your Network Security Group rule allows unrestricted inbound traffic on port 22 (SSH) or 3389 (RDP) from all IP addresses.",
        "impact": "Exposing management ports to the open internet invites automated brute-force attacks and unauthorized access attempts.",
        "remediation": "Restrict the source address prefix to your specific administrative IP address or subnet (e.g., 192.168.1.50/32) instead of using '*' or '0.0.0.0/0'."
    },

    # ------------------------------------------------------------------
    # Azure - storage accounts
    # ------------------------------------------------------------------
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
    },
    "AZURE_STORAGE_WEAK_TLS": {
        "rule_id": "AZURE_STORAGE_WEAK_TLS",
        "severity": "HIGH",
        "title": "Deprecated Minimum TLS Version",
        "description": "The storage account accepts TLS 1.0 or TLS 1.1 connections, both of which are deprecated.",
        "impact": "Legacy TLS versions have known cipher weaknesses and are rejected by most compliance baselines.",
        "remediation": "Set the minimum TLS version to TLS1_2 or higher."
    },
    "AZURE_STORAGE_CONTAINER_PUBLIC": {
        "rule_id": "AZURE_STORAGE_CONTAINER_PUBLIC",
        "severity": "CRITICAL",
        "title": "Blob Container Set to Anonymous Access",
        "description": "The container access level is set to 'blob' or 'container', which serves its contents to anonymous callers over the internet.",
        "impact": "Anyone who guesses or scrapes the container URL can download every object it holds; 'container' level additionally leaks the full file listing.",
        "remediation": "Set the container access level to 'private' and hand out short-lived SAS tokens for any sharing you need."
    },
    "AZURE_STORAGE_SHARED_KEY_ENABLED": {
        "rule_id": "AZURE_STORAGE_SHARED_KEY_ENABLED",
        "severity": "MEDIUM",
        "title": "Shared Key (Account Key) Authorization Enabled",
        "description": "The storage account still accepts the static account key as a valid credential.",
        "impact": "Account keys never expire, grant full control, and are frequently leaked through config files, screenshots and source control.",
        "remediation": "Disable shared key access and authorize with Microsoft Entra ID identities and RBAC roles instead."
    },

    # ------------------------------------------------------------------
    # Azure - virtual machines
    # ------------------------------------------------------------------
    "AZURE_VM_PASSWORD_AUTH": {
        "rule_id": "AZURE_VM_PASSWORD_AUTH",
        "severity": "HIGH",
        "title": "Password Authentication Enabled on Linux VM",
        "description": "The virtual machine is configured to accept SSH password logins instead of requiring a public key.",
        "impact": "Password logins are guessable and are the primary target of the credential-stuffing bots that scan every public cloud IP range.",
        "remediation": "Choose SSH public key authentication and paste your public key into the form; leave password authentication disabled."
    },
    "AZURE_VM_ADMIN_USERNAME_RESERVED": {
        "rule_id": "AZURE_VM_ADMIN_USERNAME_RESERVED",
        "severity": "MEDIUM",
        "title": "Predictable Administrator Username",
        "description": "Usernames such as 'admin', 'administrator' or 'root' are the first values every automated attack tries.",
        "impact": "A predictable username halves the work of a brute-force attack, and Azure rejects some of these values outright.",
        "remediation": "Pick a non-obvious administrative username specific to your team or project."
    },
    "AZURE_VM_PUBLIC_IP": {
        "rule_id": "AZURE_VM_PUBLIC_IP",
        "severity": "MEDIUM",
        "title": "Public IP Address Assigned",
        "description": "The virtual machine is being given a routable public IP address.",
        "impact": "The host is directly reachable from the internet, so every open port is exposed and every unpatched service is discoverable.",
        "remediation": "Deploy into a private subnet and reach the machine through Azure Bastion, a VPN or a load balancer."
    },
    "AZURE_VM_DISK_ENCRYPTION_DISABLED": {
        "rule_id": "AZURE_VM_DISK_ENCRYPTION_DISABLED",
        "severity": "HIGH",
        "title": "Encryption at Host Disabled",
        "description": "The OS disk is being provisioned without encryption at host, which covers the temporary disk and the host caches.",
        "impact": "Data cached on the physical host and written to the temp disk is left unencrypted, outside the platform-managed encryption that covers the managed disk itself.",
        "remediation": "Enable encryption at host for the virtual machine."
    },
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
