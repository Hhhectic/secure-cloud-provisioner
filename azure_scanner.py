"""
azure_scanner.py
Rule-based security scanner checking Azure configurations for pre-flight deployment violations.
"""

from security_messages import GET_SECURITY_MESSAGE

def check_nsg_ssh_rule(nsg_rules: list) -> list:
    """
    Checks if SSH (Port 22) or RDP (Port 3389) is exposed to the public internet (*, 0.0.0.0/0, Internet).
    """
    findings = []
    unsafe_sources = ["*", "0.0.0.0/0", "internet"]

    if not nsg_rules:
        return findings

    for rule in nsg_rules:
        direction = rule.get("direction", "Inbound").lower()
        access = rule.get("access", "Allow").lower()
        dest_port = str(rule.get("destination_port_range", ""))
        source_prefix = str(rule.get("source_address_prefix", "")).lower()

        if direction == "inbound" and access == "allow":
            if dest_port in ["22", "3389", "*"] and source_prefix in unsafe_sources:
                msg = GET_SECURITY_MESSAGE("AZURE_NSG_OPEN_SSH")
                findings.append(msg)

    return findings

def check_storage_public_access(storage_config: dict) -> list:
    """
    Checks if Blob public access is enabled on the Azure Storage Account.
    """
    findings = []
    if not storage_config:
        return findings

    if storage_config.get("allow_blob_public_access") is True:
        msg = GET_SECURITY_MESSAGE("AZURE_STORAGE_PUBLIC_ACCESS_ENABLED")
        findings.append(msg)

    return findings

def check_storage_https_only(storage_config: dict) -> list:
    """
    Checks if unencrypted HTTP access is permitted on the Azure Storage Account.
    """
    findings = []
    if not storage_config:
        return findings

    if storage_config.get("supports_https_traffic_only") is False:
        msg = GET_SECURITY_MESSAGE("AZURE_STORAGE_HTTPS_DISABLED")
        findings.append(msg)

    return findings