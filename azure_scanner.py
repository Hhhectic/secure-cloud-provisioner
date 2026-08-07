"""
azure_scanner.py
Pre-deployment security scanner for Azure infrastructure.
Evaluates proposed Azure configuration dictionaries against security rules
before any real resources are created in Azure.
"""

from security_messages import get_security_feedback


def scan_network_security_group(nsg_rules: list) -> list:
    """
    Scans a list of proposed NSG security rules for exposed ports (SSH 22, RDP 3389).
    Returns a list of security warning objects.
    """
    findings = []
    
    for rule in nsg_rules:
        # Check if rule allows inbound traffic from anywhere
        source_ip = rule.get("source_address_prefix", "")
        access = rule.get("access", "").lower()
        direction = rule.get("direction", "").lower()
        destination_port = str(rule.get("destination_port_range", ""))

        if access == "allow" and direction == "inbound" and source_ip in ["*", "0.0.0.0/0", "Internet"]:
            if destination_port in ["22", "*"]:
                findings.append(get_security_feedback("AZURE_NSG_OPEN_SSH"))
            if destination_port in ["3389", "*"]:
                findings.append(get_security_feedback("AZURE_NSG_OPEN_RDP"))

    return findings


def scan_blob_storage_config(storage_config: dict) -> list:
    """
    Scans a proposed Azure Blob Storage configuration for public access settings.
    Returns a list of security warning objects.
    """
    findings = []
    
    if storage_config.get("allow_blob_public_access", False) is True:
        findings.append(get_security_feedback("AZURE_STORAGE_PUBLIC_ACCESS"))

    return findings


def scan_azure_deployment(deployment_config: dict) -> dict:
    """
    Master pre-flight check function for Azure deployments.
    Evaluates both NSG rules and storage configurations.
    """
    warnings = []
    
    # Check NSG rules if present
    if "nsg_rules" in deployment_config:
        warnings.extend(scan_network_security_group(deployment_config["nsg_rules"]))
        
    # Check Storage Config if present
    if "storage_config" in deployment_config:
        warnings.extend(scan_blob_storage_config(deployment_config["storage_config"]))

    is_safe = len(warnings) == 0
    
    return {
        "is_safe": is_safe,
        "warning_count": len(warnings),
        "warnings": warnings
    }   