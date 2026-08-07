"""
azure_scanner.py
Individual rule evaluation functions for Azure resource configurations.
"""

from security_messages import get_security_message

def check_nsg_ssh_rule(nsg_rules: list) -> list:
    warnings = []
    for rule in nsg_rules:
        direction = rule.get("direction", "Inbound")
        access = rule.get("access", "Allow")
        destination_port = str(rule.get("destination_port_range", ""))
        source_prefix = str(rule.get("source_address_prefix", ""))

        if direction == "Inbound" and access == "Allow":
            # Updated to catch both SSH (22) and RDP (3389)
            if destination_port in ["22", "3389", "*"] and source_prefix in ["*", "0.0.0.0/0", "Internet"]:
                msg = get_security_message("AZURE_NSG_OPEN_SSH")
                msg["rule_name"] = rule.get("name", "unnamed_rule")
                warnings.append(msg)
    return warnings

def check_storage_public_access(storage_config: dict) -> list:
    warnings = []
    allow_public_access = storage_config.get("allow_blob_public_access", True)
    if allow_public_access is True:
        msg = get_security_message("AZURE_STORAGE_PUBLIC_ACCESS_ENABLED")
        msg["account_name"] = storage_config.get("name", "unnamed_storage_account")
        warnings.append(msg)
    return warnings