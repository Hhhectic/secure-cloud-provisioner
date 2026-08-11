def scan_azure_payload(payload_dict: dict) -> list[str]:
    violations = []
    
    # 1. Network Security Group Governance Rules
    nsg_data = payload_dict.get("network_security_group")
    if nsg_data and "security_rules" in nsg_data:
        for rule in nsg_data["security_rules"]:
            props = rule.get("properties", {})
            destination_port = str(props.get("destination_port_range", ""))
            source_address = str(props.get("source_address_prefix", ""))
            access = props.get("access", "").lower()
            direction = props.get("direction", "").lower()
            
            if direction == "inbound" and access == "allow":
                if source_address == "*" and destination_port in ["22", "3389"]:
                    violations.append(f"NSG Rule Error: Public access on port {destination_port} is strictly forbidden.")

    # 2. Storage Account Governance Rules
    storage_data = payload_dict.get("storage_account")
    if storage_data:
        if not storage_data.get("supports_https_traffic_only", True):
            violations.append("Storage Policy Error: 'supports_https_traffic_only' must be set to True.")
        if storage_data.get("allow_blob_public_access", False):
            violations.append("Storage Policy Error: 'allow_blob_public_access' must be set to False.")
        if storage_data.get("minimum_tls_version") != "TLS1_2":
            violations.append("Storage Policy Error: 'minimum_tls_version' must be TLS1_2.")

    # 3. Key Vault Governance Rules (NEW)
    kv_data = payload_dict.get("key_vault")
    if kv_data:
        if not kv_data.get("enable_soft_delete", True):
            violations.append("Key Vault Policy Error: 'enable_soft_delete' must be set to True.")
        if not kv_data.get("enable_purge_protection", True):
            violations.append("Key Vault Policy Error: 'enable_purge_protection' must be set to True.")
            
    return violations