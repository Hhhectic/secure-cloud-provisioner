"""
azure_crud.py
Handles CRUD provisioning operations for Azure resources using the Azure Management SDK.
"""

import os
from azure.identity import ClientSecretCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.storage import StorageManagementClient

def get_azure_credentials():
    subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
    tenant_id = os.getenv("AZURE_TENANT_ID")
    client_id = os.getenv("AZURE_CLIENT_ID")
    client_secret = os.getenv("AZURE_CLIENT_SECRET")

    credential = ClientSecretCredential(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret
    )
    return credential, subscription_id

def create_resource_group(group_name: str, location: str):
    credential, subscription_id = get_azure_credentials()
    resource_client = ResourceManagementClient(credential, subscription_id)
    rg_result = resource_client.resource_groups.create_or_update(
        group_name,
        {"location": location}
    )
    return {"name": rg_result.name, "location": rg_result.location, "status": "Created"}

def create_network_security_group(group_name: str, location: str, nsg_name: str, nsg_rules: list):
    credential, subscription_id = get_azure_credentials()
    network_client = NetworkManagementClient(credential, subscription_id)

    formatted_rules = []
    for idx, rule in enumerate(nsg_rules):
        formatted_rules.append({
            "name": rule.get("name", f"rule-{idx}"),
            "protocol": rule.get("protocol", "Tcp"),
            "source_port_range": rule.get("source_port_range", "*"),
            "destination_port_range": str(rule.get("destination_port_range", "22")),
            "source_address_prefix": rule.get("source_address_prefix", "*"),
            "destination_address_prefix": rule.get("destination_address_prefix", "*"),
            "access": rule.get("access", "Allow"),
            "priority": 100 + (idx * 10),
            "direction": rule.get("direction", "Inbound")
        })

    nsg_params = {
        "location": location,
        "security_rules": formatted_rules
    }

    poller = network_client.network_security_groups.begin_create_or_update(
        group_name,
        nsg_name,
        nsg_params
    )
    nsg_result = poller.result()
    return {"name": nsg_result.name, "location": nsg_result.location, "status": "Provisioned"}

def create_storage_account(group_name: str, location: str, account_name: str, storage_config: dict = None):
    credential, subscription_id = get_azure_credentials()
    storage_client = StorageManagementClient(credential, subscription_id)

    config = storage_config or {}
    
    parameters = {
        "location": location,
        "sku": {"name": config.get("sku", "Standard_LRS")},
        "kind": config.get("kind", "StorageV2"),
        "allow_blob_public_access": config.get("allow_blob_public_access", False),
        "supports_https_traffic_only": config.get("supports_https_traffic_only", True)
    }

    poller = storage_client.storage_accounts.begin_create(
        group_name,
        account_name,
        parameters
    )
    storage_result = poller.result()
    return {"name": storage_result.name, "location": storage_result.location, "status": "Provisioned"}