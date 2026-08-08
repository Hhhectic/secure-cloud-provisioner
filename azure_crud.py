"""
azure_crud.py
Python script utilizing Azure SDK to provision Azure Resource Groups, Storage Accounts, and Network Security Groups.
"""

import os
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.network import NetworkManagementClient

def create_resource_group(subscription_id: str, rg_name: str, location: str):
    credential = DefaultAzureCredential()
    resource_client = ResourceManagementClient(credential, subscription_id)
    rg_params = {"location": location}
    return resource_client.resource_groups.create_or_update(rg_name, rg_params)

def create_storage_account(subscription_id: str, rg_name: str, location: str, storage_account_name: str):
    credential = DefaultAzureCredential()
    storage_client = StorageManagementClient(credential, subscription_id)
    
    storage_params = {
        "location": location,
        "sku": {"name": "Standard_LRS"},
        "kind": "StorageV2",
        "properties": {
            "allowBlobPublicAccess": False,
            "minimumTlsVersion": "TLS1_2",
            "supportsHttpsTrafficOnly": True
        }
    }
    
    poller = storage_client.storage_accounts.begin_create(rg_name, storage_account_name, storage_params)
    return poller.result()

def create_network_security_group(subscription_id: str, rg_name: str, location: str, nsg_name: str, nsg_rules: list = None):
    credential = DefaultAzureCredential()
    network_client = NetworkManagementClient(credential, subscription_id)

    formatted_rules = []
    if nsg_rules:
        for idx, rule in enumerate(nsg_rules):
            formatted_rules.append({
                "name": rule.get("name", f"rule_{idx}"),
                "properties": {
                    "protocol": rule.get("protocol", "Tcp"),
                    "source_port_range": rule.get("source_port_range", "*"),
                    "destination_port_range": str(rule.get("destination_port_range", "*")),
                    "source_address_prefix": rule.get("source_address_prefix", "*"),
                    "destination_address_prefix": rule.get("destination_address_prefix", "*"),
                    "access": rule.get("access", "Allow"),
                    "priority": rule.get("priority", 100 + idx * 10),
                    "direction": rule.get("direction", "Inbound")
                }
            })

    nsg_params = {
        "location": location,
        "security_rules": formatted_rules
    }

    poller = network_client.network_security_groups.begin_create_or_update(
        rg_name,
        nsg_name,
        nsg_params
    )
    return poller.result()