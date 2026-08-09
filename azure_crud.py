"""
azure_crud.py
Azure Resource Management module for provisioning Resource Groups, Network Security Groups, and Storage Accounts.
Includes pre-flight authentication verification and sanitized exceptions.
"""

import os
from azure.identity import ClientSecretCredential

# Robust import handling for ResourceManagementClient across SDK versions
try:
    from azure.mgmt.resource import ResourceManagementClient
except ImportError:
    from azure.mgmt.resource.resources import ResourceManagementClient

from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.core.exceptions import ClientAuthenticationError, HttpResponseError


def get_azure_credentials():
    """
    Retrieves Azure environment variables and forces token acquisition to validate credentials early.
    Raises ClientAuthenticationError directly if client_secret, client_id, or tenant_id is invalid.
    """
    subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
    tenant_id = os.getenv("AZURE_TENANT_ID")
    client_id = os.getenv("AZURE_CLIENT_ID")
    client_secret = os.getenv("AZURE_CLIENT_SECRET")

    credential = ClientSecretCredential(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret
    )

    # Force immediate token acquisition against the ARM scope (clean URI string)
    credential.get_token("https://management.azure.com/.default")

    return credential, subscription_id


def create_resource_group(resource_group_name: str, location: str = "eastus") -> dict:
    """
    Provisions or updates an Azure Resource Group.
    """
    credential, subscription_id = get_azure_credentials()
    resource_client = ResourceManagementClient(credential, subscription_id)

    rg_result = resource_client.resource_groups.create_or_update(
        resource_group_name,
        {"location": location}
    )

    return {
        "name": rg_result.name,
        "location": rg_result.location,
        "provisioning_state": rg_result.properties.provisioning_state
    }


def create_network_security_group(
    resource_group_name: str,
    location: str,
    nsg_name: str,
    rules: list = None
) -> dict:
    """
    Provisions an Azure Network Security Group with custom security rules using nested Azure ARM properties format.
    """
    credential, subscription_id = get_azure_credentials()
    network_client = NetworkManagementClient(credential, subscription_id)

    formatted_rules = []
    if rules:
        for idx, rule in enumerate(rules):
            formatted_rules.append({
                "name": rule.get("name", f"rule-{idx}"),
                "properties": {
                    "protocol": rule.get("protocol", "Tcp"),
                    "sourcePortRange": "*",
                    "destinationPortRange": rule.get("destination_port_range", rule.get("destinationPortRange", "22")),
                    "sourceAddressPrefix": rule.get("source_address_prefix", rule.get("sourceAddressPrefix", "*")),
                    "destinationAddressPrefix": "*",
                    "access": rule.get("access", "Allow"),
                    "priority": 100 + idx,
                    "direction": rule.get("direction", "Inbound")
                }
            })

    nsg_params = {
        "location": location,
        "properties": {
            "securityRules": formatted_rules
        }
    }

    poller = network_client.network_security_groups.begin_create_or_update(
        resource_group_name,
        nsg_name,
        nsg_params
    )
    nsg_result = poller.result()

    return {
        "name": nsg_result.name,
        "location": nsg_result.location,
        "provisioning_state": nsg_result.provisioning_state
    }


def create_storage_account(
    resource_group_name: str,
    location: str,
    storage_account_name: str,
    storage_config: dict = None
) -> dict:
    """
    Provisions an Azure Storage Account using nested Azure ARM properties format.
    """
    credential, subscription_id = get_azure_credentials()
    storage_client = StorageManagementClient(credential, subscription_id)

    config = storage_config or {}
    sku_name = config.get("sku", "Standard_LRS")
    kind = config.get("kind", "StorageV2")

    parameters = {
        "sku": {"name": sku_name},
        "kind": kind,
        "location": location,
        "properties": {
            "supportsHttpsTrafficOnly": config.get("supports_https_traffic_only", config.get("enable_https_traffic_only", True)),
            "allowBlobPublicAccess": config.get("allow_blob_public_access", config.get("allowBlobPublicAccess", False)),
            "minimumTlsVersion": config.get("minimum_tls_version", config.get("minimumTlsVersion", "TLS1_2"))
        }
    }

    poller = storage_client.storage_accounts.begin_create(
        resource_group_name,
        storage_account_name,
        parameters
    )
    storage_result = poller.result()

    return {
        "name": storage_result.name,
        "location": storage_result.location,
        "provisioning_state": storage_result.provisioning_state
    }