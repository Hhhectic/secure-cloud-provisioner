import os
from dotenv import load_dotenv
from azure.identity import ClientSecretCredential
from azure.mgmt.resource.resources import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.network import NetworkManagementClient

# 1. Load keys from .env
load_dotenv(override=True)

credential = ClientSecretCredential(
    tenant_id=os.getenv("AZURE_TENANT_ID"),
    client_id=os.getenv("AZURE_CLIENT_ID"),
    client_secret=os.getenv("AZURE_CLIENT_SECRET")
)

subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")

# 2. Initialize Clients
resource_client = ResourceManagementClient(credential, subscription_id)
storage_client = StorageManagementClient(credential, subscription_id)
network_client = NetworkManagementClient(credential, subscription_id)

RESOURCE_GROUP_NAME = "rg-secure-cloud-provisioner-dev"
LOCATION = "eastus"
STORAGE_ACCOUNT_NAME = "stsecureclouddev01"
NSG_NAME = "nsg-secure-cloud-dev"

# --- CREATE RESOURCE GROUP ---
print(f"Creating Resource Group '{RESOURCE_GROUP_NAME}'...")
resource_client.resource_groups.create_or_update(
    RESOURCE_GROUP_NAME, {"location": LOCATION}
)

# --- CREATE STORAGE ACCOUNT (Blob Storage) ---
print(f"Creating Storage Account '{STORAGE_ACCOUNT_NAME}'...")
storage_async_operation = storage_client.storage_accounts.begin_create(
    RESOURCE_GROUP_NAME,
    STORAGE_ACCOUNT_NAME,
    {
        "location": LOCATION,
        "sku": {"name": "Standard_LRS"},
        "kind": "StorageV2"
    }
)
storage_account = storage_async_operation.result()
print(f"Successfully created Storage Account: {storage_account.name}")

# --- CREATE NETWORK SECURITY GROUP (NSG) ---
print(f"Creating Network Security Group '{NSG_NAME}'...")
nsg_async_operation = network_client.network_security_groups.begin_create_or_update(
    RESOURCE_GROUP_NAME,
    NSG_NAME,
    {"location": LOCATION}
)
nsg = nsg_async_operation.result()
print(f"Successfully created NSG: {nsg.name}")

# --- READ / LIST RESOURCES ---
print("\n--- Listing Resources in Resource Group ---")
resources = resource_client.resources.list_by_resource_group(RESOURCE_GROUP_NAME)
for item in resources:
    print(f"Resource: {item.name} | Type: {item.type}")