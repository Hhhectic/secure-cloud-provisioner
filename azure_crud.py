import os
from dotenv import load_dotenv
from azure.identity import ClientSecretCredential
from azure.mgmt.resource.resources import ResourceManagementClient

# 1. Load keys from .env file
load_dotenv(override=True)

# 2. Authenticate with Azure using your service principal keys
credential = ClientSecretCredential(
    tenant_id=os.getenv("AZURE_TENANT_ID"),
    client_id=os.getenv("AZURE_CLIENT_ID"),
    client_secret=os.getenv("AZURE_CLIENT_SECRET")
)

subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")

# 3. Connect to Azure Resource Manager
resource_client = ResourceManagementClient(credential, subscription_id)

# 4. Define Resource Group settings
RESOURCE_GROUP_NAME = "rg-secure-cloud-provisioner-dev"
LOCATION = "eastus"

print(f"Creating Resource Group '{RESOURCE_GROUP_NAME}' in '{LOCATION}'...")

# 5. Create (Provision) the Resource Group in Azure
rg_result = resource_client.resource_groups.create_or_update(
    RESOURCE_GROUP_NAME,
    {"location": LOCATION}
)

print(f"Successfully created Resource Group: {rg_result.name}")