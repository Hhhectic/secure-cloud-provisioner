import os
from dotenv import load_dotenv
from azure.identity import ClientSecretCredential
from azure.storage.blob import BlobServiceClient

# 1. Load environment variables from .env file
load_dotenv()

account_name = "freepremierstorage20119"
account_url = f"https://{account_name}.blob.core.windows.net"

# Fetch explicit Azure Service Principal credentials
tenant_id = os.getenv("AZURE_TENANT_ID")
client_id = os.getenv("AZURE_CLIENT_ID")
client_secret = os.getenv("AZURE_CLIENT_SECRET")

try:
    print(f"Connecting to {account_name} via Service Principal...")
    
    # 2. Authenticate explicitly using ClientSecretCredential
    credential = ClientSecretCredential(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret
    )
    
    blob_service_client = BlobServiceClient(account_url, credential=credential)

    # 3. Test reading containers
    containers = list(blob_service_client.list_containers())

    print("\nSUCCESS! Successfully authenticated via Azure SDK.")
    print("Found the following containers:")
    if not containers:
        print(" - (No containers found yet)")
    for c in containers:
        print(f" - {c.name}")

except Exception as e:
    print(f"\nAuthentication or Permission Error: {e}")
