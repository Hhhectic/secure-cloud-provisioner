import os
from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.storage.models import StorageAccountCreateParameters, Sku, Kind
from azure.storage.blob import BlobServiceClient


def deploy_storage_account_to_azure(config: dict, status_callback=None):
    subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
    if not subscription_id:
        raise ValueError("AZURE_SUBSCRIPTION_ID environment variable is missing.")

    if status_callback:
        status_callback("Authenticating via Microsoft Entra ID (Service Principal)...")
    credential = DefaultAzureCredential()

    storage_client = StorageManagementClient(credential, subscription_id)

    resource_group = config["resource_group"]
    account_name = config["account_name"]
    location = config["location"]

    if status_callback:
        status_callback(f"Provisioning Storage Account '{account_name}' in region '{location}'...")

    parameters = StorageAccountCreateParameters(
        sku=Sku(name=config["sku"]),
        kind=Kind.STORAGE_V2,
        location=location,
        enable_https_traffic_only=config.get("enable_https_traffic_only", True),
        minimum_tls_version=config.get("min_tls_version", "TLS1_2"),
        allow_blob_public_access=config.get("allow_blob_public_access", False)
    )

    poller = storage_client.storage_accounts.begin_create(
        resource_group_name=resource_group,
        account_name=account_name,
        parameters=parameters
    )
    storage_account = poller.result()

    if status_callback:
        status_callback("Account provisioned! Setting up container endpoints...")

    account_url = f"https://{account_name}.blob.core.windows.net"
    blob_service_client = BlobServiceClient(account_url, credential=credential)

    created_containers = []
    for c_name in config.get("containers", []):
        if status_callback:
            status_callback(f"Creating container: '{c_name}'...")
        blob_service_client.create_container(c_name)
        created_containers.append(c_name)

    return {
        "status": "SUCCESS",
        "account_id": storage_account.id,
        "endpoint": account_url,
        "containers": created_containers
    }
