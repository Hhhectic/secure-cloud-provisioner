import os
from typing import Optional, List
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
from dotenv import load_dotenv
from azure.core.exceptions import ClientAuthenticationError, HttpResponseError

from azure_crud import (
    create_resource_group,
    create_network_security_group,
    create_storage_account,
    create_key_vault
)
from azure_scanner_engine import scan_azure_payload

load_dotenv()

app = FastAPI(
    title="Azure Governance & Provisioning Engine",
    version="1.0.0"
)

# --- Pydantic Data Models ---
class NSGRuleProps(BaseModel):
    protocol: str = "Tcp"
    source_port_range: str = "*"
    destination_port_range: str
    source_address_prefix: str
    destination_address_prefix: str = "*"
    access: str = "Allow"
    priority: int = 100
    direction: str = "Inbound"

class NSGRule(BaseModel):
    name: str
    properties: NSGRuleProps

class NSGRequest(BaseModel):
    name: str
    security_rules: Optional[List[NSGRule]] = []

class StorageRequest(BaseModel):
    name: str
    supports_https_traffic_only: bool = True
    allow_blob_public_access: bool = False
    minimum_tls_version: str = "TLS1_2"

class KeyVaultRequest(BaseModel):
    name: str
    enable_soft_delete: bool = True
    enable_purge_protection: bool = True

class AzureDeployRequest(BaseModel):
    resource_group_name: str
    location: str = "eastus"
    network_security_group: Optional[NSGRequest] = None
    storage_account: Optional[StorageRequest] = None
    key_vault: Optional[KeyVaultRequest] = None

# --- REST Endpoints ---
@app.post("/api/v1/azure/scan")
def scan_azure_infrastructure(payload: AzureDeployRequest):
    violations = scan_azure_payload(payload.model_dump())
    if violations:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"status": "BLOCKED", "policy_violations": violations}
        )
    return {"status": "PASSED", "message": "Pre-flight scan complete. No violations detected."}

@app.post("/api/v1/azure/deploy")
def deploy_azure_infrastructure(payload: AzureDeployRequest):
    # Step 1: Pre-flight governance check
    payload_dict = payload.model_dump()
    violations = scan_azure_payload(payload_dict)
    if violations:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"status": "BLOCKED", "policy_violations": violations}
        )
        
    # Step 2: Azure Infrastructure Provisioning
    results = {}
    try:
        # Create Resource Group
        rg_res = create_resource_group(payload.resource_group_name, payload.location)
        results["resource_group"] = rg_res["name"]
        
        # Create NSG if requested
        if payload.network_security_group:
            rules_raw = [r.model_dump() for r in payload.network_security_group.security_rules] if payload.network_security_group.security_rules else []
            nsg_res = create_network_security_group(
                payload.resource_group_name,
                payload.location,
                payload.network_security_group.name,
                rules_raw
            )
            results["network_security_group"] = nsg_res

        # Create Storage Account if requested
        if payload.storage_account:
            st_res = create_storage_account(
                payload.resource_group_name,
                payload.location,
                payload.storage_account.name
            )
            results["storage_account"] = st_res

        # Create Key Vault if requested (NEW)
        if payload.key_vault:
            kv_res = create_key_vault(
                payload.resource_group_name,
                payload.location,
                payload.key_vault.name
            )
            results["key_vault"] = kv_res
            
        return {
            "status": "SUCCESS",
            "provision_mode": "PROVISIONED_IN_AZURE",
            "message": "Security scan passed. Infrastructure deployment authorized.",
            "results": results
        }

    except ClientAuthenticationError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Azure Authentication Failed: Invalid client credentials or tenant configuration."
        )
    except HttpResponseError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Azure SDK Deployment Error: {err.message}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal Server Error: {str(e)}"
        )