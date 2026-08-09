"""
main.py
FastAPI web server exposing REST API endpoints for cloud pre-flight scanning and provisioning.
"""

import os
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Dict, Any

# Load environment variables from .env file immediately on startup
load_dotenv()

from azure_scanner_engine import run_azure_security_scan
from azure_crud import create_resource_group, create_network_security_group, create_storage_account

app = FastAPI(
    title="Secure Cloud Provisioner API",
    description="Backend API for AWS & Azure pre-flight security scanning and provisioning.",
    version="1.0.0"
)

# Request schema for Azure Operations
class AzureDeploymentRequest(BaseModel):
    subscription_id: Optional[str] = None
    resource_group_name: str = "rg-secure-cloud-demo"
    location: str = "eastus"
    storage_account_name: Optional[str] = None
    nsg_name: Optional[str] = None
    nsg_rules: Optional[List[Dict[str, Any]]] = []
    storage_config: Optional[Dict[str, Any]] = {}

@app.get("/")
def read_root():
    return {"status": "online", "message": "Secure Cloud Provisioner API is running"}

@app.post("/api/v1/azure/scan")
def azure_preflight_scan(request: AzureDeploymentRequest):
    payload = request.dict()
    scan_result = run_azure_security_scan(payload)
    return scan_result

@app.post("/api/v1/azure/deploy")
def azure_enforced_deploy(request: AzureDeploymentRequest):
    payload = request.dict()
    
    # Step 1: Pre-flight security scan
    scan_result = run_azure_security_scan(payload)
    
    # Step 2: Security Enforcement Check
    if not scan_result.get("passed", False):
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Deployment blocked due to security violations.",
                "warnings": scan_result.get("warnings", [])
            }
        )
    
    # Step 3: Safe Provisioning Execution via Azure SDK
    try:
        sub_id = request.subscription_id or os.getenv("AZURE_SUBSCRIPTION_ID")
        
        # If an Azure Subscription ID exists, execute real Azure creation
        if sub_id and sub_id != "mock-sub-id":
            # 1. Create Resource Group
            rg_res = create_resource_group(request.resource_group_name, request.location)
            
            # 2. Create Network Security Group (if requested)
            if request.nsg_name or request.nsg_rules:
                nsg_name = request.nsg_name or "default-nsg"
                create_network_security_group(
                    group_name=request.resource_group_name,
                    location=request.location,
                    nsg_name=nsg_name,
                    nsg_rules=request.nsg_rules
                )

            # 3. Create Storage Account (if requested)
            if request.storage_account_name:
                create_storage_account(
                    group_name=request.resource_group_name,
                    location=request.location,
                    account_name=request.storage_account_name,
                    storage_config=request.storage_config
                )
                
            provision_status = "PROVISIONED_IN_AZURE"
        else:
            # Fallback for dry-run / local testing without live Azure credentials
            provision_status = "PASSED_PREFLIGHT_MOCK_PROVISIONED"

        return {
            "status": "SUCCESS",
            "provision_mode": provision_status,
            "message": "Pre-flight checks passed. Infrastructure deployment authorized.",
            "resource_group": request.resource_group_name,
            "location": request.location
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Provisioning error: {str(e)}")