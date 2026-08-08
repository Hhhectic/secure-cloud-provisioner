"""
main.py
FastAPI web server exposing REST API endpoints for cloud pre-flight scanning and provisioning.
"""

import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Dict, Any

from azure_scanner_engine import run_azure_security_scan
import azure_crud

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
        
        # If a real Azure Subscription ID is provided, execute real Azure creation
        if sub_id and sub_id != "mock-sub-id":
            # 1. Create Resource Group
            azure_crud.create_resource_group(sub_id, request.resource_group_name, request.location)
            
            # 2. Create Storage Account (if requested)
            if request.storage_account_name:
                azure_crud.create_storage_account(
                    sub_id, 
                    request.resource_group_name, 
                    request.location, 
                    request.storage_account_name
                )
            
            # 3. Create Network Security Group (if requested)
            if request.nsg_name:
                azure_crud.create_network_security_group(
                    sub_id, 
                    request.resource_group_name, 
                    request.location, 
                    request.nsg_name, 
                    request.nsg_rules
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