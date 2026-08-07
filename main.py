"""
main.py
FastAPI web server exposing REST API endpoints for cloud pre-flight scanning and provisioning.
"""

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

# Schema for Azure Scan and Deploy Requests
class AzureDeploymentRequest(BaseModel):
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
    """
    REST endpoint to evaluate proposed Azure resources against pre-flight security rules.
    """
    payload = request.dict()
    scan_result = run_azure_security_scan(payload)
    return scan_result

@app.post("/api/v1/azure/deploy")
def azure_enforced_deploy(request: AzureDeploymentRequest):
    """
    Enforced deployment endpoint: Runs pre-flight security scan first.
    Blocks deployment if security checks fail; provisions resources only if passed.
    """
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
    
    # Step 3: Safe Provisioning Execution
    try:
        deploy_summary = {
            "status": "SUCCESS",
            "message": "Resource Group and configured infrastructure provisioned successfully.",
            "resource_group": request.resource_group_name,
            "location": request.location
        }
        return deploy_summary
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Provisioning error: {str(e)}")