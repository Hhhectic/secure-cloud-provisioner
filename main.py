"""
main.py
FastAPI application entrypoint for secure cloud provisioning operations.
Integrates security scanning engine, pre-flight validation, and sanitized error handling.
"""

from dotenv import load_dotenv
load_dotenv()  # Automatically loads environment variables from .env file

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from azure.core.exceptions import ClientAuthenticationError, HttpResponseError

from azure_scanner_engine import run_azure_security_scan
from azure_crud import (
    create_resource_group,
    create_network_security_group,
    create_storage_account
)

app = FastAPI(
    title="Secure Cloud Provisioner API",
    version="1.0.0",
    description="Backend API for validating, scanning, and deploying Azure infrastructure resources securely."
)


class NSGRule(BaseModel):
    name: str = "allow-ssh-admin"
    direction: str = "Inbound"
    access: str = "Allow"
    destination_port_range: str = "22"
    source_address_prefix: str = "*"
    protocol: str = "Tcp"


class AzureDeployRequest(BaseModel):
    resource_group_name: str = Field(..., description="Target Azure Resource Group name")
    location: str = Field(default="eastus", description="Azure region location")
    storage_account_name: Optional[str] = Field(default=None, description="Azure Storage Account name")
    nsg_name: Optional[str] = Field(default=None, description="Azure Network Security Group name")
    nsg_rules: Optional[List[NSGRule]] = Field(default=None, description="List of NSG rules")
    storage_config: Optional[Dict[str, Any]] = Field(default=None, description="Optional storage configuration overrides")


@app.get("/")
def read_root():
    return {"status": "ONLINE", "message": "Secure Cloud Provisioner API is operational"}


@app.post("/api/v1/azure/scan")
def scan_azure_infrastructure(request: AzureDeployRequest):
    """
    Dry-run endpoint used by frontend forms to evaluate deployment requests against governance rules.
    """
    scan_results = run_azure_security_scan(request.dict())
    return {
        "status": "COMPLETED",
        "passed": scan_results.get("passed", False),
        "total_warnings": scan_results.get("total_warnings", 0),
        "warnings": scan_results.get("warnings", [])
    }


@app.post("/api/v1/azure/deploy")
def deploy_azure_infrastructure(request: AzureDeployRequest):
    """
    Scans incoming configuration against all security rules (SSH, RDP, Blob Access, HTTPS/TLS).
    If validation passes, provisions infrastructure using azure_crud.py with sanitized exception handling.
    """
    # 1. Full Security Engine Scan
    payload = request.dict()
    scan_results = run_azure_security_scan(payload)

    if not scan_results.get("passed", False):
        warnings = scan_results.get("warnings", [])
        formatted_warnings = "; ".join(w.get("title", "Governance Violation") for w in warnings) if warnings else "Configuration violates governance policies."
        raise HTTPException(
            status_code=400,
            detail={
                "message": f"Deployment blocked: {formatted_warnings}",
                "warnings": warnings
            }
        )

    # 2. Infrastructure Deployment Execution
    try:
        # Step A: Resource Group
        rg_res = create_resource_group(request.resource_group_name, request.location)

        # Step B: Network Security Group (Optional)
        nsg_res = None
        if request.nsg_name:
            rules_dict = [rule.dict() for rule in request.nsg_rules] if request.nsg_rules else []
            nsg_res = create_network_security_group(
                request.resource_group_name,
                request.location,
                request.nsg_name,
                rules_dict
            )

        # Step C: Storage Account (Optional)
        storage_res = None
        if request.storage_account_name:
            storage_res = create_storage_account(
                request.resource_group_name,
                request.location,
                request.storage_account_name,
                request.storage_config
            )

        return {
            "status": "SUCCESS",
            "provision_mode": "PROVISIONED_IN_AZURE",
            "message": "Security scan passed. Infrastructure deployment authorized.",
            "scan_warnings": scan_results.get("warnings", []),
            "resource_group": rg_res.get("name"),
            "location": rg_res.get("location"),
            "network_security_group": nsg_res,
            "storage_account": storage_res
        }

    except (ClientAuthenticationError, ValueError):
        # Sanitizes credential failures (hides raw Azure Entra ID Trace IDs, Tenant IDs, Client IDs)
        raise HTTPException(
            status_code=401,
            detail="Azure Authentication Failed: Invalid client credentials or tenant configuration."
        )

    except HttpResponseError as e:
        # Sanitizes API/SDK HTTP response errors while conveying actionable resource issues
        sanitized_msg = getattr(e, "message", "Invalid resource parameters or request format.")
        raise HTTPException(
            status_code=400,
            detail=f"Azure Resource Provisioning Failed: {sanitized_msg}"
        )

    except Exception:
        # Generic fallback for unhandled internal exceptions
        raise HTTPException(
            status_code=500,
            detail="An internal server error occurred during resource provisioning."
        )