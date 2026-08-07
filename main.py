"""
main.py
FastAPI web server exposing REST API endpoints for cloud pre-flight scanning and provisioning.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Dict, Any

from azure_scanner_engine import run_azure_security_scan

app = FastAPI(
    title="Secure Cloud Provisioner API",
    description="Backend API for AWS & Azure pre-flight security scanning and provisioning.",
    version="1.0.0"
)

# Request schema for Azure Scan
class AzureScanRequest(BaseModel):
    nsg_rules: Optional[List[Dict[str, Any]]] = []
    storage_config: Optional[Dict[str, Any]] = {}

@app.get("/")
def read_root():
    return {"status": "online", "message": "Secure Cloud Provisioner API is running"}

@app.post("/api/v1/azure/scan")
def azure_preflight_scan(request: AzureScanRequest):
    """
    REST endpoint to evaluate proposed Azure resources against pre-flight security rules.
    """
    payload = request.dict()
    scan_result = run_azure_security_scan(payload)
    return scan_result