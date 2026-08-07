from typing import Dict, Any, Optional
import boto3
from botocore.exceptions import ClientError
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

# Import unified AWS scanner logic, Boto3 live readers, and deployment gatekeeper
from backend.aws.scanner.aws_scanner import scan_aws_resource
from backend.aws.scanner.live_reads import (
    fetch_security_group_config,
    fetch_s3_bucket_config,
)
from backend.aws.deploy import deploy_resource, build_creators

app = FastAPI(
    title="Secure Cloud Provisioner API",
    description="Backend API for secure-by-default AWS provisioning and pre-flight scanning.",
    version="1.0.0"
)

# Initialize Boto3 session & registered deployment creators
session = boto3.Session()
creators = build_creators(session)

# -------------------------------------------------------------------
# Request / Response Models (Data Validation)
# -------------------------------------------------------------------
class ScanRequest(BaseModel):
    """Payload model for offline / pre-flight JSON configuration checks."""
    resource_type: str
    config: Dict[str, Any]


class LiveScanRequest(BaseModel):
    """Payload model for fetching and scanning live AWS infrastructure."""
    resource_type: str = Field(..., description="Resource type e.g. 'security_group' or 's3_bucket'")
    resource_id: str = Field(..., description="Security Group ID (e.g. sg-12345) or S3 Bucket name")
    region: str = Field(default="us-east-1", description="AWS region where the resource lives")


class DeployRequest(BaseModel):
    """Payload model for enforced AWS resource provisioning."""
    resource_type: str = Field(..., description="Resource type e.g. 'security_group' or 's3_bucket'")
    config: Dict[str, Any] = Field(..., description="Configuration dictionary for the resource")
    accept_risk: Optional[bool] = Field(default=False, description="Explicitly accept security risk to deploy despite CRITICAL alerts")


# -------------------------------------------------------------------
# API Routes
# -------------------------------------------------------------------
@app.get("/health", tags=["Health"])
def health_check():
    """Simple health check endpoint to verify backend service state."""
    return {"status": "ok", "service": "secure-cloud-provisioner-backend"}


@app.post("/api/v1/aws/scan", tags=["AWS Services"])
def scan_aws_config(payload: ScanRequest):
    """
    Accepts proposed resource JSON configuration and runs offline pre-flight security checks.
    """
    try:
        scan_result = scan_aws_resource(payload.resource_type, payload.config)
        return scan_result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scanner execution failed: {str(e)}")


@app.post("/api/v1/aws/scan/live", tags=["AWS Services"])
def scan_live_aws_resource(payload: LiveScanRequest):
    """
    Fetches real-time AWS configuration via Boto3 and evaluates it against security rules.
    """
    normalized_type = payload.resource_type.lower().strip()

    try:
        # 1. Fetch live AWS configuration based on resource type
        if normalized_type in ["ec2_security_group", "security_group", "sg"]:
            config = fetch_security_group_config(payload.resource_id, payload.region)
        elif normalized_type in ["s3_bucket", "s3", "bucket"]:
            config = fetch_s3_bucket_config(payload.resource_id, payload.region)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported resource type: '{payload.resource_type}'"
            )

        # 2. Run pure rule logic against fetched live configuration
        scan_result = scan_aws_resource(normalized_type, config)
        return scan_result

    except ClientError as e:
        # Catch AWS Boto3 API errors (e.g. Invalid ID, Access Denied, Bucket Not Found)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"AWS API Error: {e.response['Error']['Message']}"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Live scanner execution failed: {str(e)}"
        )


@app.post("/api/v1/aws/deploy", tags=["AWS Services"])
def deploy_aws_resource(payload: DeployRequest):
    """
    Enforced provisioning entry point. Runs pre-flight scan first; blocks deployment
    if CRITICAL security findings exist unless accept_risk is explicitly True.
    """
    try:
        result = deploy_resource(
            resource_type=payload.resource_type,
            config=payload.config,
            accept_risk=payload.accept_risk or False,
            creators=creators
        )
        return {
            "status": result.status,
            "alerts": result.alerts,
            "resource_id": result.resource_id,
            "error": result.error,
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Deployment gatekeeper failed: {str(e)}"
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)