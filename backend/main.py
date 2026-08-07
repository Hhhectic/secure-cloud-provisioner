from typing import Dict, Any
from botocore.exceptions import ClientError
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

# Import unified AWS scanner logic & Boto3 live readers
from aws.scanner.aws_scanner import scan_aws_resource
from aws.scanner.live_reads import (
    fetch_security_group_config,
    fetch_s3_bucket_config,
)

app = FastAPI(
    title="Secure Cloud Provisioner API",
    description="Backend API for secure-by-default AWS provisioning and pre-flight scanning.",
    version="1.0.0"
)

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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)