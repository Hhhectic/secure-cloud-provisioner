from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, Any

# Import your unified AWS scanner logic
from aws.scanner.aws_scanner import scan_aws_resource

app = FastAPI(
    title="Secure Cloud Provisioner API",
    description="Backend API for secure-by-default AWS provisioning and pre-flight scanning.",
    version="1.0.0"
)

# -------------------------------------------------------------------
# Request / Response Models (Data Validation)
# -------------------------------------------------------------------
class ScanRequest(BaseModel):
    resource_type: str
    config: Dict[str, Any]


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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)