"""
azure_scanner_engine.py
Unified security scanner engine module for Azure infrastructure.
Combines all individual Azure scanner rules into a single engine call.
"""

from azure_scanner import scan_azure_deployment


def run_azure_security_scan(payload: dict) -> dict:
    """
    Evaluates a full deployment payload against all Azure security rules.
    Returns a unified pass/fail scanner result object.
    """
    scan_results = scan_azure_deployment(payload)
    
    is_passed = scan_results.get("is_safe", False)
    warnings = scan_results.get("warnings", [])
    
    return {
        "status": "PASS" if is_passed else "FAIL",
        "passed": is_passed,
        "total_warnings": len(warnings),
        "warnings": warnings,
        "provider": "Azure"
    }


if __name__ == "__main__":
    # Test execution when run directly
    sample_payload = {
        "nsg_rules": [
            {
                "access": "allow",
                "direction": "inbound",
                "source_address_prefix": "*",
                "destination_port_range": "22"
            }
        ],
        "storage_config": {
            "allow_blob_public_access": True
        }
    }
    
    result = run_azure_security_scan(sample_payload)
    print("Scanner Engine Test Output:")
    print(result)