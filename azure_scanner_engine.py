"""
azure_scanner_engine.py
Aggregates individual scanner checks into a unified pre-flight security scanner result.
"""

from azure_scanner import (
    check_nsg_ssh_rule, 
    check_storage_public_access, 
    check_storage_https_only
)

def run_azure_security_scan(payload: dict) -> dict:
    """
    Evaluates a deployment payload against all Azure pre-flight security rules.
    Returns a unified scanner result containing pass/fail status and warning details.
    """
    warnings = []

    # Extract configuration blocks from payload
    nsg_rules = payload.get("nsg_rules", [])
    storage_config = payload.get("storage_config", {})

    # Execute scanner checks
    warnings.extend(check_nsg_ssh_rule(nsg_rules))
    warnings.extend(check_storage_public_access(storage_config))
    warnings.extend(check_storage_https_only(storage_config))

    is_passed = len(warnings) == 0

    return {
        "passed": is_passed,
        "total_warnings": len(warnings),
        "warnings": warnings
    }