"""
test_azure_scanner.py
Unit tests verifying pre-flight security scanner logic for Azure resources.
"""

import unittest
from azure_scanner_engine import run_azure_security_scan

class TestAzureScanner(unittest.TestCase):

    def test_open_ssh_fails(self):
        """
        Tests that an NSG rule allowing public inbound SSH (Port 22 from 0.0.0.0/0)
        triggers a security failure.
        """
        payload = {
            "nsg_rules": [
                {
                    "name": "allow-ssh-internet",
                    "direction": "Inbound",
                    "access": "Allow",
                    "destination_port_range": "22",
                    "source_address_prefix": "0.0.0.0/0"
                }
            ]
        }
        
        result = run_azure_security_scan(payload)
        
        # Scanner should block this deployment
        self.assertFalse(result["passed"])
        self.assertGreater(result["total_warnings"], 0)
        
        # Verify specific warning ID is present
        rule_ids = [w["rule_id"] for w in result["warnings"]]
        self.assertIn("AZURE_NSG_OPEN_SSH", rule_ids)

    def test_restricted_ssh_passes(self):
        """
        Tests that an NSG rule restricting SSH (Port 22) to a specific IP address
        passes the pre-flight check.
        """
        payload = {
            "nsg_rules": [
                {
                    "name": "allow-ssh-admin-only",
                    "direction": "Inbound",
                    "access": "Allow",
                    "destination_port_range": "22",
                    "source_address_prefix": "192.168.1.50/32"
                }
            ]
        }
        
        result = run_azure_security_scan(payload)
        
        # Scanner should authorize this deployment
        self.assertTrue(result["passed"])
        self.assertEqual(result["total_warnings"], 0)

    def test_public_storage_fails(self):
        """
        Tests that enabling allow_blob_public_access on a storage account
        flags the AZURE_STORAGE_PUBLIC_ACCESS_ENABLED warning.
        """
        payload = {
            "storage_config": {
                "allow_blob_public_access": True,
                "supports_https_traffic_only": True
            }
        }
        
        result = run_azure_security_scan(payload)
        
        # Scanner should block public storage
        self.assertFalse(result["passed"])
        
        # Verify the public access warning ID is present
        rule_ids = [w["rule_id"] for w in result["warnings"]]
        self.assertIn("AZURE_STORAGE_PUBLIC_ACCESS_ENABLED", rule_ids)

if __name__ == "__main__":
    unittest.main()