"""
test_azure_scanner.py
Unit tests verifying pre-flight security scanner logic for Azure resources.
"""

import unittest
from azure_scanner_engine import run_azure_security_scan

class TestAzureScanner(unittest.TestCase):

    def test_open_ssh_fails(self):
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
        self.assertFalse(result["passed"])
        self.assertGreater(result["total_warnings"], 0)
        rule_ids = [w["rule_id"] for w in result["warnings"]]
        self.assertIn("AZURE_NSG_OPEN_SSH", rule_ids)

    def test_restricted_ssh_passes(self):
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
        self.assertTrue(result["passed"])
        self.assertEqual(result["total_warnings"], 0)

    def test_public_storage_fails(self):
        payload = {
            "storage_config": {
                "allow_blob_public_access": True,
                "supports_https_traffic_only": True
            }
        }
        result = run_azure_security_scan(payload)
        self.assertFalse(result["passed"])
        rule_ids = [w["rule_id"] for w in result["warnings"]]
        self.assertIn("AZURE_STORAGE_PUBLIC_ACCESS_ENABLED", rule_ids)

    def test_unencrypted_http_storage_fails(self):
        """
        Tests that setting supports_https_traffic_only to False flags AZURE_STORAGE_HTTPS_DISABLED.
        """
        payload = {
            "storage_config": {
                "allow_blob_public_access": False,
                "supports_https_traffic_only": False
            }
        }
        result = run_azure_security_scan(payload)
        self.assertFalse(result["passed"])
        rule_ids = [w["rule_id"] for w in result["warnings"]]
        self.assertIn("AZURE_STORAGE_HTTPS_DISABLED", rule_ids)

    def test_https_storage_passes(self):
        """
        Tests that an HTTPS-only storage account passes the scanner check.
        """
        payload = {
            "storage_config": {
                "allow_blob_public_access": False,
                "supports_https_traffic_only": True
            }
        }
        result = run_azure_security_scan(payload)
        self.assertTrue(result["passed"])
        self.assertEqual(result["total_warnings"], 0)

if __name__ == "__main__":
    unittest.main()