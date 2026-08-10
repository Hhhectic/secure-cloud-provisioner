import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any


class ValidationSeverity(Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


@dataclass
class ValidationIssue:
    field: str
    rule_id: str
    severity: ValidationSeverity
    message: str


@dataclass
class PreFlightResult:
    is_valid: bool
    issues: List[ValidationIssue] = field(default_factory=list)
    sanitized_config: Dict[str, Any] = field(default_factory=dict)

    @property
    def errors(self) -> List[ValidationIssue]:
        return [i for i in self.issues if i.severity == ValidationSeverity.ERROR]

    @property
    def warnings(self) -> List[ValidationIssue]:
        return [i for i in self.issues if i.severity == ValidationSeverity.WARNING]


class StoragePreFlightValidator:
    ALLOWED_TLS = {"TLS1_2", "TLS1_3"}

    def __init__(self, config: Dict[str, Any]):
        self.raw_config = config
        self.issues: List[ValidationIssue] = []

    def validate(self) -> PreFlightResult:
        self.issues.clear()

        # 1. Storage Account Name Check
        name = str(self.raw_config.get("account_name", "")).strip().lower()
        if not name or len(name) < 3 or len(name) > 24 or not re.match(r"^[a-z0-9]+$", name):
            self.issues.append(ValidationIssue(
                field="account_name",
                rule_id="NAMING001_INVALID_NAME",
                severity=ValidationSeverity.ERROR,
                message="Name must be 3-24 chars, lowercase letters and numbers only."
            ))

        # 2. Public Access Warning Check
        if self.raw_config.get("allow_blob_public_access", False) is True:
            self.issues.append(ValidationIssue(
                field="allow_blob_public_access",
                rule_id="SEC001_PUBLIC_BLOB_ACCESS",
                severity=ValidationSeverity.WARNING,
                message="Public blob access is enabled."
            ))

        # 3. Minimum TLS Version Check
        min_tls = self.raw_config.get("min_tls_version", "TLS1_2")
        if min_tls not in self.ALLOWED_TLS:
            self.issues.append(ValidationIssue(
                field="min_tls_version",
                rule_id="SEC002_INSECURE_TLS",
                severity=ValidationSeverity.ERROR,
                message=f"TLS version '{min_tls}' is insecure."
            ))

        # 4. HTTPS Traffic Check
        if self.raw_config.get("enable_https_traffic_only", True) is False:
            self.issues.append(ValidationIssue(
                field="enable_https_traffic_only",
                rule_id="SEC003_DISABLED_HTTPS",
                severity=ValidationSeverity.ERROR,
                message="HTTPS-only traffic is disabled."
            ))

        # 5. Containers Check
        containers = self.raw_config.get("containers", [])
        for c in containers:
            c_name = str(c).strip().lower()
            if not re.match(r"^[a-z0-9]([a-z0-9-]{1,61}[a-z0-9])?$", c_name):
                self.issues.append(ValidationIssue(
                    field="containers",
                    rule_id="CONTAINER001_INVALID_NAME",
                    severity=ValidationSeverity.ERROR,
                    message=f"Container name '{c_name}' is invalid."
                ))

        has_errors = any(i.severity == ValidationSeverity.ERROR for i in self.issues)
        sanitized = {}
        if not has_errors:
            sanitized = {
                "account_name": name,
                "resource_group": str(self.raw_config.get("resource_group", "rg-backend-dev")).strip(),
                "location": str(self.raw_config.get("location", "eastus")).strip().lower(),
                "sku": self.raw_config.get("sku", "Standard_LRS"),
                "allow_blob_public_access": bool(self.raw_config.get("allow_blob_public_access", False)),
                "min_tls_version": min_tls,
                "enable_https_traffic_only": bool(self.raw_config.get("enable_https_traffic_only", True)),
                "containers": [str(c).strip().lower() for c in containers if c]
            }

        return PreFlightResult(is_valid=not has_errors, issues=self.issues, sanitized_config=sanitized)
