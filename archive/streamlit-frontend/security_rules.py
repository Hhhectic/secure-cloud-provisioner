SECURITY_RULES = {
    "SEC001_PUBLIC_BLOB_ACCESS": {
        "title": "Anonymous Public Blob Access Enabled",
        "description": "Allowing public blob access enables anyone on the internet to read or download data without authenticating.",
        "fix": "Uncheck 'Allow Blob Public Access' or restrict container access policies to private."
    },
    "SEC002_INSECURE_TLS": {
        "title": "Insecure TLS Minimum Version",
        "description": "TLS versions below TLS 1.2 are deprecated and vulnerable to network eavesdropping attacks.",
        "fix": "Enforce minimum TLS version to TLS1_2 or higher."
    },
    "SEC003_DISABLED_HTTPS": {
        "title": "HTTPS-Only Transport Disabled",
        "description": "Disabling HTTPS permits unencrypted HTTP connections, exposing data in transit.",
        "fix": "Enable 'HTTPS-Only Traffic' to mandate TLS encryption for all endpoints."
    },
    "NAMING001_INVALID_NAME": {
        "title": "Invalid Storage Account Name",
        "description": "Azure Storage Account names must be globally unique, 3-24 characters, using lowercase letters and numbers only.",
        "fix": "Remove uppercase letters, spaces, hyphens, or special characters."
    },
    "CONTAINER001_INVALID_NAME": {
        "title": "Invalid Container Name Format",
        "description": "Container names must be 3-63 characters, lowercase letters, numbers, or hyphens, starting/ending with letter/number.",
        "fix": "Format container names using only lowercase letters, numbers, and hyphens."
    }
}
