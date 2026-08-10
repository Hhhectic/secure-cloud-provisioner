"""Puts backend/ on sys.path so its modules import under the names they use.

The AWS backend imports itself absolutely - `from aws import s3_buckets`,
`from scanner.rules import check_firewall_rules` - with backend/ as the root.
Importing it as `backend.aws.s3_buckets` from here would break those imports,
so backend/ goes on the path instead and the modules keep their own names.

This is also why the pre-flight module at the repository root is called
preflight.py rather than scanner.py: `scanner` belongs to backend/ now.

Import this module before any `aws.*` or `scanner.*` import:

    import backend_path  # noqa: F401 - must precede the imports below
    from scanner.s3_rules import check_bucket_settings
"""

import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent / "backend"

if BACKEND_DIR.is_dir() and str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
