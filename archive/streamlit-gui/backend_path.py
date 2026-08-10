"""Puts backend/ and the repository root on sys.path.

Part of the archived Streamlit GUI. See README.md beside this file.


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


def _find(name):
    """Walks up from this file looking for a directory, and returns it.

    This module sat at the repository root when it was written, where
    `parent / "backend"` was enough. It is two directories down now, and a
    fixed number of `.parent` calls would be a second thing to get right every
    time anything moves. Searching upwards works from either place.
    """
    for directory in Path(__file__).resolve().parents:
        candidate = directory / name
        if candidate.is_dir():
            return candidate
    return None


BACKEND_DIR = _find("backend")

if BACKEND_DIR and str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

# security_messages.py lives at the repository root and is imported by name.
# Running this app from inside archive/streamlit-gui/ puts that directory on
# the path instead, so the root goes on explicitly.
REPO_ROOT = BACKEND_DIR.parent if BACKEND_DIR else None

if REPO_ROOT and str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
