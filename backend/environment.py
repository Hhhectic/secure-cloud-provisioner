"""Loads the repository's .env, once, at whichever entrypoint starts first.

The root `main.py` has called `load_dotenv()` since it was written. Nothing in
`backend/` did, so credentials put in `.env` - which is what `.env.example`
tells people to do, and where every set of instructions for this project points
- reached the Azure app and not the tool. The failure was quiet in the worst
way: `az/common.py` raises "Azure needs AZURE_TENANT_ID..." whether the file is
missing or merely unread, so the message sent somebody to fix a file that was
already correct.

Called from the entrypoints rather than from `az/common.py` or `aws/common.py`,
because reading configuration is a thing a program does when it starts and a
library should only ever read what is already there. It also keeps this out of
the import path that `api/registry.py` walks at startup.

python-dotenv is optional. It is a dependency of the root Azure app rather than
of this one, and a checkout without it should lose the convenience of a file
and nothing else - real environment variables still work, which is how this
runs in CI and in any container.
"""

import os
from pathlib import Path

# The repository root, one level above backend/. The file lives there because
# it is shared with the root Azure app, and because everything documenting this
# project says "a .env file at the repository root".
REPO_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = REPO_ROOT / ".env"


def load():
    """Reads .env into the environment if it is there. Returns what happened.

    Never overrides a variable that is already set. A value exported in the
    shell, or injected by CI, or set by a container runtime is a deliberate act
    by somebody who knew what they were doing; a file on disk is a default. The
    deliberate act wins - which is also what makes it possible to point one
    checkout at two subscriptions without editing anything.
    """
    if not ENV_FILE.exists():
        return False, f"no .env at {ENV_FILE}"

    try:
        from dotenv import load_dotenv
    except ImportError:
        return False, (
            f"{ENV_FILE} exists but python-dotenv is not installed, so it was "
            "not read. Either `pip install python-dotenv` or export the "
            "variables in your shell."
        )

    load_dotenv(ENV_FILE, override=False)
    return True, f"read {ENV_FILE}"


def configured(*names):
    """Which of the named variables are missing. For telling somebody why.

    Returns the missing ones rather than a boolean, because "Azure is not
    configured" and "AZURE_CLIENT_SECRET is empty" send a person to two
    different places, and the second one is nearly always the answer.
    """
    return [name for name in names if not os.getenv(name)]
