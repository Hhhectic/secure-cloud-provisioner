"""Talking to Azure, without making it a requirement of starting.

Two constraints shape this file, and both are the kind that are invisible until
they bite.

**The package cannot be called `azure`.** The Azure SDK owns that name as a
namespace package, and `pytest.ini` puts `backend/` on the path, so a directory
called `backend/azure/` becomes the top-level `azure` module and every
`import azure.identity` in the process resolves to it and fails. Verified
rather than assumed. Hence `az/`, which is also what Microsoft calls its own
command line tool.

**The SDK is imported inside functions, never at module scope.** `api/registry.py`
imports every provider module when the process starts, so an import here is an
import for the AWS half too. `.venv` holds boto3 and fastapi and not
`azure-identity`, which means a module-level import would stop the AWS half
starting on the machine it was developed on. That is precisely the objection
recorded against mounting the two applications into one process, and it would
be perverse to accept it while claiming to have avoided it.

The cost is that a missing SDK is discovered when somebody asks for an Azure
resource rather than at startup. That is the right moment: it is the first
point at which the answer actually matters, and the message can say what to
install.
"""

import os

# What a caller sees when the SDK is absent. Deliberately not an ImportError:
# the routes turn this into a sentence about what to install, and an
# ImportError escaping to a browser is a stack trace about a module nobody
# using the tool has heard of.
class AzureNotConfigured(Exception):
    """The Azure SDK or its credentials are not available in this process."""


INSTALL_HINT = (
    "The Azure half needs its own dependencies, which the AWS half does not "
    "install. Run `pip install -r requirements.txt` from the repository root."
)

CREDENTIAL_HINT = (
    "Azure needs AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET and "
    "AZURE_SUBSCRIPTION_ID. Put them in a .env file at the repository root; "
    "`.env.example` on group/main lists them."
)


def _import(name, attribute):
    """Imports one SDK symbol, or explains why it is not there.

    Inside a function on purpose. See the module docstring: importing at module
    scope would make the Azure SDK a hard requirement of starting the AWS half.
    """
    try:
        module = __import__(name, fromlist=[attribute])
    except ImportError as e:
        raise AzureNotConfigured(f"{INSTALL_HINT} (missing {name}: {e})") from e
    return getattr(module, attribute)


def subscription_id():
    """The subscription every client is scoped to."""
    found = os.getenv("AZURE_SUBSCRIPTION_ID")
    if not found:
        raise AzureNotConfigured(CREDENTIAL_HINT)
    return found


def credential():
    """A credential built from the environment.

    ClientSecretCredential rather than DefaultAzureCredential, because the
    default one silently tries six sources in order and succeeds with whichever
    happens to be lying around - which is convenient until the tool audits a
    subscription nobody meant to point it at.
    """
    tenant = os.getenv("AZURE_TENANT_ID")
    client = os.getenv("AZURE_CLIENT_ID")
    secret = os.getenv("AZURE_CLIENT_SECRET")

    if not (tenant and client and secret):
        raise AzureNotConfigured(CREDENTIAL_HINT)

    ClientSecretCredential = _import("azure.identity", "ClientSecretCredential")
    return ClientSecretCredential(tenant_id=tenant, client_id=client,
                                  client_secret=secret)


def network_client(region=None):
    """A client for network security groups. region is accepted and ignored.

    Azure puts the location on each resource rather than on the connection, so
    there is no regional endpoint to choose. The parameter exists because the
    registry hands every resource type a region, and refusing it here would
    mean the routes needing to know which provider they were talking to.
    """
    NetworkManagementClient = _import("azure.mgmt.network",
                                      "NetworkManagementClient")
    return NetworkManagementClient(credential(), subscription_id())


def storage_client(region=None):
    """A client for storage accounts. region is accepted and ignored."""
    StorageManagementClient = _import("azure.mgmt.storage",
                                      "StorageManagementClient")
    return StorageManagementClient(credential(), subscription_id())


def is_available():
    """Whether an Azure call could be made at all, without making one.

    Used by the CLI and the page to say "not configured" instead of offering
    a menu that will only produce an error.
    """
    try:
        credential()
    except AzureNotConfigured:
        return False
    return True


def resource_group_of(resource_id):
    """Pulls the resource group out of an Azure resource id.

    An id looks like
    /subscriptions/<id>/resourceGroups/<group>/providers/<...>/<name>, and
    almost every management call needs the group as a separate argument. Doing
    this by splitting the id is not elegant; the alternative is carrying the
    group alongside every identifier through the registry, which would mean a
    resource id that is not a string.
    """
    parts = (resource_id or "").split("/")
    for index, part in enumerate(parts):
        if part.lower() == "resourcegroups" and index + 1 < len(parts):
            return parts[index + 1]
    return None
