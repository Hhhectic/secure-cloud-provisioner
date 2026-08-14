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


# Separate from AzureNotConfigured on purpose, because the two send a person to
# two different places. "Not configured" means this process cannot talk to
# Azure at all and the fix is a package or a variable. This means Azure was
# reached, understood the request, and said no - the credentials are fine and
# the permission is not, which is a conversation with whoever owns the
# subscription rather than an edit to a file.
#
# Carries a sentence rather than a status code. Every create in `az/` catches
# it and returns it as the error half of (ok, error, problems), so a refusal
# arrives through the same channel as "that name is taken" instead of as a
# traceback about an HTTP response - which is what a caller got before this
# existed, and which names the missing action in the one format nobody reads
# as advice.
class AzureRefused(Exception):
    """Azure was reached and declined, for a reason the caller can act on."""


def denied(error):
    """Whether Azure refused this for permission rather than for absence.

    Every read in this package has to make this distinction, because Azure does
    not: a resource you may not see and a resource that is not there both come
    back as a refusal, and the only difference is the status code. A reader
    that checks for 404 and re-raises everything else turns "you lack a role"
    into a traceback about an HTTP response, which is the one format nobody
    reads as advice.

    Matches the code and the error string, because the two calls that produced
    this were not consistent about which one carried the answer.
    """
    return (getattr(error, "status_code", None) == 403
            or "AuthorizationFailed" in str(error))


def not_allowed_to_look(resource_group, what=None):
    """The refusal every scoped-permission read here produces. One wording.

    Written once because it was wrong in three places independently: a caller
    who names a resource group the login cannot see gets the same answer
    whether the call that noticed was a resource-group read, a security-group
    read or a virtual-network read.
    """
    where = (f"{what} in the resource group '{resource_group}'" if what
             else f"the resource group '{resource_group}'")

    return AzureRefused(
        f"This login is not allowed to look at {where}, so whether it already "
        f"exists cannot be answered and nothing was created. Azure returns "
        f"the same refusal for "
        f"something you may not see and something that is not there.\n\n"
        f"The usual cause is a service principal granted Contributor on "
        f"particular resource groups rather than on the whole subscription - "
        f"in which case only those group names work. Use a group the login "
        f"already holds."
    )


def why_azure_refused(error, doing):
    """Azure's own refusal, as a sentence a caller can act on.

    Every destructive call in this package could be refused by Azure for a
    reason that is genuinely useful - a subnet still holding a network card, a
    resource group that is locked, a vault inside its retention period - and
    not one of them caught it. The exception travelled up through the route
    and became a 500, so the page showed "HTTP 500" while Azure had said
    exactly which network card was in the way.

    The delete this was found on even had a docstring promising the opposite:
    that Azure's refusal was "left in place rather than worked around" because
    "its message names what is still attached". It was left in place in the
    sense of being unhandled, which is the one way of leaving it in place that
    stops anybody reading it.

    Same lesson as `denied` one screen up, in the other direction: a read that
    only handles 404 turns a missing role into a crash, and a write that
    handles nothing turns every refusal into one.
    """
    code = getattr(error, "error", None)
    code = getattr(code, "code", None) or getattr(error, "reason", None) or ""

    # The SDK's str() is the whole HTTP response - status line, headers and
    # body. The human sentence is in there but so is everything else.
    detail = str(getattr(error, "message", None) or error).strip()
    detail = detail.split("\n")[0].strip()

    return (f"Azure refused to {doing}"
            + (f" ({code})" if code else "") + ". "
            + (detail or "No reason was given.")).strip()


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

    # A module that imports and does not carry the symbol is the same problem
    # as one that does not import, and callers must be able to handle it the
    # same way. azure-mgmt-resource 26.0.0 is exactly this: `azure.mgmt.resource`
    # imports cleanly and exposes nothing at all, because the client moved down
    # to `azure.mgmt.resource.resources`. resource_client() already carries a
    # fallback for that move, and it never fired - it catches AzureNotConfigured
    # and this raised a bare AttributeError past it, out through the registry
    # and into the caller. Found on the first create against a real
    # subscription, where it stopped the write path on its first call.
    try:
        return getattr(module, attribute)
    except AttributeError as e:
        raise AzureNotConfigured(
            f"{name} is installed but does not provide {attribute}. The SDK "
            "moves these between versions; see resource_client() for the "
            f"fallback pattern. ({e})"
        ) from e


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


def keyvault_client(region=None):
    """A client for key vaults. region is accepted and ignored."""
    KeyVaultManagementClient = _import("azure.mgmt.keyvault",
                                       "KeyVaultManagementClient")
    return KeyVaultManagementClient(credential(), subscription_id())


def tenant_id():
    """The Entra tenant a vault's permissions are scoped to.

    Storage and network security groups need no such thing. A key vault does:
    every permission on it names a tenant, and a vault created against the
    wrong one is unopenable by everybody including its creator. It comes from
    the same environment the credential does, so it cannot disagree with the
    identity making the call.
    """
    found = os.getenv("AZURE_TENANT_ID")
    if not found:
        raise AzureNotConfigured(CREDENTIAL_HINT)
    return found


def resource_client(region=None):
    """A client for resource groups. region is accepted and ignored.

    The third client, and the only one the registry never asks for: a resource
    group is not a type this tool provisions, it is the container Azure
    requires before it will accept anything else. `az/storage.py` builds this
    itself rather than the routes learning that Azure needs two clients where
    AWS needs one.

    The import path moved between SDK versions and `azure_crud.py` on
    group/main carries the same fallback, having hit it for real.
    """
    try:
        ResourceManagementClient = _import("azure.mgmt.resource",
                                           "ResourceManagementClient")
    except AzureNotConfigured:
        ResourceManagementClient = _import("azure.mgmt.resource.resources",
                                           "ResourceManagementClient")
    return ResourceManagementClient(credential(), subscription_id())


# --------------------------------------------------- Flattening what Azure says


def plain(value):
    """An SDK value as plain data, with any enum reduced to its string.

    The readers in this package exist to turn SDK objects into dictionaries the
    scanners can read, and `scanner/` is not allowed to know that an Azure SDK
    exists. An enum leaking through is that rule being broken invisibly,
    because the Azure SDK's enums are `str` subclasses and behave like strings
    everywhere it is convenient to check:

        SecurityRuleDirection.INBOUND == "Inbound"      -> True
        isinstance(SecurityRuleDirection.INBOUND, str)  -> True
        json.dumps(SecurityRuleDirection.INBOUND)       -> '"Inbound"'

    and in exactly one place where it is not:

        str(SecurityRuleDirection.INBOUND)  -> 'SecurityRuleDirection.INBOUND'

    Since Python 3.11 a `class X(str, Enum)` renders as its qualified name
    rather than its value, so any coercion through `str()` silently produces
    something that matches nothing. `scanner/azure_nsg_rules.py` compares
    `str(rule["direction"]).lower() != "inbound"` and so skipped every rule of
    every real group: a network security group opening SSH, RDP and every other
    port to the whole internet scanned completely clean. It was found by
    pointing the tool at a group built to be as bad as possible and getting one
    note back, and nothing offline could have shown it, because the stubs
    quite reasonably used ordinary strings.

    Applied in the readers rather than in the scanners, and rather than by
    making the scanners stop calling `str()`. The boundary is where the SDK's
    types are supposed to stop, and a scanner defending itself against a type
    it is not allowed to import is the wrong shape of fix.
    """
    if isinstance(value, (list, tuple)):
        return [plain(item) for item in value]
    # .value is what every Azure enum carries and no plain string, int or None
    # has. Deliberately not isinstance(Enum), which would need the import this
    # module spends its whole docstring avoiding.
    return getattr(value, "value", value)


# ----------------------------------------------------------- Marking our work

# The tag every resource created here carries.
#
# Deliberately the same key and value as `aws/s3_buckets.py` uses. One person
# may point this tool at both clouds, and two spellings of one idea is how an
# AWS cleanup and an Azure cleanup end up disagreeing about what "ours" means.
MANAGED_TAG_KEY = "ManagedBy"
MANAGED_TAG_VALUE = "secure-cloud-provisioner"


def managed_tags():
    """The tags every resource this tool creates carries."""
    return {MANAGED_TAG_KEY: MANAGED_TAG_VALUE}


def is_managed(tags):
    """Whether a resource's tags say this tool made it.

    Azure returns None rather than an empty mapping for an untagged resource,
    which means the same thing here and does not behave the same way.
    """
    return (tags or {}).get(MANAGED_TAG_KEY) == MANAGED_TAG_VALUE


def ensure_resource_group(name, location):
    """Makes sure a resource group exists. Returns (created, note).

    Azure will not accept a storage account without one, and there is no AWS
    equivalent to borrow a default from, so the alternative to creating it is
    refusing until somebody creates it in the portal - which is a worse first
    experience than a group that appears and says it appeared. `created` is
    True only when this call made it, and the note travels back to the caller
    in the create route's `problems`: a second resource existing is not a
    failure, but it is not nothing either.

    A group that already exists is left exactly as it is, tags included.
    Stamping this tool's ownership tag on somebody else's resource group would
    make the cleanup that reads that tag a liar.

    **A group you are not allowed to see is not a group that is missing, and
    Azure answers both with a refusal.** A principal scoped to particular
    resource groups - which is what this tool asks for, and what the smoke
    test's `--azure-resource-group` exists to make possible - gets 403 on
    `resource_groups.get` for any group outside that scope, whether or not it
    exists. Treating that as "not there" would send the create straight into
    `create_or_update`, which fails again with a second 403 and a worse
    message. Letting it out unhandled is what actually happened: somebody
    typed a group name that did not exist, and a traceback about an HTTP
    response came back instead of a sentence.

    This is the third time this project has paid for the same fact, after
    `SkuNotAvailable` and the unregistered compute provider: **Azure reports
    "you may not" and "there is none" in the same words.** Every read here has
    to decide which it is being told.
    """
    client = resource_client()

    try:
        client.resource_groups.get(name)
        return False, None
    except Exception as e:
        # Matching on the status code rather than catching
        # ResourceNotFoundError, which lives behind an import this module
        # deliberately does not make at scope.
        status = getattr(e, "status_code", None)

        if denied(e):
            raise not_allowed_to_look(name) from e

        if status != 404:
            raise

    try:
        client.resource_groups.create_or_update(
            name, {"location": location, "tags": managed_tags()})
    except Exception as e:
        if denied(e):
            raise AzureRefused(
                f"The resource group '{name}' does not exist and this login "
                f"is not allowed to create one. Creating a resource group "
                f"needs permission across the subscription; using an existing "
                f"one needs only Contributor on that group. Name a group that "
                f"already exists, or have somebody create this one."
            ) from e
        raise

    return True, (
        f"Resource group '{name}' did not exist, so it was created in "
        f"{location}. It carries this tool's tag. Deleting the account does "
        "not delete the group."
    )


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
