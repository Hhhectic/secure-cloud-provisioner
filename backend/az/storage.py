"""Azure storage accounts, read for scanning.

The counterpart of `aws/s3_buckets.py`. Same arrangement, same contract: list,
read into a flat shape, record what could not be read rather than guessing at
it.

A setting the login cannot see goes into "unreadable" instead of being assumed
safe, for the reason `aws/s3_buckets.py` gives at length: a partial audit that
says which parts are missing beats no audit, and beats a confident wrong answer
by a great deal more.

This is the first Azure type that provisions as well as reads, so it is also
where the registry stops being able to say Azure is audit-only. Two things
about that are deliberate and are argued where they happen: an account name is
checked for availability rather than attempted (`_name_is_available`), and a
delete refuses without force even though Azure would carry it out
(`delete_account`). `az/nsg.py` is still read-only.
"""

from az import names
from az.common import (
    AzureNotConfigured,
    AzureRefused,
    why_azure_refused,
    ensure_resource_group,
    is_managed,
    managed_tags,
    plain,
    resource_group_of,
    storage_client,
)


def get_client(region="us-east-1"):
    """Returns a storage client. The region is accepted and ignored."""
    return storage_client(region)


def list_accounts(client, only_ours=False):
    """Every storage account in the subscription.

    only_ours narrows to accounts carrying this tool's tag. It was accepted
    and ignored while nothing here created anything, because there was no tag
    to filter on and a checkbox that does nothing is worse than no checkbox.
    It means something now.
    """
    return [
        {"id": a.id, "name": a.name,
         "resource_group": resource_group_of(a.id),
         "location": a.location}
        for a in client.storage_accounts.list()
        if not only_ours or is_managed(getattr(a, "tags", None))
    ]


def _locate(client, name):
    """Resolves an account name or resource id to (resource_group, name).

    The registry's identifier is a single string, and both a bare name and a
    full Azure resource id are things a person might paste. The group is not
    optional to any management call, so a bare name costs a listing to find
    it; an id carries the group already and costs nothing.
    """
    group = resource_group_of(name)
    short = name.split("/")[-1] if group else name

    if group:
        return group, short

    for candidate in list_accounts(client):
        if candidate["name"] == short:
            return candidate["resource_group"], short

    return None, short


def read_account_for_scanning(client, name):
    """One account's settings, flattened for the scanner.

    Accepts a bare name or a full resource id. Returns None when there is no
    such account.

    Azure returns most of these as attributes that are simply absent on an
    older account rather than raising, so "not readable" and "not set" have to
    be told apart deliberately: None from the SDK means the platform did not
    say, and the scanner is given that rather than a guess in either direction.
    """
    group, short = _locate(client, name)
    if not group:
        return None

    try:
        found = client.storage_accounts.get_properties(group, short)
    except Exception as e:
        if getattr(e, "status_code", None) == 404:
            return None
        raise

    settings = {
        "account_name": found.name,
        "resource_id": found.id,
        "resource_group": group,
        "location": found.location,
        "allow_blob_public_access": getattr(found, "allow_blob_public_access",
                                            None),
        "supports_https_traffic_only": getattr(
            found, "enable_https_traffic_only", None),
        # plain() here and on public_network_access below: both come back as
        # SDK enums, which render through str() as their qualified name rather
        # than their value. See az/common.plain - the same trap that made the
        # network security group scanner silent, and which here would make the
        # network rule fire on an account that is in fact restricted.
        "minimum_tls_version": plain(getattr(found, "minimum_tls_version",
                                             None)),
        # Absent means Enabled, and absent is the common case. Azure only
        # populates this once somebody sets it, so every account that has
        # never had its network access restricted returns None here - which
        # the rule read as "say nothing", making the check silently useless on
        # exactly the accounts it is for. Found on the first run against a real
        # subscription: two accounts, both reachable from any network, both
        # scored clean. Resolved here rather than in the rule for the reason
        # allow_shared_key_access is: the documented default is a fact about
        # Azure, and the rules are where judgement lives, not lookup.
        #
        # The AWS half learned this exact lesson from assign_public_ip - see
        # "An absent setting is not a safe setting" in CLAUDE.md.
        "public_network_access": plain(getattr(found, "public_network_access",
                                               None)) or "Enabled",
        # Null is documented as equivalent to true here, unlike the two
        # settings below: Azure says an unset allowSharedKeyAccess permits the
        # account key. That is a documented default rather than a guess, so it
        # is resolved here instead of going into "unreadable" - reporting an
        # unchecked setting for the commonest case would be noise standing in
        # front of the findings that matter.
        "allow_shared_key_access": getattr(found, "allow_shared_key_access",
                                           None) is not False,
        "containers": [],
    }

    # Which containers are actually served anonymously, as opposed to whether
    # the account permits it. These are two different questions: the account
    # switch says whether a container *may* be public, and the container's own
    # access level says whether one *is*. A reader who has turned the account
    # switch on wants to know which containers it currently affects.
    #
    # This is a second call and a second permission, so a failure is recorded
    # rather than read as "no public containers" - that answer looks identical
    # to a clean result and is the most dangerous possible way to be wrong.
    try:
        settings["containers"] = [
            {"name": c.name,
             # None means private. Azure spells the other two "Blob" (objects
             # readable, listing not) and "Container" (both).
             "public_access": plain(getattr(c, "public_access", None))}
            for c in client.blob_containers.list(group, short)
        ]
        containers_unreadable = None
    except Exception as e:
        containers_unreadable = (
            "the login could not list this account's containers "
            f"({type(e).__name__})"
        )

    # An attribute Azure did not return is a question this scan did not get an
    # answer to, and the scanner reports those rather than scoring them clean.
    unreadable = {}
    for key in ("allow_blob_public_access", "supports_https_traffic_only"):
        if settings[key] is None:
            unreadable[key] = ("Azure did not report this setting for this "
                               "account")
    if containers_unreadable:
        unreadable["containers"] = containers_unreadable

    settings["unreadable"] = unreadable
    return settings


def describe_account(settings):
    """What the account is, rather than what is wrong with it."""
    if not settings:
        return None
    return {
        "account_name": settings.get("account_name"),
        "resource_group": settings.get("resource_group"),
        "location": settings.get("location"),
        "allow_blob_public_access": settings.get("allow_blob_public_access"),
        "supports_https_traffic_only": settings.get(
            "supports_https_traffic_only"),
        "minimum_tls_version": settings.get("minimum_tls_version"),
        "allow_shared_key_access": settings.get("allow_shared_key_access"),
        "containers": [
            {"name": c.get("name"), "public_access": c.get("public_access")}
            for c in settings.get("containers") or []
        ],
        "checks_skipped": sorted(settings.get("unreadable") or {}),
    }


def _name_is_available(client, name):
    """Whether Azure will accept this as a new account name, and why not.

    Asked rather than attempted, because `begin_create` on a name that already
    exists in your own subscription *updates* that account instead of failing.
    The obvious try-it-and-catch-the-error shape would therefore rewrite a
    live account's settings to whatever this form said - silently, and
    reporting success. The same hazard sits in `create_network_security_group`
    on group/main, where the rule list is replaced wholesale.

    Storage account names are global to all of Azure, so the answer depends on
    every other customer as well and cannot be worked out locally.
    """
    answer = client.storage_accounts.check_name_availability(
        {"name": name, "type": "Microsoft.Storage/storageAccounts"})

    if getattr(answer, "name_available", False):
        return True, None

    reason = getattr(answer, "message", None) or getattr(answer, "reason", None)
    return False, (
        f"Azure will not accept '{name}' as a new storage account name: "
        f"{reason} Names are global to all of Azure and must be 3-24 "
        "characters, lowercase letters and numbers only. If this account "
        "already exists, scan it rather than creating it."
    )


def create_account(client, name, resource_group, location="eastus",
                   secure_by_default=True):
    """Creates one storage account. Returns (ok, id_or_error, problems).

    Every setting the scanner reads is stated explicitly, including the ones
    whose Azure default is already the value wanted. `aws/instances.py` learned
    what the alternative costs: `assign_public_ip=False` was implemented as not
    mentioning it, the subnet's own default decided instead, and every machine
    came up with a public address. An absent setting is not a safe setting.

    There is one switch here rather than a field per setting, and that is the
    whole design. The Streamlit form on group/main offered a TLS dropdown
    beside a scanner with no TLS rule, so it could provision a TLS 1.0 account
    and report it clean. `secure_by_default` is read by this function and by
    `check_storage_spec`, which is what makes the warnings somebody sees before
    creation the same ones they see after it.

    The returned id is the full Azure resource id rather than the name,
    because it carries the resource group - every later call needs that, and
    finding it again costs a listing of the whole subscription.
    """
    problems = []

    # Locally decidable, so decided locally. Azure answers a malformed name
    # with the same generic refusal it gives a taken one, which tells somebody
    # who typed a capital letter only that the name is unavailable.
    legal, why_not = names.check("azure-storage", name)
    if not legal:
        return False, why_not, problems

    legal, why_not = names.check("resource-group", resource_group)
    if not legal:
        return False, why_not, problems

    available, why_not = _name_is_available(client, name)
    if not available:
        return False, why_not, problems

    try:
        created, note = ensure_resource_group(resource_group, location)
    except AzureRefused as e:
        return False, str(e), problems
    if created:
        problems.append(note)

    parameters = {
        "sku": {"name": "Standard_LRS"},
        "kind": "StorageV2",
        "location": location,
        "tags": managed_tags(),
        "properties": {
            "allowBlobPublicAccess": not secure_by_default,
            "supportsHttpsTrafficOnly": secure_by_default,
            "minimumTlsVersion": "TLS1_2" if secure_by_default else "TLS1_0",
        },
    }

    account = client.storage_accounts.begin_create(
        resource_group, name, parameters).result()

    return True, account.id, problems


def delete_account(client, name, force=False):
    """Deletes one storage account, and everything inside it.

    Refuses without force, which the routes only accept alongside the
    account's own id repeated back.

    S3 gives an unforced delete a safe failure: a bucket with anything in it
    refuses, so force there means "empty it first". Azure has no such halfway
    state - `storage_accounts.delete` succeeds on a full account and takes
    every container and blob with it. Leaving force optional here would make
    the Azure path the quiet one, which is the reverse of how the rest of this
    tool behaves around anything destructive.

    Not bounded by the tag, exactly as the AWS single delete is not: naming a
    resource twice is the guard, and refusing to delete something this tool
    did not create would make it useless for the account it was pointed at.
    `cleanup_all_managed_accounts` is the bounded one.
    """
    group, short = _locate(client, name)

    if not force:
        return False, (
            f"Not deleted. Removing '{short}' destroys every container and "
            "blob inside it, and Azure offers no version of this that stops "
            "at an account with something in it the way S3 does. Ask for it "
            "explicitly, with the account's id repeated back."
        )

    if not group:
        return False, f"No storage account named '{short}' in this subscription."

    try:
        client.storage_accounts.delete(group, short)
    except Exception as e:            # HttpResponseError, imported lazily
        return False, why_azure_refused(e, f"delete '{short}'")
    return True, f"Deleted storage account '{short}' and everything in it."


def cleanup_all_managed_accounts(client, force=False):
    """Deletes every account carrying this tool's tag. Returns [(id, ok, msg)].

    Bounded by the tag, so it cannot reach an account this tool did not make.
    It is not bounded by who ran it - the tag records which tool, not which
    person - which on a shared subscription means this destroys a colleague's
    demo as readily as your own. The same is true of the AWS cleanup and is
    recorded in CLAUDE.md as an operational hazard rather than fixed here.
    """
    return [
        (account["id"],) + delete_account(client, account["id"], force=force)
        for account in list_accounts(client, only_ours=True)
    ]


# What each fixable finding changes, as {action: (properties, sentence)}.
#
# A table rather than a chain of ifs, because the thing worth checking at a
# glance is that every action here is one property and that no action touches a
# property another one does. The keys are the `action` strings
# `scanner/azure_storage_rules.py` puts in its `fix` blocks, and a mismatch
# between the two is caught by a test rather than by a caller getting "cannot
# fix that" for a button the page drew from the same scanner.
#
# camelCase, because these dicts are the request body. See az/common.plain and
# the create path: a plain dict is serialized as written, so a snake_case key
# here would be silently dropped and the fix would report success having
# changed nothing - which is the worst outcome available to a security tool.
_FIXES = {
    "disable_public_blob_access": (
        {"allowBlobPublicAccess": False},
        "Containers in '{name}' can no longer be opened to anonymous readers. "
        "Any container already set to public is now unreachable without "
        "credentials; nothing was deleted.",
    ),
    "require_https": (
        {"supportsHttpsTrafficOnly": True},
        "'{name}' now refuses unencrypted connections. Anything still "
        "addressing it over plain HTTP will start failing, which is the "
        "point - those requests were exposing whatever they carried.",
    ),
    "require_modern_tls": (
        {"minimumTlsVersion": "TLS1_2"},
        "'{name}' now requires TLS 1.2 or better. Clients too old to offer it "
        "will stop connecting.",
    ),
}


def apply_fix(client, name, warning):
    """Applies one storage finding's fix. Returns (ok, message).

    Only the three settings in `_FIXES` are offered, and each is a single
    property update. The route re-reads the account and re-runs the scanner
    before calling this, so the warning handed over is one this tool derived
    rather than one a caller described - see "Fixes are re-derived server-side"
    in CLAUDE.md.

    Two findings are deliberately not fixable here, and neither is an oversight:

    `shared_key_allowed` would be one property, and turning the account key off
    is the right end state, but it breaks every application still authenticating
    with that key - and this tool cannot see who those are. That is a migration,
    not a fix, and a button that silently starts a migration is worse than no
    button.

    `reachable_from_anywhere` would need a network rule naming which addresses
    keep access, which is information the caller has and the finding does not.
    Applying the obvious default - deny everything - would lock the account
    away from whoever pressed it, including this tool.

    Uses `update` rather than `begin_create`, which is the difference between
    changing one property and rewriting the account: `begin_create` on a name
    you already own replaces the whole configuration with whatever was sent,
    which is the hazard `_name_is_available` exists to keep out of the create
    path. Every property not named here keeps its value.
    """
    group, short = _locate(client, name)
    if not group:
        return False, f"No storage account named '{short}' in this subscription."

    action = (warning or {}).get("fix", {}).get("action")
    if action not in _FIXES:
        return False, (
            f"There is no automatic fix for '{action}'. The findings this can "
            f"fix are: {', '.join(sorted(_FIXES))}."
        )

    properties, sentence = _FIXES[action]
    client.storage_accounts.update(group, short, {"properties": properties})

    return True, sentence.format(name=short)
