"""Azure storage accounts, read for scanning.

The counterpart of `aws/s3_buckets.py`. Same arrangement, same contract: list,
read into a flat shape, record what could not be read rather than guessing at
it.

A setting the login cannot see goes into "unreadable" instead of being assumed
safe, for the reason `aws/s3_buckets.py` gives at length: a partial audit that
says which parts are missing beats no audit, and beats a confident wrong answer
by a great deal more.

Read-only. See `az/nsg.py` for why provisioning is deliberately not wired in
during this first pass.
"""

from az.common import AzureNotConfigured, resource_group_of, storage_client


def get_client(region="us-east-1"):
    """Returns a storage client. The region is accepted and ignored."""
    return storage_client(region)


def list_accounts(client, only_ours=False):
    """Every storage account in the subscription.

    only_ours is accepted and ignored: nothing here creates accounts, so there
    is no tag to filter on.
    """
    return [
        {"id": a.id, "name": a.name,
         "resource_group": resource_group_of(a.id),
         "location": a.location}
        for a in client.storage_accounts.list()
    ]


def read_account_for_scanning(client, name):
    """One account's settings, flattened for the scanner.

    Accepts a bare name or a full resource id. Returns None when there is no
    such account.

    Azure returns most of these as attributes that are simply absent on an
    older account rather than raising, so "not readable" and "not set" have to
    be told apart deliberately: None from the SDK means the platform did not
    say, and the scanner is given that rather than a guess in either direction.
    """
    group = resource_group_of(name)
    short = name.split("/")[-1] if group else name

    if not group:
        for candidate in list_accounts(client):
            if candidate["name"] == short:
                group = candidate["resource_group"]
                break
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
        "minimum_tls_version": getattr(found, "minimum_tls_version", None),
        "public_network_access": getattr(found, "public_network_access", None),
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
             "public_access": getattr(c, "public_access", None)}
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


def apply_fix(client, name, warning):
    """Not yet. Both findings here are one call away from being fixable.

    Turning off anonymous access and requiring HTTPS are single property
    updates, and the AWS side fixes their equivalents. They are not offered
    here because nothing in this module has been run against a real
    subscription: the Azure SDK is not installed in this environment, so a fix
    path would be code that has never once done what it claims. Reporting a
    finding that has not been tested is a smaller lie than offering to act on
    it.
    """
    return False, (
        "Azure storage findings are reported rather than fixed, for now. "
        "Both are a single setting change in the portal: turn off anonymous "
        "blob access, and require secure transfer."
    )
