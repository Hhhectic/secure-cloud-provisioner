"""Azure key vaults: where the secrets are, read and provisioned.

The third Azure type, ported from `create_key_vault` and
`check_key_vault_governance` on `group/feature/key-vault`. Same arrangement as
`az/storage.py`: list, read into a flat shape, create with every setting
stated, and refuse a delete that nobody asked for twice.

A vault is unlike the other two resources here in one way that shapes this
whole module. Storage and firewalls are dangerous when somebody can *reach*
them; a vault is dangerous when somebody can *destroy* it. It holds the keys
other things are encrypted with, so losing a vault can mean losing data that
was never in it. That is why the findings below are about recoverability and
about who can be seen to hold access, rather than about exposure alone.

Every SDK import happens inside `az/common.py`, inside a function, so importing
this module costs nothing on a machine with only the AWS half installed.
"""

from az import names
from az.common import (
    AzureNotConfigured,
    AzureRefused,
    denied,
    ensure_resource_group,
    is_managed,
    keyvault_client,
    managed_tags,
    not_allowed_to_look,
    plain,
    resource_group_of,
    tenant_id,
)


def get_client(region="us-east-1"):
    """Returns a key vault client. The region is accepted and ignored."""
    return keyvault_client(region)


def list_vaults(client, only_ours=False):
    """Every key vault in the subscription.

    only_ours narrows to vaults carrying this tool's tag.
    """
    return [
        {"id": v.id, "name": v.name,
         "resource_group": resource_group_of(v.id),
         "location": getattr(v, "location", None)}
        for v in client.vaults.list_by_subscription()
        if not only_ours or is_managed(getattr(v, "tags", None))
    ]


def _locate(client, name):
    """Resolves a vault name or resource id to (resource_group, name).

    The same job `az/storage.py:_locate` does, and separate from it because a
    vault is listed by a different call. Sharing one would mean passing in
    which lister to use, which is more machinery than the four lines saves.
    """
    group = resource_group_of(name)
    short = name.split("/")[-1] if group else name

    if group:
        return group, short

    for candidate in list_vaults(client):
        if candidate["name"] == short:
            return candidate["resource_group"], short

    return None, short


def read_vault_for_scanning(client, name):
    """One vault's settings, flattened for the scanner.

    Accepts a bare name or a full resource id. Returns None when there is no
    such vault, which the routes turn into a 404.

    Deliberately reads no secret, key or certificate. Those are the data plane,
    behind a different endpoint and a different permission, and a tool that
    enumerated them would be building the exact inventory an attacker wants
    while claiming to audit it. Everything here is management plane: how the
    vault is configured, never what is in it.
    """
    group, short = _locate(client, name)
    if not group:
        return None

    try:
        found = client.vaults.get(group, short)
    except Exception as e:
        # Refusal before absence, because Azure says both in the same words
        # and a handler knowing only 404 re-raises the first as a crash.
        if denied(e):
            raise not_allowed_to_look(group, "key vaults") from e
        # Matching the status code rather than catching ResourceNotFoundError,
        # which lives behind an import this module does not make at scope.
        if getattr(e, "status_code", None) == 404:
            return None
        raise

    properties = getattr(found, "properties", None)

    def prop(attribute):
        return getattr(properties, attribute, None)

    policies = prop("access_policies") or []
    acls = prop("network_acls")

    settings = {
        "vault_name": found.name,
        "resource_id": found.id,
        "resource_group": group,
        "location": getattr(found, "location", None),
        "soft_delete_enabled": prop("enable_soft_delete"),
        "purge_protection_enabled": prop("enable_purge_protection"),
        "rbac_authorization": prop("enable_rbac_authorization"),
        "soft_delete_retention_days": prop("soft_delete_retention_in_days"),
        # How many identities hold access through the vault's own policy list,
        # rather than through a role. The scanner cares about the count and not
        # about who: naming them would put a list of exactly which identities
        # to phish into a response this tool hands to a browser.
        "access_policy_count": len(policies),
        # plain() on both: the scanner lowercases these through str(), and an
        # SDK enum renders there as its qualified name rather than its value.
        # See az/common.plain.
        "public_network_access": plain(prop("public_network_access")),
        "network_default_action": plain(getattr(acls, "default_action", None)),
    }

    # A setting Azure did not report is a question this scan did not get an
    # answer to. Same contract as az/storage.py: it is reported as unchecked
    # rather than scored clean, because a partial audit that says which parts
    # are missing beats a confident wrong answer.
    #
    # Two settings are not in this list, both because null is an answer here
    # rather than a silence.
    #
    # rbac_authorization: Azure returns null for a vault created before the
    # setting existed, and null there means access policies, a documented
    # default.
    #
    # purge_protection_enabled: Azure only ever reports this property when it
    # is on. Off is modelled as absent, which is the same fact `create_vault`
    # relies on when it omits the key rather than sending false - the API
    # rejects an explicit false, because the setting cannot be turned back off
    # once on. So null means off, and calling it unreadable made every vault
    # without purge protection report "could not check" in place of the finding
    # that is the whole reason this scanner exists. It also split the contract
    # this project asserts everywhere else: `check_spec` said no_purge_protection
    # before the vault was built and the scan said unreadable_purge_protection
    # after, for the same vault and the same setting. Found on the first real
    # create; no stub had reason to leave the property out.
    unreadable = {}
    for key in ("soft_delete_enabled",):
        if settings[key] is None:
            unreadable[key] = "Azure did not report this setting for this vault"

    settings["purge_protection_enabled"] = bool(settings["purge_protection_enabled"])

    settings["unreadable"] = unreadable
    return settings


def describe_vault(settings):
    """What the vault is, rather than what is wrong with it."""
    if not settings:
        return None
    return {
        "vault_name": settings.get("vault_name"),
        "resource_group": settings.get("resource_group"),
        "location": settings.get("location"),
        "soft_delete_enabled": settings.get("soft_delete_enabled"),
        "purge_protection_enabled": settings.get("purge_protection_enabled"),
        "rbac_authorization": settings.get("rbac_authorization"),
        "soft_delete_retention_days": settings.get("soft_delete_retention_days"),
        "access_policy_count": settings.get("access_policy_count"),
        "checks_skipped": sorted(settings.get("unreadable") or {}),
    }


def _name_is_available(client, name):
    """Whether Azure will accept this as a new vault name, and why not.

    Asked rather than attempted, for the reason `az/storage.py` gives at
    length: begin_create_or_update on a name that already exists updates that
    vault rather than failing, and a create that silently rewrites a live
    vault's access configuration is the worst version of that mistake anywhere
    in this tool.

    There is a second reason here that storage does not have. A deleted vault
    keeps its name for the whole soft-delete retention period, so "this name is
    taken" routinely means "you deleted it last week", and a caller who is only
    told the create failed will try the same name again.
    """
    answer = client.vaults.check_name_availability(
        {"name": name, "type": "Microsoft.KeyVault/vaults"})

    if getattr(answer, "name_available", False):
        return True, None

    reason = getattr(answer, "message", None) or getattr(answer, "reason", None)
    return False, (
        f"Azure will not accept '{name}' as a new key vault name: {reason} "
        "Names are global to all of Azure, 3-24 characters, letters, digits "
        "and hyphens, starting with a letter. A vault deleted recently still "
        "holds its name until its soft-delete retention runs out, so this can "
        "mean a vault you removed rather than somebody else's."
    )


def create_vault(client, name, resource_group, location="eastus",
                 secure_by_default=True):
    """Creates one key vault. Returns (ok, id_or_error, problems).

    Every setting the scanner reads is stated explicitly, for the reason
    `aws/instances.py` learned the expensive way: an absent setting is not a
    safe setting, it is the platform's setting.

    **Soft delete is always on, whatever the switch says.** Azure made it
    mandatory in 2020 and the API refuses to create a vault without it, so the
    deliberately-weak option cannot weaken it and does not pretend to. This is
    the same shape as the S3 rules that cannot fire on a bucket made today:
    the platform closed the foot-gun, the rule stays because older vaults exist
    and this one states the value rather than relying on that.

    **Purge protection is left out entirely when off, not sent as false.** The
    API rejects an explicit false - once enabled it can never be disabled, so
    Azure models "not on" as absent. That is the one place this module cannot
    state a value outright, and it is Azure's constraint rather than a choice
    here.

    **The keys are camelCase, because this dict is the request body.** A plain
    dict handed to the SDK is serialized as JSON exactly as written rather than
    being mapped from the model's Python names, so a snake_case key is not the
    field it looks like - it is an unrecognised one, silently dropped. That is
    how this read `tenant_id` and failed with "an invalid value was provided
    for 'tenantId'": the value was not invalid, it was absent, because the
    field carrying it was spelled in the language of the model rather than of
    the wire. `az/storage.py` has always written camelCase here and is why the
    storage path worked while this one did not. It also means None is an
    explicit null rather than an omission, which is the reason purge protection
    is added conditionally below instead of being set to None.

    The read path is unaffected and stays snake_case: `vaults.get` returns a
    model object, where the Python names are the real ones.
    """
    problems = []

    # Locally decidable, so decided locally. See az/names.py - and note that a
    # vault's alphabet is not a storage account's, which is the kind of
    # difference that turns into a confusing refusal from Azure.
    legal, why_not = names.check("azure-keyvault", name)
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

    properties = {
        "tenantId": tenant_id(),
        "sku": {"family": "A", "name": "standard"},
        # Mandatory since 2020; stated rather than assumed.
        "enableSoftDelete": True,
        "softDeleteRetentionInDays": 90 if secure_by_default else 7,
        # Roles rather than the vault's own policy list, so that who can open
        # this vault is visible to the same audit that reads every other
        # permission in the subscription.
        "enableRbacAuthorization": secure_by_default,
        # Required by the API whenever the vault is not using roles, and
        # harmless when it is. Empty is the honest starting point: this tool
        # grants nobody access to a vault it has just made, and the scanner
        # reports an empty list as a note rather than a fault.
        "accessPolicies": [],
    }

    # Added only when on. See the docstring: absent and false are different
    # requests, and this dict is the body rather than a model.
    if secure_by_default:
        properties["enablePurgeProtection"] = True

    parameters = {
        "location": location,
        "tags": managed_tags(),
        "properties": properties,
    }

    vault = client.vaults.begin_create_or_update(
        resource_group, name, parameters).result()

    if secure_by_default:
        problems.append(
            f"Purge protection is on, which cannot be turned off again. "
            f"'{name}' and its name are held for 90 days after any delete, "
            "and nothing - including this tool - can shorten that."
        )

    return True, vault.id, problems


def delete_vault(client, name, force=False):
    """Deletes one vault. Returns (ok, message).

    Refuses without force, which the routes only accept alongside the vault's
    own id repeated back. The same demand `az/storage.py` makes, for a
    different reason: deleting a storage account destroys what is in it, while
    deleting a vault destroys the keys that other things' data is encrypted
    with. The blast radius reaches resources this tool has never looked at.

    Says plainly what a delete does and does not do. Soft delete is mandatory,
    so this removes the vault but leaves it recoverable and leaves its name
    taken; with purge protection on, not even an administrator can shorten
    that. A message saying only "deleted" would be true and would mislead
    somebody who then tries to reuse the name.

    `delete` rather than `begin_delete`: a vault delete is one of the few
    management calls Azure answers synchronously, so there is no poller to wait
    on and `begin_delete` does not exist on this operations class at all. The
    creates next door are long-running and do have one, which is what made the
    wrong spelling look right. It fails as an AttributeError at the moment of
    deleting rather than as anything the type checker or the offline suite
    could catch, because the stubs modelled the call this code made rather than
    the call the SDK offers.
    """
    group, short = _locate(client, name)

    if not force:
        return False, (
            f"Not deleted. '{short}' holds the keys and secrets other things "
            "depend on, and what breaks when it goes may be something this "
            "tool has never seen. Ask for it explicitly, with the vault's id "
            "repeated back."
        )

    if not group:
        return False, f"No key vault named '{short}' in this subscription."

    client.vaults.delete(group, short)

    return True, (
        f"Deleted key vault '{short}'. Soft delete is mandatory on Azure key "
        "vaults, so it is recoverable and its name stays reserved until the "
        "retention period runs out - and if purge protection was on, nobody "
        "can shorten that. Reusing this name before then will be refused."
    )


def cleanup_all_managed_vaults(client, force=False):
    """Deletes every vault carrying this tool's tag. Returns [(id, ok, msg)].

    Bounded by the tag and not by who ran it, exactly as the AWS cleanup and
    the storage one are: the tag records which tool, not which person. On a
    shared subscription this reaches a colleague's vault as readily as your
    own, and a vault is the worst thing here to lose by accident.
    """
    return [
        (vault["id"],) + delete_vault(client, vault["id"], force=force)
        for vault in list_vaults(client, only_ours=True)
    ]


def apply_fix(client, name, warning):
    """Not offered, and now for one reason rather than two.

    The reason recorded here used to lead with "nothing in `az/` has run
    against a real subscription". That is no longer true, and `az/storage.py`
    fixes three of its findings as of the same run. What is left is the reason
    that was always the stronger of the two: **every fix a vault has is a
    one-way door, and this function takes no confirmation.**

    Purge protection can never be switched off once switched on - it locks the
    vault and its name for the full retention period against everybody
    including an administrator. Moving to role-based authorization revokes
    every existing access policy at the moment it takes effect, and this module
    deliberately does not read who holds those policies, so it cannot tell the
    caller who is about to lose access. Restricting network access can lock out
    whoever pressed the button.

    `POST /fix` carries a rule id and nothing else - no `confirm`, no repeated
    resource name, none of the guards `DELETE` demands before doing something
    irreversible. Offering an irreversible change through the one destructive
    path with no confirmation on it would make the quiet route the dangerous
    one, which is the same objection `az/storage.py`'s delete records. If a
    vault fix is ever wanted, the guard has to come first.
    """
    return False, (
        "Key vault findings are reported rather than fixed. Two of them cannot "
        "be undone once applied - purge protection can never be switched off "
        "again, and moving to role-based access revokes every existing access "
        "policy the moment it takes effect. Make those changes in the portal, "
        "where what you are about to lose is in front of you."
    )
