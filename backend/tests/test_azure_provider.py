"""Tests for the Azure half, registered as resource types.

Two things are being protected, and only one of them is the rules.

The first is that `scanner/common.py`'s warning shape really is
provider-agnostic. It has claimed so since the first commit and nothing tested
it, because every scanner in the package read the same one cloud. These
findings come out of `api/app.py` counted and rendered by code that knows
nothing about Azure, which is the evidence.

The second matters more day to day: **neither half may be a hard requirement of
starting the other.** `api/registry.py` imports every provider module at
startup, so one module-scope SDK import in either half takes the whole page
down - both clouds - over a dependency belonging to one of them.

This used to be asserted by checking that the Azure SDK was absent from the
interpreter running the tests, `.venv` being a machine that lacked it. That
held until somebody installed it, at which point the test failed and proved
nothing, and the obvious reaction to a test failing on your own machine is to
delete it. The property is now shown by blocking each SDK inside a subprocess,
which holds on any machine - and, since `aws/common.py`, in both directions
rather than only the Azure one.

There is no moto for Azure. The reader tests use stubs shaped like the SDK's
own return values rather than a fake service, which is the same approach
`test_alarms.py` takes for the parts of AWS moto models wrongly.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from api import registry
from az import common as az_common
from az import keyvault as az_keyvault
from az import nsg as az_nsg
from az import storage as az_storage
from scanner.azure_keyvault_rules import check_key_vault, check_key_vault_spec
from scanner.azure_nsg_rules import check_nsg, check_nsg_spec
from scanner.azure_storage_rules import check_storage_account, check_storage_spec
from scanner.common import CRITICAL, WARNING, INFO, cited, fixable, summarize

SUBSCRIPTION = "00000000-1111-2222-3333-444444444444"
GROUP = "rg-demo"
NSG_ID = (f"/subscriptions/{SUBSCRIPTION}/resourceGroups/{GROUP}"
          f"/providers/Microsoft.Network/networkSecurityGroups/demo-nsg")


def _rule(**overrides):
    base = {"name": "allow-ssh", "direction": "Inbound", "access": "Allow",
            "protocol": "Tcp", "priority": 100,
            "source_address_prefix": "*", "destination_port_range": "22"}
    base.update(overrides)
    return base


def _nsg(*rules, **overrides):
    base = {
        "nsg_name": "demo-nsg",
        "resource_group": GROUP,
        "location": "eastus",
        "rules": list(rules),
        "attached_to": ["/subscriptions/x/subnets/one"],
    }
    base.update(overrides)
    return base


def _account(**overrides):
    base = {
        "account_name": "demostorage",
        "resource_group": GROUP,
        "location": "eastus",
        "allow_blob_public_access": False,
        "supports_https_traffic_only": True,
        "minimum_tls_version": "TLS1_2",
        "public_network_access": "Disabled",
        "unreadable": {},
    }
    base.update(overrides)
    return base


def _settings_of(warnings):
    return {w["rule"]["setting"] for w in warnings}


def _find(warnings, setting):
    matches = [w for w in warnings if w["rule"]["setting"] == setting]
    assert len(matches) == 1, f"expected one {setting}, got {len(matches)}"
    return matches[0]


# ================================ The AWS half must not need the Azure SDK


BACKEND = Path(__file__).resolve().parent.parent

# Refuses one SDK for the life of a subprocess, so the property can be shown on
# any machine rather than only on one that happens to lack it.
#
# This used to be asserted by checking that the Azure SDK was missing from the
# interpreter running the tests. That worked while nobody had installed it, and
# stopped meaning anything the moment somebody did - at which point the test
# fails, the obvious reaction is to delete it, and the property goes unguarded.
# A test that only holds on some machines is one nobody can trust on theirs.
_BLOCK = """
import sys

class _Block:
    def __init__(self, *names): self.names = names
    def find_spec(self, name, path=None, target=None):
        if name in self.names or any(name.startswith(n + ".") for n in self.names):
            raise ImportError("blocked: " + name)
        return None

sys.meta_path.insert(0, _Block(*{blocked!r}))
"""


def _without(blocked, body):
    """Runs body in a subprocess where the named packages cannot be imported."""
    return subprocess.run(
        [sys.executable, "-c", _BLOCK.format(blocked=tuple(blocked)) + body],
        cwd=BACKEND, capture_output=True, text=True,
        env={**os.environ, "PYTHONPATH": str(BACKEND)},
    )


AZURE_SDK = ["azure"]
AWS_SDK = ["boto3", "botocore"]


@pytest.mark.parametrize("blocked,label", [
    (AZURE_SDK, "the Azure SDK"),
    (AWS_SDK, "boto3"),
    (AZURE_SDK + AWS_SDK, "both SDKs"),
])
def test_the_page_starts_without(blocked, label):
    """Neither cloud's SDK may be a hard requirement of starting the process.

    api/registry.py imports every provider module at startup, so one module
    scope import in either half takes the whole page down - both clouds - over
    a dependency belonging to one of them.
    """
    done = _without(blocked, "import api.app\nprint('ok')\n")
    assert done.returncode == 0, f"the page did not start without {label}:\n{done.stderr}"


@pytest.mark.parametrize("blocked", [AZURE_SDK, AWS_SDK, AZURE_SDK + AWS_SDK])
def test_every_resource_type_is_still_registered_without(blocked):
    """A missing SDK hides no resource type. The tab appears and the route
    answers 503 with a sentence; a type that vanished would look like one this
    tool does not support."""
    done = _without(blocked, "from api import registry\n"
                             "print(len(registry.REGISTRY))\n")
    assert done.returncode == 0, done.stderr
    assert int(done.stdout.strip()) == len(registry.REGISTRY)


@pytest.mark.parametrize("blocked,module,error,call", [
    (AZURE_SDK, "az.nsg", "az.common.AzureNotConfigured", "get_client('eastus')"),
    (AWS_SDK, "aws.security_groups", "aws.common.AwsNotConfigured", "get_client('us-east-1')"),
])
def test_asking_for_an_absent_client_explains_itself(blocked, module, error, call):
    """An ImportError about azure.mgmt.network or botocore reaching a browser
    tells the person using the tool nothing they can act on. Both halves answer
    with the same shape of sentence, naming what to install."""
    package, _, name = error.rpartition(".")
    done = _without(blocked, f"""
import {module} as target
from {package} import {name} as Expected
try:
    target.{call}
    print("NO ERROR")
except Expected as e:
    print("pip install" in str(e))
""")
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == "True", done.stdout


def test_the_azure_modules_import_no_sdk_at_module_scope():
    """The property, asserted directly rather than inferred from the tests
    happening to pass. A module-level import here would stop api/registry.py
    importing, and the AWS half with it."""
    from pathlib import Path

    for name in ("common.py", "nsg.py", "storage.py"):
        source = Path(__file__).parent.parent / "az" / name
        for number, line in enumerate(source.read_text().splitlines(), 1):
            if line.startswith(("import azure", "from azure")):
                raise AssertionError(
                    f"az/{name}:{number} imports the SDK at module scope: {line}")


def test_missing_credentials_are_reported_separately_from_a_missing_sdk(
        monkeypatch):
    """Two different problems with two different fixes. Collapsing them sends
    somebody to pip when the answer is a .env file."""
    for var in ("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"):
        monkeypatch.delenv(var, raising=False)

    with pytest.raises(az_common.AzureNotConfigured) as raised:
        az_common.credential()
    assert "AZURE_TENANT_ID" in str(raised.value)


def test_a_resource_group_is_read_out_of_an_azure_resource_id():
    assert az_common.resource_group_of(NSG_ID) == GROUP
    assert az_common.resource_group_of("just-a-name") is None
    assert az_common.resource_group_of(None) is None


# ========================================= Network security group rules


def test_ssh_open_to_the_whole_internet_is_critical():
    found = _find(check_nsg(_nsg(_rule())), "open_22")
    assert found["level"] == CRITICAL
    assert "allow-ssh" in found["message"]


def test_the_wording_matches_the_aws_side_for_the_same_fact():
    """A port open to everyone is the same fact whoever is hosting it. If the
    two clouds described it differently, one of them would be wrong."""
    from scanner.rules import RISKY_PORTS

    azure = _find(check_nsg(_nsg(_rule())), "open_22")["message"]
    assert RISKY_PORTS[22] in azure


@pytest.mark.parametrize("source", ["*", "0.0.0.0/0", "Internet", "internet",
                                    "::/0"])
def test_every_way_azure_spells_the_whole_internet_is_recognised(source):
    assert "open_22" in _settings_of(
        check_nsg(_nsg(_rule(source_address_prefix=source))))


def test_a_rule_limited_to_one_address_says_nothing():
    assert check_nsg(_nsg(_rule(source_address_prefix="203.0.113.4"))) == []


def test_an_outbound_rule_is_not_an_inbound_one():
    assert check_nsg(_nsg(_rule(direction="Outbound"))) == []


def test_a_deny_rule_is_not_an_allow():
    assert check_nsg(_nsg(_rule(access="Deny"))) == []


def test_rdp_is_reported_as_rdp_and_not_as_ssh():
    found = _find(check_nsg(_nsg(_rule(destination_port_range="3389"))),
                  "open_3389")
    assert "RDP" in found["message"]
    assert "SSH" not in found["message"]


def test_a_port_range_covering_ssh_is_caught():
    """Azure writes ranges as a string. A rule opening 20-30 opens 22, and
    reading only exact matches would miss it."""
    assert "open_22" in _settings_of(
        check_nsg(_nsg(_rule(destination_port_range="20-30"))))


def test_a_range_that_misses_both_admin_ports_says_nothing():
    assert check_nsg(_nsg(_rule(destination_port_range="8000-8100"))) == []


def test_a_malformed_range_is_ignored_rather_than_guessed_at():
    assert check_nsg(_nsg(_rule(destination_port_range="not-a-range"))) == []


def test_opening_every_port_reports_the_named_ones_and_the_fact_itself():
    """Three findings from one rule, deliberately: the two doors this tool can
    name, and the separate fact that every other door is open too."""
    settings = _settings_of(check_nsg(_nsg(_rule(destination_port_range="*"))))
    assert settings == {"open_22", "open_3389", "open_all_ports"}


def test_a_group_attached_to_nothing_is_reported_as_unused():
    found = _find(check_nsg(_nsg(attached_to=[])), "unused")
    assert found["level"] == INFO


def test_a_group_in_use_is_not_reported_as_unused():
    assert "unused" not in _settings_of(check_nsg(_nsg()))


def test_the_scanner_tolerates_a_group_that_is_not_there():
    assert check_nsg(None) == []
    assert check_nsg({}) == []


def test_nothing_about_an_azure_rule_is_offered_as_a_fix():
    """Azure evaluates rules in priority order, so narrowing one without
    reading the rest can be silently undone by another."""
    warnings = check_nsg(_nsg(_rule(destination_port_range="*")))
    assert warnings
    assert fixable(warnings) == []


# ============================================== Storage account rules


def test_a_well_configured_account_produces_nothing():
    assert check_storage_account(_account()) == []


def test_anonymous_blob_access_is_critical():
    found = _find(check_storage_account(
        _account(allow_blob_public_access=True)), "public_blob_access")
    assert found["level"] == CRITICAL


def test_the_azure_default_is_called_out_as_different_from_the_aws_one():
    """AWS has blocked this on new buckets since April 2023, so its rule
    cannot fire on something made today. Azure has no such default, and a
    reader who knows the S3 rule will assume otherwise."""
    found = _find(check_storage_account(
        _account(allow_blob_public_access=True)), "public_blob_access")
    assert "April 2023" in found["message"]


def test_plain_http_is_critical():
    found = _find(check_storage_account(
        _account(supports_https_traffic_only=False)), "http_allowed")
    assert found["level"] == CRITICAL
    assert "access key" in found["message"]


@pytest.mark.parametrize("version", ["TLS1_0", "TLS1_1"])
def test_an_outdated_tls_floor_is_reported(version):
    assert "old_tls" in _settings_of(
        check_storage_account(_account(minimum_tls_version=version)))


@pytest.mark.parametrize("version", ["TLS1_2", "TLS1_3"])
def test_a_current_tls_floor_says_nothing(version):
    assert "old_tls" not in _settings_of(
        check_storage_account(_account(minimum_tls_version=version)))


def test_being_reachable_from_any_network_is_a_note_not_a_fault():
    found = _find(check_storage_account(
        _account(public_network_access="Enabled")), "reachable_from_anywhere")
    assert found["level"] == INFO


def test_a_setting_azure_did_not_report_is_not_scored_as_safe():
    """The same rule s3_rules follows: silence would imply the setting is
    fine, and a finding would assert something never observed."""
    warnings = check_storage_account(_account(
        allow_blob_public_access=None,
        unreadable={"allow_blob_public_access": "Azure did not report it"}))

    assert _find(warnings, "unreadable_allow_blob_public_access")["level"] == WARNING
    assert "public_blob_access" not in _settings_of(warnings)


def test_the_scanner_tolerates_an_account_that_is_not_there():
    assert check_storage_account(None) == []


# ================================== Containers, and the account key
#
# Both ported from the Streamlit frontend's preflight.py. Each asks something
# the account-level settings above do not.


@pytest.mark.parametrize("level", ["Blob", "Container"])
def test_a_container_serving_anonymous_readers_is_critical(level):
    found = _find(
        check_storage_account(_account(containers=[
            {"name": "reports", "public_access": level}])),
        "public_container_reports")
    assert found["level"] == CRITICAL


def test_a_private_container_says_nothing():
    warnings = check_storage_account(_account(containers=[
        {"name": "reports", "public_access": None},
        {"name": "backups", "public_access": "None"}]))
    assert warnings == []


def test_container_level_access_is_reported_separately_from_the_account_switch():
    """The account switch says a container *may* be anonymous; the container's
    own level says one *is*. Somebody who turned the switch on months ago needs
    the second answer to know what it is currently exposing."""
    warnings = check_storage_account(_account(
        allow_blob_public_access=True,
        containers=[{"name": "reports", "public_access": "Container"}]))

    assert {"public_blob_access", "public_container_reports"} <= _settings_of(warnings)


def test_listing_the_whole_container_is_called_out_as_worse_than_reading_one():
    listable = _find(check_storage_account(_account(containers=[
        {"name": "reports", "public_access": "Container"}])),
        "public_container_reports")
    blobs_only = _find(check_storage_account(_account(containers=[
        {"name": "reports", "public_access": "Blob"}])),
        "public_container_reports")

    assert "list everything" in listable["message"]
    assert "list everything" not in blobs_only["message"]


def test_containers_that_could_not_be_listed_are_not_scored_as_private():
    """The same rule the account settings follow. An empty container list and
    a container list the login could not read look identical, and one of them
    is the most dangerous possible way to be wrong."""
    warnings = check_storage_account(_account(
        containers=[], unreadable={"containers": "the login could not list them"}))

    assert _find(warnings, "unreadable_containers")["level"] == WARNING


def test_an_account_still_accepting_its_key_is_a_warning():
    found = _find(check_storage_account(_account(allow_shared_key_access=True)),
                  "shared_key_allowed")
    assert found["level"] == WARNING
    assert "never expires" in found["message"]


def test_an_account_requiring_entra_id_says_nothing():
    assert "shared_key_allowed" not in _settings_of(
        check_storage_account(_account(allow_shared_key_access=False)))


# ==================================== Reading those two off the SDK
#
# Stubs shaped like the SDK's return values, for the same reason the rest of
# this file uses them: there is no moto for Azure, and the parts worth testing
# here are how absent values are resolved rather than how the wire looks.

STORAGE_ID = (f"/subscriptions/{SUBSCRIPTION}/resourceGroups/{GROUP}"
              f"/providers/Microsoft.Storage/storageAccounts/demostorage")


class _Fields:
    def __init__(self, **fields):
        self.__dict__.update(fields)


class _StubAccounts:
    def __init__(self, account):
        self._account = account

    def get_properties(self, group, name):
        return self._account


class _StubContainers:
    def __init__(self, containers, error=None):
        self._containers = containers
        self._error = error

    def list(self, group, name):
        if self._error:
            raise self._error
        return self._containers


class _StubStorageClient:
    def __init__(self, account=None, containers=(), container_error=None):
        self.storage_accounts = _StubAccounts(account or _Fields(
            name="demostorage", id=STORAGE_ID, location="eastus"))
        self.blob_containers = _StubContainers(list(containers),
                                               container_error)


def test_an_unset_shared_key_setting_is_read_as_permitted():
    """Azure documents null as equivalent to true here. Treating it as
    unreadable instead would put an unchecked-setting warning on the commonest
    case, in front of the findings that matter."""
    settings = az_storage.read_account_for_scanning(
        _StubStorageClient(), STORAGE_ID)

    assert settings["allow_shared_key_access"] is True
    assert "allow_shared_key_access" not in settings["unreadable"]


def test_shared_key_turned_off_is_read_as_such():
    client = _StubStorageClient(account=_Fields(
        name="demostorage", id=STORAGE_ID, location="eastus",
        allow_shared_key_access=False))

    assert az_storage.read_account_for_scanning(
        client, STORAGE_ID)["allow_shared_key_access"] is False


def test_containers_are_read_with_their_access_level():
    client = _StubStorageClient(containers=[
        _Fields(name="reports", public_access="Container"),
        _Fields(name="private", public_access=None)])

    settings = az_storage.read_account_for_scanning(client, STORAGE_ID)

    assert settings["containers"] == [
        {"name": "reports", "public_access": "Container"},
        {"name": "private", "public_access": None},
    ]


def test_an_unset_public_network_access_is_read_as_enabled():
    """Found against a real subscription, not here.

    Azure only populates publicNetworkAccess once somebody sets it, so an
    account that has never had its network access restricted returns None -
    and the rule reads None as "say nothing". Two real accounts, both
    reachable from any network, both scored clean. Absent is not restricted;
    the documented default is Enabled.
    """
    client = _StubStorageClient()   # an account with the attribute absent

    settings = az_storage.read_account_for_scanning(client, STORAGE_ID)

    assert settings["public_network_access"] == "Enabled"
    assert "reachable_from_anywhere" in _settings_of(
        check_storage_account(settings))


def test_a_restricted_account_is_still_read_as_restricted():
    """The fix must not turn every account into a finding."""
    client = _StubStorageClient(account=_Fields(
        name="demostorage", id=STORAGE_ID, location="eastus",
        public_network_access="Disabled"))

    settings = az_storage.read_account_for_scanning(client, STORAGE_ID)

    assert settings["public_network_access"] == "Disabled"
    assert "reachable_from_anywhere" not in _settings_of(
        check_storage_account(settings))


def test_a_login_that_cannot_list_containers_says_so():
    """An empty list would be read as "no public containers", which is
    indistinguishable from a clean result and is the wrong way to be wrong."""
    client = _StubStorageClient(container_error=PermissionError("denied"))

    settings = az_storage.read_account_for_scanning(client, STORAGE_ID)

    assert settings["containers"] == []
    assert "containers" in settings["unreadable"]
    assert "could not list" in settings["unreadable"]["containers"]


# ================================================ Before anything exists


def test_a_form_with_an_open_rule_is_flagged_before_creation():
    found = check_nsg_spec({"name": "demo", "azure_rules": [_rule()]})
    assert "open_22" in _settings_of(found)


def test_a_form_is_not_told_its_unbuilt_group_is_unused():
    assert "unused" not in _settings_of(
        check_nsg_spec({"name": "demo", "azure_rules": [
            _rule(source_address_prefix="10.0.0.1")]}))


def test_an_insecure_storage_form_is_flagged_before_creation():
    warnings = check_storage_spec({"name": "demo", "secure_by_default": False})
    assert {"public_blob_access", "http_allowed"} <= _settings_of(warnings)


def test_a_secure_storage_form_still_reports_azures_own_defaults():
    """Not silent, and correctly so. An account created with every setting
    this tool would choose is still reachable from any network and still
    accepts its account key, because both are Azure's defaults rather than
    something the form decides. Saying so before creation is the point of
    scanning a form at all."""
    warnings = check_storage_spec({"name": "demo", "secure_by_default": True})

    assert _settings_of(warnings) == {"reachable_from_anywhere",
                                      "shared_key_allowed"}
    assert summarize(warnings)["critical"] == 0


# ============================================== Creating and deleting storage
#
# There is no moto for Azure, so these drive a stub shaped like
# StorageManagementClient that records what it was asked to do. That is the
# same approach test_alarms.py takes for the parts of AWS moto models wrongly,
# and it has the same limit: it proves this module asks for the right things,
# not that Azure does them. Only a live subscription can show the second.
#
# A second stub rather than an extension of _StubStorageClient above, because
# the two model different slices of one SDK object and are built from different
# things. That one is handed the account it should return and is asked to read;
# this one is handed nothing, asked to create, and examined afterwards for what
# it was told to build. One class serving both would need two constructors
# sharing no arguments.


class _StubAccount:
    def __init__(self, name, group=GROUP, tags=None, location="eastus"):
        self.name = name
        self.location = location
        self.tags = tags
        self.id = (f"/subscriptions/{SUBSCRIPTION}/resourceGroups/{group}"
                   f"/providers/Microsoft.Storage/storageAccounts/{name}")


class _StubPoller:
    def __init__(self, value):
        self._value = value

    def result(self):
        return self._value


class _NameAnswer:
    def __init__(self, available, message=None):
        self.name_available = available
        self.message = message


class _StubProvisioningClient:
    """The slice of StorageManagementClient that az/storage.py touches."""

    def __init__(self, accounts=(), name_available=True):
        self.accounts = list(accounts)
        self._name_available = name_available
        self.created = []
        self.deleted = []
        self.storage_accounts = self

    def list(self):
        return list(self.accounts)

    def check_name_availability(self, parameters):
        if self._name_available:
            return _NameAnswer(True)
        return _NameAnswer(
            False, f"The name '{parameters['name']}' is already taken.")

    def begin_create(self, group, name, parameters):
        self.created.append((group, name, parameters))
        made = _StubAccount(name, group=group, tags=parameters.get("tags"))
        self.accounts.append(made)
        return _StubPoller(made)

    def delete(self, group, name):
        self.deleted.append((group, name))
        self.accounts = [a for a in self.accounts if a.name != name]


@pytest.fixture
def group_exists(monkeypatch):
    """The resource group is already there.

    Its own behaviour needs the resource client, which needs the SDK this
    environment deliberately does not have. Tested separately below by
    replacing it outright rather than by reaching for a subscription.
    """
    monkeypatch.setattr(az_storage, "ensure_resource_group",
                        lambda name, location: (False, None))


def test_a_created_account_carries_the_tag_that_makes_cleanup_possible(
        group_exists):
    client = _StubProvisioningClient()
    ok, resource_id, _ = az_storage.create_account(client, "demo", GROUP)

    assert ok
    assert resource_id.endswith("/storageAccounts/demo")
    _, _, parameters = client.created[0]
    assert parameters["tags"] == az_common.managed_tags()


def test_every_setting_the_scanner_reads_is_stated_rather_than_defaulted(
        group_exists):
    """The lesson assign_public_ip taught on the AWS side: an absent setting
    is not a safe setting, it is the platform's setting."""
    client = _StubProvisioningClient()
    az_storage.create_account(client, "demo", GROUP)

    built = client.created[0][2]["properties"]
    assert set(built) == {"allowBlobPublicAccess", "supportsHttpsTrafficOnly",
                          "minimumTlsVersion"}
    assert built["allowBlobPublicAccess"] is False
    assert built["supportsHttpsTrafficOnly"] is True
    assert built["minimumTlsVersion"] == "TLS1_2"


@pytest.mark.parametrize("secure", [True, False])
def test_the_findings_after_creation_are_the_ones_the_form_scan_promised(
        group_exists, secure):
    """The contract _bucket_check_spec states for S3, asserted across the
    cloud boundary: what create builds is what check_spec said it would, so
    the warnings shown before creation are the ones shown after it.

    This is why there is one secure_by_default switch here and not a field per
    setting. group/main's form offered a TLS dropdown beside a scanner with no
    TLS rule, and could therefore build a TLS 1.0 account and call it clean.

    Two of the settings the reader returns are not the form's to decide, and
    they are written here as the account would actually read the moment it
    exists rather than left out. A brand new account has no containers, and
    Azure permits the account key unless somebody turns it off - which
    create_account deliberately does not do, for the reason check_storage_spec
    already gives about it. Omitting them would make this test agree by not
    asking, which is the one way it could pass while the property it exists for
    was false.
    """
    client = _StubProvisioningClient()
    az_storage.create_account(client, "demo", GROUP, secure_by_default=secure)
    built = client.created[0][2]["properties"]

    after = check_storage_account({
        "account_name": "demo",
        "allow_blob_public_access": built["allowBlobPublicAccess"],
        "supports_https_traffic_only": built["supportsHttpsTrafficOnly"],
        "minimum_tls_version": built["minimumTlsVersion"],
        "public_network_access": "Enabled",
        "allow_shared_key_access": built.get("allowSharedKeyAccess", True),
        "containers": [],
        "unreadable": {},
    })
    before = check_storage_spec({"name": "demo", "secure_by_default": secure})

    assert _settings_of(after) == _settings_of(before)


def test_an_existing_account_name_is_refused_rather_than_overwritten(
        group_exists):
    """begin_create on a name you already own updates that account instead of
    failing, so try-it-and-catch would rewrite a live account's settings and
    report success."""
    client = _StubProvisioningClient(name_available=False)
    ok, message, _ = az_storage.create_account(client, "demo", GROUP)

    assert ok is False
    assert client.created == []
    assert "already taken" in message


def test_a_resource_group_that_had_to_be_created_is_reported_not_hidden(
        monkeypatch):
    """A second resource coming into existence is not a failure, and it is not
    nothing either. problems is the channel the create route already has."""
    monkeypatch.setattr(az_storage, "ensure_resource_group",
                        lambda name, location: (True, f"made {name}"))
    client = _StubProvisioningClient()
    ok, _, problems = az_storage.create_account(client, "demo", GROUP)

    assert ok
    assert problems == [f"made {GROUP}"]


def test_deleting_an_account_refuses_without_force():
    """S3 gives an unforced delete a safe failure - a bucket with anything in
    it refuses. Azure's delete succeeds on a full account and takes every blob
    with it, so the explicit ask is the only thing standing there."""
    client = _StubProvisioningClient([_StubAccount("demo")])
    ok, message = az_storage.delete_account(client, "demo")

    assert ok is False
    assert client.deleted == []
    assert "every container and blob" in message


def test_a_forced_delete_names_the_group_from_the_resource_id():
    client = _StubProvisioningClient([_StubAccount("demo")])
    ok, message = az_storage.delete_account(
        client, client.accounts[0].id, force=True)

    assert ok
    assert client.deleted == [(GROUP, "demo")]


def test_cleanup_reaches_only_what_this_tool_tagged():
    """The bound that makes a cleanup endpoint defensible at all."""
    client = _StubProvisioningClient([
        _StubAccount("ours", tags=az_common.managed_tags()),
        _StubAccount("someone-elses", tags={"Name": "production"}),
        _StubAccount("untagged", tags=None),
    ])

    results = az_storage.cleanup_all_managed_accounts(client, force=True)

    assert [name for _, name in client.deleted] == ["ours"]
    assert len(results) == 1


def test_the_only_ours_filter_means_something_now():
    """It was accepted and ignored while nothing here created anything."""
    client = _StubProvisioningClient([
        _StubAccount("ours", tags=az_common.managed_tags()),
        _StubAccount("theirs", tags=None),
    ])

    assert [a["name"] for a in az_storage.list_accounts(client)] == [
        "ours", "theirs"]
    assert [a["name"] for a in
            az_storage.list_accounts(client, only_ours=True)] == ["ours"]


# ============================================================== Key vaults
#
# The third Azure type, and the first whose danger is destruction rather than
# exposure. Same stub approach, same limit: this proves the module asks Azure
# for the right things and cannot prove Azure does them.


class _StubVault:
    def __init__(self, name, group=GROUP, tags=None, location="eastus",
                 **properties):
        self.name = name
        self.location = location
        self.tags = tags
        self.id = (f"/subscriptions/{SUBSCRIPTION}/resourceGroups/{group}"
                   f"/providers/Microsoft.KeyVault/vaults/{name}")
        base = {
            "enable_soft_delete": True,
            "enable_purge_protection": True,
            "enable_rbac_authorization": True,
            "soft_delete_retention_in_days": 90,
            "access_policies": [],
            "public_network_access": "Disabled",
            "network_acls": None,
        }
        base.update(properties)
        self.properties = _Fields(**base)


class _StubVaultClient:
    """The slice of KeyVaultManagementClient that az/keyvault.py touches."""

    def __init__(self, vaults=(), name_available=True):
        self.vault_list = list(vaults)
        self._name_available = name_available
        self.created = []
        self.deleted = []
        self.vaults = self

    def list_by_subscription(self):
        return list(self.vault_list)

    def get(self, group, name):
        for vault in self.vault_list:
            if vault.name == name:
                return vault
        raise _NotFound()

    def check_name_availability(self, parameters):
        if self._name_available:
            return _NameAnswer(True)
        return _NameAnswer(
            False, f"The vault named '{parameters['name']}' is in a soft "
                   "deleted state.")

    def begin_create_or_update(self, group, name, parameters):
        self.created.append((group, name, parameters))
        made = _StubVault(name, group=group, tags=parameters.get("tags"))
        self.vault_list.append(made)
        return _StubPoller(made)

    def begin_delete(self, group, name):
        self.deleted.append((group, name))
        self.vault_list = [v for v in self.vault_list if v.name != name]
        return _StubWaiter()


class _NotFound(Exception):
    status_code = 404


class _StubWaiter:
    def wait(self):
        return None


@pytest.fixture
def vault_group_exists(monkeypatch):
    monkeypatch.setattr(az_keyvault, "ensure_resource_group",
                        lambda name, location: (False, None))
    monkeypatch.setattr(az_keyvault, "tenant_id", lambda: "a-tenant")


def test_a_created_vault_carries_the_tag_and_names_its_tenant(
        vault_group_exists):
    """The tenant is the one thing a vault needs that storage does not. A vault
    built against the wrong one is unopenable by everybody including whoever
    made it."""
    client = _StubVaultClient()
    ok, resource_id, _ = az_keyvault.create_vault(client, "demo", GROUP)

    assert ok
    assert resource_id.endswith("/vaults/demo")
    _, _, parameters = client.created[0]
    assert parameters["tags"] == az_common.managed_tags()
    assert parameters["properties"]["tenant_id"] == "a-tenant"


def test_soft_delete_is_stated_as_on_whichever_way_the_switch_is_set(
        vault_group_exists):
    """Azure made recoverable deletion mandatory in 2020 and refuses a vault
    without it, so the deliberately weak option cannot weaken this and does not
    pretend to. The value is still stated rather than left to the platform."""
    for secure in (True, False):
        client = _StubVaultClient()
        az_keyvault.create_vault(client, "demo", GROUP,
                                 secure_by_default=secure)
        assert client.created[0][2]["properties"]["enable_soft_delete"] is True


def test_purge_protection_off_is_sent_as_absent_not_as_false(
        vault_group_exists):
    """The API rejects an explicit false: once enabled it can never be
    disabled, so Azure models "not on" as absent. The one setting this module
    cannot state outright, and Azure's constraint rather than a choice here."""
    client = _StubVaultClient()
    az_keyvault.create_vault(client, "demo", GROUP, secure_by_default=False)

    assert client.created[0][2]["properties"]["enable_purge_protection"] is None


def test_creating_a_secure_vault_warns_that_it_cannot_be_fully_removed(
        vault_group_exists):
    """Purge protection is a one-way door, and the name stays reserved for 90
    days after any delete. Somebody creating one on a shared subscription
    should learn that from the create rather than from the delete."""
    client = _StubVaultClient()
    ok, _, problems = az_keyvault.create_vault(client, "demo", GROUP)

    assert ok
    assert any("90 days" in p for p in problems)


def test_a_vault_name_still_held_by_a_deleted_vault_is_refused(
        vault_group_exists):
    """Soft delete keeps the name. "Already taken" here routinely means "you
    deleted it last week", and a caller only told the create failed will try
    the same name again."""
    client = _StubVaultClient(name_available=False)
    ok, message, _ = az_keyvault.create_vault(client, "demo", GROUP)

    assert ok is False
    assert client.created == []
    assert "soft deleted" in message


def test_deleting_a_vault_refuses_without_force():
    client = _StubVaultClient([_StubVault("demo")])
    ok, message = az_keyvault.delete_vault(client, "demo")

    assert ok is False
    assert client.deleted == []


def test_a_forced_delete_says_the_name_stays_reserved():
    """"Deleted" on its own would be true and would mislead somebody who then
    tries to reuse the name."""
    client = _StubVaultClient([_StubVault("demo")])
    ok, message = az_keyvault.delete_vault(
        client, client.vault_list[0].id, force=True)

    assert ok
    assert client.deleted == [(GROUP, "demo")]
    assert "name stays reserved" in message


def test_vault_cleanup_reaches_only_what_this_tool_tagged():
    client = _StubVaultClient([
        _StubVault("ours", tags=az_common.managed_tags()),
        _StubVault("theirs", tags={"Name": "production"}),
    ])

    az_keyvault.cleanup_all_managed_vaults(client, force=True)

    assert [name for _, name in client.deleted] == ["ours"]


def test_a_vault_without_recoverable_deletion_is_critical():
    warnings = check_key_vault({
        "vault_name": "demo", "soft_delete_enabled": False,
        "purge_protection_enabled": True, "rbac_authorization": True,
        "access_policy_count": 0, "unreadable": {},
    })

    assert _find(warnings, "no_soft_delete")["level"] == CRITICAL


def test_access_granted_by_the_vaults_own_list_is_reported_as_invisible():
    """The finding this rule set exists for. scanner/role_rules.py can read an
    identity's entire permission set and still not know it can open this
    vault."""
    warnings = check_key_vault({
        "vault_name": "demo", "soft_delete_enabled": True,
        "purge_protection_enabled": True, "rbac_authorization": False,
        "access_policy_count": 3, "unreadable": {},
    })

    found = _find(warnings, "access_policies_not_roles")
    assert found["level"] == WARNING
    assert "3 identities hold" in found["message"]


def test_an_empty_access_list_is_a_note_rather_than_a_finding():
    warnings = check_key_vault({
        "vault_name": "demo", "soft_delete_enabled": True,
        "purge_protection_enabled": True, "rbac_authorization": False,
        "access_policy_count": 0, "unreadable": {},
    })

    assert _find(warnings, "access_policies_empty")["level"] == INFO


def test_a_setting_azure_did_not_report_on_a_vault_is_not_scored_as_safe():
    warnings = check_key_vault({
        "vault_name": "demo", "soft_delete_enabled": None,
        "purge_protection_enabled": True, "rbac_authorization": True,
        "access_policy_count": 0,
        "unreadable": {"soft_delete_enabled": "Azure did not report it"},
    })

    assert "unreadable_soft_delete_enabled" in _settings_of(warnings)
    assert "no_soft_delete" not in _settings_of(warnings)


def test_nothing_in_the_key_vault_rules_claims_a_cis_control():
    """CIS AWS Foundations is an AWS benchmark. The Azure one is a separate
    document nobody here has read."""
    warnings = check_key_vault({
        "vault_name": "demo", "soft_delete_enabled": False,
        "purge_protection_enabled": False, "rbac_authorization": False,
        "access_policy_count": 2, "public_network_access": "Enabled",
        "unreadable": {},
    })

    assert warnings
    assert cited(warnings) == []


def test_a_secure_vault_form_raises_nothing_worse_than_a_note():
    warnings = check_key_vault_spec({"name": "demo", "secure_by_default": True})

    assert summarize(warnings)["critical"] == 0
    assert summarize(warnings)["warning"] == 0


def test_an_insecure_vault_form_is_flagged_before_creation():
    warnings = check_key_vault_spec({"name": "demo",
                                     "secure_by_default": False})

    assert "no_purge_protection" in _settings_of(warnings)


@pytest.mark.parametrize("secure", [True, False])
def test_a_vault_reads_back_as_the_form_scan_promised(vault_group_exists,
                                                      secure):
    """The same parity contract storage holds to, across the third type."""
    client = _StubVaultClient()
    az_keyvault.create_vault(client, "demo", GROUP, secure_by_default=secure)
    built = client.created[0][2]["properties"]

    after = check_key_vault({
        "vault_name": "demo",
        "soft_delete_enabled": built["enable_soft_delete"],
        "purge_protection_enabled": built["enable_purge_protection"] is True,
        "rbac_authorization": built["enable_rbac_authorization"],
        "soft_delete_retention_days": built["soft_delete_retention_in_days"],
        "access_policy_count": 0,
        "public_network_access": "Enabled",
        "unreadable": {},
    })
    before = check_key_vault_spec({"name": "demo", "secure_by_default": secure})

    assert _settings_of(after) == _settings_of(before)


# ====================================== Through the registry and the routes


@pytest.fixture
def api():
    from fastapi.testclient import TestClient
    from api.app import app

    return TestClient(app, base_url="http://127.0.0.1:8000")


def test_azure_types_are_advertised_alongside_the_aws_ones(api):
    keys = {r["key"] for r in api.get("/resources").json()["resources"]}
    assert {"azure-nsg", "azure-storage"} <= keys


def test_azure_firewalls_are_audited_not_provisioned():
    """A rule's priority decides which of several overlapping rules wins, so
    neither creating one nor fixing one can be judged without reading the whole
    ordered set. Until that exists, this stays read-only."""
    assert registry.AZURE_NSG.read_only is True


def test_azure_storage_is_provisioned_like_any_aws_type():
    """The first cross-cloud create. Nothing in api/app.py changed to allow
    it: read_only going false is what opens the four routes."""
    assert registry.AZURE_STORAGE.read_only is False
    assert registry.AZURE_STORAGE.create is not registry._cannot_create
    assert registry.AZURE_STORAGE.delete is not registry._cannot_create
    assert registry.AZURE_STORAGE.cleanup is not registry._cannot_create


def test_creating_azure_storage_without_a_resource_group_is_refused():
    """A missing resource group is an Azure-only problem, so the refusal is in
    the adapter rather than the model eight AWS types also use."""
    ok, message, _ = registry.AZURE_STORAGE.create(None, {"name": "demo"})

    assert ok is False
    assert "resource group" in message


def test_an_azure_finding_is_counted_by_code_that_knows_nothing_about_azure(api):
    """The claim scanner/common.py has made since the first commit, finally
    with evidence: this response was assembled, counted and shaped by
    api/app.py, which has no idea which cloud it just described."""
    body = api.post("/resources/azure-nsg/check", json={
        "name": "demo",
        "azure_rules": [{"name": "allow-ssh", "direction": "Inbound",
                         "access": "Allow", "source_address_prefix": "*",
                         "destination_port_range": "22"}],
    }).json()

    assert body["counts"]["critical"] == 1
    assert body["fixable_count"] == 0
    assert body["warnings"][0]["level"] == "critical"


def test_an_unconfigured_azure_is_a_503_that_says_what_to_install(api):
    """Not a 500. Nothing is broken - this deployment simply has no Azure
    dependencies, which is the ordinary state of the AWS half."""
    resp = api.get("/resources/azure-nsg")
    assert resp.status_code == 503
    assert resp.json()["provider"] == "azure"


def test_the_aws_routes_still_work_while_azure_is_unconfigured(api):
    """The property that matters most. One provider being unavailable must
    not take the other down with it."""
    assert api.get("/health").json() == {"status": "ok"}
    assert api.post("/resources/security-group/check", json={
        "name": "safe",
        "rules": [{"protocol": "tcp", "from_port": 22, "to_port": 22,
                   "source": "203.0.113.4/32"}],
    }).status_code == 200


def test_azure_firewalls_cannot_be_created_deleted_or_cleaned_up(api):
    assert api.post("/resources/azure-nsg", json={"name": "x"}).status_code == 405
    assert api.delete("/resources/azure-nsg/x").status_code == 405
    assert api.post("/resources/azure-nsg/cleanup").status_code == 405


def test_storage_now_fails_at_the_sdk_rather_than_at_the_route(api):
    """It used to be 405: audited, not provisioned. The destructive routes are
    open to it now, so the first thing missing is the SDK - which is a 503
    saying what to install rather than a refusal about what the tool does.
    Two different answers to two different questions, and the change from one
    to the other is the whole of this work seen from outside.
    """
    resp = api.delete("/resources/azure-storage/x")

    assert resp.status_code == 503
    assert resp.json()["provider"] == "azure"


def test_nothing_in_the_azure_rules_claims_a_cis_control():
    """CIS AWS Foundations is an AWS benchmark. Citing it against an Azure
    resource would be borrowing authority that does not extend there; the CIS
    Microsoft Azure Foundations Benchmark is a separate document nobody here
    has read."""
    warnings = check_nsg(_nsg(_rule(destination_port_range="*")))
    warnings += check_storage_account(_account(allow_blob_public_access=True,
                                               supports_https_traffic_only=False))
    assert warnings
    assert cited(warnings) == []
