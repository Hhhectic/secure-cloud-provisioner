"""Tests for the Azure half, registered as resource types.

Two things are being protected, and only one of them is the rules.

The first is that `scanner/common.py`'s warning shape really is
provider-agnostic. It has claimed so since the first commit and nothing tested
it, because every scanner in the package read the same one cloud. These
findings come out of `api/app.py` counted and rendered by code that knows
nothing about Azure, which is the evidence.

The second matters more day to day: **the AWS half must start on a machine with
no Azure SDK installed.** `.venv` is exactly such a machine, so every test here
runs in that condition. If somebody later moves an Azure import to module scope
in `az/`, `api/registry.py` stops importing and the whole AWS half goes with
it - the precise failure recorded against mounting the two applications into
one process.

There is no moto for Azure. The reader tests use stubs shaped like the SDK's
own return values rather than a fake service, which is the same approach
`test_alarms.py` takes for the parts of AWS moto models wrongly.
"""

import pytest

from api import registry
from az import common as az_common
from az import nsg as az_nsg
from az import storage as az_storage
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


def test_the_azure_sdk_is_genuinely_absent_here():
    """Every claim below rests on this. If the SDK were installed the tests
    would pass without proving the property they exist for."""
    with pytest.raises(ImportError):
        __import__("azure.mgmt.network")


def test_the_registry_imports_without_the_azure_sdk():
    assert "azure-nsg" in registry.REGISTRY
    assert "azure-storage" in registry.REGISTRY


def test_asking_azure_for_a_client_explains_itself_rather_than_raising_import():
    """An ImportError about azure.mgmt.network reaching a browser tells the
    person using the tool nothing they can act on."""
    with pytest.raises(az_common.AzureNotConfigured) as raised:
        az_nsg.get_client("us-east-1")
    assert "pip install" in str(raised.value)


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


# ====================================== Through the registry and the routes


@pytest.fixture
def api():
    from fastapi.testclient import TestClient
    from api.app import app

    return TestClient(app, base_url="http://127.0.0.1:8000")


def test_azure_types_are_advertised_alongside_the_aws_ones(api):
    keys = {r["key"] for r in api.get("/resources").json()["resources"]}
    assert {"azure-nsg", "azure-storage"} <= keys


def test_azure_types_are_audited_not_provisioned():
    assert registry.AZURE_NSG.read_only is True
    assert registry.AZURE_STORAGE.read_only is True


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


def test_azure_cannot_be_created_deleted_or_cleaned_up(api):
    assert api.post("/resources/azure-nsg", json={"name": "x"}).status_code == 405
    assert api.delete("/resources/azure-storage/x").status_code == 405
    assert api.post("/resources/azure-nsg/cleanup").status_code == 405


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
