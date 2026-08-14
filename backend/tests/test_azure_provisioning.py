"""Tests for the Azure capabilities that used to live outside `backend/`.

Network security group creation, virtual networks and virtual machines were in
the root `azure_crud.py` and in `archive/streamlit-gui/`, reachable only from a
separate process or a page nobody runs. This file covers them where they live
now, plus the two things that made the first of them possible: the priority
evaluator in `scanner/azure_nsg_effective.py`, and the name rules in
`az/names.py`.

Stubs shaped like the SDK's return values, for the reason the rest of the Azure
tests use them: there is no moto for Azure. Where a stub models something Azure
does that the code got wrong, it says so - that is the lesson of
`_StubVaultClient`, which had grown a `begin_delete` because the code called
one and so could never have shown that no such method exists.
"""

import pytest

from azure.core.exceptions import HttpResponseError

from api import registry
from az import names as az_names
from az import nsg as az_nsg
from az import vnet as az_vnet
from az import common as az_common
from az.common import AzureRefused
from az import storage as az_storage_mod
from az import keyvault as az_keyvault_mod
from az import vm as az_vm
from scanner import azure_nsg_effective as effective
from scanner.azure_nsg_rules import check_nsg
from scanner.azure_storage_rules import check_storage_account
from scanner.azure_vnet_rules import check_vnet, check_vnet_spec
from scanner.azure_vm_rules import check_vm, check_vm_spec
from scanner.common import CRITICAL, WARNING, INFO, fixable, summarize

SUBSCRIPTION = "00000000-1111-2222-3333-444444444444"
GROUP = "rg-demo"


def _settings_of(warnings):
    return {w["rule"]["setting"] for w in warnings}


def _rule(name="allow-ssh", priority=100, access="Allow", source="*",
          ports="22", direction="Inbound", protocol="Tcp"):
    return {"name": name, "priority": priority, "access": access,
            "source_address_prefix": source, "destination_port_range": ports,
            "direction": direction, "protocol": protocol}


# ======================================================== Which rule wins
#
# The sentence that kept az/nsg.py read-only, and the root Azure app alive with
# it: a rule's priority decides which of several overlapping rules wins, so
# neither creating one nor fixing one can be judged without reading the whole
# ordered set.


def test_the_lower_priority_number_decides():
    allow = _rule("allow", priority=100)
    deny = _rule("deny", priority=200, access="Deny")

    assert effective.decide([allow, deny], "22")[0] == "Allow"
    assert effective.decide([_rule("allow", priority=200),
                             _rule("deny", priority=100, access="Deny")],
                            "22")[0] == "Deny"


def test_the_same_two_rules_in_two_orders_are_two_different_firewalls():
    """The whole argument for this module in one assertion. A per-rule scanner
    calls both of these critical, and one of them is closed."""
    open_set = [_rule("allow", priority=100),
                _rule("deny", priority=200, access="Deny")]
    closed_set = [_rule("allow", priority=200),
                  _rule("deny", priority=100, access="Deny")]

    assert summarize(check_nsg(_nsg(open_set)))[CRITICAL] == 1
    assert summarize(check_nsg(_nsg(closed_set)))[CRITICAL] == 0


def test_a_shadowed_rule_is_reported_as_worth_knowing_rather_than_silenced():
    """Not reported as critical, and not dropped either. It is one priority
    change away from being live, and somebody reading the group should be able
    to see it without diffing the rule list themselves."""
    warnings = check_nsg(_nsg([_rule("allow", priority=200),
                               _rule("deny", priority=100, access="Deny")]))

    assert "shadowed_open_22" in _settings_of(warnings)
    assert all(w["level"] != CRITICAL for w in warnings)


def test_nothing_matching_falls_through_to_azures_own_final_deny():
    """A group with no rules allows nothing inbound from outside, which is why
    a new one is safe and useless."""
    assert effective.decide([], "22")[0] == "DenyByDefault"


def test_a_rule_for_other_addresses_does_not_decide_this_packet():
    """It is not evidence of safety either - it simply is not this packet's
    rule, so the default deny is what answers."""
    decision, _ = effective.decide([_rule("office", source="203.0.113.0/24")],
                                   "22")
    assert decision == "DenyByDefault"


def test_a_rule_for_another_protocol_does_not_open_the_port():
    """UDP on 22 is not SSH."""
    assert effective.decide([_rule(protocol="Udp")], "22")[0] == "DenyByDefault"
    assert effective.decide([_rule(protocol="*")], "22")[0] == "Allow"


def test_an_outbound_rule_is_not_an_inbound_one():
    assert effective.decide([_rule(direction="Outbound")],
                            "22")[0] == "DenyByDefault"


def test_a_port_range_covers_what_is_inside_it():
    assert effective.decide([_rule(ports="20-30")], "22")[0] == "Allow"
    assert effective.decide([_rule(ports="30-40")], "22")[0] == "DenyByDefault"
    assert effective.decide([_rule(ports="*")], "22")[0] == "Allow"


def test_an_unreadable_priority_sorts_last_rather_than_first():
    """A rule whose priority cannot be read must not be able to shadow
    everything behind it, which is what a default of zero would do."""
    rules = [_rule("broken", priority=None, access="Deny"),
             _rule("allow", priority=100)]

    assert effective.decide(rules, "22")[0] == "Allow"


def _nsg(rules, **overrides):
    base = {"nsg_name": "demo-nsg", "resource_group": GROUP,
            "location": "eastus", "rules": list(rules),
            "attached_to": ["/subscriptions/x/subnets/one"]}
    base.update(overrides)
    return base


# ============================================================ Name rules


@pytest.mark.parametrize("kind,name,ok", [
    ("azure-storage", "scpdemo123", True),
    ("azure-storage", "SCPdemo", False),          # capitals
    ("azure-storage", "scp-demo", False),         # hyphen
    ("azure-storage", "ab", False),               # too short
    ("azure-keyvault", "scp-demo", True),
    ("azure-keyvault", "1scp", False),            # must start with a letter
    ("azure-keyvault", "scp-", False),            # must not end with a hyphen
    ("azure-vm", "scp-vm-1", True),
    ("azure-vm", "scp vm", False),                # spaces
    ("resource-group", "scp-demo", True),
    ("resource-group", "scp-demo.", False),       # trailing period
    ("container", "my-container", True),
    ("container", "my--container", False),        # doubled hyphen

    # Both of these were wrong, and both were measured against a real
    # subscription rather than read off a document.
    #
    # A vault name may not carry doubled hyphens either, and only the
    # container half of that rule was written down. Azure answers
    # check_name_availability for 'scp-edge--probe' with available=False,
    # reason=Invalid - so the refusal still arrived, just from Azure, after a
    # round trip, in the same words it uses for a name somebody else already
    # owns.
    ("azure-keyvault", "scp--demo", False),

    # And a one-character security group name is legal. The pattern needed a
    # first character and a last one, so it refused every one-character name
    # while its own message promised "1 to 80 characters" - an error naming
    # the rule the name had just satisfied. Verified by creating a group
    # called "a" against a real subscription, and deleting it.
    ("azure-nsg", "a", True),
    ("azure-nsg", "ab", True),
    ("azure-nsg", "a" * 80, True),
    ("azure-nsg", "a" * 81, False),
])
def test_a_name_azure_would_refuse_is_refused_locally(kind, name, ok):
    """Locally decidable, so decided locally. Azure answers a malformed
    storage account name with the same generic refusal it gives a taken one,
    which tells somebody who typed a capital letter only that the name is
    unavailable."""
    assert az_names.check(kind, name)[0] is ok


def test_a_refusal_says_what_is_allowed():
    ok, why = az_names.check("azure-storage", "Not-Valid")
    assert ok is False
    assert "lowercase" in why and "3 to 24" in why


def test_an_unknown_kind_has_no_opinion():
    """Silence here means "no opinion", not "fine". A type nobody wrote a rule
    for should not be blocked by the module that exists to catch typos."""
    assert az_names.check("something-else", "!!!") == (True, None)


# ============================== Network security groups, now that they build


class _NotFound(Exception):
    status_code = 404


class _StubPoller:
    def __init__(self, value):
        self._value = value

    def result(self):
        return self._value


class _StubNsgOps:
    def __init__(self, groups=()):
        self.groups = list(groups)
        self.created = []
        self.deleted = []

    def list_all(self):
        return list(self.groups)

    def get(self, group, name):
        for found in self.groups:
            if found.name == name:
                return found
        raise _NotFound()

    def begin_create_or_update(self, group, name, body):
        self.created.append((group, name, body))
        made = _StubNsg(name, group=group, tags=body.get("tags"))
        self.groups.append(made)
        return _StubPoller(made)

    def begin_delete(self, group, name):
        self.deleted.append((group, name))
        self.groups = [g for g in self.groups if g.name != name]
        return _StubPoller(None)


class _StubNsg:
    def __init__(self, name, group=GROUP, tags=None, rules=()):
        self.name = name
        self.location = "eastus"
        self.tags = tags
        self.id = (f"/subscriptions/{SUBSCRIPTION}/resourceGroups/{group}"
                   f"/providers/Microsoft.Network/networkSecurityGroups/{name}")
        self.security_rules = list(rules)
        self.default_security_rules = []
        self.network_interfaces = []
        self.subnets = []


class _StubNetClient:
    def __init__(self, groups=()):
        self.network_security_groups = _StubNsgOps(groups)


@pytest.fixture
def group_exists(monkeypatch):
    monkeypatch.setattr(az_nsg, "ensure_resource_group",
                        lambda name, location: (False, None))


def test_priorities_come_from_the_list_order(group_exists):
    """The list order is the precedence, which is the only arrangement where
    what somebody typed and what Azure does are the same thing. The root app
    numbers rules 100+index regardless of what the caller asked for."""
    client = _StubNetClient()
    az_nsg.create_nsg(client, "demo", GROUP, rules=[
        _rule("first", priority=None), _rule("second", priority=None),
        _rule("third", priority=None)])

    sent = client.network_security_groups.created[0][2]
    assert [r["properties"]["priority"]
            for r in sent["properties"]["securityRules"]] == [100, 110, 120]


def test_a_half_ordered_rule_set_is_refused_rather_than_resolved(group_exists):
    """"These three are automatic and this one is 400" has an answer only if
    somebody decides what it is, and guessing produces the silent misordering
    this refusal exists to prevent."""
    ok, why, _ = az_nsg.create_nsg(_StubNetClient(), "demo", GROUP, rules=[
        _rule("a", priority=200), _rule("b", priority=None)])

    assert ok is False
    assert "half ordered" in why


def test_two_rules_at_one_priority_are_refused(group_exists):
    ok, why, _ = az_nsg.create_nsg(_StubNetClient(), "demo", GROUP, rules=[
        _rule("a", priority=200), _rule("b", priority=200)])

    assert ok is False
    assert "no defined winner" in why


def test_a_priority_azure_reserves_is_refused(group_exists):
    ok, why, _ = az_nsg.create_nsg(_StubNetClient(), "demo", GROUP,
                                   rules=[_rule("a", priority=65000)])
    assert ok is False
    assert "reserved" in why


def test_creating_over_an_existing_group_is_refused(group_exists):
    """`begin_create_or_update` on a group you already own replaces its entire
    rule list and reports success, so creating a group with a name somebody
    else used deletes their firewall. The root app does exactly this."""
    client = _StubNetClient([_StubNsg("taken")])

    ok, why, _ = az_nsg.create_nsg(client, "taken", GROUP,
                                   rules=[_rule("a", priority=None)])

    assert ok is False
    assert "already exists" in why
    assert "replace its entire rule list" in why
    assert client.network_security_groups.created == []


def test_a_group_with_no_rules_says_it_allows_nothing(group_exists):
    ok, _, problems = az_nsg.create_nsg(_StubNetClient(), "demo", GROUP,
                                        rules=[])
    assert ok
    assert any("denies all inbound" in p for p in problems)


def test_a_created_group_carries_the_tag(group_exists):
    client = _StubNetClient()
    az_nsg.create_nsg(client, "demo", GROUP, rules=[])

    assert client.network_security_groups.created[0][2]["tags"] == {
        "ManagedBy": "secure-cloud-provisioner"}


def test_the_rule_body_is_camel_case(group_exists):
    """A plain dict handed to the SDK is the request body, serialized as
    written. The vault create paid for this lesson: a snake_case key is not the
    field it looks like, it is an unrecognised one."""
    client = _StubNetClient()
    az_nsg.create_nsg(client, "demo", GROUP, rules=[_rule("a", priority=None)])

    properties = (client.network_security_groups.created[0][2]
                  ["properties"]["securityRules"][0]["properties"])
    assert "sourceAddressPrefix" in properties
    assert "destinationPortRange" in properties
    assert not any("_" in key for key in properties)


def test_an_unforced_group_delete_refuses():
    client = _StubNetClient([_StubNsg("demo")])
    ok, why = az_nsg.delete_nsg(client, "demo")

    assert ok is False
    assert "firewall" in why


def test_the_group_cleanup_reaches_only_what_this_tool_tagged():
    ours = _StubNsg("ours", tags={"ManagedBy": "secure-cloud-provisioner"})
    theirs = _StubNsg("theirs", tags={"Name": "somebody else's"})
    client = _StubNetClient([ours, theirs])

    done = az_nsg.cleanup_all_managed_nsgs(client, force=True)

    assert [name for _, name in client.network_security_groups.deleted] == ["ours"]
    assert len(done) == 1


def test_the_deletion_plan_lists_what_stops_being_protected():
    """The one Azure type with a preview, and the reason is the reverse of the
    reason the other two have none: deleting a group destroys nothing inside it
    and exposes everything attached to it."""
    found = _StubNsg("demo")
    found.subnets = [type("S", (), {"id": "/subscriptions/x/subnets/one"})()]
    client = _StubNetClient([found])

    plan = az_nsg.plan_deletion(client, "demo")

    assert plan["destroys"]["network interfaces or subnets left unprotected"] == 1
    assert "stop being filtered" in plan["message"]


# ================================================= Virtual network rules


def _vnet(subnets, **overrides):
    base = {"vnet_name": "demo-vnet", "resource_group": GROUP,
            "location": "eastus", "address_prefixes": ["10.20.0.0/16"],
            "subnets": subnets, "ddos_protection_enabled": True,
            "peerings": [], "unreadable": {}}
    base.update(overrides)
    return base


def test_a_subnet_with_no_security_group_is_reported():
    warnings = check_vnet(_vnet([{"name": "app", "network_security_group": None}]))

    assert "subnet_without_firewall" in _settings_of(warnings)
    assert summarize(warnings)[WARNING] == 1


def test_a_subnet_with_a_security_group_is_left_alone():
    warnings = check_vnet(_vnet([
        {"name": "app", "network_security_group": "/subscriptions/x/nsg/one"}]))

    assert "subnet_without_firewall" not in _settings_of(warnings)


def test_a_gateway_subnet_is_not_reported_for_having_no_group():
    """Azure refuses to let a gateway subnet carry one, so reporting its
    absence would be reporting a rule Azure enforces against us."""
    warnings = check_vnet(_vnet([
        {"name": "GatewaySubnet", "network_security_group": None}]))

    assert "subnet_without_firewall" not in _settings_of(warnings)


def test_a_network_form_says_it_will_filter_nothing_before_it_is_built():
    """az/vnet.py attaches no group to a subnet it creates, so this fires on
    every subnet in a new network - which is correct and is the point."""
    warnings = check_vnet_spec({"name": "demo",
                                "subnets": [{"name": "app"}, {"name": "data"}]})

    assert [w["rule"]["setting"] for w in warnings].count(
        "subnet_without_firewall") == 2


def test_an_unreadable_network_setting_is_a_finding_not_a_silence():
    warnings = check_vnet(_vnet([], unreadable={"subnets": "the login could not"}))

    assert "unreadable_subnets" in _settings_of(warnings)


def test_ddos_and_peering_are_notes_rather_than_faults():
    warnings = check_vnet(_vnet([], ddos_protection_enabled=False,
                                peerings=["hub"]))

    assert summarize(warnings)[WARNING] == 0
    assert {"no_ddos_protection", "peered"} <= _settings_of(warnings)


# ======================================================= Virtual machines


def _vm(**overrides):
    base = {"vm_name": "demo-vm", "resource_group": GROUP, "location": "eastus",
            "vm_size": "Standard_B1s", "public_ip": None,
            "password_authentication_disabled": True,
            "os_disk_encrypted": True, "encryption_at_host": True,
            "effective_rules": [], "unreadable": {}}
    base.update(overrides)
    return base


def test_a_size_outside_the_allowlist_is_refused_not_warned_about():
    """A refusal rather than a warning, for the reason aws/instances.py gives:
    a confirmation prompt does not survive a typo."""
    ok, why, _ = az_vm.create_vm(None, "demo", GROUP,
                                 vm_size="Standard_D64s_v3",
                                 ssh_public_key="ssh-ed25519 AAAA")
    assert ok is False
    assert "not a size this tool will create" in why


def test_a_machine_cannot_be_created_without_a_public_key():
    """This tool never accepts a password for a machine it builds. A password
    logs in, so putting one in a request body puts it in the logs."""
    ok, why, _ = az_vm.create_vm(None, "demo", GROUP, ssh_public_key=None)

    assert ok is False
    assert "never accepts a password" in why


def test_a_private_key_offered_as_a_public_one_is_refused():
    ok, why, _ = az_vm.create_vm(None, "demo", GROUP,
                                 ssh_public_key="-----BEGIN OPENSSH PRIVATE KEY-----")
    assert ok is False
    assert "private half" in why


def test_this_module_never_asks_for_a_password():
    """The archived Streamlit version reads AZURE_VM_ADMIN_PASSWORD from the
    environment and sends it. Asserted by parsing the source, the same way
    test_this_module_never_calls_create_key_pair does on the AWS side.

    Parsed rather than grepped, and the difference matters here: this module's
    docstring names AZURE_VM_ADMIN_PASSWORD while explaining that it does not
    use it, so a substring search fails on the explanation. What must not exist
    is a password reaching the request body or being read from anywhere - which
    is a question about code, not about prose.
    """
    import ast
    from pathlib import Path

    tree = ast.parse((Path(__file__).parent.parent / "az" / "vm.py").read_text())

    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)):
            doc = ast.get_docstring(node, clean=False)
            if doc:
                docstrings.add(doc)

    banned = ("admin_password", "adminPassword", "AZURE_VM_ADMIN_PASSWORD",
              "disablePasswordAuthentication=False")

    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node.value in docstrings:
                continue
            for word in banned:
                assert word not in node.value, (
                    f"{word!r} appears in a string literal on line {node.lineno}")
        if isinstance(node, ast.keyword) and node.arg:
            assert node.arg not in banned, f"line {node.lineno}"
        if isinstance(node, ast.Name):
            assert node.id not in banned, f"line {node.lineno}"


def test_an_open_admin_port_is_critical_only_when_the_machine_is_reachable():
    """A wide-open rule on a machine with no public address is a warning, not a
    crisis - it is one public IP away from being one, which is exactly how it
    usually happens, so it is not silence either."""
    exposed = check_vm(_vm(public_ip="4.5.6.7",
                           effective_rules=[_rule("allow-ssh")]))
    private = check_vm(_vm(public_ip=None,
                           effective_rules=[_rule("allow-ssh")]))

    assert "open_22" in _settings_of(exposed)
    assert summarize(exposed)[CRITICAL] >= 1
    assert "open_22_no_public_address" in _settings_of(private)
    assert summarize(private)[CRITICAL] == 0


def test_a_machines_exposure_is_decided_by_the_same_evaluator_as_a_groups():
    """A machine behind a denied rule is not exposed, and the machine rules do
    not reimplement that - they ask scanner/azure_nsg_effective.py."""
    warnings = check_vm(_vm(public_ip="4.5.6.7", effective_rules=[
        _rule("allow-ssh", priority=200),
        _rule("deny-ssh", priority=100, access="Deny")]))

    assert "open_22" not in _settings_of(warnings)


def test_password_login_is_critical_on_a_reachable_machine():
    warnings = check_vm(_vm(public_ip="4.5.6.7",
                            password_authentication_disabled=False))

    assert _find_level(warnings, "password_login_allowed") == CRITICAL


def test_password_login_is_a_warning_on_an_unreachable_one():
    warnings = check_vm(_vm(password_authentication_disabled=False))

    assert _find_level(warnings, "password_login_allowed") == WARNING


def _find_level(warnings, setting):
    for w in warnings:
        if w["rule"]["setting"] == setting:
            return w["level"]
    raise AssertionError(f"no {setting} in {_settings_of(warnings)}")


def test_a_machine_form_is_judged_the_same_way_the_machine_will_be():
    """The parity contract, across the fifth type."""
    before = check_vm_spec({"name": "demo", "open_ports": ["22"],
                            "allowed_source": "*", "assign_public_ip": True})
    after = check_vm(_vm(vm_name="demo", public_ip="4.5.6.7",
                         encryption_at_host=False,
                         effective_rules=[_rule("allow-22")]))

    assert _settings_of(before) <= _settings_of(after)


def test_an_unreadable_machine_network_is_a_finding_not_a_silence():
    warnings = check_vm(_vm(unreadable={"effective_rules": "the login could not"}))

    assert "unreadable_effective_rules" in _settings_of(warnings)


def test_a_machine_delete_says_what_it_leaves_behind():
    """Reporting success and leaving somebody to find four billable leftovers
    later would be true and misleading."""
    class _Ops:
        def list_all(self):
            return []

        def begin_delete(self, group, name):
            return _StubPoller(None)

    client = type("C", (), {"virtual_machines": _Ops()})()
    ok, message = az_vm.delete_vm(
        client,
        f"/subscriptions/{SUBSCRIPTION}/resourceGroups/{GROUP}"
        f"/providers/Microsoft.Compute/virtualMachines/demo",
        force=True)

    assert ok
    assert "still there" in message
    assert "-nic" in message


class _StubCapability:
    def __init__(self, name, value):
        self.name = name
        self.value = value


class _StubSku:
    """A SKU as resource_skus.list returns one.

    capabilities is here because the real SDK sends it, and a stub that omits
    a field the code reads cannot show the code reading it wrongly. It did
    exactly that once: offered_sizes reached for sku.capabilities directly,
    the stub had none, and the AttributeError was swallowed by the blanket
    except into "this subscription is offered nothing" - a silently empty
    menu rather than a failure.

    Azure sends every capability value as a string, including the numbers.
    """

    def __init__(self, name, restrictions=(), resource_type="virtualMachines",
                 vcpus="1", memory_gb="2"):
        self.name = name
        self.resource_type = resource_type
        self.restrictions = list(restrictions)
        self.capabilities = [_StubCapability("vCPUs", vcpus),
                             _StubCapability("MemoryGB", memory_gb)]


class _StubSkuOps:
    def __init__(self, skus):
        self._skus = list(skus)

    def list(self, filter=None):
        return list(self._skus)


class _StubComputeClient:
    def __init__(self, skus=()):
        self.resource_skus = _StubSkuOps(skus)


def test_a_size_the_subscription_cannot_start_is_not_offered():
    """Azure restricts sizes per subscription as well as per region and
    reports the two identically. Every classic B-series size came back
    restricted on the subscription this was built against - in nine regions,
    with four cores of unused quota."""
    client = _StubComputeClient([
        _StubSku("Standard_B1s", restrictions=["NotAvailableForSubscription"]),
        _StubSku("Standard_F1als_v7"),
        _StubSku("Standard_D96as_v4"),          # real, but not allowlisted
        _StubSku("Standard_F1als_v7", resource_type="disks"),
    ])

    assert az_vm.available_sizes(client, "eastus") == ["Standard_F1als_v7"]


def test_the_cheapest_available_size_is_the_one_chosen():
    """Preference order rather than alphabetical: burstable before fixed,
    smaller before larger."""
    client = _StubComputeClient([
        _StubSku("Standard_F1als_v7"), _StubSku("Standard_B1s"),
        _StubSku("Standard_D2ls_v7")])

    assert az_vm.first_available_size(client, "eastus") == "Standard_B1s"


def test_a_subscription_offered_nothing_gets_none_rather_than_a_guess():
    client = _StubComputeClient([
        _StubSku("Standard_B1s", restrictions=["NotAvailableForSubscription"])])

    assert az_vm.available_sizes(client, "eastus") == []
    assert az_vm.first_available_size(client, "eastus") is None


def test_asking_which_sizes_are_available_never_raises():
    """Called to improve a refusal. A refusal that fails while explaining
    itself is worse than the plain one."""
    class _Broken:
        resource_skus = property(lambda self: (_ for _ in ()).throw(
            RuntimeError("no")))

    assert az_vm.available_sizes(_Broken(), "eastus") == []


def test_an_unavailable_size_names_what_can_be_started_instead():
    """Relaying Azure's own message leaves the caller to go and find out what
    would work. The answer is one call away and this makes it."""
    client = _StubComputeClient([_StubSku("Standard_F1als_v7")])

    why = az_vm._why_the_machine_was_refused(
        Exception("(SkuNotAvailable) The requested VM size ... is currently "
                  "not available in location 'eastus'."),
        GROUP, client=client, location="eastus")

    assert "Standard_F1als_v7" in why
    assert "eastus" in why


def test_an_unavailable_size_with_no_alternative_says_it_is_the_subscription():
    """The distinction that cost the time: this reads like a region being full
    and is not. Quota was four cores and unused."""
    why = az_vm._why_the_machine_was_refused(
        Exception("(SkuNotAvailable) not available in location 'eastus'."),
        GROUP, client=_StubComputeClient([]), location="eastus")

    assert "restriction on the subscription rather than on the region" in why


def test_an_unregistered_compute_provider_is_explained_rather_than_raised():
    """The first real create failed on this and the SDK's own message names the
    fix in a form that does not look like one. Found against a subscription
    that had never made a machine."""
    why = az_vm._why_the_machine_was_refused(
        Exception("(MissingSubscriptionRegistration) The subscription is not "
                  "registered to use namespace 'Microsoft.Compute'."), GROUP)

    assert "Microsoft.Compute" in why
    assert "Register" in why
    assert "free" in why


def test_a_missing_role_names_the_action_it_needs():
    why = az_vm._why_the_machine_was_refused(
        Exception("(AuthorizationFailed) The client does not have "
                  "authorization to perform action "
                  "'Microsoft.Compute/virtualMachines/write'."), GROUP)

    assert "'Microsoft.Compute/virtualMachines/write'" in why
    assert GROUP in why


# ============================================== Through the registry


def test_the_three_new_types_are_registered_and_writable():
    for key in ("azure-nsg", "azure-vnet", "azure-vm"):
        resource = registry.get(key)
        assert resource is not None, key
        assert resource.read_only is False, key
        assert resource.create is not registry._cannot_create, key


def test_creating_any_azure_type_without_a_resource_group_is_refused():
    """A missing resource group is an Azure-only problem, so the refusal is in
    the adapter rather than in the model eight AWS types also use."""
    for key in ("azure-nsg", "azure-vnet", "azure-vm"):
        ok, message, _ = registry.get(key).create(None, {"name": "demo"})
        assert ok is False, key
        assert "resource group" in message, key


def test_the_machine_form_offers_only_the_allowlist():
    """Off the registry rather than written out again in JavaScript, so the
    menu cannot drift from what az/vm.py will actually build."""
    offered = {c["value"] for c in registry.AZURE_VM.options(None)["vm_size"]}

    assert offered == az_vm.ALLOWED_VM_SIZES


# ================= A group you may not see, and one that is not there
#
# Azure answers both with a refusal, which is the third time this project has
# paid for that fact - after SkuNotAvailable and the unregistered compute
# provider. Found by typing a resource group name that did not exist into the
# CLI under a service principal scoped to particular groups: a traceback about
# an HTTP response came back instead of a sentence.


class _Forbidden(Exception):
    status_code = 403

    def __str__(self):
        return ("(AuthorizationFailed) The client '...' does not have "
                "authorization to perform action "
                "'Microsoft.Resources/subscriptions/resourcegroups/read'")


class _Missing(Exception):
    status_code = 404


class _StubGroups:
    def __init__(self, error=None):
        self._error = error
        self.created = []

    def get(self, name):
        if self._error:
            raise self._error
        return object()

    def create_or_update(self, name, body):
        self.created.append((name, body))


class _StubResourceClient:
    def __init__(self, error=None):
        self.resource_groups = _StubGroups(error)


@pytest.fixture
def resource_client_raising(monkeypatch):
    def _install(error):
        client = _StubResourceClient(error)
        monkeypatch.setattr(az_common, "resource_client", lambda *a, **k: client)
        return client
    return _install


def test_a_resource_group_you_may_not_read_is_a_refusal_not_a_crash(
        resource_client_raising):
    """403 used to fall through the `!= 404` guard and out of the process."""
    resource_client_raising(_Forbidden())

    with pytest.raises(az_common.AzureRefused) as raised:
        az_common.ensure_resource_group("cdkhcd", "eastus")

    assert "not allowed to look at the resource group 'cdkhcd'" in str(raised.value)
    assert "same refusal" in str(raised.value)


def test_it_does_not_try_to_create_a_group_it_could_not_read(
        resource_client_raising):
    """Treating 403 as "not there" sends the create straight into
    create_or_update, which fails again with a second 403 and a worse
    message."""
    client = resource_client_raising(_Forbidden())

    with pytest.raises(az_common.AzureRefused):
        az_common.ensure_resource_group("cdkhcd", "eastus")

    assert client.resource_groups.created == []


def test_a_group_that_is_genuinely_missing_is_still_created(
        resource_client_raising):
    """The 404 path must keep working. It is the reason this function exists."""
    client = resource_client_raising(_Missing())

    created, note = az_common.ensure_resource_group("brand-new", "eastus")

    assert created is True
    assert "did not exist, so it was created" in note
    assert client.resource_groups.created[0][0] == "brand-new"


def test_being_unable_to_create_a_group_is_also_a_sentence(monkeypatch):
    """Reading may be allowed while creating is not - Azure grants the two
    separately, and a subscription-wide grant is what creating one needs."""
    class _ReadableUncreatable(_StubGroups):
        def get(self, name):
            raise _Missing()

        def create_or_update(self, name, body):
            raise _Forbidden()

    client = _StubResourceClient()
    client.resource_groups = _ReadableUncreatable()
    monkeypatch.setattr(az_common, "resource_client", lambda *a, **k: client)

    with pytest.raises(az_common.AzureRefused) as raised:
        az_common.ensure_resource_group("brand-new", "eastus")

    assert "not allowed to create one" in str(raised.value)


@pytest.mark.parametrize("key,extra", [
    ("azure-storage", {}),
    ("azure-keyvault", {}),
    ("azure-nsg", {"azure_rules": []}),
    ("azure-vnet", {}),
    ("azure-vm", {"public_key": "ssh-ed25519 AAAA", "vm_size": "Standard_B1s"}),
])
def test_every_create_returns_the_refusal_rather_than_raising(
        key, extra, resource_client_raising, monkeypatch):
    """The registry contract is (ok, error, problems). A permission failure has
    to arrive through that channel like every other refusal, or the caller gets
    a traceback and loses `problems` with it - which is how a failed machine
    create left four billable resources nobody was told about."""
    resource_client_raising(_Forbidden())
    monkeypatch.setattr(az_names, "check", lambda kind, name: (True, None))

    resource = registry.get(key)
    spec = {"name": "demo", "resource_group": "cdkhcd", "region": "eastus"}
    spec.update(extra)

    # The name-availability calls happen before this and need a client; the
    # ones that make them are stubbed to say the name is free.
    for module in (az_storage_mod, az_keyvault_mod, az_nsg, az_vnet):
        if hasattr(module, "_name_is_available"):
            monkeypatch.setattr(module, "_name_is_available",
                                lambda *a, **k: (True, None))
        if hasattr(module, "_name_is_taken"):
            monkeypatch.setattr(module, "_name_is_taken",
                                lambda *a, **k: (False, None))

    ok, message, problems = resource.create(_AnyClient(), spec)

    assert ok is False, key
    assert "not allowed" in message, key
    assert isinstance(problems, list), key


class _AnyClient:
    """Accepts any attribute access and any call. The creates above never get
    as far as using it, because the resource group check fails first."""

    def __getattr__(self, name):
        return _AnyClient()

    def __call__(self, *args, **kwargs):
        return _AnyClient()


# ================================= A refused read is not an absent resource


class _StatusError(HttpResponseError):
    """An SDK error carrying a status, which is all the readers match on."""

    def __init__(self, status):
        super().__init__(message=f"status {status}")
        self.status_code = status


class _RaisingClient:
    """Every call raises the status it was built with."""

    def __init__(self, status):
        self._status = status

    def __getattr__(self, name):
        return self

    def get(self, *args, **kwargs):
        raise _StatusError(self._status)

    def get_properties(self, *args, **kwargs):
        raise _StatusError(self._status)


_A_RESOURCE_ID = "/subscriptions/s/resourceGroups/g/providers/p/t/name"

_READERS = [
    ("azure-storage", az_storage_mod.read_account_for_scanning),
    ("azure-keyvault", az_keyvault_mod.read_vault_for_scanning),
    ("azure-nsg", az_nsg.read_nsg_for_scanning),
    ("azure-vnet", az_vnet.read_vnet_for_scanning),
    ("azure-vm", az_vm.read_vm_for_scanning),
]


@pytest.mark.parametrize("label,reader", _READERS)
def test_a_read_that_is_refused_is_not_reported_as_absent(label, reader):
    """Azure answers "you may not look" and "there is none" in the same words.

    Every one of these handled 404 and re-raised everything else, so a
    resource group the identity holds no role on arrived as a 500 and a
    traceback about an HTTP response - the fifth instance of the mistake
    CLAUDE.md already records four times, and the one place the create paths
    had been fixed and the read paths had not.

    404 is still absence and still returns None; the test below holds that
    half in place, because a fix that turned every missing resource into a
    refusal would be worse than the bug.
    """
    with pytest.raises(AzureRefused):
        reader(_RaisingClient(403), _A_RESOURCE_ID)


@pytest.mark.parametrize("label,reader", _READERS)
def test_a_resource_that_is_absent_still_reads_back_as_nothing(label, reader):
    """The other half of the contract every AWS reader here follows: a reader
    returns None when the thing is not there, and the routes turn that into a
    404."""
    assert reader(_RaisingClient(404), _A_RESOURCE_ID) is None


# ============================ Storage checks that came from the Prowler run
#
# Prowler was pointed at the subscription and covered eleven storage checks
# this did not. Two of them earned a place here; docs/benchmark.md says why the
# rest did not. Neither of these is about exposure, which is the reason both
# are warnings: severity here means how reachable something is, and a thing
# that cannot be got back is a different axis.


def _account(**overrides):
    """A storage account as the reader hands one to the scanner."""
    base = {
        "account_name": "scpdemo", "resource_group": GROUP, "location": "eastus",
        "allow_blob_public_access": False, "supports_https_traffic_only": True,
        "minimum_tls_version": "TLS1_2", "public_network_access": "Disabled",
        "allow_shared_key_access": False, "key_age_days": 3,
        "blob_soft_delete": True, "container_soft_delete": True,
        "containers": [], "unreadable": {},
    }
    base.update(overrides)
    return base


def test_a_key_nobody_has_rotated_is_reported():
    warnings = check_storage_account(_account(key_age_days=400))
    assert "stale_account_key" in _settings_of(warnings)


def test_a_freshly_rotated_key_is_not():
    assert "stale_account_key" not in _settings_of(
        check_storage_account(_account(key_age_days=3)))


def test_the_rotation_threshold_is_a_convention_and_is_not_off_by_one():
    """Ninety days is Prowler's number and most Azure guidance repeats it. It
    is a convention rather than a measurement, which is exactly why the
    boundary should be pinned: a rule nobody has fixed the edge of drifts."""
    from scanner.azure_storage_rules import KEY_ROTATION_DAYS

    at = _settings_of(check_storage_account(_account(key_age_days=KEY_ROTATION_DAYS)))
    over = _settings_of(check_storage_account(
        _account(key_age_days=KEY_ROTATION_DAYS + 1)))

    assert "stale_account_key" not in at
    assert "stale_account_key" in over


def test_a_key_age_azure_did_not_report_is_a_question_not_a_pass():
    """An account old enough to predate the field returns nothing here, and
    nothing is not zero. Reporting it as freshly rotated would be the one
    answer that is both wrong and reassuring."""
    settings = _account(key_age_days=None,
                        unreadable={"key_age_days": "Azure did not report it"})
    found = _settings_of(check_storage_account(settings))

    assert "stale_account_key" not in found
    assert "unreadable_key_age_days" in found


def test_containers_that_cannot_be_recovered_are_reported():
    assert "no_container_soft_delete" in _settings_of(
        check_storage_account(_account(container_soft_delete=False)))


def test_blobs_that_cannot_be_recovered_are_reported_separately():
    """Two settings, not one. Azure keeps blob and container retention apart,
    and an account with blob soft delete on still loses everything if somebody
    deletes the container."""
    both = _settings_of(check_storage_account(
        _account(blob_soft_delete=False, container_soft_delete=False)))
    assert {"no_blob_soft_delete", "no_container_soft_delete"} <= both

    blob_only = _settings_of(check_storage_account(
        _account(blob_soft_delete=True, container_soft_delete=False)))
    assert "no_blob_soft_delete" not in blob_only
    assert "no_container_soft_delete" in blob_only


def test_neither_recovery_finding_is_critical():
    """Severity means exposure here. Nothing is reachable that should not be;
    something cannot be undone, which is a different axis and a quieter one."""
    warnings = check_storage_account(
        _account(blob_soft_delete=False, container_soft_delete=False,
                 key_age_days=400))
    assert all(w["level"] != CRITICAL for w in warnings)


def test_a_soft_delete_setting_that_could_not_be_read_says_so():
    """The blob service is a second call and a second permission. A failure
    there must not read as "no soft delete", which is what a bare False would
    say."""
    settings = _account(
        blob_soft_delete=None, container_soft_delete=None,
        unreadable={"blob_soft_delete": "the login could not read it",
                    "container_soft_delete": "the login could not read it"})
    found = _settings_of(check_storage_account(settings))

    assert "no_blob_soft_delete" not in found
    assert "no_container_soft_delete" not in found
    assert "unreadable_blob_soft_delete" in found
# ------------------------------------- an Azure refusal is an answer, not a 500


class _AzureRefuses:
    """An operations object whose delete is declined by Azure.

    Modelled on the real thing: HttpResponseError carries the human sentence
    on .message and a machine code on .error.code, and its str() is the whole
    HTTP response rather than either of those.
    """

    class _Error:
        code = "InUseSubnetCannotBeDeleted"

    def __init__(self):
        self.error = self._Error()
        self.message = ("Subnet default is in use by /subscriptions/x/"
                        "networkInterfaces/TEST-VM-NIC and cannot be deleted.")

    def _raise(self, *a, **k):
        error = Exception("(InUseSubnetCannotBeDeleted) Subnet default is in use")
        error.error = self.error
        error.message = self.message
        raise error

    def begin_delete(self, *a, **k):
        self._raise()

    def delete(self, *a, **k):
        self._raise()


@pytest.mark.parametrize("module,attr,op", [
    ("az.vnet", "delete_vnet", "virtual_networks"),
    ("az.nsg", "delete_nsg", "network_security_groups"),
    ("az.vm", "delete_vm", "virtual_machines"),
])
def test_an_azure_refusal_on_delete_is_reported_not_raised(module, attr, op,
                                                           monkeypatch):
    """It became a 500, and the page showed "HTTP 500" and nothing else.

    Azure had said exactly which network card was holding the subnet. None of
    the five destructive calls in az/ caught HttpResponseError, so every
    refusal Azure can give during a delete - a subnet in use, a lock, a vault
    in its retention period - arrived as a traceback. delete_vnet's own
    docstring promised Azure's message was "left in place rather than worked
    around", and it was: unhandled, which is the one way of leaving it in
    place that stops anybody reading it.
    """
    import importlib

    mod = importlib.import_module(module)
    monkeypatch.setattr(mod, "_locate", lambda client, name: ("rg", name))

    class _Client:
        pass
    client = _Client()
    setattr(client, op, _AzureRefuses())

    ok, message = getattr(mod, attr)(client, "test-vm-vnet", force=True)

    assert ok is False
    assert "InUseSubnetCannotBeDeleted" in message
    assert "TEST-VM-NIC" in message, "Azure's own sentence has to survive"
