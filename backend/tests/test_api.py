"""Tests for the HTTP layer.

TestClient calls the endpoints in-process, so there is no server to start and no
port to bind. moto intercepts the AWS calls underneath. The whole suite runs
offline against no account.

The moto mock has to be active before the app builds a boto3 client, and the app
builds one per request, so the fixture wraps each test rather than the module.
"""

import dataclasses
import json
import os
import re

import boto3
import pytest
from fastapi.testclient import TestClient
from moto import mock_aws

from api import audit, models, registry
from api.app import app
from aws import security_groups as sg

WORLD = "0.0.0.0/0"
MY_IP = "203.0.113.25/32"


@pytest.fixture
def client():
    with mock_aws():
        yield TestClient(app, base_url="http://127.0.0.1:8000")


@pytest.fixture
def vpc_id():
    """The default VPC moto creates, looked up the way the app looks it up."""
    ec2 = boto3.client("ec2", region_name="us-east-1")
    found, err = sg.get_default_vpc(ec2)
    assert err is None, err
    return found


def _open_ssh_spec(name="api-test-sg", vpc_id=None):
    """A group these tests can create, in a network chosen here rather than guessed.

    This used to omit vpc_id entirely and _sg_create fell back to the account
    default. Now that it refuses - placement is asked for, never assumed - the
    choice has to be made by somebody, and a test making it explicitly is the
    right end: these tests are about the routes, not about where a group lands.
    """
    if vpc_id is None:
        ec2 = boto3.client("ec2", region_name="us-east-1")
        vpc_id, err = sg.get_default_vpc(ec2)
        assert err is None, err

    return {
        "name": name,
        "vpc_id": vpc_id,
        "rules": [{"protocol": "tcp", "from_port": 22, "to_port": 22,
                   "source": WORLD}],
    }


# ------------------------------------------------------------------ Discovery


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_resource_types_are_advertised(client):
    keys = {r["key"] for r in client.get("/resources").json()["resources"]}
    assert keys == {"security-group", "bucket", "key-pair", "instance",
                    "network", "iam", "snapshot", "alarm", "role",
                    "azure-nsg", "azure-storage", "azure-keyvault",
                    "azure-vnet", "azure-vm", "azure-monitor"}


def test_every_resource_says_whether_it_can_be_changed(client):
    """So a frontend can leave out buttons that would only be refused."""
    for entry in client.get("/resources").json()["resources"]:
        assert "read_only" in entry


def test_every_resource_says_which_cloud_it_is_in(client):
    """The page shows one cloud at a time and has to be told which is which.

    The alternative it would otherwise fall back on is splitting the list on
    the "azure-" prefix in JavaScript, which is this registry's own knowledge
    written down a second time somewhere no test can reach it.
    """
    body = client.get("/resources").json()

    for entry in body["resources"]:
        assert entry["provider"] in {"aws", "azure"}, entry["key"]


def test_the_azure_types_are_the_ones_in_the_azure_provider(client):
    """Guards the field itself. A type defaulting to aws by accident would put
    an Azure storage account on the AWS page, where the region control means
    something it does not mean."""
    entries = client.get("/resources").json()["resources"]
    azure = {r["key"] for r in entries if r["provider"] == "azure"}
    assert azure == {"azure-nsg", "azure-storage", "azure-keyvault",
                     "azure-vnet", "azure-vm", "azure-monitor"}


def test_the_provisioned_types_are_all_writable(client):
    """Guards the default. A resource silently becoming read-only would
    remove its create button with no other symptom."""
    entries = {r["key"]: r for r in client.get("/resources").json()["resources"]}
    provisioned = {"security-group", "bucket", "key-pair", "instance", "network"}
    assert all(not entries[key]["read_only"] for key in provisioned)


def test_the_audited_types_are_advertised_as_read_only(client):
    """The other half of the same guard. A type quietly becoming writable
    would put a delete button on somebody's credentials."""
    entries = {r["key"]: r for r in client.get("/resources").json()["resources"]}
    assert entries["iam"]["read_only"] is True
    assert entries["snapshot"]["read_only"] is True
    assert entries["role"]["read_only"] is True
    # No Azure type is here any more. azure-nsg was, until the priority
    # ordering that blocked it was solved in scanner/azure_nsg_effective.py;
    # all five Azure types now provision. The guard this test exists to be is
    # that a type does not become writable quietly - not that Azure never
    # does - so the Azure half is asserted the other way round below.
    for key in ("azure-storage", "azure-keyvault", "azure-nsg", "azure-vnet",
                "azure-vm"):
        assert entries[key]["read_only"] is False


def test_an_audited_resource_refuses_the_destructive_routes(client, monkeypatch):
    """405, and a sentence saying what this tool does instead.

    Written before there is an audit-only resource to try it on, because the
    behaviour belongs to the routes rather than to whichever type arrives
    first. IAM and snapshots both need it and neither should have to discover
    it separately.
    """
    from dataclasses import replace
    from api import registry as registry_module

    audited = replace(registry_module.BUCKET, key="audited", read_only=True)
    monkeypatch.setitem(registry_module.REGISTRY, "audited", audited)

    created = client.post("/resources/audited", json={"name": "x"})
    assert created.status_code == 405
    assert "audited by this tool" in created.json()["detail"]

    assert client.delete("/resources/audited/x").status_code == 405
    assert client.post("/resources/audited/cleanup").status_code == 405


def test_an_audited_resource_can_still_be_listed_and_scanned(client, monkeypatch):
    """Refusing to change something is not a reason to refuse to look at it."""
    from dataclasses import replace
    from api import registry as registry_module

    audited = replace(registry_module.BUCKET, key="audited", read_only=True)
    monkeypatch.setitem(registry_module.REGISTRY, "audited", audited)

    assert client.get("/resources/audited").status_code == 200
    assert client.post("/resources/audited/check",
                       json={"name": "x"}).status_code == 200


def test_unknown_resource_type_is_a_404_that_lists_the_known_ones(client):
    resp = client.post("/resources/lambda-function/check", json={"name": "x"})
    assert resp.status_code == 404
    assert "security-group" in resp.json()["detail"]


# ---------------------------------------------------------- Check before create


def test_check_flags_open_ssh_without_creating_anything(client):
    resp = client.post("/resources/security-group/check", json=_open_ssh_spec())
    assert resp.status_code == 200

    body = resp.json()
    assert body["counts"]["critical"] == 1
    assert "22" in body["warnings"][0]["message"]

    listed = client.get("/resources/security-group").json()["resources"]
    assert listed == []


def test_check_on_a_safe_rule_returns_nothing(client):
    resp = client.post("/resources/security-group/check", json={
        "name": "safe",
        "rules": [{"protocol": "tcp", "from_port": 22, "to_port": 22,
                   "source": MY_IP}],
    })
    assert resp.json()["warnings"] == []


def test_proposed_rules_are_not_fixable(client):
    """A rule that does not exist yet has no ID, so there is nothing to fix."""
    body = client.post("/resources/security-group/check",
                       json=_open_ssh_spec()).json()
    assert body["counts"]["critical"] == 1
    assert body["fixable_count"] == 0


def test_check_a_weak_bucket_before_creating_it(client):
    body = client.post("/resources/bucket/check", json={
        "name": "api-test-bucket", "secure_by_default": False,
    }).json()
    assert body["counts"]["critical"] > 0


def test_check_a_secure_bucket_before_creating_it(client):
    body = client.post("/resources/bucket/check", json={
        "name": "api-test-bucket", "secure_by_default": True,
    }).json()
    assert body["counts"]["critical"] == 0


# --------------------------------------------------------------- Input rejected


def test_a_port_outside_the_valid_range_is_rejected(client):
    resp = client.post("/resources/security-group/check", json={
        "name": "bad", "rules": [{"protocol": "tcp", "from_port": 70000,
                                  "to_port": 70000, "source": WORLD}],
    })
    assert resp.status_code == 422


def test_a_backwards_port_range_is_rejected(client):
    resp = client.post("/resources/security-group/check", json={
        "name": "bad", "rules": [{"protocol": "tcp", "from_port": 443,
                                  "to_port": 22, "source": WORLD}],
    })
    assert resp.status_code == 422


def test_a_missing_name_is_rejected(client):
    assert client.post("/resources/bucket/check", json={}).status_code == 422


# ------------------------------------------------- What the resource actually is


def test_a_scan_reports_the_resource_as_well_as_its_findings(client, vpc_id):
    """A page showing a machine needs its addresses, not only its problems.

    The settings were already being read to run the scanner over them and then
    discarded, so the API could say a bucket's versioning was off without being
    able to say what its versioning was.
    """
    created = client.post("/resources/security-group?accept_risk=true",
                          json=_open_ssh_spec()).json()

    body = client.get(f"/resources/security-group/{created['resource_id']}").json()

    assert body["settings"] is not None
    assert body["settings"]["group_id"] == created["resource_id"]
    assert [r["from_port"] for r in body["settings"]["rules"]] == [22]


def test_creating_returns_the_resource_too(client, vpc_id):
    body = client.post("/resources/security-group?accept_risk=true", json=_open_ssh_spec()).json()

    assert body["settings"]["name"] == "api-test-sg"
    assert body["settings"]["in_use"] is False


def test_a_network_reports_its_subnets(client):
    """Without this a frontend cannot offer a placement choice at all."""
    created = client.post("/resources/network",
                          json={"name": "api-test-net"}).json()

    body = client.get(f"/resources/network/{created['resource_id']}").json()
    subnets = body["settings"]["subnets"]

    assert len(subnets) == 2
    assert {s["declared_role"] for s in subnets} == {"public", "private"}
    assert any(s["reaches_internet"] for s in subnets)
    assert any(not s["reaches_internet"] for s in subnets)
    assert all(s["subnet_id"] and s["cidr"] for s in subnets)


def test_an_instance_reports_its_addresses(client, vpc_id):
    created = client.post("/resources/instance",
                          json={"name": "api-test-server"}).json()

    body = client.get(f"/resources/instance/{created['resource_id']}").json()
    settings = body["settings"]

    assert settings["instance_id"] == created["resource_id"]
    assert settings["private_ip"]
    assert settings["imdsv2_required"] is True


def test_the_instance_settings_are_not_the_internal_wrapper(client, vpc_id):
    """read() returns {"instance", "firewall"} so the scanner can see both.

    That wrapper is the registry's arrangement, not a description of a
    machine, and the firewall half is already reported as warnings. Handing it
    to a browser would say the same thing twice in two different shapes.
    """
    created = client.post("/resources/instance",
                          json={"name": "api-test-server"}).json()

    settings = client.get(
        f"/resources/instance/{created['resource_id']}"
    ).json()["settings"]

    assert "instance" not in settings
    assert "firewall" not in settings


def test_checking_something_not_yet_created_has_no_settings(client):
    """Nothing exists to describe, so the field stays empty rather than
    inventing a description of a thing that has not been made."""
    body = client.post("/resources/security-group?accept_risk=true",
                       json=_open_ssh_spec()).json()
    assert body["settings"] is not None

    proposed = client.post("/resources/security-group/check",
                           json=_open_ssh_spec()).json()
    assert proposed["settings"] is None


@pytest.mark.parametrize("resource_type,resource_id", [
    ("key-pair", "no-such-key"),
    ("bucket", "no-such-bucket-anywhere"),
    ("security-group", "sg-0000000000000000f"),
    ("instance", "i-0000000000000000f"),
    ("network", "vpc-0000000000000000f"),
])
def test_scanning_something_that_does_not_exist_is_a_404(client, resource_type,
                                                         resource_id):
    """AWS reports "no such thing" by raising, not by returning nothing.

    Every reader used to let that exception travel upwards, so asking about a
    resource that is not there produced a 500 and a traceback rather than the
    404 the question deserves. All five are checked because all five had it.
    """
    resp = client.get(f"/resources/{resource_type}/{resource_id}")

    assert resp.status_code == 404, resp.text
    assert resource_id in resp.json()["detail"]


# ------------------------------------------------------------ Placement


def test_a_group_with_no_network_named_is_refused(client, vpc_id):
    """The last place in this program that guessed where to put something.

    A network cannot be changed after creation and it decides more about what
    a group can reach than any rule in it. The CLI and the page both ask, so
    the only caller who could reach the old default-VPC fallback was a script -
    the one least likely to notice its group had gone somewhere it did not
    choose.
    """
    spec = _open_ssh_spec()
    del spec["vpc_id"]

    resp = client.post("/resources/security-group?accept_risk=true", json=spec)

    assert resp.status_code == 400
    detail = str(resp.json()["detail"])
    assert "vpc_id" in detail, "the refusal has to name the field that is missing"


def test_the_refused_group_is_not_created_anyway(client, vpc_id):
    """A refusal that still builds the thing is not a refusal."""
    spec = _open_ssh_spec("placeless")
    del spec["vpc_id"]

    client.post("/resources/security-group?accept_risk=true", json=spec)

    listed = client.get("/resources/security-group").json()["resources"]
    assert not any(g["name"] == "placeless" for g in listed)


# ------------------------------------------------- The pre-flight refusal


def test_a_critical_configuration_is_not_created(client, vpc_id):
    """The scan already knew this was dangerous. Building it anyway and
    mentioning the problem afterwards leaves the decision to whoever reads the
    response, which is nobody when the caller is a script."""
    resp = client.post("/resources/security-group", json=_open_ssh_spec())

    assert resp.status_code == 400
    assert "Not created" in resp.json()["detail"]["message"]


def test_nothing_is_created_when_the_refusal_fires(client, vpc_id):
    """The refusal has to happen before AWS is touched, not after."""
    client.post("/resources/security-group", json=_open_ssh_spec("ghost"))

    listed = client.get("/resources/security-group").json()["resources"]
    assert not any(g["name"] == "ghost" for g in listed)


def test_the_refusal_carries_the_findings_that_caused_it(client, vpc_id):
    """Same bargain as the deletion plan: a caller that is stopped learns what
    it nearly did without having to ask a second time."""
    detail = client.post("/resources/security-group",
                         json=_open_ssh_spec()).json()["detail"]

    assert len(detail["warnings"]) == 1
    assert detail["warnings"][0]["level"] == "critical"
    assert "22" in detail["warnings"][0]["message"]


def test_only_critical_findings_block_a_create(client, vpc_id):
    """A warning is advice. If everything blocked, the flag would be needed
    every time and would stop meaning anything."""
    resp = client.post("/resources/network", json={"name": "plain-network"})
    assert resp.status_code == 201


def test_a_safe_configuration_needs_no_permission_to_proceed(client, vpc_id):
    safe = {"name": "narrow-sg", "vpc_id": vpc_id,
            "rules": [{"protocol": "tcp", "from_port": 22, "to_port": 22,
                       "source": MY_IP}]}
    resp = client.post("/resources/security-group", json=safe)

    assert resp.status_code == 201
    assert resp.json()["counts"]["critical"] == 0


def test_accepting_the_risk_builds_it_anyway(client, vpc_id):
    """There are legitimate reasons to build something this tool disapproves
    of, and being unable to is worse than being warned."""
    resp = client.post("/resources/security-group?accept_risk=true",
                       json=_open_ssh_spec())

    assert resp.status_code == 201
    assert resp.json()["counts"]["critical"] == 1


def test_accepting_the_risk_does_not_change_what_gets_built(client, vpc_id):
    """The flag is permission to proceed, not an instruction to build
    something different."""
    body = client.post("/resources/security-group?accept_risk=true",
                       json=_open_ssh_spec()).json()

    scanned = client.get(f"/resources/security-group/{body['resource_id']}").json()
    assert scanned["counts"]["critical"] == 1


def test_an_audited_resource_is_refused_before_the_scan_runs(client, monkeypatch):
    """405 for a read-only type, not a 400 about its settings. The type cannot
    be created at all, which is a different answer from 'not like that'."""
    from dataclasses import replace
    from api import registry as registry_module

    audited = replace(registry_module.BUCKET, key="audited2", read_only=True)
    monkeypatch.setitem(registry_module.REGISTRY, "audited2", audited)

    assert client.post("/resources/audited2", json={"name": "x"}).status_code == 405


# --------------------------------------------------------------------- Create


def test_creating_a_group_reports_what_is_actually_live(client, vpc_id):
    resp = client.post("/resources/security-group?accept_risk=true", json=_open_ssh_spec())
    assert resp.status_code == 201

    body = resp.json()
    assert body["resource_id"].startswith("sg-")
    assert body["problems"] == []
    assert body["counts"]["critical"] == 1


def test_created_group_appears_in_the_list_with_a_severity(client, vpc_id):
    created = client.post("/resources/security-group?accept_risk=true",
                          json=_open_ssh_spec()).json()

    listed = client.get("/resources/security-group").json()["resources"]
    assert len(listed) == 1
    assert listed[0]["id"] == created["resource_id"]
    assert listed[0]["worst_level"] == "critical"


def test_list_can_skip_scanning(client, vpc_id):
    client.post("/resources/security-group?accept_risk=true", json=_open_ssh_spec())

    listed = client.get(
        "/resources/security-group", params={"with_scan": False}
    ).json()["resources"]
    assert listed[0]["counts"] is None


def test_creating_a_bucket_returns_its_live_settings(client):
    resp = client.post("/resources/bucket?accept_risk=true", json={
        "name": "api-test-bucket", "secure_by_default": False,
    })
    assert resp.status_code == 201
    assert resp.json()["counts"]["critical"] > 0


# ------------------------------------------------------------------------ Fix


def test_fixing_a_group_narrows_the_rule_and_clears_the_finding(client, vpc_id):
    """The demo, driven entirely over HTTP."""
    created = client.post("/resources/security-group?accept_risk=true",
                          json=_open_ssh_spec()).json()
    sg_id = created["resource_id"]

    scan = client.get(f"/resources/security-group/{sg_id}").json()
    assert scan["fixable_count"] == 1
    rule_id = scan["warnings"][0]["rule_id"]

    fixed = client.post(f"/resources/security-group/{sg_id}/fix",
                        json={"rule_id": rule_id, "new_cidr": MY_IP})
    assert fixed.status_code == 200, fixed.text
    assert MY_IP in fixed.json()["message"]

    # Not empty: a group nothing is attached to is correctly reported as unused,
    # and a group created through the API is never attached to anything. What
    # matters is that the exposure is gone and there is nothing left to fix.
    after = client.get(f"/resources/security-group/{sg_id}").json()
    assert after["counts"]["critical"] == 0
    assert after["fixable_count"] == 0
    assert {w["level"] for w in after["warnings"]} == {"info"}


def test_fixing_a_bucket_clears_its_criticals(client):
    created = client.post("/resources/bucket?accept_risk=true", json={
        "name": "api-test-bucket", "secure_by_default": False,
    }).json()
    name = created["resource_id"]

    scan = client.get(f"/resources/bucket/{name}").json()
    for w in scan["warnings"]:
        if w["fix"]:
            resp = client.post(f"/resources/bucket/{name}/fix",
                               json={"rule_id": w["rule_id"]})
            assert resp.status_code == 200, resp.text

    after = client.get(f"/resources/bucket/{name}").json()
    assert after["counts"]["critical"] == 0


def test_fixing_an_unknown_rule_id_is_a_404(client, vpc_id):
    created = client.post("/resources/security-group?accept_risk=true",
                          json=_open_ssh_spec()).json()

    resp = client.post(
        f"/resources/security-group/{created['resource_id']}/fix",
        json={"rule_id": "sgr-does-not-exist"},
    )
    assert resp.status_code == 404
    assert "Re-scan" in resp.json()["detail"]


def test_fixing_the_same_rule_twice_fails_the_second_time(client, vpc_id):
    """After the first fix the finding is gone, so the ID no longer resolves.

    This is the stale-page case: two tabs open, both showing the same warning.
    The second click must not act on a rule that is already dealt with.
    """
    created = client.post("/resources/security-group?accept_risk=true",
                          json=_open_ssh_spec()).json()
    sg_id = created["resource_id"]
    rule_id = client.get(
        f"/resources/security-group/{sg_id}"
    ).json()["warnings"][0]["rule_id"]

    first = client.post(f"/resources/security-group/{sg_id}/fix",
                        json={"rule_id": rule_id, "new_cidr": MY_IP})
    assert first.status_code == 200

    second = client.post(f"/resources/security-group/{sg_id}/fix",
                         json={"rule_id": rule_id, "new_cidr": MY_IP})
    assert second.status_code == 404


def test_a_client_supplied_action_is_ignored(client, vpc_id):
    """The server decides what a fix does. The request only names the target.

    Posting "remove" against a finding the scanner marked narrow_to_my_ip must
    narrow it, not delete it. If this ever fails, the API has become a remote
    execution endpoint for whatever the caller feels like.
    """
    created = client.post("/resources/security-group?accept_risk=true",
                          json=_open_ssh_spec()).json()
    sg_id = created["resource_id"]
    rule_id = client.get(
        f"/resources/security-group/{sg_id}"
    ).json()["warnings"][0]["rule_id"]

    resp = client.post(
        f"/resources/security-group/{sg_id}/fix",
        json={"rule_id": rule_id, "new_cidr": MY_IP,
              "fix": {"action": "remove"}, "action": "remove"},
    )
    assert resp.status_code == 200

    live = client.get(f"/resources/security-group/{sg_id}").json()
    assert live["counts"]["critical"] == 0

    ec2 = boto3.client("ec2", region_name="us-east-1")
    rules = sg.read_group_for_scanning(ec2, sg_id)
    assert len(rules) == 1, "the rule was removed instead of narrowed"
    assert rules[0]["source"] == MY_IP


# --------------------------------------------------------- Delete and teardown


def test_deleting_a_group(client, vpc_id):
    created = client.post("/resources/security-group?accept_risk=true",
                          json=_open_ssh_spec()).json()

    resp = client.delete(f"/resources/security-group/{created['resource_id']}")
    assert resp.status_code == 200
    assert client.get("/resources/security-group").json()["resources"] == []


def test_deleting_a_bucket_with_files_needs_force_and_then_confirmation(client):
    # Unhardened deliberately: the CIS 2.1.1 policy denies non-TLS requests and
    # moto serves plain HTTP, so a hardened bucket refuses put_object in-process.
    client.post("/resources/bucket?accept_risk=true", json={"name": "api-test-bucket",
                                           "secure_by_default": False})
    boto3.client("s3", region_name="us-east-1").put_object(
        Bucket="api-test-bucket", Key="notes.txt", Body=b"hello"
    )

    refused = client.delete("/resources/bucket/api-test-bucket")
    assert refused.status_code == 400
    assert "still has files" in refused.json()["detail"]

    # force alone is not enough any more. It destroys every file in the bucket
    # and the caller named none of them, which is the same shape of surprise
    # as a network cascade even though the contents are smaller.
    forced = client.delete("/resources/bucket/api-test-bucket",
                           params={"force": True})
    assert forced.status_code == 400

    confirmed = client.delete("/resources/bucket/api-test-bucket",
                              params={"force": True,
                                      "confirm": "api-test-bucket"})
    assert confirmed.status_code == 200


# ------------------------------------------------- The cascade over HTTP


def _network(client, name="api-test-net"):
    created = client.post("/resources/network", json={"name": name})
    assert created.status_code == 201, created.text
    return created.json()["resource_id"]


def test_the_deletion_plan_lists_what_a_cascade_would_destroy(client):
    """The CLI has printed this list since it was written. Over HTTP the same
    call was a query parameter and no inventory at all."""
    network = _network(client)

    plan = client.get(f"/resources/network/{network}/deletion-plan")
    assert plan.status_code == 200, plan.text
    body = plan.json()

    assert body["preview_available"] is True
    assert body["confirm_with"] == network

    # The network itself goes last, after everything that sits inside it.
    kinds = [item["kind"] for item in body["items"]]
    assert kinds[-1] == "network"
    assert "subnet" in kinds
    assert body["destroys"]["subnet"] == 2

    ids = [item["id"] for item in body["items"]]
    assert network in ids


def test_a_forced_delete_without_confirmation_is_refused(client):
    """force is one character away from being set by accident, by a copied
    example, or by a checkbox nobody read."""
    network = _network(client)

    refused = client.delete(f"/resources/network/{network}",
                            params={"force": True})
    assert refused.status_code == 400

    # Still there.
    assert client.get(f"/resources/network/{network}").status_code == 200


def test_the_refusal_carries_the_plan_so_the_caller_learns_what_it_nearly_did(client):
    network = _network(client)

    refused = client.delete(f"/resources/network/{network}",
                            params={"force": True})
    detail = refused.json()["detail"]

    assert detail["preview_available"] is True
    assert detail["confirm_with"] == network
    assert detail["items"], "the refusal has to say what it stopped"
    assert f"confirm={network}" in detail["message"]


def test_confirming_with_the_wrong_id_is_still_refused(client):
    """Pasting the wrong ID is exactly the mistake this is here to catch."""
    network = _network(client)
    other = _network(client, "api-test-other")

    refused = client.delete(f"/resources/network/{network}",
                            params={"force": True, "confirm": other})
    assert refused.status_code == 400
    assert client.get(f"/resources/network/{network}").status_code == 200


def test_confirming_with_the_right_id_goes_ahead(client):
    network = _network(client)

    deleted = client.delete(f"/resources/network/{network}",
                            params={"force": True, "confirm": network})
    assert deleted.status_code == 200, deleted.text
    assert client.get(f"/resources/network/{network}").status_code == 404


def test_a_type_with_no_preview_says_so_rather_than_showing_an_empty_list(client):
    """An empty table and "cannot tell you" must not render the same way.

    A bucket's forced delete empties it first, so "nothing else would be
    destroyed" would be a lie told in front of the most destructive button
    the interface has.
    """
    client.post("/resources/bucket", json={"name": "api-plan-bucket"})

    plan = client.get("/resources/bucket/api-plan-bucket/deletion-plan").json()
    assert plan["preview_available"] is False
    assert plan["items"] == []
    assert "not the same as saying it would take nothing" in plan["message"]


def test_no_deletion_plan_is_offered_for_a_type_this_tool_only_audits(client):
    refused = client.get("/resources/iam/123456789012/deletion-plan")
    assert refused.status_code == 405


def test_a_deletion_plan_for_something_absent_is_a_404(client):
    missing = client.get("/resources/network/vpc-00000000000000000/deletion-plan")
    assert missing.status_code == 404


def test_a_forced_cleanup_needs_a_token_it_had_to_fetch(client):
    """The loudest endpoint must not be the least guarded one.

    confirm used to be the resource type, which every caller already knows -
    the weakness that made the cross-site hole damaging, because an attacker
    who could not read a single response could still guess "network". The
    token has to be fetched, and fetching means reading a response.
    """
    _network(client, "api-cleanup-net")

    refused = client.post("/resources/network/cleanup", params={"force": True})
    assert refused.status_code == 400
    assert "cleanup-plan" in refused.json()["detail"]

    guessed = client.post("/resources/network/cleanup",
                          params={"force": True, "confirm": "network"})
    assert guessed.status_code == 400

    plan = client.get("/resources/network/cleanup-plan").json()
    assert plan["count"] >= 1
    assert plan["items"], "the preview has to say what would go"

    done = client.post("/resources/network/cleanup",
                       params={"force": True, "confirm": plan["confirm_with"]})
    assert done.status_code == 200


def test_a_cleanup_token_is_good_only_once(client):
    """So a token overheard or replayed cannot be spent twice."""
    token = client.get("/resources/security-group/cleanup-plan").json()["confirm_with"]

    first = client.post("/resources/security-group/cleanup",
                        params={"force": True, "confirm": token})
    assert first.status_code == 200

    again = client.post("/resources/security-group/cleanup",
                        params={"force": True, "confirm": token})
    assert again.status_code == 400


def test_a_cleanup_token_does_not_work_on_another_type(client):
    token = client.get("/resources/security-group/cleanup-plan").json()["confirm_with"]

    wrong = client.post("/resources/network/cleanup",
                        params={"force": True, "confirm": token})
    assert wrong.status_code == 400


def test_an_unforced_cleanup_is_unchanged(client):
    """Without force it refuses anything occupied on its own, so demanding a
    second word for it would be ceremony rather than safety."""
    client.post("/resources/security-group?accept_risk=true", json=_open_ssh_spec("tidy"))

    done = client.post("/resources/security-group/cleanup")
    assert done.status_code == 200
    assert len(done.json()["results"]) == 1


# ------------------------------------------------------- Form options


def test_the_form_is_offered_the_instance_types_the_tool_will_accept(client):
    """The menu cannot disagree with the allowlist, because it is the allowlist.

    A hardcoded list in the page would be a second copy of a refusal that
    lives in aws/instances.py, and an offer the tool then rejects looks like
    a bug rather than a guardrail.
    """
    from aws import instances as ec2i

    body = client.get("/resources/instance/options").json()
    offered = {o["value"] for o in body["options"]["instance_type"]}
    assert offered == set(ec2i.ALLOWED_INSTANCE_TYPES)


def test_the_port_menu_names_a_port_the_way_the_warning_will(client):
    """The phrase someone picks has to appear in the warning they get back.

    This used to demand the scanner's *whole* phrase - "3389 — Remote Desktop,
    the remote login door for Windows servers" - which is right in a finding,
    where there is a sentence to read, and 63 characters in a 133px dropdown.
    Measured, it overflowed by 280px, so the closed menu read "3389 — Remote
    Desktop, the remo…" and the port somebody had just chosen could not be read
    back at all.

    What has to hold is that the two agree, not that they are identical. Every
    menu label is contained in the scanner's phrase for that port, so picking
    "Remote Desktop" and then reading "Remote Desktop, the remote login door
    for Windows servers" is recognisably the same thing.
    """
    from api.registry import PORT_MENU_LABELS
    from scanner.rules import RISKY_PORTS

    body = client.get("/resources/security-group/options").json()
    labels = {o["value"]: o["label"] for o in body["options"]["port"]}

    for port, prose in RISKY_PORTS.items():
        short = PORT_MENU_LABELS[port]
        assert short in prose, f"the menu calls {port} something the warning does not"
        assert short in labels[str(port)]
        assert str(port) in labels[str(port)]

    # 80 and 443 belong in a form but must never be in RISKY_PORTS, since
    # everything there produces a finding.
    assert "443" in labels
    assert 443 not in RISKY_PORTS


def test_networks_are_offered_from_the_account_rather_than_typed(client, vpc_id):
    body = client.get("/resources/security-group/options").json()
    assert vpc_id in {o["value"] for o in body["options"]["vpc_id"]}


def test_a_type_with_nothing_to_offer_answers_empty_rather_than_404(client):
    """So a form can ask unconditionally and fall back to plain text."""
    body = client.get("/resources/bucket/options")
    assert body.status_code == 200
    assert body.json()["options"] == {}


def test_options_for_an_unknown_type_is_still_a_404(client):
    assert client.get("/resources/nonsense/options").status_code == 404


# --------------------------------------------------------- The blueprint


def test_the_blueprint_refuses_to_build_without_supplied_public_keys(client):
    """The endpoint's whole safety property.

    Without keys the blueprint generates them with ssh-keygen, which writes
    private halves to the machine running the code. Over HTTP that is the
    server. Refusing rather than defaulting is what keeps this endpoint from
    being safe only while nobody omits a field.
    """
    refused = client.post("/blueprints/bastion", json={"name": "demo"})
    assert refused.status_code == 400

    detail = refused.json()["detail"]
    assert "bastion-key" in detail and "private-key" in detail
    assert "will not create a private key" in detail


def test_the_blueprint_refuses_when_only_one_key_is_supplied(client):
    refused = client.post("/blueprints/bastion", json={
        "name": "demo",
        "public_keys": {"bastion-key": "ssh-ed25519 AAAA comment"},
    })
    assert refused.status_code == 400
    assert "private-key" in refused.json()["detail"]


def test_the_blueprint_has_no_field_for_a_private_key(client):
    """A caller cannot send one even by accident: the model has nowhere to
    put it, and the page never asks for one."""
    schema = client.get("/openapi.json").json()
    spec = schema["components"]["schemas"]["BastionSpec"]["properties"]
    assert "public_keys" in spec
    assert not [f for f in spec if "private" in f.lower()]


# ------------------------------------------------- Cross-site writes


def test_a_write_from_another_site_is_refused(client):
    """CORS does not cover this, and the gap is the destructive half.

    A POST with no custom header and no JSON body is a simple request: the
    browser sends it without a preflight, so any page in any tab can reach a
    server bound to localhost. CORS then hides the response, which is the
    wrong half - the cleanup already ran.

    POST /resources/{type}/cleanup needs no body at all and its confirm value
    is the resource type, so the most destructive endpoint here was also the
    most reachable.
    """
    refused = client.post(
        "/resources/security-group/cleanup?force=true&confirm=anything",
        headers={"Origin": "https://evil.example"},
    )
    assert refused.status_code == 403
    assert "another site" in refused.json()["detail"]


def test_a_write_from_the_tools_own_page_is_allowed(client):
    allowed = client.post("/resources/security-group/cleanup",
                          headers={"Origin": "http://127.0.0.1:8000"})
    assert allowed.status_code == 200


def test_a_write_with_no_origin_is_allowed(client):
    """curl, the CLI and the smoke test send none, and a hostile page cannot
    suppress the header."""
    allowed = client.post("/resources/security-group/cleanup")
    assert allowed.status_code == 200


def test_a_request_for_a_rebound_hostname_is_refused(client):
    """DNS rebinding: a page at evil.example whose record now points at
    127.0.0.1. The browser treats it as same-origin, so a read carries no
    Origin at all and the Origin check above never fires - but the Host header
    still names what the page actually asked for.

    Checked on reads too, because a same-origin read hands the response to the
    attacking page.
    """
    refused = client.get("/resources", headers={"Host": "evil.example"})
    assert refused.status_code == 403
    assert "rebinding" in refused.json()["detail"]

    written = client.post("/resources/security-group/cleanup",
                          headers={"Host": "evil.example"})
    assert written.status_code == 403


def test_localhost_by_any_of_its_names_is_accepted(client):
    for host in ("127.0.0.1:8000", "localhost:8000", "localhost", "[::1]:8000"):
        assert client.get("/health", headers={"Host": host}).status_code == 200, host


def test_reading_from_another_site_is_not_blocked_here(client):
    """Left to CORS, which is what it is for. A GET changes nothing, and the
    response is withheld from the page by the browser."""
    fine = client.get("/resources", headers={"Origin": "https://evil.example"})
    assert fine.status_code == 200


def test_the_metric_says_its_own_unit(client):
    """Reported twice from screenshots.

    First as a menu of dollar amounts offered while CPU was selected - not a
    cosmetic mismatch, because those numbers are valid for CPUUtilization and
    "$20" would have created an alarm at 20 percent. Then as a sentence under
    the box, which was a line of prose to convey one character.

    The unit is in the label now, where it is already being read, and a
    threshold is typed because any number is legitimate.
    """
    from aws import alarms

    body = client.get("/resources/alarm/options").json()["options"]

    assert "threshold" not in body, "a threshold is typed, not chosen"

    labels = {c["value"]: c["label"] for c in body["namespace"]}
    assert "($)" in labels[alarms.BILLING_NAMESPACE]
    assert "(%)" in labels[alarms.CPU_NAMESPACE]


def test_the_metric_labels_stay_short_enough_to_read(client):
    """They sit in a menu, where anything long is simply cut off."""
    body = client.get("/resources/alarm/options").json()["options"]
    for choice in body["namespace"]:
        assert len(choice["label"]) <= 30, choice["label"]


# --------------------------------------------------------------- The page


def test_the_page_is_served_from_the_same_process_as_the_api(client):
    """One thing to run, and no CORS between the page and its own backend.

    The wordmark is Sanctum rather than the repository's own name. That is the
    page's title only - the CLI, the README and this package are all still
    Secure Cloud Provisioner - so this asserts the page was served rather than
    asserting a product name, and the two scripts below are the substance of
    the check either way.
    """
    page = client.get("/ui/")
    assert page.status_code == 200
    assert "Sanctum" in page.text

    for asset in ("/ui/app.js", "/ui/style.css", "/ui/keygen.js"):
        assert client.get(asset).status_code == 200, asset


def test_the_page_may_not_be_reused_without_asking_first(client):
    """The failure this prevents is a page that is not stale but broken.

    With no Cache-Control header a browser decides for itself how long a file
    stays fresh, and it decides per file - so a load can pair a *new* app.js
    with an *old* style.css. That is markup the stylesheet has never heard of,
    rendering as unstyled fragments: the severity counts arrived as new tally
    elements against a stylesheet with no rule for them and stacked up reading
    "2critical".

    Worth a test rather than a comment because of how it presents. "I
    refreshed and nothing changed" cannot be told from "the change did not
    work", so the next hour goes on looking for a bug in code that is already
    correct.
    """
    # The assets, not the page: /ui/ is served from its own route and is
    # no-store, because it is what carries the versioned URLs and a cached
    # copy of it would pin every asset to yesterday's version.
    for asset in ("/ui/app.js", "/ui/style.css", "/ui/keygen.js"):
        answered = client.get(asset)
        assert "no-cache" in answered.headers.get("cache-control", ""), asset
        # An ETag as well, because no-cache means "ask", and without something
        # to ask about every load would re-send the whole file.
        assert answered.headers.get("etag"), asset


def test_every_asset_url_carries_a_version(client):
    """The header was necessary and was not sufficient.

    Cache-Control governs responses fetched *after* it exists. A browser
    holding style.css from before it was added gives that copy a heuristic
    freshness lifetime and then uses it without asking - so it never sends the
    request that would carry the new header, and refreshing changes nothing.
    Two rounds of "hard-refresh and it will be fine" went that way.

    A URL the cache is not keyed on is what actually forces a fetch. The
    version is the file's mtime, so it changes exactly when the file does:
    edit the stylesheet and every browser gets it once, edit nothing and every
    browser keeps what it has.
    """
    page = client.get("/ui/")
    assert page.status_code == 200

    for asset in ("style.css", "app.js", "keygen.js"):
        assert f'{asset}?v=' in page.text, f"{asset} is unversioned"

    # And the versioned URL is really served, rather than 404ing on the query.
    stamped = re.search(r'href="(style\.css\?v=\d+)"', page.text).group(1)
    assert client.get(f"/ui/{stamped}").status_code == 200


def test_the_version_follows_the_file(client, tmp_path, monkeypatch):
    """A version somebody has to remember to bump is a version that goes
    stale, which is the bug it was added to fix wearing a different hat."""
    from api import app as api_app

    page = client.get("/ui/")
    before = re.search(r'style\.css\?v=(\d+)', page.text).group(1)

    stylesheet = api_app._PAGE / "style.css"
    was = stylesheet.stat().st_mtime
    try:
        os.utime(stylesheet, (was + 500, was + 500))
        after = re.search(r'style\.css\?v=(\d+)',
                          client.get("/ui/").text).group(1)
    finally:
        os.utime(stylesheet, (was, was))

    assert after != before


def test_the_page_itself_is_never_served_from_a_cache(client):
    """It is the one document that carries the new URLs, so a cached copy of
    it pins every asset to the versions it already had."""
    assert "no-store" in client.get("/ui/").headers.get("cache-control", "")


def test_an_unchanged_asset_still_answers_304(client):
    """no-cache is not no-store. The file stays cached; the browser just has
    to check. This is what keeps the cost of the header at one conditional
    request rather than a full re-send on every load."""
    first = client.get("/ui/style.css")
    again = client.get("/ui/style.css",
                       headers={"If-None-Match": first.headers["etag"]})

    assert again.status_code == 304
    assert not again.content


def test_the_root_sends_you_to_the_page(client):
    landing = client.get("/", follow_redirects=False)
    assert landing.status_code in (307, 308)
    assert landing.headers["location"] == "/ui/"


def test_mounting_the_page_did_not_shadow_the_api(client):
    """A mount reorders route matching. The API is the product; the page is
    one caller of it, and must not be able to take a path from it."""
    assert client.get("/health").json() == {"status": "ok"}
    assert client.get("/resources").status_code == 200


def test_cleanup_removes_every_managed_group(client, vpc_id):
    client.post("/resources/security-group?accept_risk=true", json=_open_ssh_spec("one"))
    client.post("/resources/security-group?accept_risk=true", json=_open_ssh_spec("two"))

    results = client.post("/resources/security-group/cleanup").json()["results"]
    assert len(results) == 2
    assert all(r["ok"] for r in results)
    assert client.get("/resources/security-group").json()["resources"] == []


def test_cleanup_leaves_groups_this_tool_did_not_make(client, vpc_id):
    client.post("/resources/security-group?accept_risk=true", json=_open_ssh_spec())
    ec2 = boto3.client("ec2", region_name="us-east-1")
    ec2.create_security_group(GroupName="not-ours", Description="theirs",
                              VpcId=vpc_id)

    client.post("/resources/security-group/cleanup")

    everything = client.get(
        "/resources/security-group", params={"only_ours": False,
                                             "with_scan": False}
    ).json()["resources"]
    assert "not-ours" in [r["name"] for r in everything]


def test_each_type_says_how_its_list_can_be_narrowed(client):
    """Whether a list can be filtered is a different question from whether the
    resource can be changed, and the page used to infer one from the other.

    That held while the audited types were IAM and snapshots. Roles broke it:
    the filter is meaningful there, it just means "written by somebody here"
    rather than "made by this tool" - so the role list showed AWS's own
    service roles with no way to hide them.
    """
    entries = {r["key"]: r for r in client.get("/resources").json()["resources"]}

    # Tagged by this tool, so the default wording is right. azure-storage is
    # here because it tags what it creates with the same key and value the AWS
    # side uses, which is the whole reason its cleanup can be bounded.
    for key in ("security-group", "bucket", "instance", "alarm", "snapshot",
                "azure-storage", "azure-keyvault", "azure-nsg", "azure-vnet",
                "azure-vm"):
        assert entries[key]["only_ours_label"] == "only ones this tool made"

    # Meaningful, but not by tag - this tool creates no roles at all.
    assert entries["role"]["only_ours_label"] == "only ones somebody here wrote"

    # Nothing to narrow: one account. azure-nsg used to be here because
    # nothing created one and so nothing carried the tag; create_nsg changed
    # that, and a filter that silently returns everything is worse on a type
    # this tool can now destroy than on one it could only read.
    for key in ("iam",):
        assert entries[key]["only_ours_label"] is None


def test_a_filterable_type_is_not_decided_by_whether_it_is_read_only(client):
    """The regression this guards: snapshots and roles are both audited and
    both filterable, so read_only cannot be the signal."""
    entries = {r["key"]: r for r in client.get("/resources").json()["resources"]}

    for key in ("snapshot", "role"):
        assert entries[key]["read_only"] is True
        assert entries[key]["only_ours_label"] is not None


# ----------------------------------------------------- what a row is keyed by


AZURE_LISTS = [
    ("azure-nsg", "az.nsg", "list_nsgs"),
    ("azure-storage", "az.storage", "list_accounts"),
    ("azure-keyvault", "az.keyvault", "list_vaults"),
    ("azure-vnet", "az.vnet", "list_vnets"),
    ("azure-vm", "az.vm", "list_vms"),
]


@pytest.mark.parametrize("key,module,func", AZURE_LISTS)
def test_an_azure_row_is_keyed_by_the_identifier_the_routes_accept(
        key, module, func, monkeypatch):
    """A row's id has to survive being one segment of a URL path.

    The list returned the full ARM path, which carries eight slashes, and a
    route takes its id as a single path segment - so /resources/azure-storage/
    <that> matched no route and 404'd before any Azure code ran. The page
    passes a row's id straight into scan, fix and delete, so all three failed
    against a resource it had just created.

    The readers accept either form, which is exactly why the offline suite
    never noticed: every test that called one passed it a name, and every test
    that called a route used a type whose id had no slashes in it.
    """
    import importlib

    from api import registry

    arm = (f"/subscriptions/0000/resourceGroups/rg/providers/"
           f"Microsoft.Whatever/things/thing-one")
    monkeypatch.setattr(importlib.import_module(module), func,
                        lambda *a, **k: [{"id": arm, "name": "thing-one"}])

    known = registry.get(key)
    rows = known.list_all(object(), False)

    assert rows[0]["id"] == "thing-one", (
        f"{key} keyed its row by {rows[0]['id']!r}, which no route accepts"
    )
    assert "/" not in rows[0]["id"], "an id has to be one path segment"

    # Where the thing is travels with it, so the table has something to show
    # besides the name. Asserted as keys rather than values because this stub
    # hands back a resource id with no resource group in it - what matters
    # here is that the adapter carries the fields through rather than
    # dropping them, which is what left the page printing the name twice.
    assert set(rows[0]) == {"id", "name", "resource_group", "location"}


# --------------------------------------------- a deletion plan in either shape


class _Planner:
    """The two attributes _deletion_plan reads off a ResourceType."""

    label = "Azure network security group"

    def __init__(self, plan):
        self._plan = plan

    def plan_deletion(self, client, resource_id):
        return self._plan


AZURE_PLANNERS = [
    ("az.nsg", "read_nsg_for_scanning",
     {"attached_to": ["subnet-a", "nic-b"]}),
    ("az.vnet", "read_vnet_for_scanning",
     {"subnets": [{"name": "default"}]}),
    ("az.vm", "read_vm_for_scanning",
     {"vm_name": "demo", "public_ip": "203.0.113.9"}),
]


@pytest.mark.parametrize("module,reader,settings", AZURE_PLANNERS)
def test_an_azure_deletion_plan_reaches_the_route_without_a_500(
        module, reader, settings, monkeypatch):
    """The producers and the consumer disagreed about the shape, in production.

    AWS returns a flat list of things a delete destroys. All three Azure
    planners return {"items", "destroys", "message"}, and the route did
    DeletionPlanItem(**item) over it - which iterates a dict as its keys and
    raises TypeError on the first one. GET /deletion-plan and DELETE both
    answered 500 for azure-nsg, azure-vnet and azure-vm, so those three could
    not be deleted through the API at all. The offline suite never caught it
    because it exercised the planners and the route separately; this drives the
    real planner into the real route, which is the only place they meet.
    """
    import importlib

    from api.app import _deletion_plan

    mod = importlib.import_module(module)
    monkeypatch.setattr(mod, reader, lambda *a, **k: settings)

    known = _Planner(mod.plan_deletion(object(), "demo"))
    got = _deletion_plan(known, object(), "azure-thing", "demo")

    assert got.preview_available is True
    assert got.confirm_with == "demo"
    # Its own sentence survives. The generic one counts items and says they
    # would be destroyed, which is false of a security group - deleting one
    # destroys nothing and merely stops filtering whatever was behind it.
    assert "To go ahead, repeat the delete with confirm=demo." in got.message
    assert len(got.message) > len("To go ahead, repeat the delete with "
                                  "confirm=demo.")
    for item in got.items:
        assert item.kind and item.id and item.label


def test_the_aws_shape_still_writes_its_own_sentence_from_a_count():
    """The list form is the older contract and must not have shifted."""
    from api.app import _deletion_plan

    known = _Planner([
        {"kind": "server", "id": "i-1", "label": "web",
         "created_by_this_tool": False},
        {"kind": "subnet", "id": "subnet-1", "label": "public",
         "created_by_this_tool": True},
    ])
    got = _deletion_plan(known, object(), "network", "vpc-1")

    assert got.preview_available is True
    assert got.destroys == {"server": 1, "subnet": 1}
    assert got.foreign_count == 1
    assert "Deleting this would destroy 2 things." in got.message
    assert "1 running machine would be terminated" in got.message


def test_a_planner_that_cannot_read_the_resource_says_there_is_no_preview():
    """None must not become an empty inventory in front of a delete button."""
    from api.app import _deletion_plan

    got = _deletion_plan(_Planner(None), object(), "azure-nsg", "gone")

    assert got.preview_available is False
    assert got.items == []


def test_a_size_this_subscription_cannot_start_is_not_offered(monkeypatch):
    """The menu is a claim about what will work, and it was not one.

    Azure restricts sizes per subscription as well as per region and reports
    both as SkuNotAvailable, so ALLOWED_VM_SIZES is what this tool permits
    rather than what any given subscription can launch. Against the real one
    the form offered fourteen and nine of them could not start - including the
    three Standard_B1* entries at the top of the list, which is what somebody
    picks. az/vm.py already knew the answer; the form was not asking it.
    """
    from api import registry
    from az import vm as az_vm

    monkeypatch.setattr(
        az_vm, "offered_sizes",
        lambda client, location: [{"name": "Standard_F1als_v7",
                                   "vcpus": 1, "memory_gb": 2}])

    offered = registry.get("azure-vm").options(object())["vm_size"]

    assert [o["value"] for o in offered] == ["Standard_F1als_v7"]

    # And the label says what the machine is, not only what Azure calls it.
    # "Standard_F1als_v7" and "Standard_F1as_v7" differ by one letter and by
    # twice the memory; nobody chooses correctly between those from the name.
    assert offered[0]["label"] == "Standard_F1als_v7 — 1 core, 2 GB memory"


def test_an_unanswerable_size_lookup_falls_back_rather_than_emptying_the_menu():
    """offered_sizes never raises and returns [] when it cannot tell.

    An empty menu is a dead form. The allowlist is the honest second answer:
    it is still every size this tool permits, and the create refuses anything
    outside it either way.
    """
    from api import registry
    from az import vm as az_vm

    import pytest as _pytest
    with _pytest.MonkeyPatch.context() as mp:
        mp.setattr(az_vm, "available_sizes", lambda client, location: [])
        offered = registry.get("azure-vm").options(object())["vm_size"]

    assert [o["value"] for o in offered] == sorted(az_vm.ALLOWED_VM_SIZES)


# ------------------------------------------------- the machine form's fields


def test_a_machine_form_asking_to_open_ssh_to_the_world_is_reported_critical(client):
    """The pre-flight said 0 critical about the one thing this type is for.

    ResourceSpec declared no open_ports, no allowed_source and no vm_size, and
    pydantic drops what a model does not declare - so check_vm_spec built its
    rule list from an empty `open_ports` every time and found nothing to warn
    about. A form asking for port 22 open to the entire internet on a machine
    with a public address came back clean, which is the tool actively saying
    the dangerous configuration is safe.
    """
    body = client.post("/resources/azure-vm/check", json={
        "name": "probe",
        "resource_group": "rg",
        "location": "eastus",
        "vm_size": "Standard_F1als_v7",
        "public_key": "ssh-ed25519 AAAA",
        "open_ports": ["22"],
        "allowed_source": "*",
        "assign_public_ip": True,
    }).json()

    assert body["counts"]["critical"] >= 1
    assert any("22" in w["message"] for w in body["warnings"])


def test_the_same_form_without_a_public_address_is_not_critical(client):
    """The severity depends on reachability, so the rule has to still do that.

    Guards against 'fixed' meaning 'now always critical'.
    """
    body = client.post("/resources/azure-vm/check", json={
        "name": "probe",
        "resource_group": "rg",
        "location": "eastus",
        "open_ports": ["22"],
        "allowed_source": "*",
        "assign_public_ip": False,
    }).json()

    assert body["counts"]["critical"] == 0


def test_the_machine_fields_survive_the_spec_model(client):
    """Every field the form submits has to reach the adapter that reads it.

    Asserted on the model rather than through a create, because the create
    talks to Azure. _az_vm_create reads all four of these by name.
    """
    spec = models_module().ResourceSpec(
        name="m", resource_group="rg", vm_size="Standard_F1als_v7",
        open_ports=["22", "443"], allowed_source="*",
        encryption_at_host=True,
    ).as_dict()

    assert spec["vm_size"] == "Standard_F1als_v7"
    assert spec["open_ports"] == ["22", "443"]
    assert spec["allowed_source"] == "*"
    assert spec["encryption_at_host"] is True


def test_a_password_cannot_be_asked_for_over_http():
    """The refusal in az/vm.py is only half of it if the model accepts one.

    check_vm_spec reads allow_password_login with a default of False, so the
    field staying undeclared is what keeps the HTTP surface unable to request
    password login at all.
    """
    spec = models_module().ResourceSpec(
        name="m", resource_group="rg", allow_password_login=True,
    ).as_dict()

    assert "allow_password_login" not in spec


def models_module():
    from api import models
    return models


# ------------------------------------------------------- which cloud a type is


def test_every_type_declares_which_cloud_it_belongs_to(client):
    """The page shows one cloud at a time and must not guess from the key.

    Matching on an "azure-" prefix would be the frontend inferring a provider
    from a naming convention nothing enforces, and it would need editing again
    for a third cloud - which is the one thing adding a second was meant to
    prove unnecessary.
    """
    entries = {r["key"]: r for r in client.get("/resources").json()["resources"]}

    azure = {"azure-nsg", "azure-storage", "azure-keyvault", "azure-vnet",
             "azure-vm", "azure-monitor"}
    for key, entry in entries.items():
        assert entry["provider"] in {"aws", "azure"}, key
        assert entry["provider"] == ("azure" if key in azure else "aws"), key


def test_a_short_label_is_offered_for_somewhere_the_cloud_is_already_known(client):
    """Every Azure label starts with the word Azure, and in a one-cloud column
    that is a word repeated in every row. The long label stays for the CLI,
    which lists all fourteen types together and needs it."""
    entries = {r["key"]: r for r in client.get("/resources").json()["resources"]}

    assert entries["azure-storage"]["label"] == "Azure storage account"
    assert entries["azure-storage"]["short_label"] == "Storage account"

    # Everything else already was short, and must still answer the question
    # rather than being absent and making the caller fall back.
    assert entries["bucket"]["short_label"] == entries["bucket"]["label"]
    for entry in entries.values():
        assert entry["short_label"]


def test_the_body_the_firewall_form_sends_is_a_body_this_route_accepts(client):
    """The exact shape frontend/app.js builds for an Azure security group.

    Written because the two halves silently disagreed once. The widget sent
    `rules` with a `source` field, which is the AWS spelling; the model keeps
    Azure rules under `azure_rules` with `source_address_prefix`, and
    ResourceSpec ignores fields a resource does not use. So the route accepted
    the request, `_az_nsg_create` read an empty `azure_rules`, and Azure built
    a group with none of the rules in it and reported success. The page said
    it worked. Only a real subscription disagreed.

    A jsdom stub cannot catch that - it answers whatever it is sent. This
    can, because it validates against the model the route actually uses.
    """
    body = {
        "name": "scp-form-shaped",
        "resource_group": "scp-demo",
        "location": "eastus",
        "azure_rules": [
            {"name": "deny-ssh", "direction": "Inbound", "access": "Deny",
             "protocol": "Tcp", "destination_port_range": "22",
             "source_address_prefix": "*"},
            {"name": "allow-https", "direction": "Inbound", "access": "Allow",
             "protocol": "Tcp", "destination_port_range": "443",
             "source_address_prefix": "*"},
        ],
    }

    spec = models.ResourceSpec(**body)
    assert spec.azure_rules is not None, "the model dropped the rules"
    assert len(spec.azure_rules) == 2

    # Order is precedence and must survive the round trip, because az/nsg
    # numbers the priorities from it.
    assert [r.name for r in spec.azure_rules] == ["deny-ssh", "allow-https"]
    assert spec.azure_rules[0].access == "Deny"

    # And the adapter reads the same key. A create that reached Azure with an
    # empty list is exactly the failure above.
    passed = spec.as_dict().get("azure_rules")
    assert passed and len(passed) == 2, "the adapter would receive no rules"


def test_an_aws_shaped_rule_is_not_accepted_as_an_azure_one(client):
    """The mistake itself, pinned. `source` is the AWS field; an Azure rule
    needs `source_address_prefix`, and a model that quietly accepted the AWS
    spelling would put the drift back."""
    with pytest.raises(Exception):
        models.AzureSecurityRule(name="x", source="*",
                                 destination_port_range="22")
# ------------------------------------------- the region a pre-flight judges by


def test_a_billing_alarm_in_the_wrong_region_is_refused_from_the_page(client):
    """The guardrail was reachable only by a caller who knew to bypass the form.

    Region arrives as a query parameter, not in the body, so `spec["region"]`
    was always None and billing_wrong_region could not fire at all. A billing
    alarm built in us-west-2 pre-flighted as 0 critical and was created - and
    AWS publishes spending figures only to us-east-1, so it then sat in
    INSUFFICIENT_DATA forever, which is the state the rule's own text calls
    "easy to read as nothing is wrong".
    """
    spec = {"name": "spend", "namespace": "AWS/Billing",
            "metric_name": "EstimatedCharges", "threshold": 5, "notify": True}

    right = client.post("/resources/alarm/check?region=us-east-1", json=spec).json()
    assert right["counts"]["critical"] == 0

    wrong = client.post("/resources/alarm/check?region=us-west-2", json=spec).json()
    assert wrong["counts"]["critical"] == 1
    assert "us-west-2" in wrong["warnings"][0]["message"]

    # And the create refuses rather than building something that cannot work.
    refused = client.post("/resources/alarm?region=us-west-2", json=spec)
    assert refused.status_code == 400


def test_a_region_stated_in_the_body_still_wins(client):
    """setdefault, not assignment: a caller who said so meant it."""
    body = client.post("/resources/alarm/check?region=us-east-1", json={
        "name": "spend", "namespace": "AWS/Billing",
        "metric_name": "EstimatedCharges", "threshold": 5, "notify": True,
        "region": "eu-west-1",
    }).json()

    assert body["counts"]["critical"] == 1
    assert "eu-west-1" in body["warnings"][0]["message"]


def test_an_azure_spec_does_not_get_an_aws_region_injected(client):
    """`region` on an Azure spec carries the location.

    _az_vm_create reads `spec.get("region") or spec.get("location")`, so
    injecting the AWS query parameter here would try to build a storage
    account in "us-east-1" - a place Azure has never heard of - for anybody
    who left the location blank.
    """
    from api import registry as registry_module
    from api.app import _spec_for_checking
    from api import models as models_module

    spec = models_module.ResourceSpec(name="acct", resource_group="rg")

    azure = _spec_for_checking(registry_module.get("azure-storage"), spec,
                               "us-east-1")
    assert "region" not in azure or azure["region"] != "us-east-1"

    aws = _spec_for_checking(registry_module.get("alarm"), spec, "us-east-1")
    assert aws["region"] == "us-east-1"


# ------------------------------------------------------------ Acknowledgements
#
# The route that reverses this project's longest-standing refusal. It exists
# because the demo feedback was that the CLI should be minimal, and the CLI was
# the only way to record intent. What replaces the old "no endpoint writes
# these" rule is the set of guards exercised below - most importantly that the
# server re-scans and refuses a rule id its own scan does not report.


@pytest.fixture
def somewhere_to_write(tmp_path, monkeypatch):
    """A file per test. Without this the suite writes the real one."""
    where = tmp_path / "acknowledged.json"
    monkeypatch.setenv("SCP_ACKNOWLEDGED", str(where))
    return where


def _a_group_with_ssh_open(client, vpc_id, name="ack-test-sg"):
    """Creates a group with a finding on it, and returns its id and rule id."""
    spec = _open_ssh_spec(name) | {"vpc_id": vpc_id}
    made = client.post("/resources/security-group?accept_risk=true", json=spec)
    assert made.status_code in (200, 201), made.text
    group_id = made.json()["resource_id"]

    scanned = client.get(f"/resources/security-group/{group_id}")
    assert scanned.status_code == 200, scanned.text
    ids = [w["rule_id"] for w in scanned.json()["warnings"] if w.get("rule_id")]
    assert ids, "the group should report at least one finding with an id"
    return group_id, ids[0]


def _body(group_id, rule_id, **overrides):
    return {
        "resource_type": "security-group",
        "resource_id": group_id,
        "rule_id": rule_id,
        "reason": "this host is a deliberate jump box, reviewed in August",
        "by": "richard",
        "confirm": rule_id,
    } | overrides


def test_acknowledging_a_finding_marks_it_without_removing_it(
        client, vpc_id, somewhere_to_write):
    """The property the whole feature rests on: quieter, never absent."""
    group_id, rule_id = _a_group_with_ssh_open(client, vpc_id)

    written = client.post("/acknowledgements", json=_body(group_id, rule_id))
    assert written.status_code == 200, written.text
    assert written.json()["ok"] is True

    again = client.get(f"/resources/security-group/{group_id}").json()
    marked = [w for w in again["warnings"] if w.get("rule_id") == rule_id]
    assert len(marked) == 1, "the finding is still reported"
    assert marked[0]["acknowledged"]["by"] == "richard"
    # Still counted at its own severity, which is what stops this being a
    # suppression list that empties the screen.
    assert again["counts"]["acknowledged"] == 1


def test_an_acknowledgement_can_be_taken_back_through_the_api(
        client, vpc_id, somewhere_to_write):
    """A decision somebody made has to be one somebody can unmake.

    Without this the only way out of a stale entry was editing the file by
    hand, which is the position the write path was moved away from for exactly
    the same reason: a documented feature whose only route is a text editor is
    one most people never use.
    """
    group_id, rule_id = _a_group_with_ssh_open(client, vpc_id, "ack-undo-sg")
    client.post("/acknowledgements", json=_body(group_id, rule_id))

    marked = client.get(f"/resources/security-group/{group_id}").json()
    assert marked["counts"]["acknowledged"] == 1

    undone = client.delete(
        f"/acknowledgements/{rule_id}", params={"confirm": rule_id})
    assert undone.status_code == 200, undone.text
    # The reason comes back with it. The file no longer holds it and this
    # response is the last place it exists.
    assert "deliberate jump box" in undone.json()["message"]

    after = client.get(f"/resources/security-group/{group_id}").json()
    still = [w for w in after["warnings"] if w.get("rule_id") == rule_id]
    assert len(still) == 1, "the finding was never removed, only un-dimmed"
    assert not still[0].get("acknowledged")
    assert after["counts"]["acknowledged"] == 0
    assert after["counts"]["critical"] == marked["counts"]["critical"], (
        "and its severity never depended on being accepted")


def test_taking_back_an_acknowledgement_still_names_the_rule_twice(
        client, vpc_id, somewhere_to_write):
    """Lighter guards than the write, but not none.

    Nothing here re-scans or asks for a reason: every one of those exists to
    make *quietening* a finding expensive, and this direction only makes one
    louder. confirm stays because it is the one thing separating a request
    meaning this acknowledgement from one cross-wired to a different one.
    """
    group_id, rule_id = _a_group_with_ssh_open(client, vpc_id, "ack-undo2-sg")
    client.post("/acknowledgements", json=_body(group_id, rule_id))

    refused = client.delete(f"/acknowledgements/{rule_id}",
                            params={"confirm": "yes"})
    assert refused.status_code == 400
    assert "confirm" in refused.json()["detail"]

    still = client.get(f"/resources/security-group/{group_id}").json()
    assert still["counts"]["acknowledged"] == 1, "and nothing was removed"


def test_taking_back_one_that_was_never_written_says_so(
        client, somewhere_to_write):
    """A 404 rather than a cheerful no-op: "there was nothing to undo" and "it
    is undone" are different answers and the caller acted on one of them."""
    gone = client.delete("/acknowledgements/bucket:invented",
                         params={"confirm": "bucket:invented"})

    assert gone.status_code == 404
    assert "nothing to take back" in gone.json()["detail"]


def test_a_rule_the_scan_does_not_report_is_refused(
        client, vpc_id, somewhere_to_write):
    """The guard with no CLI equivalent, and the strongest one here.

    The server re-scans rather than believing the request, so an entry cannot
    be written for a finding that does not exist.
    """
    group_id, _ = _a_group_with_ssh_open(client, vpc_id, "ack-invented-sg")

    refused = client.post("/acknowledgements",
                          json=_body(group_id, "security-group:invented"))

    assert refused.status_code == 400
    assert "Nothing in the current scan" in refused.json()["detail"]
    assert not somewhere_to_write.exists(), "nothing should have been written"


def test_the_rule_id_has_to_be_repeated(client, vpc_id, somewhere_to_write):
    """The demand every forced delete here already makes."""
    group_id, rule_id = _a_group_with_ssh_open(client, vpc_id, "ack-confirm-sg")

    refused = client.post("/acknowledgements",
                          json=_body(group_id, rule_id, confirm="yes"))

    assert refused.status_code == 400
    assert "confirm" in refused.json()["detail"]
    assert not somewhere_to_write.exists()


def test_a_reason_nobody_could_check_is_refused(
        client, vpc_id, somewhere_to_write):
    """A reason is read later by somebody deciding whether it still holds."""
    group_id, rule_id = _a_group_with_ssh_open(client, vpc_id, "ack-reason-sg")

    refused = client.post("/acknowledgements",
                          json=_body(group_id, rule_id, reason="fine"))

    assert refused.status_code == 400
    assert not somewhere_to_write.exists()


def test_an_expiry_beyond_the_cap_is_refused(
        client, vpc_id, somewhere_to_write):
    """A far-future date turns the expiry off while leaving it looking on."""
    group_id, rule_id = _a_group_with_ssh_open(client, vpc_id, "ack-expiry-sg")

    refused = client.post("/acknowledgements",
                          json=_body(group_id, rule_id, until="2100-06-07"))

    assert refused.status_code == 400
    assert not somewhere_to_write.exists()


def test_acknowledging_is_refused_from_another_site(
        client, vpc_id, somewhere_to_write):
    """The objection the old design was built around, answered by middleware.

    This is the attack the "no endpoint writes acknowledgements" rule existed
    to prevent: a page on another origin quietly suppressing a critical
    finding on a tool with no login. It is refused before the route runs, by
    the same middleware that guards every destructive path here.
    """
    group_id, rule_id = _a_group_with_ssh_open(client, vpc_id, "ack-origin-sg")

    refused = client.post("/acknowledgements", json=_body(group_id, rule_id),
                          headers={"Origin": "http://evil.example"})

    assert refused.status_code == 403
    assert not somewhere_to_write.exists()


# ------------------------------------------------ Watching a delete happen
#
# A cascade with running machines spends four or five minutes inside one
# request, nearly all of it waiting for AWS to detach network interfaces. The
# page showed nothing for the whole of it, which is indistinguishable from a
# hang and was reported as one.


def test_a_streamed_delete_reports_its_steps_then_the_outcome(client, vpc_id):
    """The stream is newline-delimited JSON: steps, then one final object."""
    made = client.post("/resources/network?accept_risk=true",
                       json={"name": "stream-delete-vpc", "cidr": "10.9.0.0/16"})
    assert made.status_code in (200, 201), made.text
    new_vpc = made.json()["resource_id"]

    answered = client.request(
        "DELETE",
        f"/resources/network/{new_vpc}?force=true&confirm={new_vpc}&stream=true")

    assert answered.status_code == 200
    assert "ndjson" in answered.headers["content-type"]

    lines = [json.loads(l) for l in answered.text.splitlines() if l.strip()]
    steps = [l["step"] for l in lines if "step" in l]
    final = [l for l in lines if l.get("done")]

    assert steps, "the cascade names its steps and used to throw them away"
    assert any("subnets" in s for s in steps)
    assert len(final) == 1, "exactly one closing object"
    assert final[0]["ok"] is True
    assert new_vpc in final[0]["message"]
    # The outcome arrives last, so a reader can take the final object as the
    # answer without having to know how many steps there were.
    assert lines[-1] is final[0]


def test_the_unstreamed_delete_is_unchanged(client, vpc_id):
    """Everything already calling this wants one answer.

    The CLI, the smoke test and every other test here read a JSON body with
    ok and message on it. Streaming is opt-in precisely so none of them had to
    change.
    """
    made = client.post("/resources/network?accept_risk=true",
                       json={"name": "plain-delete-vpc", "cidr": "10.8.0.0/16"})
    new_vpc = made.json()["resource_id"]

    answered = client.request(
        "DELETE", f"/resources/network/{new_vpc}?force=true&confirm={new_vpc}")

    assert answered.status_code == 200
    assert answered.json()["ok"] is True
    assert "application/json" in answered.headers["content-type"]


def test_a_streamed_delete_still_refuses_before_it_streams(client, vpc_id):
    """The confirm guard runs before the response begins.

    It has to: a streamed body has already sent 200 by the time the first step
    is written, so a refusal discovered partway through could not change the
    status. Everything that can refuse this does so first, which is why the
    page can still show a 400 with the deletion plan in it.
    """
    made = client.post("/resources/network?accept_risk=true",
                       json={"name": "refuse-stream-vpc", "cidr": "10.7.0.0/16"})
    new_vpc = made.json()["resource_id"]

    answered = client.request(
        "DELETE",
        f"/resources/network/{new_vpc}?force=true&confirm=wrong&stream=true")

    assert answered.status_code == 400
    assert answered.json()["detail"]["confirm_with"] == new_vpc

    # And nothing was destroyed on the way to saying so.
    still = client.get(f"/resources/network/{new_vpc}")
    assert still.status_code == 200


# ------------------------------------------------------------------ Activity


def test_activity_reports_what_was_done_and_what_was_refused(client, tmp_path,
                                                             monkeypatch):
    """Written since the first commit and never readable until now.

    The refusals are the half of this tool's behaviour that leaves no trace
    anywhere else: CloudTrail records that an API call happened and cannot
    record that somebody asked for a cascade, failed to type the ID back, and
    was stopped. A log nobody can see is a file somebody has to know about and
    go and find.
    """
    log = tmp_path / "audit.log"
    monkeypatch.setenv("SCP_AUDIT_LOG", str(log))

    # A refusal: force without the id repeated back.
    refused = client.request("DELETE", "/resources/network/vpc-nope?force=true")
    assert refused.status_code in (400, 404)

    answered = client.get("/activity")
    assert answered.status_code == 200

    entries = answered.json()["activity"]
    assert entries, "the refusal should be recorded"
    assert entries[0]["path"] == "/resources/network/vpc-nope"
    assert entries[0]["method"] == "DELETE"


def test_activity_is_newest_first_and_bounded(tmp_path, monkeypatch):
    """A page asking for twelve lines should not read a log of a hundred
    thousand, and should get the twelve that just happened."""
    log = tmp_path / "audit.log"
    monkeypatch.setenv("SCP_AUDIT_LOG", str(log))

    for n in range(40):
        audit.record(method="POST", path=f"/thing/{n}", outcome="done")

    found = audit.read_recent(limit=5)
    assert [e["path"] for e in found] == [f"/thing/{n}"
                                          for n in (39, 38, 37, 36, 35)]


def test_a_truncated_line_does_not_take_the_panel_with_it(tmp_path, monkeypatch):
    """The writer never raises, so a line cut short by a full disk is a thing
    that can exist. One bad line should cost one line."""
    log = tmp_path / "audit.log"
    monkeypatch.setenv("SCP_AUDIT_LOG", str(log))

    audit.record(method="POST", path="/first", outcome="done")
    with log.open("a", encoding="utf-8") as handle:
        handle.write('{"at": "2026-08-15T00:00:00", "method": "POST"\n')
    audit.record(method="POST", path="/last", outcome="done")

    found = audit.read_recent()
    assert [e["path"] for e in found] == ["/last", "/first"]


def test_an_absent_log_is_empty_rather_than_an_error(tmp_path, monkeypatch):
    """A tool that has changed nothing has no log, and that is not a fault."""
    monkeypatch.setenv("SCP_AUDIT_LOG", str(tmp_path / "never-written.log"))
    assert audit.read_recent() == []


# ------------------------------------- the create sees the request that ran


@pytest.mark.parametrize("region", ["us-west-2", "eu-west-1"])
def test_a_bucket_is_created_in_the_region_that_was_chosen(client, region,
                                                           monkeypatch):
    """The region reached the pre-flight and not the create.

    `region` is a query parameter and never a body field, and
    _spec_for_checking injected it for the check while the create was handed a
    bare spec.as_dict(). So _bucket_create fell through to DEFAULT_REGION
    "us-east-1" while the client was built for the region actually asked for,
    and create_bucket branches on that argument rather than on the client: it
    omits CreateBucketConfiguration for us-east-1, which a regional endpoint
    rejects. Every bucket outside us-east-1 failed, quoting raw AWS text at
    somebody who had picked a region from a menu.

    Asserted on the argument the cloud call receives rather than on where the
    bucket ended up, because moto takes the location from the client and
    records the right answer even when the argument is wrong - so the
    end-to-end version of this test passes against the bug. Real S3 rejects
    the mismatch outright, which is how this was found.
    """
    seen = {}
    real = registry.s3.create_bucket

    def spy(s3_client, bucket_name, region=None, **kw):
        seen["region"] = region
        return real(s3_client, bucket_name, region=region, **kw)

    monkeypatch.setattr(registry.s3, "create_bucket", spy)

    made = client.post(f"/resources/bucket?region={region}",
                       json={"name": f"scp-region-{region}",
                             "secure_by_default": True})
    assert made.status_code in (200, 201), made.text
    assert seen["region"] == region


def test_a_server_is_launched_from_the_chosen_regions_own_image(client,
                                                                monkeypatch):
    """The same defect as the bucket, in the type that costs money.

    `launch_instance` does `latest_ami(region, ...)`, and an AMI id is
    region-specific. With the region missing from the create's spec it was
    pinned to DEFAULT_REGION while the EC2 client was built for the region
    actually chosen, so a machine launched anywhere but us-east-1 was handed a
    us-east-1 image id and RunInstances answers InvalidAMIID.NotFound.

    It went unnoticed because `instance` is the one type nobody creates while
    testing - it is the one that spends money - so the failure sat behind the
    same fix the bucket needed and was never seen on its own.
    """
    seen = {}
    monkeypatch.setattr(
        registry.ec2i, "launch_instance",
        lambda ec2, name, region="us-east-1", **kw: (
            seen.update(region=region, client_region=ec2.meta.region_name)
            or (False, "not launched", [])))

    client.post("/resources/instance?region=us-west-2&accept_risk=true",
                json={"name": "scp-ami", "instance_type": "t3.micro"})

    assert seen["region"] == "us-west-2"
    assert seen["region"] == seen["client_region"]


def test_the_pre_flight_and_the_create_judge_the_same_request(client, monkeypatch):
    """Two calls built two dicts and only one carried the region.

    Asserted on the dicts rather than on a symptom, because the symptom was
    S3-specific and the divergence was not: any rule reading a field the check
    is given and the create is not would pass its own test and mislead here.
    """
    seen = {}
    # ResourceType is frozen, so the spy is a replaced copy put into the
    # registry rather than two attributes patched onto the real one.
    spy = dataclasses.replace(
        registry.get("bucket"),
        check_spec=lambda spec: (seen.update(check=dict(spec)) or []),
        create=lambda c, spec: (seen.update(create=dict(spec))
                                or (True, "b", [])),
    )
    monkeypatch.setitem(registry.REGISTRY, "bucket", spy)

    client.post("/resources/bucket?region=eu-west-1",
                json={"name": "scp-same-request", "secure_by_default": True})
    assert seen["check"] == seen["create"]
    assert seen["create"]["region"] == "eu-west-1"


def test_an_azure_create_answers_with_an_id_its_own_routes_accept(monkeypatch):
    """Azure hands back an ARM path; a route takes an id as one segment.

    So read, scan, fix, the deletion plan and delete all 404'd on the id the
    create had just returned, before any Azure code ran - a resource built
    from the page could not then be deleted from the page. The list adapters
    were fixed for this and the create adapters were not, which is why nothing
    caught it: a list-then-act flow works and a create-then-act flow does not.
    """
    arm = ("/subscriptions/x/resourceGroups/scp-demo/providers"
           "/Microsoft.Network/virtualNetworks/demo-net")
    monkeypatch.setattr(registry.az_vnet, "create_vnet",
                        lambda *a, **k: (True, arm, []))

    ok, resource_id, _ = registry.get("azure-vnet").create(
        None, {"name": "demo-net", "resource_group": "scp-demo"})
    assert ok
    assert resource_id == "demo-net"


def test_a_refused_azure_create_keeps_its_whole_error(monkeypatch):
    """Shortening the id must not touch the error half.

    An adapter answers (ok, id_or_error, problems) on one channel, so a
    refusal is a sentence sitting where an id sits. A sentence containing a
    slash, trimmed to its last word, would be an error message destroyed by a
    fix aimed at something else.
    """
    refusal = "Azure puts every resource in a group, and/or none was named."
    monkeypatch.setattr(registry.az_vnet, "create_vnet",
                        lambda *a, **k: (False, refusal, ["built: nothing"]))

    ok, message, problems = registry.get("azure-vnet").create(
        None, {"name": "demo-net", "resource_group": "scp-demo"})
    assert ok is False
    assert message == refusal
    assert problems == ["built: nothing"]


def test_the_location_the_azure_form_asks_for_is_the_one_used(monkeypatch):
    """All five Azure forms ask for `location` and the model declared only
    `region`, so pydantic dropped it and every resource was built in the
    default: westeurope typed, eastus built, reported as success."""
    seen = {}
    monkeypatch.setattr(
        registry.az_storage, "create_account",
        lambda c, n, g, location=None, **k: (seen.update(location=location)
                                             or (True, f"/x/y/{n}", [])))
    make = registry.get("azure-storage").create

    make(None, {"name": "a", "resource_group": "g", "location": "westeurope"})
    assert seen["location"] == "westeurope"

    # region still wins: it is what the CLI and the smoke test have always sent.
    make(None, {"name": "a", "resource_group": "g",
                "region": "uksouth", "location": "westeurope"})
    assert seen["location"] == "uksouth"

    make(None, {"name": "a", "resource_group": "g"})
    assert seen["location"] == registry.DEFAULT_AZURE_LOCATION


def test_choosing_cpu_builds_an_alarm_that_watches_cpu(monkeypatch):
    """The menu chooses a namespace and a metric together, and only the
    namespace was carried: metric_name fell back to EstimatedCharges
    unconditionally, so "CPU usage (%)" built an alarm on AWS/EC2 +
    EstimatedCharges. That pair has no data, CloudWatch accepts it without
    complaint, and it sits in INSUFFICIENT_DATA forever - the exact silence
    scanner/alarm_rules.py exists to report, and could not, because no rule
    reads metric_name."""
    seen = {}
    monkeypatch.setattr(registry.alarms, "create_alarm",
                        lambda c, **kw: (seen.update(kw) or (True, kw["name"], [])))
    make = registry.get("alarm").create

    make(None, {"name": "cpu", "namespace": registry.alarms.CPU_NAMESPACE,
                "threshold": 80})
    assert seen["metric_name"] == registry.alarms.CPU_METRIC

    make(None, {"name": "spend", "namespace": registry.alarms.BILLING_NAMESPACE,
                "threshold": 5})
    assert seen["metric_name"] == registry.alarms.BILLING_METRIC

    # An explicit metric still wins, because the CLI and smoke test send one.
    make(None, {"name": "custom", "namespace": registry.alarms.CPU_NAMESPACE,
                "metric_name": "NetworkIn", "threshold": 1})
    assert seen["metric_name"] == "NetworkIn"


def test_the_launch_preflight_does_not_call_a_firewall_sound_unread(client):
    """It said "They currently look sound" about rules nobody had opened.

    `_instance_check_spec` calls check_instance with no firewall findings,
    because check_spec is a pure function of a spec and has no client to read
    groups with. That made exposed_ports empty, which sent every public-address
    launch to the branch that reports the firewall as fine. Naming a real
    group, naming one that does not exist, and naming none at all produced
    byte-identical output - proof the groups were never consulted, and the
    reassurance was about nothing.

    This is the AWS twin of the azure-vm defect this file already covers: the
    tool declaring safe the exact configuration the type exists to warn about.
    """
    def check(groups):
        return client.post("/resources/instance/check?region=us-east-1", json={
            "name": "probe", "instance_type": "t3.micro",
            "assign_public_ip": True, "security_group_ids": groups,
        }).json()

    body = check(["sg-real"])
    ids = [w["rule_id"] for w in body["warnings"]]

    assert "probe:firewall_not_examined" in ids, (
        "the pre-flight says the rules were not read")
    assert "probe:public_ip" not in ids, (
        "and does not also claim they look sound")
    assert body["counts"]["warning"] >= 1, (
        "an unread firewall on a machine that would be reachable is not a "
        "zero-warning launch")

    # Still silent where there is nothing to be unsure about: no public
    # address means the rules cannot let anyone in whether they were read or
    # not, and a warning there would be noise on every private machine.
    quiet = client.post("/resources/instance/check?region=us-east-1", json={
        "name": "probe", "instance_type": "t3.micro",
        "assign_public_ip": False,
    }).json()
    assert not any(w["rule_id"] == "probe:firewall_not_examined"
                   for w in quiet["warnings"])


def test_a_live_scan_still_says_the_firewall_looks_sound_when_it_read_them(
        client):
    """The other half. [] means read and clean, and that verdict is earned -
    a fix that made every instance report an unread firewall would have
    replaced a false reassurance with a false doubt."""
    from scanner.instance_rules import check_instance

    warnings = check_instance(
        {"instance_id": "i-1", "name": "i-1", "public_ip": "203.0.113.10",
         "imdsv2_required": True, "metadata_endpoint_enabled": True,
         "metadata_hop_limit": 1, "root_volume_encrypted": True,
         "key_name": "k", "ssh_reachable": True},
        [],
    )
    ids = [w["rule_id"] for w in warnings]
    assert "i-1:public_ip" in ids
    assert "i-1:firewall_not_examined" not in ids


def test_a_namespace_with_no_known_metric_is_refused_rather_than_guessed(
        monkeypatch):
    """The first fix for the above ended `return BILLING_METRIC`, which pairs
    any third namespace with EstimatedCharges and rebuilds the same silent
    alarm the moment one is added - the defect reproduced by its own repair.

    Refused rather than guessed, because a wrong pairing says nothing and a
    refusal says what to send. The mapping answers None and the adapter turns
    that into the error half of (ok, error, problems), so nothing reaches
    CloudWatch at all.
    """
    assert registry._metric_for("AWS/Lambda") is None

    called = []
    monkeypatch.setattr(registry.alarms, "create_alarm",
                        lambda c, **kw: called.append(kw) or (True, "x", []))

    ok, error, problems = registry.get("alarm").create(
        None, {"name": "lambda-errors", "namespace": "AWS/Lambda",
               "threshold": 1})

    assert ok is False
    assert not called, "and no alarm was built on a guess"
    assert "AWS/Lambda" in error
    assert "metric_name" in error
