"""Tests for the HTTP layer.

TestClient calls the endpoints in-process, so there is no server to start and no
port to bind. moto intercepts the AWS calls underneath. The whole suite runs
offline against no account.

The moto mock has to be active before the app builds a boto3 client, and the app
builds one per request, so the fixture wraps each test rather than the module.
"""

import boto3
import pytest
from fastapi.testclient import TestClient
from moto import mock_aws

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


def _open_ssh_spec(name="api-test-sg"):
    return {
        "name": name,
        "rules": [{"protocol": "tcp", "from_port": 22, "to_port": 22,
                   "source": WORLD}],
    }


# ------------------------------------------------------------------ Discovery


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_resource_types_are_advertised(client):
    keys = {r["key"] for r in client.get("/resources").json()["resources"]}
    assert keys == {"security-group", "bucket", "key-pair", "instance",
                    "network", "iam", "snapshot", "alarm"}


def test_every_resource_says_whether_it_can_be_changed(client):
    """So a frontend can leave out buttons that would only be refused."""
    for entry in client.get("/resources").json()["resources"]:
        assert "read_only" in entry


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


def test_the_port_menu_uses_the_scanners_own_words(client):
    """So the phrase someone picks is the phrase the warning uses back."""
    from scanner.rules import RISKY_PORTS

    body = client.get("/resources/security-group/options").json()
    labels = {o["value"]: o["label"] for o in body["options"]["port"]}

    assert RISKY_PORTS[22] in labels["22"]
    assert RISKY_PORTS[3389] in labels["3389"]
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


# --------------------------------------------------------------- The page


def test_the_page_is_served_from_the_same_process_as_the_api(client):
    """One thing to run, and no CORS between the page and its own backend."""
    page = client.get("/ui/")
    assert page.status_code == 200
    assert "Secure Cloud Provisioner" in page.text

    for asset in ("/ui/app.js", "/ui/style.css"):
        assert client.get(asset).status_code == 200, asset


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
