"""Adversarial cases for the lab BOLA workflow: incomplete evidence must fail closed.

Every case uses the real loopback lab, but each one breaks exactly one link of
the evidence chain. None of them may produce CONFIRMED or SAFE.
"""
import pytest

import targetlab.testing as lab_server
from canarygate.network.targetlab import TargetLabRefused, TargetLabRunner
from canarygate.oracles.read_bola import evaluate_read_bola
from canarygate.scan.lab_bola import run_lab_bola_scan
from canarygate.scan.lab_bola_scenarios import (SECURE_RESOURCE, VULNERABLE_RESOURCE,
                                                build_bola_plan)
from canarygate.scan.lab_scenarios import build_lab_scope
from canarygate.seed.recipe import Resource
from canarygate.seed.registry import collect_guarded_ownership


@pytest.fixture()
def lab():
    with lab_server.LabTlsServer() as server:
        yield server


def runner_for(lab, *, plan=None):
    plan = plan or build_bola_plan(lab.port)
    return TargetLabRunner(plan.scope, plan.credentials, ca_file=str(lab_server.TARGETLAB_CERT))


def ownership_for(runner, resource, accounts=("mallapa", "sakshi")):
    for account in accounts:
        runner.login(account)
    return collect_guarded_ownership(runner, resource_type="record", resource=resource,
                                     accounts=accounts, profile_path="/profile",
                                     identity_field="identity")


def test_a_mutated_response_is_never_evidence(lab):
    runner = runner_for(lab)
    try:
        ownership = ownership_for(runner, VULNERABLE_RESOURCE)
        assert ownership.ownership_status == "SUCCESS"
        response = runner.get("mallapa", "/records/BRD-2026-018")
        assert response.status_code == 200
        decision = evaluate_read_bola(
            ownership=ownership, resource_type="record", resource=VULNERABLE_RESOURCE,
            actor="mallapa", owner="sakshi", response=response, expected_access="owner-only",
            expected_source="targetlab declared record policy")
        assert decision.verdict == "CONFIRMED"
        # Mutate the recorded body: provenance must fail and the verdict must drop.
        response._content = response.content.replace(b"targetlab-sakshi-private-marker",
                                                     b"targetlab-mallapa-private-marker")
        mutated = evaluate_read_bola(
            ownership=ownership, resource_type="record", resource=VULNERABLE_RESOURCE,
            actor="mallapa", owner="sakshi", response=response, expected_access="owner-only",
            expected_source="targetlab declared record policy")
        assert mutated.verdict == "INCONCLUSIVE"
        assert mutated.checklist["attacker_request"] is False
    finally:
        runner.close()


def test_a_response_recorded_for_another_actor_is_rejected(lab):
    runner = runner_for(lab)
    try:
        ownership = ownership_for(runner, VULNERABLE_RESOURCE)
        response = runner.get("mallapa", "/records/BRD-2026-018")
        assert runner.verifies_recorded_read(response, "mallapa", "/records/BRD-2026-018") is True
        assert runner.verifies_recorded_read(response, "sakshi", "/records/BRD-2026-018") is False
        decision = evaluate_read_bola(
            ownership=ownership, resource_type="record", resource=VULNERABLE_RESOURCE,
            actor="sakshi", owner="mallapa", response=response, expected_access="owner-only",
            expected_source="targetlab declared record policy")
        assert decision.verdict == "INCONCLUSIVE"
    finally:
        runner.close()


def test_ownership_from_another_endpoint_cannot_be_reused(lab):
    """A secure-route ownership proof must not authorise a vulnerable-route claim."""
    runner = runner_for(lab)
    try:
        secure_ownership = ownership_for(runner, SECURE_RESOURCE)
        assert secure_ownership.ownership_status == "SUCCESS"
        response = runner.get("mallapa", "/records/BRD-2026-018")
        decision = evaluate_read_bola(
            ownership=secure_ownership, resource_type="record", resource=VULNERABLE_RESOURCE,
            actor="mallapa", owner="sakshi", response=response, expected_access="owner-only",
            expected_source="targetlab declared record policy")
        assert decision.verdict == "INCONCLUSIVE"
        assert decision.checklist["ownership_verified"] is False
    finally:
        runner.close()


@pytest.mark.parametrize("model", ["shared", "public"])
def test_shared_or_public_ownership_is_never_confirmed(lab, model):
    resource = Resource.model_validate({**VULNERABLE_RESOURCE.model_dump(),
                                        "ownership_model": model})
    runner = runner_for(lab)
    try:
        ownership = ownership_for(runner, resource)
        assert ownership.ownership_status != "SUCCESS"
        decision = evaluate_read_bola(
            ownership=ownership, resource_type="record", resource=resource,
            actor="mallapa", owner="sakshi", response=None, expected_access="owner-only",
            expected_source="targetlab declared record policy")
        assert decision.verdict == "INCONCLUSIVE"
        assert decision.checklist["private_resource"] is False
    finally:
        runner.close()


def test_authentication_is_one_shot_per_run(lab):
    """A duplicate login attempt is refused by the shared guard, not retried."""
    runner = runner_for(lab)
    try:
        assert runner.login("mallapa") is True
        with pytest.raises(ValueError):
            runner.login("mallapa")
        assert runner.stats()["requests_sent"] == 1
    finally:
        runner.close()


def test_an_untrusted_policy_source_is_never_confirmed(lab):
    """The lab runner only trusts its own declared source."""
    runner = runner_for(lab)
    try:
        ownership = ownership_for(runner, VULNERABLE_RESOURCE)
        response = runner.get("mallapa", "/records/BRD-2026-018")
        for source in ("synthetic fixture policy", "offline scenario policy", "self declared"):
            decision = evaluate_read_bola(
                ownership=ownership, resource_type="record", resource=VULNERABLE_RESOURCE,
                actor="mallapa", owner="sakshi", response=response, expected_access="owner-only",
                expected_source=source)
            assert decision.verdict == "INCONCLUSIVE", source
            assert decision.checklist["policy_denies_access"] is False
    finally:
        runner.close()


def test_a_wrong_identity_halts_ownership_and_never_confirms(lab):
    """If a token appears to identify another account, the run stops."""
    runner = runner_for(lab)
    try:
        runner.login("mallapa")
        runner.login("sakshi")
        # Swap sakshi's token for mallapa's: the profile for "sakshi" will report mallapa.
        runner._tokens["sakshi"] = runner._tokens["mallapa"]
        plan = build_bola_plan(lab.port)
        run = run_lab_bola_scan(plan, runner)
        assert run.verdict != "CONFIRMED"
        assert run.ownership["vulnerable"]["status"] != "SUCCESS"
        assert all(check.verdict != "CONFIRMED" for check in run.checks)
        assert all(check.verdict != "SAFE" for check in run.checks)
    finally:
        runner.close()


def test_the_ground_truth_route_is_unreachable_through_the_transport(lab):
    runner = runner_for(lab)
    try:
        for path in ("/lab/ground-truth", "/lab/ground-truth/", "/openapi.json"):
            with pytest.raises((TargetLabRefused, ValueError)):
                runner.get("mallapa", path)
    finally:
        runner.close()


def test_a_second_scan_cannot_reuse_a_closed_runner(lab):
    plan = build_bola_plan(lab.port)
    runner = TargetLabRunner(plan.scope, plan.credentials,
                             ca_file=str(lab_server.TARGETLAB_CERT))
    run = run_lab_bola_scan(plan, runner)
    assert run.verdict == "CONFIRMED"
    spent = runner.stats()["requests_sent"]
    runner.close()
    # A closed runner has no tokens: a second run cannot authenticate again.
    second = run_lab_bola_scan(plan, runner)
    assert second.verdict != "CONFIRMED"
    assert runner.stats()["requests_sent"] == spent


def test_the_scope_cannot_name_another_destination():
    from canarygate.scope.authorized import AuthorizedScope

    data = build_lab_scope(8765).model_dump()
    for host in ("127.0.0.2", "192.168.0.10", "10.1.2.3", "example.com", "::1"):
        with pytest.raises(ValueError):
            AuthorizedScope.model_validate({**data, "hostname": host, "organizer_ip": host})
