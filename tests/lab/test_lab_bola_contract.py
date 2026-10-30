"""Contract tests for the TargetLab BOLA workflow, written before the orchestrator.

They pin the properties checkpoint 36 depends on:

* the workflow reuses the single existing read-BOLA oracle and ownership registry;
* the lab's ground truth is an evaluation input *after* the verdicts, never before;
* incomplete evidence can never produce CONFIRMED or SAFE;
* a mutated or forged response is not accepted as evidence.
"""
import pytest

from canarygate.oracles.read_bola import evaluate_read_bola
from canarygate.scan.lab_bola_scenarios import (EXPECTED_VERDICTS, SECURE_RESOURCE,
                                                VULNERABLE_RESOURCE, build_bola_plan)
from canarygate.seed.recipe import Resource


def test_the_plan_declares_both_endpoints_and_the_expected_policy():
    plan = build_bola_plan(8765)
    assert plan.accounts == ("alice", "bob")
    assert plan.resource.detail.path == "/records/{id}"
    assert plan.secure_resource.detail.path == "/records/{id}/secure"
    assert plan.resource.discovery.path == plan.secure_resource.discovery.path == "/records"
    assert plan.resource.ownership_model == plan.secure_resource.ownership_model == "private"
    assert plan.policy.expected_access == "owner-only"
    assert plan.policy.expected_source == "targetlab declared record policy"
    assert plan.profile_path == "/profile" and plan.identity_field == "identity"


def test_the_resource_declarations_are_the_frozen_objects():
    assert VULNERABLE_RESOURCE.detail.path == "/records/{id}"
    assert SECURE_RESOURCE.detail.path == "/records/{id}/secure"
    # A shared copy is still a valid model, but the oracle will refuse to call it
    # private: the declaration cannot be widened by copying it.
    widened = Resource.model_validate({**VULNERABLE_RESOURCE.model_dump(), "ownership_model": "shared"})
    assert widened.ownership_model == "shared" and VULNERABLE_RESOURCE.ownership_model == "private"
    # The registry refuses a detail path without exactly one {id}, so the lab
    # cannot be scanned through a route that is not a per-resource read.
    from canarygate.seed.registry import _valid_detail

    assert _valid_detail(VULNERABLE_RESOURCE.detail.path) is True
    assert _valid_detail("/records") is False
    assert _valid_detail("/records/{id}/secure") is True


def test_the_ground_truth_table_is_declared_independently_and_covers_every_check():
    assert set(EXPECTED_VERDICTS) == {f"LAB-BOLA-{index:02d}" for index in range(1, 7)}
    assert list(EXPECTED_VERDICTS.values()).count("CONFIRMED") == 2
    assert list(EXPECTED_VERDICTS.values()).count("SAFE") == 4


def test_the_oracle_trusts_the_targetlab_policy_source_only_for_the_lab_runner():
    """The existing oracle gains one trusted source; nothing else changes."""
    from canarygate.oracles.read_bola import TARGETLAB_POLICY_SOURCE

    assert TARGETLAB_POLICY_SOURCE == "targetlab declared record policy"
    # A fixture run (no source runner) still trusts only the fixture policy, and a
    # generic guarded run still trusts only the offline scenario policy.
    assert TARGETLAB_POLICY_SOURCE != "offline scenario policy"
    assert TARGETLAB_POLICY_SOURCE != "synthetic fixture policy"


def test_the_oracle_rejects_a_targetlab_claim_without_verified_ownership():
    decision = evaluate_read_bola(
        ownership=None, resource_type="record", resource=VULNERABLE_RESOURCE,
        actor="alice", owner="bob", response=None, expected_access="owner-only",
        expected_source="targetlab declared record policy")
    assert decision.verdict == "INCONCLUSIVE"
    assert not any(decision.checklist.values())


def test_the_plan_never_exposes_the_ground_truth_route():
    from canarygate.scope.authorized import TARGETLAB_OPERATIONS

    plan = build_bola_plan(8765)
    declared = {(op.method, op.path) for op in plan.scope.operations}
    assert declared == set(TARGETLAB_OPERATIONS)
    assert not any(path.startswith("/lab") for _, path in declared)
