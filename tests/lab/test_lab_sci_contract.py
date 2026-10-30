"""Contract tests for the TargetLab control-interaction (SCI) workflow.

The workflow must reuse the one SCI decision engine, declare the rejected-login
probe in the scope, and keep the lab's ground truth out of the decision path.
"""
import json

import pytest

from canarygate.oracles.authn_probes import credential_rejection_decision
from canarygate.oracles.interaction import INTERACTION_CONTROLS, decide
from canarygate.scan.lab_sci_scenarios import (ACCOUNT_ORDER, DENIAL_BODY, EXPECTED,
                                               GUARDED_RESOURCE, KIND, LOGIN_PATH,
                                               MIN_REQUEST_BUDGET, POLICY_SOURCE,
                                               REJECTED_LOGIN_PROBE, REJECTION_BODY,
                                               build_sci_plan, wrong_password_body)


def test_the_plan_declares_the_frozen_interaction_kind():
    plan = build_sci_plan(8765)
    assert plan.scenario_id == "targetlab-sci"
    assert plan.kind == KIND == "AUTHN+AUTHZ"
    assert tuple(INTERACTION_CONTROLS[KIND]) == ("Authentication", "Authorization")
    assert plan.accounts == ACCOUNT_ORDER == ("alice", "bob")
    assert plan.controls == ("Authentication", "Authorization")


def test_the_guarded_route_is_the_declared_dependency():
    assert GUARDED_RESOURCE.detail.path == "/records/{id}/guarded"
    assert GUARDED_RESOURCE.discovery.path == "/records"
    assert GUARDED_RESOURCE.ownership_model == "private"
    assert GUARDED_RESOURCE.private_field == "private_note"


def test_the_scope_declares_the_rejected_login_probe_only_on_the_login_operation():
    plan = build_sci_plan(8765)
    login = [op for op in plan.scope.operations
             if (op.method, op.path) == ("POST", LOGIN_PATH)]
    assert len(login) == 1
    assert login[0].classification == "AUTHENTICATION"
    assert tuple(login[0].input_probes) == (REJECTED_LOGIN_PROBE,)
    for operation in plan.scope.operations:
        if (operation.method, operation.path) != ("POST", LOGIN_PATH):
            assert operation.input_probes == (), operation.path


def test_the_probe_is_only_permitted_where_the_scope_declares_it():
    from canarygate.scope.authorized import AuthorizedOperation

    unprobed = AuthorizedOperation.model_validate(
        {"method": "POST", "path": "/login", "classification": "AUTHENTICATION"})
    assert unprobed.input_probes == ()
    probed = AuthorizedOperation.model_validate(
        {"method": "POST", "path": "/login", "classification": "AUTHENTICATION",
         "input_probes": (REJECTED_LOGIN_PROBE,)})
    assert probed.input_probes == (REJECTED_LOGIN_PROBE,)
    # A body-carrying probe can never be declared on a read operation.
    with pytest.raises(ValueError):
        AuthorizedOperation.model_validate({"method": "GET", "path": "/profile",
                                            "classification": "READ_ONLY",
                                            "input_probes": (REJECTED_LOGIN_PROBE,)})


def test_the_probe_body_is_well_formed_json_with_a_wrong_password_and_no_real_secret():
    body = wrong_password_body("alice")
    assert json.loads(body) == {"username": "alice",
                                "password": "targetlab-wrong-password-for-alice"}
    assert "alice-lab-password" not in body and "bob-lab-password" not in body
    assert len(body.encode("utf-8")) <= 4096
    # A broken-JSON body would never reach the lab's account state machine.
    assert json.loads(body) is not None


def test_the_denial_and_rejection_contracts_are_exact_bodies():
    assert DENIAL_BODY == {"error": "forbidden"}
    assert REJECTION_BODY == {"error": "invalid_credentials"}
    safe, _ = credential_rejection_decision(401, {"error": "invalid_credentials"},
                                            expected_denial_body=REJECTION_BODY,
                                            identity_effect="none")
    assert safe == "SAFE"


def test_the_ground_truth_table_is_separate_and_never_imported_for_a_decision():
    assert EXPECTED["SCI-01"] == "CONFIRMED"
    assert set(EXPECTED) == {"SCI-01", "RESET-01", "RESET-02", "RESET-03", "RESET-04"}
    import canarygate.scan.lab_sci as module

    source = open(module.__file__, encoding="utf-8").read()
    assert "EXPECTED" not in source


def test_the_budget_floor_covers_the_declared_requests():
    plan = build_sci_plan(8765)
    # 2 logins + 2 profile + 2 discovery + 2 owner baselines + denial + probe + leak
    assert plan.required_requests == 11
    assert MIN_REQUEST_BUDGET < plan.required_requests
    with pytest.raises(ValueError):
        build_sci_plan(80)
    with pytest.raises(ValueError):
        build_sci_plan(8765, budget=MIN_REQUEST_BUDGET - 1)
    with pytest.raises(ValueError):
        build_sci_plan(8765, budget=41)


def test_the_policy_source_names_the_lab_not_an_offline_scenario():
    assert POLICY_SOURCE == "targetlab declared interaction policy"
    assert "offline" not in POLICY_SOURCE
