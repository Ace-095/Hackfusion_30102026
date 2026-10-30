"""Safe input-validation and disclosure decisions, scope rules and guard enforcement.

Offline and synthetic only: no socket is created, no request body is ever sent to
a real host, and every verdict must rest on an observed recorded response.
"""
import httpx
import pytest

from canarygate.guard.authorized_preflight import AuthorizedPreflight
from canarygate.guard.run_guard import RunSafetyGuard
from canarygate.oracles.disclosure import (disclosure_signals, excess_fields_decision,
                                           inspect_extra_fields, inspect_sensitive_json,
                                           inspect_sensitive_payload, sensitive_field_decision,
                                           signal_verdict)
from canarygate.oracles.validation import (enumeration_decision, extra_property_decision,
                                           malformed_json_decision, special_characters_decision)
from canarygate.scan import validation_scenarios
from canarygate.scan.validation_generic import ValidationOrchestrator, run_offline_validation
from canarygate.scan.validation_runner import OfflineValidationRunner, ValidationRunnerConfig
from canarygate.scan.validation_transcript import ProbeEntry, ValidationTranscript
from canarygate.scope.authorized import AuthorizedScope

FIELD = "is_admin"
TRACEBACK = {"error": "Traceback (most recent call last): TypeError"}
LONG_ERROR = {"error": "x" * 600}


def response(status, body, headers=None):
    return httpx.Response(status, json=body, headers=headers or {})


# ---------------------------------------------------------------- INPUT-05


def test_extra_property_rejection_requires_a_field_specific_bounded_error():
    assert extra_property_decision(422, {"error": "unexpected property: is_admin"}, field=FIELD,
                                   effect_observed=False)[0] == "SAFE"
    assert extra_property_decision(422, {"error": "invalid request"}, field=FIELD,
                                   effect_observed=False)[0] == "INCONCLUSIVE"


def test_extra_property_acceptance_is_suspected_until_an_effect_is_observed():
    verdict, reason = extra_property_decision(200, {"identity": "account-a"}, field=FIELD,
                                              effect_observed=False)
    assert verdict == "SUSPECTED" and "no effect" in reason
    assert extra_property_decision(200, {"identity": "account-a"}, field=FIELD,
                                   effect_observed=True)[0] == "CONFIRMED"


def test_extra_property_internal_error_text_is_never_counted_as_safe():
    body = {"error": "unexpected property: is_admin\nTraceback (most recent call last):"}
    assert extra_property_decision(422, body, field=FIELD, effect_observed=False)[0] == "INCONCLUSIVE"


def test_extra_property_without_a_usable_body_is_inconclusive():
    assert extra_property_decision(422, None, field=FIELD, effect_observed=False)[0] == "INCONCLUSIVE"
    assert extra_property_decision(500, {"error": "unexpected property: is_admin"}, field=FIELD,
                                   effect_observed=False)[0] == "INCONCLUSIVE"


# ---------------------------------------------------------------- INPUT-06


def test_malformed_json_rejection_requires_a_bounded_parse_error():
    assert malformed_json_decision(400, {"error": "malformed JSON body"})[0] == "SAFE"
    assert malformed_json_decision(422, {"error": "malformed JSON body"})[0] == "SAFE"


def test_malformed_json_acceptance_is_suspected_not_safe():
    assert malformed_json_decision(200, {"identity": "account-a"})[0] == "SUSPECTED"
    assert malformed_json_decision(204, None)[0] == "SUSPECTED"


def test_malformed_json_error_bodies_that_leak_internals_are_inconclusive():
    assert malformed_json_decision(400, TRACEBACK)[0] == "INCONCLUSIVE"
    assert malformed_json_decision(400, LONG_ERROR)[0] == "INCONCLUSIVE"
    assert malformed_json_decision(400, {"detail": "malformed JSON"})[0] == "INCONCLUSIVE"


@pytest.mark.parametrize("status", [401, 403, 404, 409, 500, 502])
def test_malformed_json_unexpected_statuses_are_inconclusive(status):
    assert malformed_json_decision(status, {"error": "malformed JSON body"})[0] == "INCONCLUSIVE"


# ---------------------------------------------------------------- INPUT-07


def test_special_characters_validation_error_and_ordinary_rejection_are_safe():
    assert special_characters_decision(422, {"error": "invalid characters in username"})[0] == "SAFE"
    assert special_characters_decision(401, {"error": "invalid credentials"})[0] == "SAFE"


def test_special_characters_acceptance_or_server_error_is_not_safe():
    assert special_characters_decision(200, {"identity": "account-a"})[0] == "SUSPECTED"
    assert special_characters_decision(500, {"error": "failure"})[0] == "SUSPECTED"


def test_special_characters_ambiguous_responses_are_inconclusive():
    assert special_characters_decision(409, {"error": "conflict"})[0] == "INCONCLUSIVE"
    assert special_characters_decision(401, {"error": "invalid\nTraceback (most recent call last):"})[0] != "SAFE"


# ---------------------------------------------------------------- DISC-06


def test_identical_error_responses_are_safe_and_different_ones_confirm_enumeration():
    assert enumeration_decision(403, {"error": "forbidden"}, 403, {"error": "forbidden"})[0] == "SAFE"
    verdict, reason = enumeration_decision(403, {"error": "account exists"}, 404, {"error": "no such account"})
    assert verdict == "CONFIRMED" and "distinguish" in reason


def test_enumeration_comparison_requires_two_usable_error_responses():
    assert enumeration_decision(200, {"identity": "account-b"}, 404, {"error": "missing"})[0] == "INCONCLUSIVE"
    assert enumeration_decision(500, {"error": "db"}, 404, {"error": "missing"})[0] == "INCONCLUSIVE"
    assert enumeration_decision(403, None, 404, {"error": "missing"})[0] == "INCONCLUSIVE"


# ---------------------------------------------------------------- DISC-01/02/05


def test_disclosure_signals_detect_only_bounded_signatures():
    traced = response(500, {"error": "Traceback (most recent call last): TypeError"})
    assert "stack_trace" in disclosure_signals(traced)
    sql = response(400, {"error": "SQLSTATE 22P02 invalid_text_representation"})
    assert "internal_error_detail" in disclosure_signals(sql)
    path = response(400, {"error": 'File "/srv/app/routes.py", line 42, in handler'})
    assert "internal_error_detail" in disclosure_signals(path)
    assert disclosure_signals(response(400, {"error": "invalid request"})) == set()
    assert disclosure_signals(response(200, {"server": "fixture-server/1.4.2"})) == set()


def test_disclosure_header_signals_require_a_version_or_debug_header():
    versioned = response(200, {"identity": "a"}, {"server": "fixture-server/1.4.2"})
    assert "version_header" in disclosure_signals(versioned)
    debug = response(200, {"identity": "a"}, {"x-debug-mode": "verbose"})
    assert "debug_header" in disclosure_signals(debug)
    assert disclosure_signals(response(200, {"identity": "a"}, {"server": "plain"})) == set()


def test_signal_verdict_confirms_observation_and_never_guesses():
    assert signal_verdict({"stack_trace"}, "stack_trace")[0] == "CONFIRMED"
    assert signal_verdict(set(), "stack_trace")[0] == "SAFE"
    assert signal_verdict(None, "stack_trace")[0] == "INCONCLUSIVE"


# ---------------------------------------------------------------- DISC-03/04


def test_sensitive_field_verdict_requires_complete_traversal_for_safe():
    assert sensitive_field_decision(set(), True)[0] == "SAFE"
    assert sensitive_field_decision(set(), False)[0] == "INCONCLUSIVE"
    assert sensitive_field_decision({"name"}, False)[0] == "CONFIRMED"
    assert sensitive_field_decision({"pattern"}, True)[0] == "CONFIRMED"
    assert "pattern" in sensitive_field_decision({"pattern"}, True)[1]


def test_sensitive_json_scan_reports_nested_secrets_and_ignores_redaction():
    found, complete = inspect_sensitive_json(response(200, {"outer": [{"password": "synthetic-digest"}]}))
    assert (found, complete) == (True, True)
    found, complete = inspect_sensitive_json(response(200, {"password": "[redacted]"}))
    assert (found, complete) == (False, True)
    found, complete = inspect_sensitive_json(response(200, {"password": None}))
    assert (found, complete) == (False, True)


def test_sensitive_values_are_detected_by_pattern_without_returning_them():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhY2NvdW50LWEifQ.c2lnbmF0dXJl"
    signals, complete = inspect_sensitive_payload(response(200, {"session": jwt}))
    assert signals == {"pattern"} and complete is True
    signals, _ = inspect_sensitive_payload(response(200, {"note": "-----BEGIN RSA PRIVATE KEY-----"}))
    assert "pattern" in signals
    signals, _ = inspect_sensitive_payload(response(200, {"key": "sk_live_abcdefgh12345"}))
    assert "pattern" in signals
    signals, complete = inspect_sensitive_payload(response(200, {"identity": "account-a"}))
    assert signals == set() and complete is True
    assert "eyJ" not in repr(signals)


def test_sensitive_json_scan_is_bounded_and_reports_incompleteness():
    nested = {"identity": "account-a"}
    for _ in range(40):
        nested = {"identity": nested}
    found, complete = inspect_sensitive_json(response(200, nested))
    assert found is False and complete is False


def test_excess_field_comparison_needs_a_closed_simple_schema():
    closed = {"200": {"type": "object", "additionalProperties": False,
                      "properties": {"identity": {"type": "string"}}}}
    open_schema = {"200": {"type": "object", "properties": {"identity": {"type": "string"}}}}
    assert inspect_extra_fields(response(200, {"identity": "a", "password_hash": "x"}), closed) == (True, True)
    assert inspect_extra_fields(response(200, {"identity": "a"}), closed) == (False, True)
    assert inspect_extra_fields(response(200, {"identity": "a"}), open_schema) == (False, False)
    assert excess_fields_decision(False, False)[0] == "INCONCLUSIVE"
    assert excess_fields_decision(True, True)[0] == "CONFIRMED"
    assert excess_fields_decision(False, True)[0] == "SAFE"


# ---------------------------------------------------------------- scope rules


def test_input_probes_are_only_permitted_on_the_exact_authentication_post():
    scope = validation_scenarios.scope_without_input_probes()
    operation = {"method": "GET", "path": "/profile", "classification": "READ_ONLY",
                 "input_probes": ["malformed_json"]}
    with pytest.raises(ValueError):
        AuthorizedScope.model_validate({**scope.model_dump(), "operations": [operation]})
    state_changing = {"method": "POST", "path": "/login", "classification": "STATE_CHANGING",
                      "creation_authorization_reference": "written approval", "input_probes": ["malformed_json"]}
    with pytest.raises(ValueError):
        AuthorizedScope.model_validate({**scope.model_dump(), "operations": [state_changing]})
    duplicate = {"method": "POST", "path": "/login", "classification": "AUTHENTICATION",
                 "input_probes": ["malformed_json", "malformed_json"]}
    with pytest.raises(ValueError):
        AuthorizedScope.model_validate({**scope.model_dump(), "operations": [duplicate]})


def test_scope_without_declared_input_probes_rejects_them_fail_closed():
    scope = validation_scenarios.scope_without_input_probes()
    preflight = AuthorizedPreflight(scope)
    with pytest.raises(ValueError):
        preflight.check("account-a", "POST", scope.origin + "/login", input_probe="malformed_json")
    assert validation_scenarios.VALIDATION_SCOPE.operations[0].input_probes == \
        validation_scenarios.INPUT_PROBES


def test_preflight_rejects_unknown_or_combined_probe_kinds():
    scope = validation_scenarios.VALIDATION_SCOPE
    preflight = AuthorizedPreflight(scope)
    assert preflight.check("account-a", "POST", scope.origin + "/login",
                           input_probe="malformed_json") == "AUTHENTICATION"
    with pytest.raises(ValueError):
        preflight.check("account-a", "POST", scope.origin + "/login", input_probe="sql_injection")
    with pytest.raises(ValueError):
        preflight.check("account-a", "POST", scope.origin + "/login", probe="missing",
                        input_probe="malformed_json")


def test_run_guard_allows_each_declared_input_probe_at_most_once():
    scope = validation_scenarios.VALIDATION_SCOPE
    guard = RunSafetyGuard(scope)
    guard.authorize_authentication("account-a", scope.origin + "/login", input_probe="malformed_json")
    with pytest.raises(ValueError):
        guard.authorize_authentication("account-a", scope.origin + "/login", input_probe="malformed_json")
    guard.authorize_authentication("account-a", scope.origin + "/login", input_probe="extra_property")
    assert guard.stats()["blocked_by_guard"] == 1
    with pytest.raises(ValueError):
        guard.authorize_authentication("account-a", scope.origin + "/profile", input_probe="control")


# ---------------------------------------------------------------- transcript rules


def test_transcript_rejects_unknown_duplicate_oversized_or_hostile_entries():
    base = {"actor": "account-a", "method": "POST", "path": "/login", "status": 400,
            "body": {"error": "malformed JSON body"}}
    with pytest.raises(ValueError):
        ProbeEntry(**{**base, "probe": "sql_injection"})
    with pytest.raises(ValueError):
        ProbeEntry(**{**base, "probe": "malformed_json", "path": "/login?debug=1"})
    with pytest.raises(ValueError):
        ProbeEntry(**{**base, "probe": "malformed_json", "status": 302})
    with pytest.raises(ValueError):
        ProbeEntry(**{**base, "probe": "malformed_json", "headers": {"x-bad": "line\r\nbreak"}})
    entry = ProbeEntry(**{**base, "probe": "malformed_json"})
    with pytest.raises(ValueError):
        ValidationTranscript(entries=(entry, entry))


def test_transcript_digest_changes_with_the_recorded_body():
    first = ProbeEntry(actor="account-a", method="POST", path="/login", probe="malformed_json",
                       status=400, body={"error": "malformed JSON body"})
    second = ProbeEntry(actor="account-a", method="POST", path="/login", probe="malformed_json",
                        status=400, body={"error": "different"})
    assert ValidationTranscript(entries=(first,)).sha256() != ValidationTranscript(entries=(second,)).sha256()


# ---------------------------------------------------------------- runner rules


def test_runner_requires_a_declared_body_and_a_scoped_authentication_operation():
    plan = validation_scenarios.build_validation_scenario("synthetic-validation-secure")
    runner = validation_scenarios.runner_for(plan)
    with pytest.raises(ValueError):
        runner.submit("account-a", "logout_reuse")
    with pytest.raises(ValueError):
        runner.submit("account-b", "control")
    with pytest.raises(ValueError):
        OfflineValidationRunner(plan.scope, {"account-a": "t"}, plan.reads, plan.probes,
                                config=ValidationRunnerConfig(login_path="/profile",
                                                              requests=dict(validation_scenarios.REQUEST_BODIES)))


def test_runner_rejects_mutated_responses_and_repeated_submissions():
    plan = validation_scenarios.build_validation_scenario("synthetic-validation-secure")
    runner = validation_scenarios.runner_for(plan)
    recorded = runner.submit("account-a", "malformed_json")
    assert runner.verifies_recorded_submission(recorded, "account-a", "malformed_json")
    assert not runner.verifies_recorded_submission(recorded, "account-a", "extra_property")
    recorded._content = recorded.content + b" "
    assert not runner.verifies_recorded_submission(recorded, "account-a", "malformed_json")
    with pytest.raises(ValueError):
        runner.submit("account-a", "malformed_json")
    assert runner.guard.stats()["blocked_by_guard"] == 1


def test_runner_refuses_probes_missing_from_the_recorded_transcript():
    plan = validation_scenarios.build_validation_scenario("synthetic-validation-secure")
    empty_probe = plan.probes.entries[0]
    transcript = ValidationTranscript(entries=(empty_probe,))
    runner = OfflineValidationRunner(plan.scope,
                                     {"account-a": "token-a", "account-b": "token-b"},
                                     plan.reads, transcript,
                                     config=ValidationRunnerConfig(
                                         login_path="/login",
                                         requests=dict(validation_scenarios.REQUEST_BODIES)))
    assert runner.verifies_recorded_submission(runner.submit("account-a", "control"), "account-a", "control")
    with pytest.raises(ValueError):
        runner.submit("account-a", "malformed_json")


# ---------------------------------------------------------------- orchestration


def test_unverifiable_submissions_never_produce_safe_input_verdicts(monkeypatch):
    plan = validation_scenarios.build_validation_scenario("synthetic-validation-secure")
    runner = validation_scenarios.runner_for(plan)
    monkeypatch.setattr(runner, "verifies_recorded_submission", lambda *args, **kwargs: False)
    run = run_offline_validation(plan, runner)
    input_checks = [check for check in run.checks if check.id.startswith("INPUT")]
    assert {check.verdict for check in input_checks} == {"INCONCLUSIVE"}


def test_unverifiable_reads_never_produce_safe_disclosure_verdicts(monkeypatch):
    plan = validation_scenarios.build_validation_scenario("synthetic-validation-secure")
    runner = validation_scenarios.runner_for(plan)
    monkeypatch.setattr(runner, "verifies_recorded_read", lambda *args, **kwargs: False)
    run = run_offline_validation(plan, runner)
    read_checks = [check for check in run.checks if check.id.startswith("DISC")]
    assert {check.verdict for check in read_checks} == {"INCONCLUSIVE"}


def test_budget_exhaustion_degrades_to_inconclusive_without_leaking_requests():
    plan = validation_scenarios.build_validation_scenario("synthetic-validation-secure")
    runner = validation_scenarios.runner_for(plan, budget=2)
    run = run_offline_validation(plan, runner)
    assert run.requests_sent == 2
    assert run.blocked_by_guard >= 1
    assert run.summary.inconclusive >= 1


def test_orchestrator_never_carries_request_bodies_into_evidence():
    plan = validation_scenarios.build_validation_scenario("synthetic-validation-secure")
    run = run_offline_validation(plan, validation_scenarios.runner_for(plan))
    dumped = run.model_dump_json()
    assert "offline-valid-credential" not in dumped
    for check in run.checks:
        assert check.evidence is None or "body" not in check.evidence


def test_validation_run_is_redacted_before_it_is_returned():
    plan = validation_scenarios.build_validation_scenario("synthetic-validation-weak")
    run = run_offline_validation(plan, validation_scenarios.runner_for(plan))
    dumped = run.model_dump_json()
    assert "synthetic-digest" not in dumped
    assert "offline-validation-token" not in dumped
    confirmed = [check for check in run.checks if check.verdict == "CONFIRMED"]
    assert confirmed and all(check.remediation for check in confirmed)
