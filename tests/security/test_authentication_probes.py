"""AUTHN-04a/04b/05/06/08 decisions, token crafting and guard enforcement.

These tests are offline and synthetic: no socket is created, no credential is
verified, and a decoded JWT claim is never treated as identity or privilege.
"""
import base64
import json

import pytest

from canarygate.oracles.authn_probes import (
    API_KEY_SKIP_REASON,
    JWT_SKIP_REASON,
    NO_ADMIN_REASON,
    alg_none_decision,
    api_key_decision,
    craft_token,
    credential_rejection_decision,
    logout_reuse_decision,
    observe_identity,
    role_tamper_decision,
    subject_tamper_decision,
)
from canarygate.oracles.authentication import inspect_jwt_metadata, is_supported_jwt
from canarygate.scan import auth_scenarios
from canarygate.scan.auth_runner import OfflineAuthRunner
from canarygate.scan.auth_transcript import AuthTranscriptEntry, AuthenticationTranscript

TOKEN_A = auth_scenarios.account_token("account-a")
TOKEN_B = auth_scenarios.account_token("account-b")


def decode_segment(segment):
    raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    return json.loads(raw)


def test_crafting_keeps_the_original_signature_and_only_changes_the_claim():
    crafted = craft_token(TOKEN_A, sub="account-b")
    original = TOKEN_A.split(".")
    changed = crafted.split(".")
    assert changed[2] == original[2], "the original signature segment must be retained"
    assert decode_segment(changed[1])["sub"] == "account-b"
    assert decode_segment(changed[1])["role"] == "user"
    assert is_supported_jwt(crafted)
    metadata = inspect_jwt_metadata(crafted)
    assert metadata.claims_unverified is True and metadata.subject == "account-b"


def test_crafting_a_role_token_and_an_alg_none_token():
    role = craft_token(TOKEN_A, role="admin")
    assert decode_segment(role.split(".")[1])["role"] == "admin"
    assert role.split(".")[2] == TOKEN_A.split(".")[2]

    unsigned = craft_token(TOKEN_A, alg_none=True)
    header, payload, signature = unsigned.split(".")
    assert decode_segment(header)["alg"] == "none"
    assert decode_segment(payload)["sub"] == "account-a"
    assert signature == ""
    assert is_supported_jwt(unsigned)


@pytest.mark.parametrize("token", ["offline-token-account-a", "a.b", "", "eyJ!.eyJ!.x"])
def test_crafting_rejects_tokens_that_are_not_supported_jwts(token):
    with pytest.raises(ValueError):
        craft_token(token, sub="account-b")


@pytest.mark.parametrize("status,body,identity,expected", [
    (401, {}, "unobserved", "SAFE"),
    (403, {}, "unobserved", "SAFE"),
    (200, {"identity": "account-a"}, "self", "CONFIRMED"),
    (200, {"status": "ok"}, "unobserved", "INCONCLUSIVE"),
    (403, {"error": "forbidden"}, "unobserved", "INCONCLUSIVE"),
    (500, {}, "unobserved", "INCONCLUSIVE"),
    (200, [], "unobserved", "INCONCLUSIVE"),
])
def test_credential_rejection_decision(status, body, identity, expected):
    verdict, reason = credential_rejection_decision(
        status, body, expected_denial_body={}, identity_effect=identity)
    assert verdict == expected and reason


def test_denial_body_must_match_the_declared_contract_exactly():
    # A denial carrying unexpected fields is not a checked denial.
    verdict, _ = credential_rejection_decision(
        403, {"error": "forbidden", "secret": "synthetic-alpha-private"},
        expected_denial_body={}, identity_effect="unobserved")
    assert verdict == "INCONCLUSIVE"
    verdict, _ = credential_rejection_decision(
        403, {"error": "forbidden"}, expected_denial_body={"error": "forbidden"},
        identity_effect="unobserved")
    assert verdict == "SAFE"


@pytest.mark.parametrize("status,identity,expected", [
    (401, "unobserved", "SAFE"),
    (403, "unobserved", "SAFE"),
    (200, "target", "CONFIRMED"),
    (200, "self", "SUSPECTED"),
    (200, "other", "SUSPECTED"),
    (200, "unobserved", "INCONCLUSIVE"),
    (302, "unobserved", "INCONCLUSIVE"),
])
def test_subject_tampering_requires_an_observable_identity_change(status, identity, expected):
    verdict, reason = subject_tamper_decision(
        status, {}, expected_denial_body={}, identity_effect=identity)
    assert verdict == expected and reason
    assert verdict != "SAFE" or status in (401, 403)


@pytest.mark.parametrize("status,capability,expected", [
    (401, "unobserved", "SAFE"),
    (403, "unobserved", "SAFE"),
    (200, "granted", "CONFIRMED"),
    (200, "none", "SUSPECTED"),
    (200, "unobserved", "INCONCLUSIVE"),
    (200, None, "INCONCLUSIVE"),
])
def test_role_tampering_requires_an_observed_admin_capability(status, capability, expected):
    verdict, reason = role_tamper_decision(
        status, {}, expected_denial_body={}, capability=capability)
    assert verdict == expected and reason


@pytest.mark.parametrize("status,identity,expected", [
    (401, "unobserved", "SAFE"),
    (403, "unobserved", "SAFE"),
    (200, "self", "CONFIRMED"),
    (200, "target", "CONFIRMED"),
    (200, "other", "CONFIRMED"),
    (200, "unobserved", "SUSPECTED"),
    (500, "unobserved", "INCONCLUSIVE"),
])
def test_alg_none_acceptance_is_never_safe(status, identity, expected):
    verdict, reason = alg_none_decision(
        status, {}, expected_denial_body={}, identity_effect=identity)
    assert verdict == expected and reason
    assert verdict != "SAFE" or status in (401, 403)


@pytest.mark.parametrize("status,identity,expected", [
    (401, "unobserved", "SAFE"),
    (403, "unobserved", "SAFE"),
    (200, "self", "SUSPECTED"),
    (200, "target", "SUSPECTED"),
    (200, "unobserved", "INCONCLUSIVE"),
    (500, "unobserved", "INCONCLUSIVE"),
])
def test_logout_reuse_reports_behaviour_and_never_confirms(status, identity, expected):
    verdict, reason = logout_reuse_decision(
        status, {}, expected_denial_body={}, identity_effect=identity)
    assert verdict == expected and reason
    assert verdict not in ("CONFIRMED",)


def test_api_key_decision_uses_the_strictest_of_both_observations():
    verdict, reason = api_key_decision("SAFE", "CONFIRMED")
    assert verdict == "CONFIRMED" and "key" in reason
    assert api_key_decision("SAFE", "SAFE")[0] == "SAFE"
    assert api_key_decision("SAFE", "INCONCLUSIVE")[0] == "INCONCLUSIVE"
    assert api_key_decision("SAFE", "SUSPECTED")[0] == "SUSPECTED"


def test_identity_observation_uses_only_the_declared_field():
    assert observe_identity({"identity": "account-a"}, field="identity",
                            actor="account-a", target="account-b") == "self"
    assert observe_identity({"identity": "account-b"}, field="identity",
                            actor="account-a", target="account-b") == "target"
    assert observe_identity({"identity": "someone"}, field="identity",
                            actor="account-a", target="account-b") == "other"
    assert observe_identity({"user": "account-a"}, field="identity",
                            actor="account-a", target="account-b") == "unobserved"
    assert observe_identity(["account-a"], field="identity",
                            actor="account-a", target="account-b") == "unobserved"
    assert observe_identity({"identity": 7}, field="identity",
                            actor="account-a", target="account-b") == "unobserved"


def test_skip_reasons_are_the_frozen_spec_wording():
    assert JWT_SKIP_REASON == "Token is not a supported JWT format; JWT-specific test not applicable."
    assert API_KEY_SKIP_REASON and NO_ADMIN_REASON


def test_scope_must_explicitly_permit_each_crafted_probe():
    from canarygate.guard.authorized_preflight import AuthorizedPreflight
    plan = auth_scenarios.build_auth_scenario("synthetic-jwt-secure")
    narrowed = plan.model_copy(update={"scope": auth_scenarios.scope_without_probes()})
    with pytest.raises(ValueError):
        auth_scenarios.runner_for(narrowed)
    scope = auth_scenarios.scope_without_probes()
    preflight = AuthorizedPreflight(scope)
    with pytest.raises(ValueError):
        preflight.check("account-a", "GET", scope.origin + "/profile", probe="jwt_sub")
    assert preflight.remaining == scope.request_budget


def test_probe_requires_a_recorded_response_and_a_scoped_path():
    runner = auth_scenarios.runner_for(auth_scenarios.build_auth_scenario("synthetic-jwt-secure"))
    with pytest.raises(ValueError):
        runner.probe("account-a", "/profile", "api_key_missing")
    assert runner.stats()["requests_sent"] == 0
    assert runner.probe("account-a", "/profile", "malformed").status_code == 401
    with pytest.raises(ValueError):
        runner.probe("account-a", "/not-scoped", "jwt_sub")
    assert runner.stats()["requests_sent"] == 1
    with pytest.raises(ValueError):
        runner.probe("account-b", "/profile", "jwt_sub")


def test_probe_release_is_blocked_when_the_run_budget_is_exhausted():
    plan = auth_scenarios.build_auth_scenario("synthetic-jwt-secure")
    runner = auth_scenarios.runner_for(plan, budget=1)
    assert runner.get("account-a", "/profile").status_code == 200
    before = runner.stats()
    with pytest.raises(ValueError):
        runner.probe("account-a", "/profile", "missing")
    after = runner.stats()
    assert after["requests_sent"] == before["requests_sent"]
    assert after["blocked_by_guard"] == before["blocked_by_guard"] + 1


def test_probe_responses_carry_provenance_and_detect_mutation():
    runner = auth_scenarios.runner_for(auth_scenarios.build_auth_scenario("synthetic-jwt-secure"))
    response = runner.probe("account-a", "/profile", "jwt_sub")
    assert runner.verifies_recorded_probe(response, "account-a", "GET", "/profile", "jwt_sub")
    assert not runner.verifies_recorded_probe(response, "account-a", "GET", "/profile", "alg_none")
    response._content = b'{"identity":"account-b"}'
    assert not runner.verifies_recorded_probe(response, "account-a", "GET", "/profile", "jwt_sub")


def test_transcript_rejects_duplicate_or_unsupported_entries():
    entry = AuthTranscriptEntry(actor="account-a", method="GET", path="/profile",
                                probe="missing", status=401, body={})
    with pytest.raises(ValueError):
        AuthenticationTranscript(entries=(entry, entry))
    with pytest.raises(ValueError):
        AuthTranscriptEntry(actor="account-a", method="POST", path="/profile",
                            probe="missing", status=401, body={})
    with pytest.raises(ValueError):
        AuthTranscriptEntry(actor="account-a", method="GET", path="/profile",
                            probe="delete", status=401, body={})


def _with_probe_bodies(plan, probes, body, status=200):
    entries = tuple(entry.model_copy(update={"body": body, "status": status})
                    if entry.probe in probes else entry
                    for entry in plan.probes.entries)
    return plan.model_copy(update={"probes": AuthenticationTranscript(entries=entries)})


def test_malformed_probe_bodies_cannot_become_safe():
    from canarygate.scan.auth_generic import run_authentication_scan
    plan = auth_scenarios.build_auth_scenario("synthetic-jwt-secure")
    updated = _with_probe_bodies(plan, {"missing", "malformed", "wrong_scheme"}, ["not-an-object"])
    runner = auth_scenarios.runner_for(updated)
    try:
        run = run_authentication_scan(runner, updated)
    finally:
        runner.close()
    checks = {check["id"]: check for check in run["checks"]}
    for check_id in ("AUTHN-01", "AUTHN-02", "AUTHN-03"):
        assert checks[check_id]["verdict"] == "INCONCLUSIVE"
        assert checks[check_id]["evidence"]["identity_effect"] == "unobserved"
    assert checks["AUTHN-04a"]["verdict"] == "SAFE"
    assert run["status"] == "completed"


def test_unverifiable_probe_response_marks_only_that_check_inconclusive():
    from canarygate.scan.auth_generic import run_authentication_scan
    plan = auth_scenarios.build_auth_scenario("synthetic-jwt-secure")
    runner = auth_scenarios.runner_for(plan)
    original = runner.probe

    def tampered(actor, path, probe):
        response = original(actor, path, probe)
        if probe == "malformed":
            response._content = b'{"identity":"account-a"}'
        return response

    runner.probe = tampered
    try:
        run = run_authentication_scan(runner, plan)
    finally:
        runner.close()
    checks = {check["id"]: check for check in run["checks"]}
    assert checks["AUTHN-02"]["verdict"] == "INCONCLUSIVE"
    assert checks["AUTHN-01"]["verdict"] == "SAFE"
    assert run["status"] == "completed"


def test_orchestrator_rejects_a_runner_built_from_a_different_transcript():
    from canarygate.scan.auth_generic import run_authentication_scan
    plan = auth_scenarios.build_auth_scenario("synthetic-jwt-secure")
    other = auth_scenarios.build_auth_scenario("synthetic-jwt-sub-confirmed")
    runner = auth_scenarios.runner_for(other)
    try:
        with pytest.raises(ValueError):
            run_authentication_scan(runner, plan)
        assert runner.stats()["requests_sent"] == 0
    finally:
        runner.close()
