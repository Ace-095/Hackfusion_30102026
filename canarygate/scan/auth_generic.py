"""Transport-guarded orchestrator for the remaining P0 authentication checks.

Every probe passes the shared run guard immediately before a recorded response
is released. Verdicts rest on recorded API behaviour: a decoded JWT claim is
never treated as identity or privilege, an accepted request is never SAFE, and
missing evidence yields SKIPPED or INCONCLUSIVE rather than a clean result.
"""
from datetime import datetime, timezone
from uuid import uuid4

from canarygate.evidence.redaction import digest
from canarygate.oracles.authn_probes import (
    API_KEY_SKIP_REASON,
    JWT_SKIP_REASON,
    NO_ADMIN_REASON,
    NO_LOGOUT_REASON,
    alg_none_decision,
    api_key_decision,
    credential_rejection_decision,
    logout_reuse_decision,
    observe_capability,
    observe_identity,
    role_tamper_decision,
    subject_tamper_decision,
)
from canarygate.scan.auth_plan import AuthenticationPlan
from canarygate.scan.auth_runner import OfflineAuthRunner
from canarygate.seed.registry import _json

CHECK_IDS = ("AUTHN-01", "AUTHN-02", "AUTHN-03", "AUTHN-04a", "AUTHN-04b",
             "AUTHN-05", "AUTHN-06", "AUTHN-08")
CATEGORY = "Authentication"

LIMITATIONS = (
    "Offline recorded transport only: no live target, socket, DNS lookup or organizer approval was used.",
    "JWT claims are decoded without signature verification; decoding is not verification and never proves identity or privilege.",
    "No signing keys are available, so algorithm-confusion and expired-token forgery remain out of scope.",
    "Recorded responses are keyed by account; no credential is transmitted on the offline transport.",
    "Production guarded HTTPX execution remains disabled pending separate safety review and written approval.",
)

REMEDIATION = {
    "AUTHN-01": "Require a valid credential for every protected operation and reject unauthenticated requests.",
    "AUTHN-02": "Reject malformed credentials before any protected operation is evaluated.",
    "AUTHN-03": "Accept only the documented authentication scheme.",
    "AUTHN-04a": "Verify the token signature and derive identity from the verified subject, not from a client-supplied claim.",
    "AUTHN-04b": "Verify the token signature and derive privileges from server-side role data, not from a client-supplied claim.",
    "AUTHN-05": "Reject unsigned tokens and accept only an explicitly approved algorithm.",
    "AUTHN-08": "Require a valid API key for every protected operation and reject missing or unknown keys.",
}


def _check(check_id, verdict, reason, *, evidence=None, remediation=None):
    return {"id": check_id, "category": CATEGORY, "verdict": verdict, "reason": reason,
            "evidence": evidence, "remediation": remediation}


def _skipped(check_id, reason):
    return _check(check_id, "SKIPPED", reason)


def _inconclusive(check_id, reason):
    return _check(check_id, "INCONCLUSIVE", reason)


def _evidence(*, phase, timestamp, actor, role, method, path_template, probe, status_code,
              identity_effect="unobserved", capability=None, denial_checked=False,
              alternate_status=None, flags):
    summary = {
        "phase": phase, "timestamp": timestamp, "actor": actor, "role": role,
        "method": method, "path_template": path_template, "probe": probe,
        "status_code": status_code, "identity_effect": identity_effect,
        "capability": capability, "denial_body_checked": bool(denial_checked),
        "alternate_status_code": alternate_status,
        "checklist": {key: bool(value) for key, value in flags.items()},
        "redacted": True,
    }
    summary["sha256"] = digest({key: value for key, value in summary.items()
                                if key not in {"sha256", "redacted"}})
    return summary


def _constraints(runner, baseline=None):
    stats = runner.stats()
    baseline = baseline or {}
    return {
        "requests_sent": max(0, stats.get("requests_sent", 0) - baseline.get("requests_sent", 0)),
        "blocked_by_guard": max(0, stats.get("blocked_by_guard", 0) - baseline.get("blocked_by_guard", 0)),
        "redirects_observed": stats.get("redirects_observed", 0),
        "redirects_followed": 0,
        "out_of_scope_requests_executed": 0,
        "destructive_requests_executed": 0,
        "external_requests_executed": 0,
        "budget_remaining": stats.get("budget_remaining", 0),
        "network_transport_enabled": False,
        "halted_reason": "halted" if stats.get("halted") else None,
    }


def _base_run(plan, timestamp, transport):
    scope = plan.scope
    return {
        "id": str(uuid4()), "created_at": timestamp, "mode": "offline_authentication",
        "status": "completed", "scenario_id": plan.scenario_id, "title": plan.title,
        "transport": transport, "network_transport_enabled": False,
        "scheme": plan.scheme, "claims_unverified": True, "signature_verification": "not_performed",
        "scope": {
            "origin": scope.origin, "hostname": scope.hostname, "port": scope.port,
            "written_authorization_reference": scope.written_authorization_reference,
            "scope_sha256": digest(scope.model_dump(mode="json")),
            "request_budget": scope.request_budget,
            "accounts": [{"account": item.account, "role": item.role} for item in scope.accounts],
        },
        "checks": [], "summary": {"total": len(CHECK_IDS), "executed": 0, "confirmed": 0,
                                  "suspected": 0, "safe": 0, "inconclusive": 0, "skipped": 0},
        "constraints": {},
        "transcript_sha256": plan.combined_sha256(),
        "limitations": list(LIMITATIONS),
    }


def _probe(runner, plan, actor, target, probe, path):
    """Execute one probe; distinguish a guard block from an invalid plan."""
    before = runner.stats()["blocked_by_guard"]
    try:
        response = runner.probe(actor, path, probe)
    except ValueError:
        if runner.stats()["blocked_by_guard"] > before:
            return None
        raise
    if not runner.verifies_recorded_probe(response, actor, "GET", path, probe):
        raise ValueError("probe response provenance could not be verified")
    return response


def _identity_probe(runner, plan, roles, actor, target, probe, check_id, decision, timestamp):
    response = _probe(runner, plan, actor, target, probe, plan.profile_path)
    if response is None:
        return _skipped(check_id, "The safety guard blocked the probe; it was not executed")
    body = _json(response)
    effect = observe_identity(body, field=plan.identity_field, actor=actor, target=target)
    verdict, reason = decision(response.status_code, body,
                               expected_denial_body=plan.denial_body, identity_effect=effect)
    evidence = _evidence(phase="probe", timestamp=timestamp, actor=actor, role=roles[actor],
                         method="GET", path_template=plan.profile_path, probe=probe,
                         status_code=response.status_code, identity_effect=effect,
                         denial_checked=verdict == "SAFE",
                         flags={"response_checked": True, "identity_observed": effect != "unobserved",
                                "identity_changed": effect == "target",
                                "denial_body_checked": verdict == "SAFE"})
    return _check(check_id, verdict, reason, evidence=evidence,
                  remediation=REMEDIATION.get(check_id) if verdict == "CONFIRMED" else None)


def _api_key_checks(runner, plan, roles, actor, target, timestamp):
    results = {}
    for probe in ("api_key_missing", "api_key_invalid"):
        response = _probe(runner, plan, actor, target, probe, plan.profile_path)
        if response is None:
            return None
        body = _json(response)
        effect = observe_identity(body, field=plan.identity_field, actor=actor, target=target)
        results[probe] = (response.status_code, effect,
                          credential_rejection_decision(response.status_code, body,
                                                        expected_denial_body=plan.denial_body,
                                                        identity_effect=effect))
    missing, invalid = results["api_key_missing"], results["api_key_invalid"]
    verdict, reason = api_key_decision(missing[2][0], invalid[2][0])
    evidence = _evidence(
        phase="probe", timestamp=timestamp, actor=actor, role=roles[actor], method="GET",
        path_template=plan.profile_path, probe="api_key_missing",
        status_code=missing[0], identity_effect=missing[1],
        alternate_status=invalid[0], denial_checked=verdict == "SAFE",
        flags={"missing_key_checked": True, "invalid_key_checked": True,
               "identity_observed": "unobserved" not in {missing[1], invalid[1]},
               "denial_body_checked": verdict == "SAFE"})
    return _check("AUTHN-08", verdict, reason, evidence=evidence,
                  remediation=REMEDIATION["AUTHN-08"] if verdict == "CONFIRMED" else None)


def _role_check(runner, plan, roles, actor, target, timestamp):
    baseline = runner.get(actor, plan.admin_path)
    if baseline.status_code != 403:
        return _inconclusive("AUTHN-04b", "The declared admin operation did not deny a normal account; "
                                          "the modified role cannot be isolated")
    response = _probe(runner, plan, actor, target, "jwt_role", plan.admin_path)
    if response is None:
        return _skipped("AUTHN-04b", "The safety guard blocked the role probe; it was not executed")
    body = _json(response)
    capability = observe_capability(body, field=plan.admin_capability_field)
    verdict, reason = role_tamper_decision(response.status_code, body,
                                           expected_denial_body=plan.denial_body, capability=capability)
    evidence = _evidence(phase="probe", timestamp=timestamp, actor=actor, role=roles[actor],
                         method="GET", path_template=plan.admin_path, probe="jwt_role",
                         status_code=response.status_code, capability=capability,
                         denial_checked=verdict == "SAFE",
                         flags={"response_checked": True, "capability_observed": capability != "unobserved",
                                "capability_granted": capability == "granted",
                                "denial_body_checked": verdict == "SAFE"})
    return _check("AUTHN-04b", verdict, reason, evidence=evidence,
                  remediation=REMEDIATION["AUTHN-04b"] if verdict == "CONFIRMED" else None)


def _logout_check(runner, plan, roles, actor, target, baseline_identity, timestamp):
    if baseline_identity != "self":
        return _inconclusive("AUTHN-06", "The pre-logout baseline did not establish the account identity")
    before = runner.stats()["blocked_by_guard"]
    try:
        logout = runner.authenticate(actor, plan.logout_path)
    except ValueError:
        if runner.stats()["blocked_by_guard"] > before:
            return _skipped("AUTHN-06", "The safety guard blocked the logout request; it was not executed")
        raise
    if not runner.verifies_recorded_probe(logout, actor, "POST", plan.logout_path, "logout"):
        raise ValueError("logout provenance could not be verified")
    if not 200 <= logout.status_code < 300:
        return _inconclusive("AUTHN-06", "The logout request did not produce a successful recorded response")
    response = _probe(runner, plan, actor, target, "logout_reuse", plan.profile_path)
    if response is None:
        return _skipped("AUTHN-06", "The safety guard blocked the post-logout read; it was not executed")
    body = _json(response)
    effect = observe_identity(body, field=plan.identity_field, actor=actor, target=target)
    verdict, reason = logout_reuse_decision(response.status_code, body,
                                            expected_denial_body=plan.denial_body,
                                            identity_effect=effect)
    evidence = _evidence(phase="logout", timestamp=timestamp, actor=actor, role=roles[actor],
                         method="GET", path_template=plan.profile_path, probe="logout_reuse",
                         status_code=response.status_code, identity_effect=effect,
                         denial_checked=verdict == "SAFE",
                         flags={"logout_observed": True, "post_logout_rejected": verdict == "SAFE",
                                "post_logout_accepted": response.status_code == 200,
                                "baseline_identity": True})
    return _check("AUTHN-06", verdict, reason, evidence=evidence)


def _guarded(check_id, function):
    """Isolate one check: an unusable response is INCONCLUSIVE, never SAFE."""
    try:
        return function()
    except ValueError:
        return _inconclusive(check_id, "The probe response could not be validated; no conclusion was drawn")


def _summarise(checks):
    summary = {"total": len(checks), "executed": 0, "confirmed": 0, "suspected": 0,
               "safe": 0, "inconclusive": 0, "skipped": 0}
    for check in checks:
        key = check["verdict"].lower()
        summary[key] = summary.get(key, 0) + 1
        if check["verdict"] != "SKIPPED":
            summary["executed"] += 1
    return summary


def run_authentication_scan(runner, plan):
    """Run every applicable P0 authentication check through one guarded boundary."""
    if not isinstance(runner, OfflineAuthRunner) or not isinstance(plan, AuthenticationPlan):
        raise ValueError("a guarded offline authentication runner and validated plan are required")
    if runner.scope.origin != plan.scope.origin or runner.transcript_sha256 != plan.combined_sha256():
        raise ValueError("runner scope or recorded transcript does not match the plan")
    timestamp = datetime.now(timezone.utc).isoformat()
    roles = plan.account_roles()
    actor, target = plan.accounts
    run = _base_run(plan, timestamp, runner.transport_label)
    baseline_stats = runner.stats()
    checks = {}
    try:
        baseline = runner.get(actor, plan.profile_path)
        baseline_body = _json(baseline)
        baseline_identity = observe_identity(baseline_body, field=plan.identity_field,
                                             actor=actor, target=target)
        for check_id, probe in (("AUTHN-01", "missing"), ("AUTHN-02", "malformed"),
                                ("AUTHN-03", "wrong_scheme")):
            checks[check_id] = _guarded(check_id, lambda c=check_id, p=probe: _identity_probe(
                runner, plan, roles, actor, target, p, c, credential_rejection_decision, timestamp))
        if runner.credential_is_supported_jwt(actor):
            checks["AUTHN-04a"] = _guarded("AUTHN-04a", lambda: _identity_probe(
                runner, plan, roles, actor, target, "jwt_sub", "AUTHN-04a",
                subject_tamper_decision, timestamp))
            if plan.admin_path is None:
                checks["AUTHN-04b"] = _inconclusive("AUTHN-04b", NO_ADMIN_REASON)
            else:
                checks["AUTHN-04b"] = _guarded("AUTHN-04b", lambda: _role_check(
                    runner, plan, roles, actor, target, timestamp))
            checks["AUTHN-05"] = _guarded("AUTHN-05", lambda: _identity_probe(
                runner, plan, roles, actor, target, "alg_none", "AUTHN-05",
                alg_none_decision, timestamp))
        else:
            for check_id in ("AUTHN-04a", "AUTHN-04b", "AUTHN-05"):
                checks[check_id] = _skipped(check_id, JWT_SKIP_REASON)
        if plan.logout_path is None:
            checks["AUTHN-06"] = _skipped("AUTHN-06", NO_LOGOUT_REASON)
        else:
            checks["AUTHN-06"] = _guarded("AUTHN-06", lambda: _logout_check(
                runner, plan, roles, actor, target, baseline_identity, timestamp))
        if plan.scheme != "api_key":
            checks["AUTHN-08"] = _skipped("AUTHN-08", API_KEY_SKIP_REASON)
        else:
            checks["AUTHN-08"] = _guarded("AUTHN-08", lambda: _api_key_checks(
                runner, plan, roles, actor, target, timestamp))
    except Exception:
        run["status"] = "failed"
        for check_id in CHECK_IDS:
            checks.setdefault(check_id, _inconclusive(
                check_id, "The authentication scenario failed closed; no conclusion was drawn"))
    ordered = [checks.get(check_id) or _inconclusive(
        check_id, "The authentication scenario failed closed; check was not executed")
        for check_id in CHECK_IDS]
    run["checks"] = ordered
    run["summary"] = _summarise(ordered)
    run["constraints"] = _constraints(runner, baseline_stats)
    return run
