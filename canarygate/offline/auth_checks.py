"""Run only explicitly scoped authentication probes against the fixture."""
from canarygate.guard.safety_guard import GuardRejected
from canarygate.offline.runner import FixtureResponseTooLarge
from canarygate.oracles.authentication import auth_verdict, is_supported_jwt
from canarygate.seed.registry import _json

PROBES = (("AUTHN-01", "missing"), ("AUTHN-02", "malformed"), ("AUTHN-03", "wrong_scheme"))
JWT_REASON = "Token is not a supported JWT format; JWT-specific test not applicable."


def pending_checks(reason="Authentication probe prerequisites were not met", token=None):
    checks = [{"id": check_id, "category": "Authentication", "verdict": "SKIPPED",
               "reason": reason, "evidence": None, "remediation": None} for check_id, _ in PROBES]
    jwt_reason = JWT_REASON if token is not None and not is_supported_jwt(token) else (
        "JWT tampering checks are not implemented" if token is not None else reason)
    for check_id in ("AUTHN-04a", "AUTHN-04b", "AUTHN-05"):
        checks.append({"id": check_id, "category": "Authentication", "verdict": "SKIPPED",
                       "reason": jwt_reason, "evidence": None, "remediation": None})
    for check_id, why in (("AUTHN-06", "Logout check not implemented"),
                          ("AUTHN-07", "Public endpoint check not implemented"),
                          ("AUTHN-08", "API key check not implemented")):
        checks.append({"id": check_id, "category": "Authentication", "verdict": "SKIPPED",
                       "reason": why, "evidence": None, "remediation": None})
    return checks


def run_auth_checks(runner, *, actor, role, path, token, private_field, baseline, summary, observations=None):
    checks = pending_checks(token=token)
    if not isinstance(baseline, str) or not baseline:
        return checks
    for index, (check_id, probe) in enumerate(PROBES):
        try:
            response = runner.request(actor, "GET", runner.scope.origin + path, auth_probe=probe)
        except FixtureResponseTooLarge:
            checks[index]["verdict"] = "INCONCLUSIVE"
            checks[index]["reason"] = "Probe executed but the response exceeded the fixture size limit"
            continue
        except GuardRejected:
            checks[index]["reason"] = "Probe blocked by fixture scope or request budget; not executed"
            continue
        if observations is not None and probe == "missing":
            observations["missing"] = response
        # The fixture's denial contract is an empty body. Nonempty malformed,
        # duplicate-key or unexpected bodies cannot be labelled SAFE.
        body = {} if not response.content else _json(response)
        if response.status_code in (401, 403) and response.content and baseline in response.text:
            body = None
        verdict, reason = auth_verdict(response.status_code, body, private_field=private_field, baseline=baseline)
        matched = verdict == "CONFIRMED"
        metadata = {"authentication_probe": probe}
        if verdict == "SAFE":
            metadata["denial_body_checked"] = True
        checks[index].update({"verdict": verdict, "reason": reason,
                              "evidence": summary(actor, role, response, matched, **metadata),
                              "remediation": "Require and validate authentication for protected operations." if matched else None})
    return checks


def run_public_check(runner, *, actor, role, endpoints, summary):
    """Check one explicitly declared and scoped fixture public operation only."""
    check = {"id": "AUTHN-07", "category": "Authentication", "verdict": "SKIPPED",
             "reason": "No scoped public fixture health operation was declared", "evidence": None, "remediation": None}
    if not any(e.get("method") == "GET" and e.get("path") == "/public-health"
               and e.get("expected_access") == "public" and e.get("security") == [] for e in endpoints):
        return check
    try:
        response = runner.request(actor, "GET", runner.scope.origin + "/public-health", auth_probe="missing")
    except FixtureResponseTooLarge:
        check.update(verdict="INCONCLUSIVE", reason="Public fixture response exceeded the size limit")
        return check
    except GuardRejected:
        check["reason"] = "Public fixture probe blocked by scope, halt or budget; not executed"
        return check
    body = _json(response)
    if response.status_code == 200 and body == {"status": "ok", "service": "fixture"}:
        check.update(verdict="SAFE", reason="Declared public fixture health response was available without credentials")
    else:
        check.update(verdict="INCONCLUSIVE", reason="Public fixture response did not establish expected behavior")
    check["evidence"] = summary(actor, role, response, False, authentication_probe="missing")
    return check
