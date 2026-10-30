"""Run only explicitly scoped authentication probes against the fixture."""
from canarygate.guard.safety_guard import GuardRejected
from canarygate.offline.runner import FixtureResponseTooLarge
from canarygate.oracles.authentication import auth_verdict, is_supported_jwt

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


def run_auth_checks(runner, *, actor, role, path, token, private_field, baseline, summary):
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
        try:
            body = response.json()
        except (ValueError, UnicodeError, RecursionError):
            body = None
        verdict, reason = auth_verdict(response.status_code, body, private_field=private_field, baseline=baseline)
        matched = verdict == "CONFIRMED"
        checks[index].update({"verdict": verdict, "reason": reason,
                              "evidence": summary(actor, role, response, matched, authentication_probe=probe),
                              "remediation": "Require and validate authentication for protected operations." if matched else None})
    return checks
