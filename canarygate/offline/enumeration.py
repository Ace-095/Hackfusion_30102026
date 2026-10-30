"""Fixture-only enumeration comparison against one known-absent synthetic ID.

The existing-resource response comes from the guarded missing-auth probe. The
second request is another exact scope entry, not general resource guessing.
"""
import httpx

from canarygate.guard.safety_guard import GuardRejected
from canarygate.offline.runner import FixtureResponseTooLarge

_EXISTING_PATH = "/items/alice-item"
_MISSING_PATH = "/items/nonexistent-item"


def _skipped(reason):
    return {"id": "DISC-06", "category": "Disclosure", "verdict": "SKIPPED",
            "reason": reason, "evidence": None, "remediation": None}


def run_enumeration_check(runner, *, actor, role, baseline, owner_verified, summary):
    result = _skipped("Verified fixture ownership and a missing-auth denial baseline are required")
    if actor != "alice" or role != "user" or owner_verified is not True or baseline is None:
        return result
    try:
        request = baseline.request
    except RuntimeError:
        return result
    if (request.method != "GET" or request.url != httpx.URL(runner.scope.origin + _EXISTING_PATH)
            or any(header in request.headers for header in ("authorization", "proxy-authorization", "cookie"))
            or baseline.status_code not in (401, 403)):
        return result
    try:
        response = runner.request(actor, "GET", runner.scope.origin + _MISSING_PATH, auth_probe="missing")
    except FixtureResponseTooLarge:
        result.update(verdict="INCONCLUSIVE", reason="Comparison request executed but response exceeded the fixture size limit")
        return result
    except GuardRejected:
        result["reason"] = "Comparison blocked by fixture scope, safety halt or budget; not executed"
        return result

    metadata = {"baseline_status": baseline.status_code}
    if response.status_code not in (401, 403, 404):
        result.update(verdict="INCONCLUSIVE", reason="The comparison response did not establish a reliable denial",
                      evidence=summary(actor, role, response, False, **metadata))
        return result
    # Compare bytes in memory only. Never persist raw error text or its hash.
    different = (response.status_code != baseline.status_code or response.content != baseline.content
                 or response.headers.get("content-type", "").lower() != baseline.headers.get("content-type", "").lower())
    metadata["responses_differ"] = different
    if different:
        result.update(verdict="SUSPECTED", reason="The two fixture denial responses differ; manual review is required",
                      remediation="Use consistent denial responses for existing and nonexistent resources.")
    else:
        result.update(verdict="SAFE", reason="No status, content-type and body difference was observed for this one synthetic resource pair")
    result["evidence"] = summary(actor, role, response, False, **metadata)
    return result
