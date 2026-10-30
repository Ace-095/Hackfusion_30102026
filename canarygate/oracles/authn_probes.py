"""Conservative decisions for crafted-credential authentication checks.

Observations are recorded synthetic API behaviour. JWT claims are decoded
without verification solely to build a tampered token that retains the original
signature; a decoded claim is never evidence of identity, privilege or policy.
An accepted request is never SAFE, and an unobservable effect is never SAFE.
"""
import base64
import json
import re

from canarygate.oracles.authentication import inspect_jwt_metadata

JWT_SKIP_REASON = "Token is not a supported JWT format; JWT-specific test not applicable."
NO_LOGOUT_REASON = "No scoped logout operation is declared; post-logout token reuse is not applicable."
NO_ADMIN_REASON = "No scoped admin-only operation was declared; the modified role cannot be observed."
NO_IDENTITY_REASON = "No identity-revealing response field was observed; the effective identity cannot be determined."
API_KEY_SKIP_REASON = "The API does not use an API-key scheme; missing or invalid API-key checks are not applicable."

DENIAL_STATUSES = (401, 403)
_SEGMENT = re.compile(r"[A-Za-z0-9_-]+")


def is_checked_denial(status, body, expected_denial_body):
    """A denial counts only with a denial status and the exact declared body."""
    return (type(status) is int and status in DENIAL_STATUSES
            and isinstance(expected_denial_body, dict) and body == expected_denial_body)


def observe_identity(body, *, field, actor, target):
    """Map a response body to a coarse identity effect; never guess."""
    if not isinstance(body, dict) or not isinstance(field, str):
        return "unobserved"
    value = body.get(field)
    if not isinstance(value, str) or not value:
        return "unobserved"
    if value == actor:
        return "self"
    if value == target:
        return "target"
    return "other"


def observe_capability(body, *, field):
    """Observe an exact boolean capability marker; anything else is unobserved."""
    if not isinstance(body, dict) or not isinstance(field, str):
        return "unobserved"
    value = body.get(field)
    if value is True:
        return "granted"
    if value is False:
        return "none"
    return "unobserved"


def _decode(segment):
    if not isinstance(segment, str) or not _SEGMENT.fullmatch(segment):
        raise ValueError("token segment is not base64url")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate claim")
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError("invalid JSON constant")

    raw = base64.b64decode(segment + "=" * (-len(segment) % 4), altchars=b"-_", validate=True)
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant)


def _encode(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def craft_token(token, *, sub=None, role=None, alg_none=False):
    """Return a tampered token that retains the original signature segment.

    This is format manipulation, not signature forgery: no key material is used
    and the result is never verified by this project.
    """
    if inspect_jwt_metadata(token) is None:
        raise ValueError("token is not a supported JWT")
    if sub is not None and (not isinstance(sub, str) or not 0 < len(sub) <= 256):
        raise ValueError("invalid subject claim")
    if role is not None and (not isinstance(role, str) or not 0 < len(role) <= 256):
        raise ValueError("invalid role claim")
    header_segment, payload_segment, signature = token.split(".")
    header, payload = _decode(header_segment), _decode(payload_segment)
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("token segments must be JSON objects")
    crafted_header = {"alg": "none", "typ": "JWT"} if alg_none else header
    if alg_none:
        signature = ""
    payload = dict(payload)
    if sub is not None:
        payload["sub"] = sub
    if role is not None:
        payload["role"] = role
    result = f"{_encode(crafted_header)}.{_encode(payload)}.{signature}"
    if inspect_jwt_metadata(result) is None:
        raise ValueError("crafted token is not a supported JWT")
    return result


def credential_rejection_decision(status, body, *, expected_denial_body, identity_effect):
    """AUTHN-01/02/03 and API-key probes: rejected is SAFE, accepted needs proof."""
    if is_checked_denial(status, body, expected_denial_body):
        return "SAFE", "The API rejected the request with the checked denial body"
    if status == 200 and identity_effect in {"self", "target", "other"}:
        return "CONFIRMED", "The API returned an authenticated identity to a request without a valid credential"
    if status == 200:
        return "INCONCLUSIVE", "The API accepted the request but no identity effect could be observed"
    return "INCONCLUSIVE", "The response established neither a checked denial nor an observable credential effect"


def subject_tamper_decision(status, body, *, expected_denial_body, identity_effect):
    """AUTHN-04a: only an observable identity change confirms the weakness."""
    if is_checked_denial(status, body, expected_denial_body):
        return "SAFE", "The API rejected the modified sub claim with the checked denial body"
    if status == 200 and identity_effect == "target":
        return "CONFIRMED", "The modified sub claim changed the effective identity to the second account"
    if status == 200 and identity_effect == "self":
        return "SUSPECTED", "The modified sub claim was accepted but the response still showed the original account"
    if status == 200 and identity_effect == "other":
        return "SUSPECTED", "The modified sub claim was accepted and showed an unexpected identity; investigate"
    if status == 200:
        return "INCONCLUSIVE", "The modified sub claim was accepted but the effective identity was not observable"
    return "INCONCLUSIVE", "The response did not establish whether the modified sub claim took effect"


def role_tamper_decision(status, body, *, expected_denial_body, capability):
    """AUTHN-04b: only an observed admin capability confirms escalation."""
    if is_checked_denial(status, body, expected_denial_body):
        return "SAFE", "The API rejected the modified role claim with the checked denial body"
    if status == 200 and capability == "granted":
        return "CONFIRMED", "The modified role claim granted the scoped admin capability"
    if status == 200 and capability == "none":
        return "SUSPECTED", "The modified role claim was accepted but no admin capability was observed"
    if status == 200:
        return "INCONCLUSIVE", "The modified role claim was accepted but admin capability could not be observed"
    return "INCONCLUSIVE", "The response did not establish whether the modified role claim took effect"


def alg_none_decision(status, body, *, expected_denial_body, identity_effect):
    """AUTHN-05: accepting an unsigned token is never SAFE."""
    if is_checked_denial(status, body, expected_denial_body):
        return "SAFE", "The API rejected the unsigned alg:none token with the checked denial body"
    if status == 200 and identity_effect in {"self", "target", "other"}:
        return "CONFIRMED", "An unsigned alg:none token was accepted and its identity claim was honoured"
    if status == 200:
        return "SUSPECTED", "An unsigned alg:none token was accepted but no identity effect could be observed"
    return "INCONCLUSIVE", "The response did not establish whether the unsigned token was honoured"


def logout_reuse_decision(status, body, *, expected_denial_body, identity_effect):
    """AUTHN-06 reports observed behaviour; it never confirms on its own."""
    if is_checked_denial(status, body, expected_denial_body):
        return "SAFE", "The token was rejected after logout with the checked denial body"
    if status == 200 and identity_effect in {"self", "target", "other"}:
        return "SUSPECTED", ("The token was still accepted after logout; stateless tokens may behave "
                             "this way, so this is an observation requiring investigation, not a confirmed weakness")
    if status == 200:
        return "INCONCLUSIVE", "The request succeeded after logout but the identity effect was not observable"
    return "INCONCLUSIVE", "The post-logout behaviour could not be established"


def api_key_decision(missing_verdict, invalid_verdict):
    """Combine the two AUTHN-08 observations using the strictest outcome."""
    observed = (missing_verdict, invalid_verdict)
    detail = f"(missing key: {missing_verdict}, invalid key: {invalid_verdict})"
    if "CONFIRMED" in observed:
        return "CONFIRMED", "A missing or invalid API key was accepted with an authenticated identity " + detail
    if "SUSPECTED" in observed:
        return "SUSPECTED", "A missing or invalid API key was accepted without an observable identity " + detail
    if "INCONCLUSIVE" in observed:
        return "INCONCLUSIVE", "API-key observations did not all establish a checked denial " + detail
    return "SAFE", "Both the missing and invalid API-key probes were rejected with checked denial bodies"
