"""Conservative helpers for the first fixture authentication checks."""
import base64
from dataclasses import dataclass, field
import json
import re


@dataclass(frozen=True)
class UnverifiedJWTMetadata:
    """Transient, untrusted JWT metadata; it never establishes identity or policy."""
    algorithm: str = field(repr=False)
    subject: str | None = field(repr=False)
    role: str | None = field(repr=False)
    expiration: int | None = field(repr=False)
    claims_unverified: bool = field(default=True, init=False)


def inspect_jwt_metadata(token: str) -> UnverifiedJWTMetadata | None:
    """Decode bounded metadata without signature verification; do not persist it."""
    if not isinstance(token, str) or len(token) > 8192:
        return None
    parts = token.split(".")
    if len(parts) != 3 or not parts[0] or not parts[1]:
        return None

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError("invalid JSON constant")

    try:
        decoded = []
        for part in parts[:2]:
            if not re.fullmatch(r"[A-Za-z0-9_-]+", part):
                return None
            raw = base64.b64decode(part + "=" * (-len(part) % 4), altchars=b"-_", validate=True)
            decoded.append(json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant))
        header, payload = decoded
        if (not isinstance(header, dict) or not isinstance(payload, dict)
                or not isinstance(header.get("alg"), str) or not header["alg"]):
            return None
        def safe_claim(name):
            value = payload.get(name)
            return value if isinstance(value, str) and 0 < len(value) <= 256 else None
        exp = payload.get("exp")
        exp = exp if type(exp) is int and -(2**63) <= exp < 2**63 else None
        return UnverifiedJWTMetadata(header["alg"], safe_claim("sub"), safe_claim("role"), exp)
    except (ValueError, UnicodeError, TypeError, RecursionError):
        return None


def is_supported_jwt(token: str) -> bool:
    """Detect JWT format for applicability only; never verify identity."""
    return inspect_jwt_metadata(token) is not None


def auth_verdict(status_code: int, response_body, *, private_field: str, baseline: str) -> tuple[str, str]:
    """A 200 alone is never proof that private access was granted."""
    if status_code in (401, 403) and response_body == {}:
        return "SAFE", "The fixture rejected the authentication probe with a checked empty body"
    if (status_code == 200 and isinstance(response_body, dict)
            and private_field.lower() not in {"id", "status", "owner", "user_id"}
            and isinstance(baseline, str) and baseline
            and response_body.get(private_field) == baseline):
        return "CONFIRMED", "The probe received private data matching the authenticated baseline"
    return "INCONCLUSIVE", "The response did not establish either denial or private disclosure"
