"""Conservative helpers for the first fixture authentication checks."""
import base64
import json
import re


def is_supported_jwt(token: str) -> bool:
    """Detect JWT-shaped tokens for applicability only; never verify identity."""
    if not isinstance(token, str) or len(token) > 8192:
        return False
    parts = token.split(".")
    if len(parts) != 3 or not parts[0] or not parts[1]:
        return False
    try:
        decoded = []
        for part in parts[:2]:
            if not re.fullmatch(r"[A-Za-z0-9_-]+", part):
                return False
            raw = base64.b64decode(part + "=" * (-len(part) % 4), altchars=b"-_", validate=True)
            decoded.append(json.loads(raw))
        header, payload = decoded
        return isinstance(header, dict) and isinstance(payload, dict) and isinstance(header.get("alg"), str) and bool(header["alg"])
    except (ValueError, UnicodeError, TypeError):
        return False


def auth_verdict(status_code: int, response_body, *, private_field: str, baseline: str) -> tuple[str, str]:
    """A 200 alone is never proof that private access was granted."""
    if status_code in (401, 403):
        return "SAFE", "The fixture rejected the authentication probe"
    if (status_code == 200 and isinstance(response_body, dict)
            and private_field.lower() not in {"id", "status", "owner", "user_id"}
            and isinstance(baseline, str) and baseline
            and response_body.get(private_field) == baseline):
        return "CONFIRMED", "The probe received private data matching the authenticated baseline"
    return "INCONCLUSIVE", "The response did not establish either denial or private disclosure"
