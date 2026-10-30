"""Narrow disclosure signatures for bounded, redacted fixture responses."""
import re


def disclosure_signals(response) -> set[str]:
    # Only scan already-bounded responses. Findings are signature names, not raw
    # body snippets or header values, so fixture evidence cannot expose secrets.
    text = response.text
    signals = set()
    if re.search(r"Traceback \(most recent call last\):", text, re.IGNORECASE):
        signals.add("stack_trace")
    if re.search(r"\bSQLSTATE\s+[A-Z0-9]{5}\b", text, re.IGNORECASE) or re.search(
        r"\bFile\s+[\"']/(?:srv|var|home)/[^\"']+[\"']\s*,\s*line\s+\d+", text, re.IGNORECASE
    ):
        signals.add("internal_error_detail")
    for header in ("server", "x-powered-by"):
        value = response.headers.get(header, "")
        if re.search(r"(?:/|\s)v?\d+\.\d+(?:\.\d+)?\b", value, re.IGNORECASE):
            signals.add("version_header")
    for header in ("x-debug", "x-debug-token", "x-debug-mode", "x-debug-info"):
        value = response.headers.get(header, "").strip()
        if value:
            signals.add("debug_header")
    return signals

# Fixed signatures and bounded JSON traversal, for the synthetic search fixture.
# The caller receives booleans only: never return names, paths or secret values.
_SENSITIVE_FIELDS = {"password", "passwd", "password_hash", "passwordhash", "access_token",
                     "refresh_token", "token", "api_key", "apikey", "client_secret", "secret"}
_REDACTED_VALUES = {"[redacted]", "<redacted>", "redacted", "[masked]", "<masked>", "masked"}
_MAX_JSON_NODES = 10000
_MAX_JSON_DEPTH = 32


def _json_body(response):
    content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        return None, False
    try:
        return response.json(), True
    except (ValueError, UnicodeError, RecursionError):
        return None, False


def inspect_sensitive_json(response) -> tuple[bool, bool]:
    """Return (sensitive value observed, traversal complete) without raw data."""
    body, valid = _json_body(response)
    if not valid:
        return False, False
    found, complete = False, True
    stack = [(body, 0)]
    count = 0
    while stack:
        item, depth = stack.pop()
        count += 1
        if count > _MAX_JSON_NODES:
            return found, False
        if depth > _MAX_JSON_DEPTH:
            complete = False
            continue
        if isinstance(item, dict):
            for key, value in item.items():
                normalized = key.casefold().replace("-", "_") if isinstance(key, str) else ""
                if normalized in _SENSITIVE_FIELDS:
                    if isinstance(value, str):
                        stripped = value.strip()
                        if stripped and stripped.casefold() not in _REDACTED_VALUES and set(stripped) != {"*"}:
                            found = True
                    elif value is not None:
                        # Non-string values may be secrets, but name alone is insufficient.
                        complete = False
                stack.append((value, depth + 1))
        elif isinstance(item, list):
            stack.extend((value, depth + 1) for value in item)
    return found, complete


def inspect_extra_fields(response, response_schemas) -> tuple[bool, bool]:
    """Compare only top-level keys against an explicitly closed, simple schema."""
    if not isinstance(response_schemas, dict):
        return False, False
    schema = response_schemas.get(str(response.status_code))
    if (not isinstance(schema, dict) or schema.get("type") != "object"
            or schema.get("additionalProperties") is not False
            or not isinstance(schema.get("properties"), dict)
            or any(key in schema for key in ("allOf", "oneOf", "anyOf", "patternProperties", "$ref"))):
        return False, False
    body, valid = _json_body(response)
    if not valid or not isinstance(body, dict):
        return False, False
    return bool(set(body) - set(schema["properties"])), True
