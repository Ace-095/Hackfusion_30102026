"""Narrow disclosure signatures for bounded, redacted fixture responses."""
import re


def disclosure_signals(response) -> set[str]:
    # Only scan already-bounded responses. Findings are signature names, not raw
    # body snippets or header values, so fixture evidence cannot expose secrets.
    text = response.text
    signals = set()
    if re.search(r"Traceback \(most recent call last\):", text, re.IGNORECASE):
        signals.add("stack_trace")
    # JSON bodies escape quotes, so an internal path may appear as \"/srv/...\".
    if re.search(r"\bSQLSTATE\s+[A-Z0-9]{5}\b", text, re.IGNORECASE) or re.search(
        r"\bFile\s+\\?[\"']/(?:srv|var|home|usr|opt)/[^\"'\\]+\\?[\"']\s*,\s*line\s+\d+",
        text, re.IGNORECASE
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
# Value patterns are fixed and conservative: a match is a disclosure signal, not
# a secret copy. The walker never returns the matched text.
_SENSITIVE_PATTERNS = (
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("api_key", re.compile(r"\b(?:sk_live|sk_test|AKIA|ghp_|xoxb-)[A-Za-z0-9_]{8,}\b")),
)


def _json_body(response):
    content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        return None, False
    try:
        return response.json(), True
    except (ValueError, UnicodeError, RecursionError):
        return None, False


def inspect_sensitive_payload(response) -> tuple[set[str], bool]:
    """Return disclosure signal kinds and traversal completeness; never raw values.

    A field is reported by name when a fixed sensitive name carries an
    unredacted value, and by pattern when a value matches a fixed high-signal
    pattern (JWT, private key, provider API key). Only kinds are returned.
    """
    body, valid = _json_body(response)
    if not valid:
        return set(), False
    signals, complete = set(), True
    stack = [(body, 0)]
    count = 0
    while stack:
        item, depth = stack.pop()
        count += 1
        if count > _MAX_JSON_NODES:
            return signals, False
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
                            signals.add("name")
                    elif value is not None:
                        complete = False
                if isinstance(value, str) and any(
                        pattern.search(value) for _, pattern in _SENSITIVE_PATTERNS):
                    signals.add("pattern")
                stack.append((value, depth + 1))
        elif isinstance(item, list):
            for value in item:
                if isinstance(value, str) and any(
                        pattern.search(value) for _, pattern in _SENSITIVE_PATTERNS):
                    signals.add("pattern")
                stack.append((value, depth + 1))
    return signals, complete


def inspect_sensitive_json(response) -> tuple[bool, bool]:
    """Return (sensitive value observed, traversal complete) without raw data."""
    signals, complete = inspect_sensitive_payload(response)
    return bool(signals), complete


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


SIGNAL_REASONS = {
    "stack_trace": "A stack trace or framework error text was observed in the response",
    "internal_error_detail": "Internal paths, SQLSTATE details or framework internals were observed",
    "version_header": "A server or framework version header was observed",
    "debug_header": "A debug header was observed",
}


def signal_verdict(signals, signal):
    """DISC-01/02/05: an observed signature confirms; a clean scan is SAFE."""
    if not isinstance(signals, set):
        return "INCONCLUSIVE", "The response could not be scanned for disclosure signatures"
    if signal in signals:
        return "CONFIRMED", SIGNAL_REASONS[signal]
    return "SAFE", "The bounded response did not contain the disclosure signature"


def sensitive_field_decision(signals, complete):
    """DISC-03: SAFE requires a complete traversal, not just an absent match."""
    kinds = set(signals) if signals else set()
    if "name" in kinds:
        return "CONFIRMED", "A sensitive field name carried a non-redacted value"
    if "pattern" in kinds:
        return "CONFIRMED", "A value matched a fixed sensitive-value pattern"
    if not complete:
        return "INCONCLUSIVE", "The JSON traversal was incomplete, so absence cannot be established"
    return "SAFE", "No sensitive field name or value pattern was observed in the bounded JSON"


def excess_fields_decision(excess, usable):
    """DISC-04: only an explicitly closed schema supports a SAFE verdict."""
    if not usable:
        return "INCONCLUSIVE", "No usable closed response schema was available for comparison"
    if excess:
        return "CONFIRMED", "Response fields were observed outside the declared response schema"
    return "SAFE", "The observed top-level fields matched the declared closed response schema"
