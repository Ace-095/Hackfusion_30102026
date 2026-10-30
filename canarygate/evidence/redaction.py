"""Defense-in-depth redaction for fixture-only persistence.

This is not a complete redactor for arbitrary live API traffic. The scanner does
not accept live targets, credentials, or externally supplied scan payloads.
"""
import copy
import hashlib
import hmac
import json
import re

REDACTED = "[REDACTED]"
_SENSITIVE_KEYS = {"authorization", "proxy-authorization", "cookie", "set-cookie", "password", "passwd",
                   "secret", "client-secret", "api-key", "access-token", "refresh-token", "token", "private-note"}
_KNOWN_FIXTURE_SECRETS = ("fixture-token-alice", "fixture-token-bob", "malformed-fixture", "synthetic-fixture",
                          "synthetic-alice-private-note", "synthetic-bob-private-canary")
_AUTH_VALUE = re.compile(r"(?i)\b(?:bearer|basic)\s+[^\s\"',;]+")
_JWT_VALUE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b")
_SECRET_ASSIGNMENT = re.compile(r"(?i)\b(password|passwd|token|secret|api[_-]?key)\s*[:=]\s*[^\s\"',;]+")


class EvidenceIntegrityError(ValueError):
    """Persisted or supplied evidence does not match its redacted hash."""


def canonical_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def redact(value):
    """Redact known credential fields, patterns, and built-in synthetic secrets."""
    if isinstance(value, dict):
        output = {}
        for key, item in value.items():
            normalized = key.lower().replace("_", "-") if isinstance(key, str) else ""
            if normalized in _SENSITIVE_KEYS:
                output[key] = REDACTED
            else:
                output[key] = redact(item)
        return output
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        text = _AUTH_VALUE.sub(REDACTED, value)
        text = _JWT_VALUE.sub(REDACTED, text)
        text = _SECRET_ASSIGNMENT.sub(lambda match: match.group(1) + "=" + REDACTED, text)
        for secret in _KNOWN_FIXTURE_SECRETS:
            text = text.replace(secret, REDACTED)
        return text
    return value


def _evidence_items(report):
    for evidence in report["evidence"].values():
        if evidence is not None:
            yield evidence
    for check in report["checks"]:
        if check["evidence"] is not None:
            yield check["evidence"]


def verify_evidence(report):
    for evidence in _evidence_items(report):
        actual_hash = evidence.get("sha256")
        summary = {key: value for key, value in evidence.items() if key not in {"sha256", "redacted"}}
        if evidence.get("redacted") is not True or not isinstance(actual_hash, str) or re.fullmatch(r"[0-9a-f]{64}", actual_hash) is None or not hmac.compare_digest(actual_hash, digest(summary)):
            raise EvidenceIntegrityError("fixture evidence failed integrity verification")


def prepare_for_storage(report):
    """Validate incoming hashes; minimize and redact before recalculating them."""
    original = copy.deepcopy(report)
    verify_evidence(original)
    cleaned = redact(original)
    # Evidence request/response data is deliberately minimized to a small safe
    # subset. Unknown headers, cookies, raw bodies and extra fields are dropped.
    for evidence in _evidence_items(cleaned):
        headers = evidence.get("request", {}).get("headers", {})
        if not isinstance(headers, dict):
            raise ValueError("invalid fixture evidence headers")
        evidence["request"] = {"headers": {"Authorization": REDACTED} if any(
            isinstance(k, str) and k.lower() == "authorization" for k in headers
        ) else {}}
        body = evidence.get("response", {}).get("body")
        if isinstance(body, dict):
            # Only these known synthetic identifiers may be retained verbatim.
            body = {key: body[key] for key in ("id", "owner", "private_note") if key in body}
            if "id" in body and body["id"] not in ("alice-item", "bob-item"):
                body["id"] = REDACTED
            if "owner" in body and body["owner"] not in ("alice", "bob"):
                body["owner"] = REDACTED
            if "private_note" in body:
                body["private_note"] = REDACTED
        else:
            body = None
        evidence["response"] = {"body": body}
        # Only known fixture checklist keys and narrowly typed values survive.
        allowed_bools = {"both_owner_baselines", "cross_list_isolation", "matches_owner_private_baseline",
                         "valid_control_observed", "responses_differ", "denial_body_checked"}
        allowed_values = {"authentication_probe": {"missing", "malformed", "wrong_scheme"},
                          "input_case": {"valid_control", "missing_required_limit", "wrong_type", "out_of_range", "invalid_enum_limit"},
                          "disclosure_signature": {"stack_trace", "internal_error_detail", "version_header", "debug_header", "sensitive_field", "unexpected_top_level_field"}}
        source = evidence.get("checklist", {})
        if not isinstance(source, dict):
            raise ValueError("invalid fixture evidence checklist")
        checklist = {key: value for key, value in source.items() if key in allowed_bools and type(value) is bool}
        for key, permitted in allowed_values.items():
            if isinstance(source.get(key), str) and source[key] in permitted:
                checklist[key] = source[key]
        if type(source.get("baseline_status")) is int and 100 <= source["baseline_status"] <= 599:
            checklist["baseline_status"] = source["baseline_status"]
        if type(source.get("inspected_fixture_responses")) is int and 0 <= source["inspected_fixture_responses"] <= 5:
            checklist["inspected_fixture_responses"] = source["inspected_fixture_responses"]
        evidence["checklist"] = checklist
        evidence["redacted"] = True
        evidence["sha256"] = digest({key: value for key, value in evidence.items() if key not in {"sha256", "redacted"}})
    verify_evidence(cleaned)
    return cleaned
