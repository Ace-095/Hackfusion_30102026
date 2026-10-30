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
                   "secret", "client-secret", "api-key", "x-api-key", "access-token", "refresh-token", "id-token",
                   "token", "x-auth-token", "x-access-token", "x-csrf-token", "private-note", "password-hash",
                   "pwd", "passphrase", "session-id", "sessionid", "session-token", "jwt",
                   "tokens", "credentials", "credential", "secrets", "cookies", "auth", "bearer",
                   "authorization-header", "x-amz-security-token"}
_KNOWN_FIXTURE_SECRETS = ("fixture-token-alice", "fixture-token-bob", "malformed-fixture", "synthetic-fixture",
                          "synthetic-alice-private-note", "synthetic-bob-private-canary",
                          "sci-interaction-secret-value",
                          # TargetLab: public, documented lab fixtures. They are listed so a
                          # regression that leaks one is scrubbed as well as asserted against.
                          "lab-token-alice", "lab-token-bob", "alice-lab-password", "bob-lab-password",
                          "targetlab-wrong-password-for-alice", "targetlab-wrong-password-for-bob",
                          "targetlab-alice-private-marker", "targetlab-bob-private-marker",
                          # The three-account demo tenant added for the judge playground. The
                          # two-account fixture values stay listed above: the frozen offline
                          # dataset still ships them.
                          "lab-token-mallapa", "lab-token-sakshi", "lab-token-harsha",
                          "mallapa-lab-password", "sakshi-lab-password", "harsha-lab-password",
                          "targetlab-wrong-password-for-mallapa", "targetlab-wrong-password-for-sakshi",
                          "targetlab-wrong-password-for-harsha",
                          "targetlab-mallapa-private-marker", "targetlab-sakshi-private-marker",
                          "targetlab-harsha-private-marker",
                          "targetlab-trace-marker")
_AUTH_VALUE = re.compile(r"(?i)\b(?:bearer|basic)\s+[^\s\"',;]+")
_JWT_VALUE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(password[_-]?hash|password|passwd|pwd|passphrase|access[_-]?token|refresh[_-]?token|"
    r"id[_-]?token|session[_-]?(?:id|token)|client[_-]?secret|token|secret|api[_-]?key)"
    r"\s*[:=]\s*(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s\"',;]+)"
)
_COOKIE_HEADER = re.compile(r"(?i)\b((?:set-)?cookie)\s*[:=][^\r\n]*")
_CAMEL_BOUNDARY = re.compile(r"([a-z0-9])([A-Z])")


class EvidenceIntegrityError(ValueError):
    """Persisted or supplied evidence does not match its redacted hash."""


def canonical_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _sensitive_key(key):
    normalized = _CAMEL_BOUNDARY.sub(r"\1-\2", key).lower().replace("_", "-") if isinstance(key, str) else ""
    return (normalized in _SENSITIVE_KEYS
            or normalized.endswith(("-token", "-secret", "-password", "-api-key", "-session-id",
                                    "-authorization", "-cookie")))


def redact(value):
    """Redact known credential fields, patterns, and built-in synthetic secrets."""
    if isinstance(value, dict):
        output = {}
        for key, item in value.items():
            if _sensitive_key(key):
                output[key] = REDACTED
            else:
                output[key] = redact(item)
        return output
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        text = _COOKIE_HEADER.sub(lambda match: match.group(1) + ": " + REDACTED, value)
        text = _AUTH_VALUE.sub(REDACTED, text)
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
