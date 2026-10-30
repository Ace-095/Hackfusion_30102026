"""Conservative input-validation and enumeration verdicts.

Every deciding verdict requires an observed response body. A success status is
never treated as proof that the input was validated, and a validation error is
only counted when the body is bounded and field-specific.
"""
import re

INPUT_PROBE_NAMES = ("control", "extra_property", "malformed_json", "special_characters")
_INTERNAL_DETAIL = re.compile(r"traceback|sqlstate|exception|stack trace|\bFile\s+[\"']/", re.IGNORECASE)


def input_verdict(status_code: int, body=None) -> tuple[str, str]:
    """Require a successful control and a fixture error referring to the field.

    A status code alone cannot prove why the operation failed. Unexpected error
    bodies and server internals are inconclusive, even when the status is 400.
    """
    if status_code in (400, 422):
        message = body.get("error") if isinstance(body, dict) else None
        if (isinstance(message, str) and re.search(r"\blimit\b", message, re.IGNORECASE)
                and not re.search(r"traceback|sqlstate|exception", message, re.IGNORECASE)):
            return "SAFE", "The invalid fixture limit was rejected with a field-specific error"
        return "INCONCLUSIVE", "The error response did not establish schema validation"
    if 200 <= status_code < 300:
        return "SUSPECTED", "The invalid fixture input was accepted; verify whether it was ignored or defaulted"
    return "INCONCLUSIVE", "The response does not establish whether input validation worked"


def _bounded_error(body):
    return (isinstance(body, dict) and isinstance(body.get("error"), str)
            and 0 < len(body["error"]) <= 512)


def _checked_error(status, body, *, field=None):
    if status not in (400, 422) or not _bounded_error(body):
        return False
    message = body["error"]
    if _INTERNAL_DETAIL.search(message):
        return False
    return field is None or field.casefold() in message.casefold()


def extra_property_decision(status, body, *, field, effect_observed):
    """INPUT-05: an extra JSON property is rejected, accepted, or unproven."""
    if _checked_error(status, body, field=field):
        return "SAFE", "The unexpected property was rejected with a field-specific error"
    if 200 <= status < 300 and effect_observed:
        return "CONFIRMED", "The unexpected property was accepted and its effect was observed"
    if 200 <= status < 300:
        return "SUSPECTED", "The unexpected property was accepted; no effect was observed"
    return "INCONCLUSIVE", "The response did not establish whether the unexpected property was rejected"


def malformed_json_decision(status, body):
    """INPUT-06: a malformed JSON body must be rejected with a bounded error."""
    if _checked_error(status, body):
        return "SAFE", "The malformed JSON body was rejected with a bounded parse error"
    if 200 <= status < 300:
        return "SUSPECTED", "The malformed JSON body was accepted; investigate parser leniency"
    return "INCONCLUSIVE", "The response did not establish how the malformed JSON body was handled"


def special_characters_decision(status, body):
    """INPUT-07: observe error handling only; never infer from acceptance."""
    if _checked_error(status, body):
        return "SAFE", "Special characters were rejected with a bounded validation error"
    if status == 401 and _bounded_error(body) and not _INTERNAL_DETAIL.search(body["error"]):
        return "SAFE", "Special characters were handled as ordinary invalid credentials"
    if 500 <= status < 600:
        return "SUSPECTED", "Special characters produced a server error; investigate error handling"
    if 200 <= status < 300:
        return "SUSPECTED", "Special characters were accepted without a validation error"
    return "INCONCLUSIVE", "The response did not establish the special-character handling"


def enumeration_decision(known_status, known_body, unknown_status, unknown_body):
    """DISC-06: only differing bounded error responses confirm enumeration."""
    if (not isinstance(known_body, dict) or not isinstance(unknown_body, dict)
            or 500 <= known_status < 600 or 500 <= unknown_status < 600):
        return "INCONCLUSIVE", "The error responses were not usable for an existence comparison"
    if not (400 <= known_status < 500 and 400 <= unknown_status < 500):
        return "INCONCLUSIVE", "The compared responses were not both error responses"
    if (known_status, known_body) == (unknown_status, unknown_body):
        return "SAFE", "Existing and nonexistent resources produced identical error responses"
    return "CONFIRMED", "Differing error responses distinguish existing from nonexistent resources"
