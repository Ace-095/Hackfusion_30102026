"""Conservative fixture input-validation verdicts."""
import re


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
