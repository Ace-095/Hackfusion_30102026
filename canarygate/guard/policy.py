"""One shared safety-policy contract for every execution boundary.

These checks are identical for the in-process fixture guard and the validated
authorized-scope preflight used by guarded HTTPX and offline replay. Scope
models and operation classification remain separate; the prohibitions and
budget semantics below may not drift between execution paths.

Nothing here performs IO, DNS, or authorization of a target.
"""
from threading import Lock

PROHIBITED_METHODS = frozenset({"DELETE", "PUT", "PATCH", "TRACE", "CONNECT"})
READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
MAX_RESPONSE_BYTES = 64 * 1024


class SafetyPolicyViolation(ValueError):
    """A request violates the shared safety contract; no execution is allowed."""


def check_common(actor, method, allowed_accounts, allowed_methods, remaining):
    """Enforce shared prohibitions; never consume budget and never perform IO."""
    if (not isinstance(actor, str) or not isinstance(method, str)
            or not isinstance(allowed_accounts, frozenset) or not isinstance(allowed_methods, frozenset)
            or type(remaining) is not int):
        raise SafetyPolicyViolation("invalid request metadata")
    if actor not in allowed_accounts:
        raise SafetyPolicyViolation("unauthorized actor")
    if method in PROHIBITED_METHODS:
        raise SafetyPolicyViolation("method blocked by shared safety policy")
    if method not in allowed_methods:
        raise SafetyPolicyViolation("method not permitted by shared safety policy")
    if remaining <= 0:
        raise SafetyPolicyViolation("request budget exhausted")
    return None


class DecisionCounter:
    """Thread-safe counters shared by both guards for honest constraint reports."""
    def __init__(self):
        self._lock = Lock()
        self.requests_sent = 0
        self.blocked = 0
        self.redirects_observed = 0

    def sent(self):
        with self._lock:
            self.requests_sent += 1

    def block(self):
        with self._lock:
            self.blocked += 1

    def redirect(self):
        with self._lock:
            self.redirects_observed += 1

    def snapshot(self):
        with self._lock:
            return {"requests_sent": self.requests_sent, "blocked_by_guard": self.blocked,
                    "redirects_observed": self.redirects_observed}
