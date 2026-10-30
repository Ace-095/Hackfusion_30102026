"""Offline policy preflight; this is not a live transport or connection guard.

A successful decision cannot authorize a network request. A future live runner
must enforce all safety rules again at the connection boundary, including pinned
resolution, sequential execution, redirect handling and authentication bodies.
"""
from threading import Lock

from canarygate.guard.policy import check_common
from canarygate.scope.authorized import AuthorizedScope


class AuthorizedPreflight:
    """Conservative exact-string checks and a per-instance decision budget."""

    def __init__(self, scope: AuthorizedScope):
        if not isinstance(scope, AuthorizedScope):
            raise ValueError("validated scope required")
        # Pydantic model_copy(update=...) does not validate updates.
        scope = AuthorizedScope.model_validate(scope.model_dump())
        self._accounts = frozenset(account.account for account in scope.accounts)
        self._operations = {(op.method, scope.origin + op.path):
                            (op.classification, frozenset(op.auth_probes), frozenset(op.input_probes))
                            for op in scope.operations}
        self._methods = frozenset(scope.allowed_methods)
        self._remaining = scope.request_budget
        self._lock = Lock()

    @property
    def remaining(self):
        with self._lock:
            return self._remaining

    def check(self, actor: str, method: str, url: str, *, probe: str | None = None,
              input_probe: str | None = None) -> str:
        """Consume one decision; no URL normalization, DNS, or IO is performed.

        A probe is permitted only where the validated scope declares it on that
        exact operation; the probe never replaces the method/URL/actor checks.
        """
        if not all(isinstance(item, str) for item in (actor, method, url)):
            raise ValueError("invalid request metadata")
        with self._lock:
            check_common(actor, method, self._accounts, self._methods, self._remaining)
            if probe is not None and input_probe is not None:
                raise ValueError("a request cannot be both a credential probe and an input probe")
            classification, probes, input_probes = self._operations.get(
                (method, url), (None, frozenset(), frozenset()))
            if not ((classification == "READ_ONLY" and method in {"GET", "HEAD", "OPTIONS"})
                    or (classification == "AUTHENTICATION" and method == "POST")):
                raise ValueError("operation not permitted by preflight")
            if probe is not None and probe not in probes:
                raise ValueError("authentication probe not permitted by scope")
            if input_probe is not None and (classification != "AUTHENTICATION"
                                            or input_probe not in input_probes):
                raise ValueError("validation probe not permitted by scope")
            if self._remaining <= 0:
                raise ValueError("decision budget exhausted")
            self._remaining -= 1
            return classification
