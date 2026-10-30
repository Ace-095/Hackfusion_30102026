"""Operation-aware guard for the fixture runner, not a live transport guard."""
import httpx

from canarygate.scope.loader import FixtureScope, OperationClass


class GuardRejected(ValueError):
    pass


class SafetyGuard:
    def __init__(self, scope: FixtureScope, budget: int | None = None):
        self.scope = scope
        # Snapshot mutable list fields; later caller mutation cannot widen scope.
        self._scheme, self._hostname, self._port = scope.scheme, scope.hostname, scope.port
        self._accounts = frozenset(scope.accounts)
        self._methods = frozenset(scope.allowed_methods)
        if budget is not None and (budget <= 0 or budget > scope.request_budget):
            raise ValueError("budget must be positive and cannot exceed scope")
        self.remaining = scope.request_budget if budget is None else budget
        self.blocked = 0
        self._operations = {(op.method, op.path): (op.classification, frozenset(op.auth_probes)) for op in scope.operations}

    def _reject(self, reason):
        self.blocked += 1
        raise GuardRejected(reason)

    def authorize(self, actor: str, method: str, url: str, *, auth_probe: str | None = None) -> httpx.URL:
        try:
            target = httpx.URL(url)
        except (httpx.InvalidURL, ValueError, TypeError) as exc:
            self.blocked += 1
            raise GuardRejected("invalid URL") from exc
        default_port = 443 if self._scheme == "https" else 80
        if (target.scheme != self._scheme or target.host != self._hostname
                or (target.port or default_port) != self._port or target.userinfo
                or target.query or target.fragment):
            self._reject("outside fixture scope")
        if actor not in self._accounts:
            self._reject("unauthorized actor")
        if method == "DELETE" or method not in self._methods:
            self._reject("method blocked")
        # Compare raw path, not decoded path: encodings cannot change operation identity.
        try:
            path = target.raw_path.decode("ascii")
        except UnicodeError:
            self._reject("invalid operation path")
        operation = self._operations.get((method, path))
        if operation is None:
            self._reject("operation not classified or authorized")
        classification, auth_probes = operation
        if auth_probe is not None and auth_probe not in auth_probes:
            self._reject("authentication probe not authorized for this operation")
        if classification == OperationClass.DESTRUCTIVE:
            self._reject("destructive operation blocked")
        if classification == OperationClass.STATE_CHANGING:
            self._reject("state-changing operation not enabled")
        if classification == OperationClass.READ_ONLY and method not in {"GET", "HEAD", "OPTIONS"}:
            self._reject("read-only classification conflicts with method")
        if classification == OperationClass.AUTHENTICATION and method != "POST":
            self._reject("authentication operation conflicts with method")
        if self.remaining <= 0:
            self._reject("request budget exhausted")
        self.remaining -= 1
        return target
