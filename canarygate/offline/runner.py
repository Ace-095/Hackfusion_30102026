"""Guarded HTTPX runner using an in-process transport only.

This runner cannot make live requests; live DNS and connection pinning remain
unimplemented. In particular, it never invokes a DNS resolver.
"""
import threading
import httpx

from canarygate.guard.safety_guard import GuardRejected, SafetyGuard
from canarygate.scope.loader import fixture_scope, FixtureScope, OperationClass


class FixtureResponseTooLarge(GuardRejected):
    """A fixture request was sent, but its response could not be inspected."""


class FixtureRunner:
    def __init__(self, handler, budget: int | None = None, scope: FixtureScope | None = None):
        self.scope = scope or fixture_scope()
        self.guard = SafetyGuard(self.scope, budget)
        self._lock = threading.Lock()
        self.requests_sent = 0
        self.authentication_requests = 0
        self.redirects_observed = 0
        self._server_error_streak = 0
        self.halted_reason: str | None = None
        self._client = httpx.Client(transport=httpx.MockTransport(handler),
                                    follow_redirects=False, trust_env=False)

    def request(self, actor: str, method: str, url: str, *, token: str | None = None,
                json_body: dict | None = None, auth_probe: str | None = None) -> httpx.Response:
        with self._lock:
            if self.halted_reason:
                raise GuardRejected("fixture execution halted: " + self.halted_reason)
            # These are fixed synthetic probe values, never supplied credentials.
            probe_headers = {"missing": {}, "malformed": {"Authorization": "Bearer malformed-fixture"},
                             "wrong_scheme": {"Authorization": "Basic synthetic-fixture"}}
            if auth_probe is not None:
                if auth_probe not in probe_headers or method != "GET" or token is not None or json_body is not None:
                    raise GuardRejected("invalid fixture authentication probe")
                headers = probe_headers[auth_probe]
            else:
                # Fixture-specific credential binding; not real credential handling.
                if method == "POST" and (json_body != {"account": actor} or token is not None):
                    raise GuardRejected("only exact fixture login payloads are authorized")
                if method in {"GET", "HEAD", "OPTIONS"} and (token != f"fixture-token-{actor}" or json_body is not None):
                    raise GuardRejected("fixture token does not match actor")
                headers = {"Authorization": f"Bearer {token}"} if token else {}
            # Every probe and ordinary request passes the shared operation guard.
            target = self.guard.authorize(actor, method, url, auth_probe=auth_probe)
            self.requests_sent += 1
            if method == "POST":
                self.authentication_requests += 1
            # HTTPX otherwise persists Set-Cookie from a prior response and can
            # silently authenticate a later missing-auth probe as another user.
            self._client.cookies.clear()
            try:
                response = self._client.request(method, target, json=json_body, headers=headers)
            finally:
                self._client.cookies.clear()
            if 300 <= response.status_code < 400:
                self.redirects_observed += 1
            # Stop rather than retry on repeated server errors, account lockout,
            # or rate limiting. Normal auth probes may intentionally yield 401/403.
            self._server_error_streak = self._server_error_streak + 1 if response.status_code >= 500 else 0
            if self._server_error_streak >= 2:
                self.halted_reason = "repeated server errors"
            elif response.status_code in (423, 429):
                self.halted_reason = "account lockout or rate limit"
            if len(response.content) > 64 * 1024:
                raise FixtureResponseTooLarge("fixture response too large")
            return response

    def close(self):
        self._client.close()
