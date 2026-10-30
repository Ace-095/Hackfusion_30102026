"""Shared, fail-closed run state for the experimental guarded HTTPX boundary.

This controls one explicitly constructed run. It does not authenticate users,
resolve DNS, verify approval, or by itself make a live scan safe.
"""
from contextlib import contextmanager
from threading import RLock

from canarygate.guard.authorized_preflight import AuthorizedPreflight
from canarygate.scope.authorized import AuthorizedScope


class RunSafetyGuard:
    def __init__(self, scope: AuthorizedScope):
        if not isinstance(scope, AuthorizedScope):
            raise ValueError("validated scope required")
        self._scope = AuthorizedScope.model_validate(scope.model_dump())
        self._policy = AuthorizedPreflight(self._scope)
        self._lock = RLock()
        self._halted = False
        self._server_error_streak = 0
        self._authentication_attempts = set()
        self._blocked = 0
        self._redirects = 0

    @property
    def scope(self):
        return self._scope

    @property
    def remaining(self):
        return self._policy.remaining

    @contextmanager
    def execution(self):
        # Held across the complete network operation, not just the budget check.
        with self._lock:
            if self._halted:
                raise ValueError("execution halted")
            yield

    def authorize(self, actor, method, url):
        try:
            return self._policy.check(actor, method, url)
        except ValueError:
            with self._lock:
                self._blocked += 1
            raise

    def authorize_authentication(self, actor, url):
        with self._lock:
            if actor in self._authentication_attempts:
                self._blocked += 1
                raise ValueError("authentication already attempted in this run")
            try:
                classification = self._policy.check(actor, "POST", url)
            except ValueError:
                self._blocked += 1
                raise
            if classification != "AUTHENTICATION":
                self._blocked += 1
                raise ValueError("not an authentication operation")
            self._authentication_attempts.add(actor)

    def stats(self):
        """Counters for honest constraint reports; never includes credentials or bodies."""
        with self._lock:
            return {"requests_sent": self._scope.request_budget - self._policy.remaining,
                    "budget_remaining": self._policy.remaining,
                    "blocked_by_guard": self._blocked,
                    "redirects_observed": self._redirects,
                    "halted": self._halted}

    def halt(self):
        with self._lock:
            self._halted = True

    def record_status(self, status):
        with self._lock:
            if 300 <= status < 400:
                self._redirects += 1
            self._server_error_streak = self._server_error_streak + 1 if status >= 500 else 0
            if self._server_error_streak >= 2 or status in (423, 429) or 300 <= status < 400:
                self._halted = True
