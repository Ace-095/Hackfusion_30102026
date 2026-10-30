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
        return self._policy.check(actor, method, url)

    def halt(self):
        with self._lock:
            self._halted = True

    def record_status(self, status):
        with self._lock:
            self._server_error_streak = self._server_error_streak + 1 if status >= 500 else 0
            if self._server_error_streak >= 2 or status in (423, 429) or 300 <= status < 400:
                self._halted = True
