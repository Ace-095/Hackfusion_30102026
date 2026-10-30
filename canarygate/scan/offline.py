"""Guarded read-only runner over a bounded recorded transcript (no sockets/DNS)."""
import hmac
import json
import re

import httpx

from canarygate.guard.policy import MAX_RESPONSE_BYTES
from canarygate.guard.run_guard import RunSafetyGuard
from canarygate.network.boundary import GuardedReadRunner, PAGINATION_METADATA_KEY
from canarygate.scope.authorized import AuthorizedScope
from canarygate.scan.transcript import OfflineTranscript

TOKEN_PATTERN = re.compile(r"[A-Za-z0-9._~+/-]+={0,2}")


class OfflineGuardedRunner(GuardedReadRunner):
    """Replays recorded synthetic responses through the shared run guard.

    Every read is authorized by `RunSafetyGuard` immediately before the
    recorded response is released. There is no socket, DNS lookup, redirect
    following, retry, or credential transmission.
    """
    transport_label = "offline_transcript"

    def __init__(self, scope, tokens, transcript, *, run_guard=None):
        super().__init__()
        if not isinstance(scope, AuthorizedScope) or not isinstance(transcript, OfflineTranscript):
            raise ValueError("validated scope and transcript required")
        scope = AuthorizedScope.model_validate(scope.model_dump())
        accounts = {item.account for item in scope.accounts}
        if not isinstance(tokens, dict) or not tokens or not set(tokens).issubset(accounts):
            raise ValueError("invalid offline credentials")
        for token in tokens.values():
            if (not isinstance(token, str) or not token or len(token) > 4096
                    or TOKEN_PATTERN.fullmatch(token) is None):
                raise ValueError("invalid offline credentials")
        if len(set(tokens.values())) != len(tokens):
            raise ValueError("offline credentials must be distinct")
        paths = frozenset(op.path for op in scope.operations
                          if op.method == "GET" and op.classification == "READ_ONLY")
        for entry in transcript.entries:
            if entry.actor not in accounts or entry.path not in paths:
                raise ValueError("transcript entry is outside the authorized read scope")
        if run_guard is None:
            run_guard = RunSafetyGuard(scope)
        if not isinstance(run_guard, RunSafetyGuard) or run_guard.scope != scope:
            raise ValueError("run guard scope mismatch")
        self._scope = scope
        self._tokens = dict(tokens)
        self._transcript = transcript
        self._entries = transcript.responses()
        self._paths = paths
        self._run_guard = run_guard

    @property
    def scope(self):
        return self._scope

    @property
    def guard(self):
        return self._run_guard

    @property
    def transcript_sha256(self):
        return self._transcript.sha256()

    def supports_read_path(self, path):
        return isinstance(path, str) and path in self._paths

    def has_distinct_credentials(self, actor_a, actor_b):
        if not isinstance(actor_a, str) or not isinstance(actor_b, str) or actor_a == actor_b:
            return False
        with self._run_guard.execution():
            first, second = self._tokens.get(actor_a), self._tokens.get(actor_b)
            return first is not None and second is not None and not hmac.compare_digest(first, second)

    def get(self, actor, path):
        if not isinstance(actor, str) or not isinstance(path, str):
            raise ValueError("invalid offline request metadata")
        with self._run_guard.execution():
            # The shared guard is the authority immediately before release.
            self._run_guard.authorize(actor, "GET", self._scope.origin + path)
            if path not in self._paths:
                raise ValueError("path is not a scoped read operation")
            entry = self._entries.get((actor, "GET", path))
            if entry is None:
                raise ValueError("no recorded offline response")
            body = entry.body_bytes()
            if len(body) > MAX_RESPONSE_BYTES:
                raise ValueError("recorded response exceeds size limit")
            request = httpx.Request("GET", self._scope.origin + path,
                                    extensions={"canary_actor": actor})
            response = httpx.Response(entry.status, content=body, request=request,
                                      extensions={PAGINATION_METADATA_KEY: False})
            self._run_guard.record_status(entry.status)
            self._record_read(response, actor, path)
            return response

    def halt(self):
        self._run_guard.halt()

    def stats(self):
        stats = self._run_guard.stats()
        stats.update({"transport": self.transport_label,
                      "transcript_sha256": self.transcript_sha256,
                      "network_transport_enabled": False})
        return stats

    def close(self):
        return None
