"""Guarded offline runner for crafted-credential authentication probes.

Every probe is authorized by the shared `RunSafetyGuard` immediately before a
recorded response is released. Probe kinds and credentials come from the
validated plan; a caller cannot introduce a token, header or path at runtime.
No socket, DNS lookup, redirect or retry exists on this path.
"""
import hashlib
import hmac
import re
import threading
import weakref

import httpx
from pydantic import BaseModel, ConfigDict, Field, model_validator

from canarygate.guard.policy import MAX_RESPONSE_BYTES
from canarygate.oracles.authentication import is_supported_jwt
from canarygate.network.boundary import PAGINATION_METADATA_KEY
from canarygate.scan.auth_transcript import AuthenticationTranscript, PROBE_NAMES
from canarygate.scan.offline import OfflineGuardedRunner
from canarygate.scope.authorized import AUTH_PROBE_NAMES

_ABSENT = object()
_HEADER_NAME = re.compile(r"^[A-Za-z0-9-]{3,64}$")


class AuthRunnerConfig(BaseModel):
    """Validated credentials and scheme for one offline authentication run."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    scheme: str = Field(pattern=r"^(bearer_jwt|bearer_opaque|api_key)$")
    header_name: str
    profile_path: str
    logout_path: str | None = None
    credentials: dict[str, str | None]

    @model_validator(mode="after")
    def coherent_config(self):
        if _HEADER_NAME.fullmatch(self.header_name) is None:
            raise ValueError("invalid authentication header name")
        if not set(self.credentials).issubset(PROBE_NAMES):
            raise ValueError("unexpected probe credential")
        for probe, value in self.credentials.items():
            if probe == "logout":
                raise ValueError("logout is authorized by the scope, not a credential")
            if value is not None and (not isinstance(value, str) or not value
                                      or len(value) > 4096 or any(char in value for char in "\r\n\0")):
                raise ValueError("invalid probe credential")
        if self.logout_path is not None and (
                not isinstance(self.logout_path, str)
                or re.fullmatch(r"/[A-Za-z0-9_./~-]{1,511}", self.logout_path) is None):
            raise ValueError("invalid logout path")
        return self


class OfflineAuthRunner(OfflineGuardedRunner):
    """Extends the recorded offline transport with explicitly permitted probes."""

    transport_label = "offline_transcript"

    def __init__(self, scope, tokens, reads, probes, *, config, run_guard=None):
        super().__init__(scope, tokens, reads, run_guard=run_guard)
        if not isinstance(probes, AuthenticationTranscript) or not isinstance(config, AuthRunnerConfig):
            raise ValueError("validated probe transcript and runner config required")
        if config.logout_path is not None:
            logout = [op for op in self._scope.operations
                      if op.method == "POST" and op.path == config.logout_path
                      and op.classification == "AUTHENTICATION"]
            if not logout:
                raise ValueError("logout path is not a scoped authentication operation")
        operations = {(op.method, op.path): frozenset(op.auth_probes) for op in self._scope.operations}
        accounts = {item.account for item in self._scope.accounts}
        for entry in probes.entries:
            if entry.actor not in accounts:
                raise ValueError("probe actor is not scoped")
            if entry.method == "GET":
                allowed = operations.get(("GET", entry.path), frozenset())
                if not self.supports_read_path(entry.path) or entry.probe not in allowed:
                    raise ValueError("probe is not permitted by the authorized scope")
                if entry.probe == "logout_reuse" and (
                        config.logout_path is None or entry.path != config.profile_path):
                    raise ValueError("post-logout reuse requires the declared logout operation")
            else:
                if (entry.probe != "logout" or config.logout_path is None
                        or entry.path != config.logout_path
                        or operations.get(("POST", entry.path)) is None):
                    raise ValueError("logout observation is not authorized")
        self._probes = probes
        self._config = config
        self._probe_entries = {(entry.actor, entry.method, entry.path, entry.probe): entry
                               for entry in probes.entries}
        self._probe_records = weakref.WeakKeyDictionary()
        self._probe_records_lock = threading.Lock()

    @property
    def transcript_sha256(self):
        payload = f"{self._transcript.sha256()}:{self._probes.sha256()}"
        return hashlib.sha256(payload.encode("ascii")).hexdigest()

    @property
    def config(self):
        return self._config

    def credential_is_supported_jwt(self, actor):
        """Applicability only: the token's format, never its signature or claims."""
        token = self._tokens.get(actor)
        return isinstance(token, str) and is_supported_jwt(token)

    def _headers(self, actor, probe):
        if probe == "logout":
            token = self._tokens.get(actor)
            value = f"Bearer {token}" if self._config.scheme.startswith("bearer") else token
            return {self._config.header_name: value}
        credential = self._config.credentials.get(probe, _ABSENT)
        if credential is _ABSENT:
            raise ValueError("no credential configured for probe")
        return {} if credential is None else {self._config.header_name: credential}

    def _release(self, actor, method, path, probe):
        entry = self._probe_entries.get((actor, method, path, probe))
        if entry is None:
            raise ValueError("no recorded probe response")
        body = entry.body_bytes()
        if len(body) > MAX_RESPONSE_BYTES:
            raise ValueError("recorded probe response exceeds size limit")
        request = httpx.Request(method, self._scope.origin + path, headers=self._headers(actor, probe),
                                extensions={"canary_actor": actor, "canary_probe": probe})
        response = httpx.Response(entry.status, content=body, request=request,
                                  extensions={PAGINATION_METADATA_KEY: False})
        self._run_guard.record_status(entry.status)
        self._record_probe(response, actor, method, path, probe, request)
        return response

    def _record_probe(self, response, actor, method, path, probe, request):
        with self._probe_records_lock:
            self._probe_records[response] = (
                actor, method, path, probe, response.status_code,
                hashlib.sha256(response.content).digest(),
                request.headers.get(self._config.header_name))

    def verifies_recorded_probe(self, response, actor, method, path, probe):
        """Same-run provenance for one probe response; detects post-receipt mutation."""
        if not isinstance(response, httpx.Response):
            return False
        with self._probe_records_lock:
            record = self._probe_records.get(response)
        if record is None or record[:5] != (actor, method, path, probe, response.status_code):
            return False
        try:
            request = response.request
            return (request.method == method and request.url == httpx.URL(self._scope.origin + path)
                    and request.extensions.get("canary_actor") == actor
                    and request.extensions.get("canary_probe") == probe
                    and len(response.content) <= MAX_RESPONSE_BYTES
                    and hmac.compare_digest(record[5], hashlib.sha256(response.content).digest())
                    and request.headers.get(self._config.header_name) == record[6])
        except (AttributeError, RuntimeError, TypeError, ValueError):
            return False

    def probe(self, actor, path, probe):
        """Release one recorded probe response after the shared guard authorizes it."""
        if (not isinstance(actor, str) or not isinstance(path, str) or not isinstance(probe, str)
                or probe not in AUTH_PROBE_NAMES):
            raise ValueError("invalid authentication probe metadata")
        with self._run_guard.execution():
            self._run_guard.authorize(actor, "GET", self._scope.origin + path, probe=probe)
            if probe == "logout_reuse":
                if self._config.logout_path is None or path != self._config.profile_path:
                    raise ValueError("post-logout reuse requires the declared logout operation")
            elif not self.supports_read_path(path):
                raise ValueError("probe path is not a scoped read operation")
            return self._release(actor, "GET", path, probe)

    def authenticate(self, actor, path):
        """Release the recorded logout response; only the declared logout is allowed."""
        if not isinstance(actor, str) or not isinstance(path, str):
            raise ValueError("invalid authentication metadata")
        with self._run_guard.execution():
            self._run_guard.authorize_authentication(actor, self._scope.origin + path)
            if self._config.logout_path is None or path != self._config.logout_path:
                raise ValueError("not the declared logout operation")
            return self._release(actor, "POST", path, "logout")

    def close(self):
        return None
