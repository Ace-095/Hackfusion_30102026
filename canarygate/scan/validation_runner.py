"""Guarded offline runner for safe input-validation and disclosure probes.

The only body-carrying operation is the exact scoped authentication POST. Each
declared probe may execute at most once per actor per run (the shared run guard
tracks `(actor, probe)`), is authorized immediately before release, and is
recorded in memory only. No socket, DNS lookup, redirect or retry exists here.
"""
import hashlib
import hmac
import re
import threading
import weakref

import httpx
from pydantic import BaseModel, ConfigDict, Field, model_validator

from canarygate.guard.policy import MAX_RESPONSE_BYTES
from canarygate.network.boundary import PAGINATION_METADATA_KEY
from canarygate.oracles.validation import INPUT_PROBE_NAMES
from canarygate.scan.offline import OfflineGuardedRunner
from canarygate.scan.validation_transcript import ValidationTranscript

MAX_REQUEST_BODY = 4096
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class ValidationRunnerConfig(BaseModel):
    """Declared request bodies for one offline validation run (never persisted)."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    login_path: str
    content_type: str = Field(default="application/json", pattern=r"^application/json$")
    requests: dict[str, str]

    @model_validator(mode="after")
    def coherent_config(self):
        if not isinstance(self.login_path, str) or re.fullmatch(
                r"/[A-Za-z0-9_./~-]{1,511}", self.login_path) is None:
            raise ValueError("invalid login path")
        if not set(self.requests).issubset(INPUT_PROBE_NAMES):
            raise ValueError("unexpected validation probe request")
        for value in self.requests.values():
            if (not isinstance(value, str) or not value or len(value) > MAX_REQUEST_BODY
                    or _CONTROL.search(value)):
                raise ValueError("invalid validation probe request body")
        return self


class OfflineValidationRunner(OfflineGuardedRunner):
    """Adds explicitly declared, once-only recorded validation submissions."""

    transport_label = "offline_transcript"

    def __init__(self, scope, tokens, reads, probes, *, config, run_guard=None):
        super().__init__(scope, tokens, reads, run_guard=run_guard)
        if not isinstance(probes, ValidationTranscript) or not isinstance(config, ValidationRunnerConfig):
            raise ValueError("validated probe transcript and runner config required")
        operations = {(op.method, op.path): op for op in self._scope.operations}
        login = operations.get(("POST", config.login_path))
        if login is None or login.classification != "AUTHENTICATION":
            raise ValueError("login path is not the scoped authentication operation")
        accounts = {item.account for item in self._scope.accounts}
        for entry in probes.entries:
            if (entry.actor not in accounts or entry.path != config.login_path
                    or entry.probe not in login.input_probes):
                raise ValueError("validation probe is not permitted by the authorized scope")
        self._probes = probes
        self._config = config
        self._probe_entries = {(entry.actor, entry.path, entry.probe): entry for entry in probes.entries}
        self._probe_records = weakref.WeakKeyDictionary()
        self._probe_records_lock = threading.Lock()

    @property
    def transcript_sha256(self):
        payload = f"{self._transcript.sha256()}:{self._probes.sha256()}"
        return hashlib.sha256(payload.encode("ascii")).hexdigest()

    @property
    def config(self):
        return self._config

    def submit(self, actor, probe):
        """Release one recorded validation response after the shared guard allows it."""
        if not isinstance(actor, str) or not isinstance(probe, str) or probe not in INPUT_PROBE_NAMES:
            raise ValueError("invalid validation probe metadata")
        if probe not in self._config.requests:
            raise ValueError("no declared request body for probe")
        with self._run_guard.execution():
            self._run_guard.authorize_authentication(actor, self._scope.origin + self._config.login_path,
                                                     input_probe=probe)
            entry = self._probe_entries.get((actor, self._config.login_path, probe))
            if entry is None:
                raise ValueError("no recorded validation response")
            body = entry.body_bytes()
            if len(body) > MAX_RESPONSE_BYTES:
                raise ValueError("recorded validation response exceeds size limit")
            headers = {"content-type": "application/json", **{
                key: value for key, value in entry.headers.items()
                if key.lower() not in {"content-type"}}}
            request = httpx.Request("POST", self._scope.origin + self._config.login_path,
                                    content=self._config.requests[probe].encode("utf-8"),
                                    headers={"content-type": self._config.content_type},
                                    extensions={"canary_actor": actor, "canary_input_probe": probe})
            response = httpx.Response(entry.status, content=body, headers=headers, request=request,
                                      extensions={PAGINATION_METADATA_KEY: False})
            self._run_guard.record_status(entry.status)
            with self._probe_records_lock:
                self._probe_records[response] = (
                    actor, probe, response.status_code, hashlib.sha256(body).digest(),
                    hashlib.sha256(request.content).digest())
            return response

    def verifies_recorded_submission(self, response, actor, probe):
        """Same-run provenance for one recorded validation submission."""
        if not isinstance(response, httpx.Response):
            return False
        with self._probe_records_lock:
            record = self._probe_records.get(response)
        if record is None or record[:3] != (actor, probe, response.status_code):
            return False
        try:
            request = response.request
            return (request.method == "POST"
                    and request.url == httpx.URL(self._scope.origin + self._config.login_path)
                    and request.extensions.get("canary_actor") == actor
                    and request.extensions.get("canary_input_probe") == probe
                    and len(response.content) <= MAX_RESPONSE_BYTES
                    and hmac.compare_digest(record[3], hashlib.sha256(response.content).digest())
                    and hmac.compare_digest(record[4], hashlib.sha256(request.content).digest()))
        except (AttributeError, RuntimeError, TypeError, ValueError):
            return False

    def close(self):
        return None
