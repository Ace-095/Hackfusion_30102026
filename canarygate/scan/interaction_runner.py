"""Guarded offline runner for the combined leg of an SCI interaction.

The combined read is released only after (a) a declared input probe was accepted
in this run and (b) the shared `RunSafetyGuard` authorized the read immediately
before release. Recorded responses stay in memory; no socket, DNS lookup,
redirect, retry or credential transmission exists here.
"""
import hashlib
import hmac
import threading
import weakref

import httpx

from canarygate.guard.policy import MAX_RESPONSE_BYTES
from canarygate.network.boundary import PAGINATION_METADATA_KEY
from canarygate.oracles.validation import INPUT_PROBE_NAMES
from canarygate.scan.interaction_transcript import InteractionTranscript
from canarygate.scan.validation_runner import OfflineValidationRunner


class OfflineInteractionRunner(OfflineValidationRunner):
    """Adds the ordering-bound combined read to the guarded validation runner."""

    transport_label = "offline_transcript"

    def __init__(self, scope, tokens, reads, probes, combined, *, config, run_guard=None):
        super().__init__(scope, tokens, reads, probes, config=config, run_guard=run_guard)
        if not isinstance(combined, InteractionTranscript):
            raise ValueError("validated combined transcript required")
        operations = {(op.method, op.path): op for op in self._scope.operations}
        accounts = {item.account for item in self._scope.accounts}
        for entry in combined.entries:
            operation = operations.get((entry.method, entry.path))
            if entry.actor not in accounts or operation is None or operation.classification != "READ_ONLY":
                raise ValueError("combined read is outside the authorized read scope")
        self._combined = combined
        self._combined_entries = {(entry.actor, entry.path, entry.probe): entry
                                  for entry in combined.entries}
        self._submitted = set()
        self._combined_records = weakref.WeakKeyDictionary()
        self._combined_lock = threading.Lock()

    @property
    def transcript_sha256(self):
        payload = f"{super().transcript_sha256}:{self._combined.sha256()}"
        return hashlib.sha256(payload.encode("ascii")).hexdigest()

    def submit(self, actor, probe):
        response = super().submit(actor, probe)
        if not isinstance(probe, str) or probe not in INPUT_PROBE_NAMES:
            raise ValueError("invalid input probe")
        self._submitted.add((actor, probe))
        return response

    def get_after(self, actor, path, probe):
        """Release the recorded combined read, bounded to a prior accepted probe."""
        if not isinstance(actor, str) or not isinstance(path, str) \
                or not isinstance(probe, str) or probe not in INPUT_PROBE_NAMES:
            raise ValueError("invalid combined request metadata")
        if (actor, probe) not in self._submitted:
            raise ValueError("no declared probe was accepted before the combined read")
        with self._run_guard.execution():
            self._run_guard.authorize(actor, "GET", self._scope.origin + path)
            entry = self._combined_entries.get((actor, path, probe))
            if entry is None:
                raise ValueError("no recorded combined response")
            body = entry.body_bytes()
            if len(body) > MAX_RESPONSE_BYTES:
                raise ValueError("recorded combined response exceeds size limit")
            request = httpx.Request("GET", self._scope.origin + path,
                                    extensions={"canary_actor": actor, "canary_probe": probe})
            headers = dict(entry.headers)
            if body and "content-type" not in {key.lower() for key in headers}:
                headers["content-type"] = "application/json"
            response = httpx.Response(entry.status, content=body, headers=headers, request=request,
                                      extensions={PAGINATION_METADATA_KEY: False})
            self._run_guard.record_status(entry.status)
            with self._combined_lock:
                self._combined_records[response] = (
                    actor, path, probe, response.status_code, hashlib.sha256(body).digest())
            return response

    def verifies_combined_read(self, response, actor, path, probe):
        if not isinstance(response, httpx.Response):
            return False
        with self._combined_lock:
            record = self._combined_records.get(response)
        if record is None or record[:4] != (actor, path, probe, response.status_code):
            return False
        try:
            request = response.request
            return (request.method == "GET"
                    and request.url == httpx.URL(self._scope.origin + path)
                    and request.extensions.get("canary_actor") == actor
                    and request.extensions.get("canary_probe") == probe
                    and len(response.content) <= MAX_RESPONSE_BYTES
                    and hmac.compare_digest(record[4], hashlib.sha256(response.content).digest()))
        except (AttributeError, RuntimeError, TypeError, ValueError):
            return False
