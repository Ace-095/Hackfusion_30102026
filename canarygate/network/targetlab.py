"""Dedicated loopback-only HTTPS transport for TargetLab.

This is deliberately **not** the production transport. It accepts only a scope
whose mode is ``local_lab``, pinned to the literal address ``127.0.0.1``, and it
can therefore never reach a competition or organizer target. The production
transport (`GuardedHTTPXTransport`) is unchanged and still refuses to run.

Safety properties, each enforced in code rather than documented:

* destination is the literal loopback address; no hostname is resolved and no
  resolver is consulted;
* TLS is verified against an explicit test-only CA file with hostname checking
  on, so a certificate whose SAN does not contain ``IP:127.0.0.1`` fails;
* every request passes ``RunSafetyGuard`` immediately before the socket is
  created, so budgets, scope, methods and one-shot authentication apply;
* redirects are refused instead of followed, and nothing is ever retried;
* responses are capped at ``MAX_RESPONSE_BYTES`` and the request has a deadline;
* credentials live only in memory and are never returned by the run.
"""
from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import re
import socket
import ssl
import threading
import weakref
from pathlib import Path

import httpx

from canarygate.guard.policy import MAX_RESPONSE_BYTES
from canarygate.guard.run_guard import RunSafetyGuard
from canarygate.network.boundary import PAGINATION_METADATA_KEY, GuardedReadRunner
from canarygate.scope.authorized import (TARGETLAB_HOST, TARGETLAB_OPERATIONS,
                                         AuthorizedScope)

DEFAULT_TIMEOUT_SECONDS = 5.0
MAX_TOKEN_BYTES = 4096
MAX_REQUEST_BYTES = 16 * 1024
_TOKEN = re.compile(r"[A-Za-z0-9._~+/-]+={0,2}")


class TargetLabRefused(ValueError):
    """A request was refused by policy before or instead of being satisfied."""


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate response key")
        result[key] = value
    return result


#: The lab publishes its process identity in this header; only a 16-hex value is
#: accepted, and the raw header is never stored. Two lab processes may reuse the
#: same loopback port, so this is the identity the evidence is attributed to.
LAB_INSTANCE_HEADER = "X-Lab-Instance"
LAB_INSTANCE_PATTERN = re.compile(r"^[0-9a-f]{16}$")


class TargetLabTransport:
    """The only code path that may open a socket to TargetLab."""

    def __init__(self, scope: AuthorizedScope, *, ca_file, run_guard: RunSafetyGuard | None = None,
                 timeout: float = DEFAULT_TIMEOUT_SECONDS):
        if not isinstance(scope, AuthorizedScope):
            raise ValueError("validated scope required")
        scope = AuthorizedScope.model_validate(scope.model_dump())
        if scope.mode != "local_lab":
            raise TargetLabRefused("TargetLab transport requires local_lab mode")
        if scope.hostname != TARGETLAB_HOST:
            raise TargetLabRefused("TargetLab transport requires the literal address 127.0.0.1")
        ca_path = Path(ca_file)
        if not ca_path.is_file():
            raise TargetLabRefused("TargetLab CA file not found")
        if not isinstance(timeout, (int, float)) or not 0 < timeout <= 30:
            raise ValueError("invalid timeout")
        context = ssl.create_default_context(cafile=str(ca_path))
        # Never a shortcut: verification and hostname checking stay on.
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self._context = context
        self._scope = scope
        self._timeout = float(timeout)
        self._run_guard = run_guard if run_guard is not None else RunSafetyGuard(scope)
        if not isinstance(self._run_guard, RunSafetyGuard) or self._run_guard.scope != scope:
            raise ValueError("run guard scope mismatch")
        self._lock = threading.Lock()
        self._requests = 0
        self._lab_instance: str | None = None

    @property
    def scope(self):
        return self._scope

    @property
    def lab_instance(self) -> str | None:
        """The lab process this transport talked to, if it published an id."""
        with self._lock:
            return self._lab_instance

    def _note_lab_instance(self, value: str | None) -> None:
        """Record the lab identity once; a change means the evidence spans two labs."""
        if value is None:
            return
        with self._lock:
            if self._lab_instance is None:
                self._lab_instance = value
                return
            if self._lab_instance == value:
                return
        self._run_guard.halt()
        raise TargetLabRefused("the TargetLab instance changed during the run")

    @property
    def requests_sent(self):
        with self._lock:
            return self._requests

    def stats(self):
        return self._run_guard.stats()

    def _validate(self, method: str, path: str):
        if not isinstance(method, str) or not isinstance(path, str):
            raise TargetLabRefused("invalid request metadata")
        declared = TARGETLAB_OPERATIONS.get((method, path))
        if declared is None:
            raise TargetLabRefused("path is not a declared TargetLab route")
        scoped = [(op.classification, op.path) for op in self._scope.operations
                  if op.method == method and op.path == path]
        if not scoped or scoped[0][0] != declared:
            raise TargetLabRefused("path is outside the validated TargetLab scope")

    def request(self, actor: str, method: str, path: str, *, token: str | None = None,
                body: bytes | None = None, content_type: str | None = None,
                input_probe: str | None = None) -> httpx.Response:
        """Perform exactly one guarded request. Never retries, never redirects."""
        self._validate(method, path)
        url = self._scope.origin + path
        if isinstance(body, bytes) and len(body) > MAX_REQUEST_BYTES:
            raise TargetLabRefused("request body exceeds limit")
        if method == "POST" and body is None:
            raise TargetLabRefused("POST requires a bounded body")
        if method != "POST" and body is not None:
            raise TargetLabRefused("GET must not carry a body")
        with self._run_guard.execution():
            # The single authorization point, immediately before the connection.
            if method == "POST":
                self._run_guard.authorize_authentication(actor, url, input_probe=input_probe)
            else:
                self._run_guard.authorize(actor, method, url)
            return self._send(actor, method, path, token=token, body=body,
                              content_type=content_type)

    def _send(self, actor, method, path, *, token, body, content_type):
        headers = {"Host": f"{TARGETLAB_HOST}:{self._scope.port}", "Accept": "application/json",
                   "Accept-Encoding": "identity", "Connection": "close"}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        if body is not None:
            headers["Content-Type"] = content_type or "application/json"
            headers["Content-Length"] = str(len(body))
        connection = None
        sock = None
        try:
            # Connect to the numeric literal itself: no resolver is consulted, so
            # there is no hostname that DNS rebinding could redirect.
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._timeout)
            sock.connect((TARGETLAB_HOST, self._scope.port))
            tls = self._context.wrap_socket(sock, server_hostname=TARGETLAB_HOST)
            connection = http.client.HTTPConnection(TARGETLAB_HOST, self._scope.port,
                                                    timeout=self._timeout)
            connection.sock = tls
            connection.request(method, path, body=body, headers=headers)
            raw = connection.getresponse()
            status = raw.status
            if 300 <= status < 400:
                raise TargetLabRefused("redirect refused")
            published = (raw.getheader(LAB_INSTANCE_HEADER) or "").strip()
            if published and not LAB_INSTANCE_PATTERN.fullmatch(published):
                raise TargetLabRefused("malformed TargetLab instance header")
            content = raw.read(MAX_RESPONSE_BYTES + 1)
            if len(content) > MAX_RESPONSE_BYTES:
                raise TargetLabRefused("response exceeds size limit")
        except TargetLabRefused:
            self._run_guard.halt()
            raise
        except Exception:
            self._run_guard.halt()
            raise TargetLabRefused("TargetLab request failed; execution halted") from None
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    self._run_guard.halt()
            elif sock is not None:
                try:
                    sock.close()
                except Exception:
                    self._run_guard.halt()
        self._note_lab_instance(published or None)
        self._run_guard.record_status(status)
        with self._lock:
            self._requests += 1
        request = httpx.Request(method, self._scope.origin + path,
                                headers={"accept": "application/json"},
                                extensions={"canary_actor": actor})
        return httpx.Response(status_code=status, content=content, request=request,
                              extensions={PAGINATION_METADATA_KEY: False})


class TargetLabRunner(GuardedReadRunner):
    """Guard-backed session used by the TargetLab evidence workflow."""

    transport_label = "targetlab_https"

    def __init__(self, scope: AuthorizedScope, credentials, *, ca_file,
                 run_guard: RunSafetyGuard | None = None, timeout: float = DEFAULT_TIMEOUT_SECONDS):
        super().__init__()
        if not isinstance(credentials, dict) or not credentials:
            raise ValueError("TargetLab credentials are required")
        accounts = {account.account for account in scope.accounts}
        for account, password in credentials.items():
            if account not in accounts:
                raise ValueError("credential for an account outside the scope")
            if not isinstance(password, str) or not 0 < len(password.encode("utf-8")) <= 4096:
                raise ValueError("invalid credential")
        self._transport = TargetLabTransport(scope, ca_file=ca_file, run_guard=run_guard,
                                             timeout=timeout)
        self._scope = self._transport.scope
        self._credentials = dict(credentials)
        self._tokens: dict[str, str] = {}
        self._paths = frozenset(op.path for op in self._scope.operations
                                if op.method == "GET" and op.classification == "READ_ONLY")
        self._lock = threading.Lock()
        self._probe_records = weakref.WeakKeyDictionary()

    @property
    def scope(self):
        return self._scope

    @property
    def lab_instance(self) -> str | None:
        """The lab process this runner authenticated against, if it published one."""
        return self._transport.lab_instance

    def supports_read_path(self, path: str) -> bool:
        return isinstance(path, str) and path in self._paths

    def has_distinct_credentials(self, actor_a: str, actor_b: str) -> bool:
        if not isinstance(actor_a, str) or not isinstance(actor_b, str) or actor_a == actor_b:
            return False
        with self._lock:
            first, second = self._tokens.get(actor_a), self._tokens.get(actor_b)
        return (first is not None and second is not None
                and not hmac.compare_digest(first, second))

    def token_for(self, actor: str) -> str | None:
        with self._lock:
            return self._tokens.get(actor)

    def login(self, actor: str) -> bool:
        """Authenticate once. Returns True when a distinct token was obtained."""
        if actor not in self._credentials:
            raise ValueError("account is not provisioned")
        body = json.dumps({"username": actor, "password": self._credentials[actor]},
                          ensure_ascii=True, separators=(",", ":")).encode("ascii")
        response = self._transport.request(actor, "POST", "/login", body=body)
        if response.status_code != 200:
            return False
        try:
            data = json.loads(response.content, object_pairs_hook=_unique_object)
        except (ValueError, UnicodeError, RecursionError):
            return False
        token = data.get("token") if isinstance(data, dict) else None
        identity = data.get("identity") if isinstance(data, dict) else None
        if (not isinstance(token, str) or not _TOKEN.fullmatch(token)
                or len(token) > MAX_TOKEN_BYTES or identity != actor):
            return False
        if hmac.compare_digest(token, self._credentials[actor]):
            return False
        with self._lock:
            self._tokens[actor] = token
        return True

    def get(self, actor: str, path: str) -> httpx.Response:
        if not self.supports_read_path(path):
            raise TargetLabRefused("read path is outside the TargetLab scope")
        token = self.token_for(actor)
        if token is None:
            raise TargetLabRefused("account is not authenticated")
        response = self._transport.request(actor, "GET", path, token=token)
        self._record_read(response, actor, path)
        return response

    def submit(self, actor: str, path: str, probe: str, body: str) -> httpx.Response:
        """Send one declared input probe, at most once per actor (guard enforced)."""
        if not isinstance(body, str) or len(body.encode("utf-8")) > MAX_REQUEST_BYTES:
            raise ValueError("invalid probe body")
        self._validate_probe(path, probe)
        response = self._transport.request(actor, "POST", path, body=body.encode("utf-8"),
                                           input_probe=probe)
        self._probe_records[response] = (actor, path, response.status_code,
                                         hashlib.sha256(response.content).digest())
        return response

    def _validate_probe(self, path, probe):
        if probe not in ("control", "extra_property", "malformed_json", "special_characters",
                         "wrong_password"):
            raise ValueError("unknown input probe")
        operation = next((op for op in self._scope.operations
                          if op.method == "POST" and op.path == path), None)
        if operation is None or operation.classification != "AUTHENTICATION":
            raise TargetLabRefused("probe path is not the declared authentication operation")
        if probe not in operation.input_probes:
            raise TargetLabRefused("probe is not declared for this operation")

    def verifies_response(self, response, actor: str, path: str) -> bool:
        record = self._probe_records.get(response)
        if record is None or record[:3] != (actor, path, response.status_code):
            return False
        return hmac.compare_digest(record[3], hashlib.sha256(response.content).digest())

    def halt(self):
        self._run_guard.halt()

    def stats(self):
        return self._transport.stats()

    def close(self):
        with self._lock:
            self._tokens.clear()
