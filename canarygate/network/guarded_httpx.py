"""Experimental guarded HTTPX read boundary; not wired into the scanner or API.

Every wire request passes the scope guard in this transport immediately before
socket creation. Direct use can connect to a supplied IP: do not use against a
real target until independently reviewed and explicitly authorized.
"""
import http.client
import ipaddress
import re
import socket
import ssl
import threading
import time

import httpx

from canarygate.guard.run_guard import RunSafetyGuard
from canarygate.scope.authorized import AuthorizedScope

MAX_RESPONSE_BYTES = 64 * 1024
MAX_TOKEN_BYTES = 4096
TOTAL_DEADLINE_SECONDS = 10.0


class _NetworkDeadline:
    """Interrupt blocking socket operations when the total network deadline expires."""
    def __init__(self, seconds):
        self._end = time.monotonic() + seconds
        self._lock = threading.Lock()
        self._socket = None
        self._expired = False
        self._closed = False
        self._timer = threading.Timer(seconds, self._expire)
        self._timer.daemon = True

    def start(self):
        self._timer.start()

    @staticmethod
    def _interrupt(sock):
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass

    def _expire(self):
        with self._lock:
            if not self._closed:
                self._expired = True
                self._interrupt(self._socket)

    def attach(self, sock):
        with self._lock:
            self._socket = sock
            if self._expired or time.monotonic() >= self._end:
                self._expired = True
                self._interrupt(sock)
                raise TimeoutError("network deadline expired")

    def remaining(self):
        with self._lock:
            remaining = self._end - time.monotonic()
            if self._expired or remaining <= 0:
                self._expired = True
                raise TimeoutError("network deadline expired")
            return remaining

    def close(self):
        with self._lock:
            self._closed = True
            self._socket = None
        self._timer.cancel()


class GuardedHTTPXTransport(httpx.BaseTransport):
    """The sole live-network boundary: guard, pin, TLS, and a bounded response.

    GET-only until authentication, discovery and full live-run safety are
    implemented. No resolver, proxy, cookies, redirect, retries or raw headers.
    """
    def __init__(self, scope: AuthorizedScope, bearer_tokens: dict[str, str], *, run_guard: RunSafetyGuard | None = None):
        if not isinstance(scope, AuthorizedScope):
            raise ValueError("validated scope required")
        scope = AuthorizedScope.model_validate(scope.model_dump())
        if scope.organizer_ip is None or scope.scheme != "https":
            raise ValueError("an organizer-pinned IP and HTTPS are required")
        accounts = {account.account for account in scope.accounts}
        if not isinstance(bearer_tokens, dict) or not bearer_tokens:
            raise ValueError("account credentials required")
        for account, token in bearer_tokens.items():
            if (account not in accounts or not isinstance(token, str) or len(token) > MAX_TOKEN_BYTES
                    or not re.fullmatch(r"[A-Za-z0-9._~+/-]+={0,2}", token)):
                raise ValueError("invalid account credentials")
        self._tokens = dict(bearer_tokens)
        self._scope = scope
        if run_guard is None:
            run_guard = RunSafetyGuard(scope)
        if not isinstance(run_guard, RunSafetyGuard) or run_guard.scope != scope:
            raise ValueError("run guard scope mismatch")
        self._run_guard = run_guard
        self._ip = ipaddress.ip_address(scope.organizer_ip)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        with self._run_guard.execution():
            actor = request.extensions.get("canary_actor")
            target = request.url
            try:
                body = request.content
                path = target.raw_path.decode("ascii")
            except (httpx.RequestNotRead, UnicodeError):
                raise ValueError("invalid request metadata") from None
            if (not isinstance(actor, str) or actor not in self._tokens or request.method != "GET" or body
                    or target.scheme != self._scope.scheme or target.host != self._scope.hostname
                    or (target.port or 443) != self._scope.port or target.userinfo or target.fragment):
                raise ValueError("request outside scope")
            # The sole guard check is at the transport boundary, immediately before
            # socket creation; callers cannot override Host, auth or destination.
            self._run_guard.authorize(actor, "GET", self._scope.origin + path)
            sock = None
            connection = None
            deadline = _NetworkDeadline(TOTAL_DEADLINE_SECONDS)
            try:
                deadline.start()
                family = socket.AF_INET if self._ip.version == 4 else socket.AF_INET6
                sock = socket.socket(family, socket.SOCK_STREAM)
                deadline.attach(sock)
                sock.settimeout(min(5.0, deadline.remaining()))
                sock.connect((str(self._ip), self._scope.port))
                deadline.remaining()
                context = ssl.create_default_context()
                context.keylog_filename = None
                # Avoid a blocking handshake before the watchdog can reference
                # the wrapped socket. The timer can interrupt handshake and reads.
                sock = context.wrap_socket(sock, server_hostname=self._scope.hostname,
                                           do_handshake_on_connect=False)
                deadline.attach(sock)
                sock.settimeout(min(5.0, deadline.remaining()))
                sock.do_handshake()
                deadline.remaining()
                connection = http.client.HTTPConnection(self._scope.hostname, self._scope.port, timeout=5.0)
                connection.sock = sock
                host = f"[{self._scope.hostname}]" if ":" in self._scope.hostname else self._scope.hostname
                connection.request("GET", path, headers={
                    "Host": f"{host}:{self._scope.port}", "Accept": "application/json",
                    "Accept-Encoding": "identity", "Authorization": "Bearer " + self._tokens[actor],
                    "Connection": "close",
                })
                response = connection.getresponse()
                content = response.read(MAX_RESPONSE_BYTES + 1)
                deadline.remaining()
                if len(content) > MAX_RESPONSE_BYTES:
                    raise ValueError("response exceeds size limit")
                # Halt is shared by all transports in this run.
                self._run_guard.record_status(response.status)
                # No unreviewed headers or cookies leave this prototype boundary.
                return httpx.Response(status_code=response.status, content=content, request=request)
            except Exception:
                self._run_guard.halt()
                raise ValueError("network request failed; execution halted") from None
            finally:
                deadline.close()
                try:
                    if connection is not None:
                        connection.close()
                    elif sock is not None:
                        sock.close()
                except Exception:
                    self._run_guard.halt()
                    raise ValueError("network cleanup failed; execution halted") from None


class GuardedHTTPXRunner:
    """Narrow client wrapper; every request goes through GuardedHTTPXTransport."""
    def __init__(self, scope: AuthorizedScope, bearer_tokens: dict[str, str], *, run_guard: RunSafetyGuard | None = None):
        self._transport = GuardedHTTPXTransport(scope, bearer_tokens, run_guard=run_guard)
        self._scope = self._transport._scope
        self._paths = frozenset(op.path for op in self._scope.operations
                                if op.method == "GET" and op.classification == "READ_ONLY")
        self._client = httpx.Client(transport=self._transport, trust_env=False, follow_redirects=False)

    def get(self, actor: str, path: str) -> httpx.Response:
        if not isinstance(path, str) or path not in self._paths:
            raise ValueError("request outside scope")
        return self._client.get(self._scope.origin + path, extensions={"canary_actor": actor})

    def close(self):
        self._client.close()
