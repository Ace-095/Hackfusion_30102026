"""Experimental guarded HTTPX read boundary; not wired into the scanner or API.

Every wire request passes the scope guard in this transport immediately before
socket creation. Production network execution is disabled pending complete
safety review; tests explicitly replace the gate using mocked network resources.
"""
import http.client
import hmac
import json
import os
import ipaddress
import re
import socket
import ssl
import threading
import time

import httpx

from canarygate.accounts.login_config import LoginConfig
from canarygate.guard.run_guard import RunSafetyGuard
from canarygate.scope.authorized import AuthorizedScope

MAX_RESPONSE_BYTES = 64 * 1024
MAX_TOKEN_BYTES = 4096
TOTAL_DEADLINE_SECONDS = 10.0


def _network_execution_enabled():
    # Deliberately no configuration or environment override: until the live
    # scanner and its safety review are complete, this path is disabled. Tests
    # replace this function while using mock sockets or an in-process socketpair.
    return False


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

    Supports exact classified GET and a narrowly configured POST login only.
    No resolver, proxy, cookies, redirect, retries or raw response headers.
    """
    def __init__(self, scope: AuthorizedScope, bearer_tokens: dict[str, str], *, run_guard: RunSafetyGuard | None = None, login_config: LoginConfig | None = None):
        if not isinstance(scope, AuthorizedScope):
            raise ValueError("validated scope required")
        scope = AuthorizedScope.model_validate(scope.model_dump())
        if scope.organizer_ip is None or scope.scheme != "https":
            raise ValueError("an organizer-pinned IP and HTTPS are required")
        accounts = {account.account for account in scope.accounts}
        if not isinstance(bearer_tokens, dict):
            raise ValueError("invalid account credentials")
        if login_config is not None:
            if not isinstance(login_config, LoginConfig):
                raise ValueError("invalid login configuration")
            login_config = LoginConfig.model_validate(login_config.model_dump())
            if (not set(login_config.password_env).issubset(accounts)
                    or not any(op.method == "POST" and op.path == login_config.path
                               and op.classification == "AUTHENTICATION" for op in scope.operations)):
                raise ValueError("login configuration outside scope")
        if not bearer_tokens and login_config is None:
            raise ValueError("account credentials required")
        for account, token in bearer_tokens.items():
            if (account not in accounts or not isinstance(token, str) or len(token) > MAX_TOKEN_BYTES
                    or not re.fullmatch(r"[A-Za-z0-9._~+/-]+={0,2}", token)):
                raise ValueError("invalid account credentials")
        self._tokens = dict(bearer_tokens)
        self._login = login_config
        self._password_env = dict(login_config.password_env) if login_config is not None else {}
        self._scope = scope
        if run_guard is None:
            run_guard = RunSafetyGuard(scope)
        if not isinstance(run_guard, RunSafetyGuard) or run_guard.scope != scope:
            raise ValueError("run guard scope mismatch")
        self._run_guard = run_guard
        self._ip = ipaddress.ip_address(scope.organizer_ip)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        with self._run_guard.execution():
            if not _network_execution_enabled():
                raise ValueError("live network execution disabled pending safety review")
            actor = request.extensions.get("canary_actor")
            target = request.url
            try:
                body = request.content
                path = target.raw_path.decode("ascii")
            except (httpx.RequestNotRead, UnicodeError):
                raise ValueError("invalid request metadata") from None
            if (not isinstance(actor, str) or body or target.scheme != self._scope.scheme
                    or target.host != self._scope.hostname or (target.port or 443) != self._scope.port
                    or target.userinfo or target.fragment):
                raise ValueError("request outside scope")
            is_login = request.method == "POST" and self._login is not None and path == self._login.path
            payload = None
            if is_login:
                if actor not in self._password_env or actor in self._tokens:
                    raise ValueError("login account not permitted")
                password = os.environ.get(self._password_env[actor])
                try:
                    if not password or len(password.encode("utf-8")) > 4096:
                        raise ValueError("credential unavailable or invalid")
                    payload = json.dumps({self._login.username_field: actor,
                                          self._login.password_field: password},
                                         ensure_ascii=True, separators=(",", ":")).encode("ascii")
                except UnicodeError:
                    raise ValueError("credential unavailable or invalid") from None
                if len(payload) > 16384:
                    raise ValueError("credential unavailable or invalid")
            elif request.method != "GET" or actor not in self._tokens:
                raise ValueError("request outside scope")
            # The sole guard check is at the transport boundary, immediately before
            # socket creation; callers cannot override Host, auth or destination.
            if is_login:
                self._run_guard.authorize_authentication(actor, self._scope.origin + path)
            else:
                self._run_guard.authorize(actor, request.method, self._scope.origin + path)
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
                headers = {"Host": f"{host}:{self._scope.port}", "Accept": "application/json",
                           "Accept-Encoding": "identity", "Connection": "close"}
                if is_login:
                    headers["Content-Type"] = "application/json"
                    connection.request("POST", path, body=payload, headers=headers)
                else:
                    headers["Authorization"] = "Bearer " + self._tokens[actor]
                    connection.request("GET", path, headers=headers)
                response = connection.getresponse()
                content = response.read(MAX_RESPONSE_BYTES + 1)
                deadline.remaining()
                if len(content) > MAX_RESPONSE_BYTES:
                    raise ValueError("response exceeds size limit")
                # Halt is shared by all transports in this run.
                self._run_guard.record_status(response.status)
                if is_login:
                    def unique_object(pairs):
                        obj = {}
                        for key, value in pairs:
                            if key in obj:
                                raise ValueError("duplicate login response key")
                            obj[key] = value
                        return obj
                    token = None
                    if response.status == 200:
                        try:
                            data = json.loads(content, object_pairs_hook=unique_object)
                            token = data.get(self._login.token_field) if isinstance(data, dict) else None
                        except (ValueError, UnicodeError, RecursionError):
                            pass
                    authenticated = (isinstance(token, str) and token != password and len(token) <= MAX_TOKEN_BYTES
                                     and re.fullmatch(r"[A-Za-z0-9._~+/-]+={0,2}", token) is not None)
                    if authenticated:
                        self._tokens[actor] = token
                    # Never return login response bodies or credential-bearing request data.
                    return httpx.Response(status_code=response.status,
                                          json={"token_obtained": bool(authenticated), "identity_verified": False}, request=request)
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
    def __init__(self, scope: AuthorizedScope, bearer_tokens: dict[str, str], *, run_guard: RunSafetyGuard | None = None, login_config: LoginConfig | None = None):
        self._transport = GuardedHTTPXTransport(scope, bearer_tokens, run_guard=run_guard, login_config=login_config)
        self._scope = self._transport._scope
        self._paths = frozenset(op.path for op in self._scope.operations
                                if op.method == "GET" and op.classification == "READ_ONLY")
        self._client = httpx.Client(transport=self._transport, trust_env=False, follow_redirects=False)

    @property
    def scope(self):
        return self._scope

    def supports_read_path(self, path: str) -> bool:
        return isinstance(path, str) and path in self._paths

    def has_distinct_credentials(self, actor_a: str, actor_b: str) -> bool:
        if not isinstance(actor_a, str) or not isinstance(actor_b, str) or actor_a == actor_b:
            return False
        with self._transport._run_guard.execution():
            first = self._transport._tokens.get(actor_a)
            second = self._transport._tokens.get(actor_b)
            return first is not None and second is not None and not hmac.compare_digest(first, second)

    def halt(self):
        self._transport._run_guard.halt()

    def get(self, actor: str, path: str) -> httpx.Response:
        if not isinstance(path, str) or path not in self._paths:
            raise ValueError("request outside scope")
        return self._client.get(self._scope.origin + path, extensions={"canary_actor": actor})

    def login(self, actor: str) -> httpx.Response:
        if self._transport._login is None:
            raise ValueError("login is not configured")
        return self._client.post(self._scope.origin + self._transport._login.path,
                                 extensions={"canary_actor": actor})

    def close(self):
        self._client.close()
