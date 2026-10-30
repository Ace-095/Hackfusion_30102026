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

import httpx

from canarygate.guard.authorized_preflight import AuthorizedPreflight
from canarygate.scope.authorized import AuthorizedScope

MAX_RESPONSE_BYTES = 64 * 1024
MAX_TOKEN_BYTES = 4096


class GuardedHTTPXTransport(httpx.BaseTransport):
    """The sole live-network boundary: guard, pin, TLS, and a bounded response.

    GET-only until authentication, discovery and full live-run safety are
    implemented. No resolver, proxy, cookies, redirect, retries or raw headers.
    """
    def __init__(self, scope: AuthorizedScope, bearer_tokens: dict[str, str]):
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
        self._policy = AuthorizedPreflight(scope)
        self._ip = ipaddress.ip_address(scope.organizer_ip)
        self._lock = threading.Lock()
        self._halted = False
        self._server_error_streak = 0

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        with self._lock:
            if self._halted:
                raise ValueError("execution halted")
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
            self._policy.check(actor, "GET", self._scope.origin + path)
            sock = None
            connection = None
            try:
                family = socket.AF_INET if self._ip.version == 4 else socket.AF_INET6
                sock = socket.socket(family, socket.SOCK_STREAM)
                sock.settimeout(5.0)
                sock.connect((str(self._ip), self._scope.port))
                context = ssl.create_default_context()
                context.keylog_filename = None
                sock = context.wrap_socket(sock, server_hostname=self._scope.hostname)
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
                if len(content) > MAX_RESPONSE_BYTES:
                    raise ValueError("response exceeds size limit")
                self._server_error_streak = self._server_error_streak + 1 if response.status >= 500 else 0
                # No redirect is ever followed, even if someone wraps the transport
                # in an HTTPX client configured with follow_redirects=True.
                if self._server_error_streak >= 2 or response.status in (423, 429) or 300 <= response.status < 400:
                    self._halted = True
                # No unreviewed headers or cookies leave this prototype boundary.
                return httpx.Response(status_code=response.status, content=content, request=request)
            except Exception:
                self._halted = True
                raise ValueError("network request failed; execution halted") from None
            finally:
                try:
                    if connection is not None:
                        connection.close()
                    elif sock is not None:
                        sock.close()
                except Exception:
                    self._halted = True
                    raise ValueError("network cleanup failed; execution halted") from None


class GuardedHTTPXRunner:
    """Narrow client wrapper; every request goes through GuardedHTTPXTransport."""
    def __init__(self, scope: AuthorizedScope, bearer_tokens: dict[str, str]):
        self._transport = GuardedHTTPXTransport(scope, bearer_tokens)
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
