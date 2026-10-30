"""Experimental HTTPS read transport for a single organizer-pinned IP.

Not wired into the application, scanner, login, or reports. This narrow component
is not a complete live scanning backend. Only use after independent scope review.
Responses contain unredacted data and must not be persisted as evidence.
"""
from dataclasses import dataclass, field
import http.client
import ipaddress
import re
import socket
import ssl
import threading

from canarygate.guard.authorized_preflight import AuthorizedPreflight
from canarygate.scope.authorized import AuthorizedScope

MAX_RESPONSE_BYTES = 64 * 1024
MAX_TOKEN_BYTES = 4096


@dataclass(frozen=True)
class ReadResponse:
    status: int
    # Raw content is intentionally excluded from repr; it can contain secrets.
    body: bytes = field(repr=False)


class PinnedReader:
    """Sequential HTTPS GET only, with no redirect, retry, cookie or proxy support."""

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
        self._tokens = dict(bearer_tokens)  # memory only; never persisted or included in results
        self._scope = scope
        self._policy = AuthorizedPreflight(scope)
        self._ip = ipaddress.ip_address(scope.organizer_ip)
        self._lock = threading.Lock()
        self._halted = False
        self._server_error_streak = 0

    def get(self, actor: str, path: str) -> ReadResponse:
        with self._lock:
            if self._halted:
                raise ValueError("execution halted")
            if not isinstance(actor, str) or actor not in self._tokens or not isinstance(path, str):
                raise ValueError("invalid request metadata")
            # Policy checks the literal scope origin and path immediately before
            # opening a socket. No client-controlled scheme, host, port or query.
            self._policy.check(actor, "GET", self._scope.origin + path)
            sock = None
            connection = None
            try:
                family = socket.AF_INET if self._ip.version == 4 else socket.AF_INET6
                sock = socket.socket(family, socket.SOCK_STREAM)
                sock.settimeout(5.0)
                sock.connect((str(self._ip), self._scope.port))
                context = ssl.create_default_context()
                # CPython honors SSLKEYLOGFILE by default; never write TLS session
                # secrets even when the process inherited that environment value.
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
                body = response.read(MAX_RESPONSE_BYTES + 1)
                if len(body) > MAX_RESPONSE_BYTES:
                    self._halted = True
                    raise ValueError("response exceeds size limit")
                self._server_error_streak = self._server_error_streak + 1 if response.status >= 500 else 0
                if self._server_error_streak >= 2 or response.status in (423, 429):
                    self._halted = True
                return ReadResponse(status=response.status, body=body)
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
