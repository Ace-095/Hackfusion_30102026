"""Mock sockets and HTTP/TLS only. No network or DNS is used by these tests."""
import socket
from collections import deque
from concurrent.futures import ThreadPoolExecutor

import pytest

from canarygate.scope.authorized import load_authorized_scope

SCOPE = '''
mode: competition
scheme: https
hostname: api.organizer.example
port: 443
organizer_ip: 203.0.113.12
written_authorization_reference: organizer-approval
allowed_methods: [GET, POST, DELETE]
request_budget: 3
accounts:
 - {account: alice, role: user}
 - {account: bob, role: user}
operations:
 - {method: GET, path: /items, classification: READ_ONLY}
 - {method: GET, path: /erase, classification: DESTRUCTIVE}
 - {method: POST, path: /login, classification: AUTHENTICATION}
 - {method: DELETE, path: /items, classification: DESTRUCTIVE}
'''


class FakeSocket:
    def __init__(self, events): self.events = events
    def settimeout(self, value): self.events.append(('timeout', value))
    def do_handshake(self): pass
    def connect(self, target): self.events.append(('connect', target))
    def close(self): self.events.append(('close-socket',))


class FakeResponse:
    def __init__(self, status, body): self.status, self.body = status, body
    def read(self, maximum): return self.body[:maximum]


class FakeHTTP:
    def __init__(self, events, responses):
        self.events, self.responses, self.sock = events, responses, None
    def request(self, method, path, *, headers, body=None):
        self.events.append(('request', method, path, headers.copy(), body))
    def getresponse(self): return self.responses.popleft()
    def close(self):
        if self.sock: self.sock.close()


@pytest.fixture
def mocked_wire(monkeypatch):
    events = []
    responses = deque([FakeResponse(200, b'{"ok":true}')] * 10)
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **k: pytest.fail('DNS invoked'))
    monkeypatch.setattr(socket, 'gethostbyname', lambda *a, **k: pytest.fail('DNS invoked'))
    def sock(family, kind):
        events.append(('socket', family, kind))
        return FakeSocket(events)
    monkeypatch.setattr(socket, 'socket', sock)
    from canarygate.network import guarded_httpx
    class FakeTLS:
        def wrap_socket(self, connection, *, server_hostname, do_handshake_on_connect=False):
            events.append(('tls', server_hostname))
            return connection
    monkeypatch.setattr(guarded_httpx.ssl, 'create_default_context', lambda: FakeTLS())
    monkeypatch.setattr(guarded_httpx.http.client, 'HTTPConnection', lambda *a, **k: FakeHTTP(events, responses))
    return events, responses


def reader():
    from canarygate.network.guarded_httpx import GuardedHTTPXRunner
    return GuardedHTTPXRunner(load_authorized_scope(SCOPE), {'alice': 'token-alice', 'bob': 'token-bob'})


def test_pins_socket_and_retains_tls_hostname_and_host_header(mocked_wire):
    events, _ = mocked_wire
    result = reader().get('alice', '/items')
    assert result.status_code == 200 and result.content == b'{"ok":true}'
    assert ('connect', ('203.0.113.12', 443)) in events
    assert ('tls', 'api.organizer.example') in events
    request = next(e for e in events if e[0] == 'request')
    assert request[1:3] == ('GET', '/items')
    assert request[3]['Host'] == 'api.organizer.example:443'
    assert request[3]['Authorization'] == 'Bearer token-alice'


@pytest.mark.parametrize('actor,path', [
    ('eve', '/items'), ('alice', '/erase'), ('alice', '/login'),
    ('alice', '/items?x=1'), ('alice', '/items#fragment'), ('alice', '/a/../items'),
    ('alice', '/%69tems'), ('alice', 'https://evil.invalid/items'),
])
def test_unlisted_or_destructive_requests_never_connect(mocked_wire, actor, path):
    events, _ = mocked_wire
    with pytest.raises(ValueError): reader().get(actor, path)
    assert not any(event[0] in ('socket', 'connect', 'request') for event in events)


def test_redirect_is_observed_but_not_followed(mocked_wire):
    events, responses = mocked_wire
    responses.appendleft(FakeResponse(302, b''))
    assert reader().get('alice', '/items').status_code == 302
    assert sum(e[0] == 'connect' for e in events) == 1


def test_budget_covers_each_request_and_no_retry(mocked_wire):
    events, _ = mocked_wire
    client = reader()
    for _ in range(3): client.get('alice', '/items')
    with pytest.raises(ValueError): client.get('alice', '/items')
    assert sum(e[0] == 'connect' for e in events) == 3


def test_oversized_response_is_not_returned(mocked_wire):
    _, responses = mocked_wire
    responses.appendleft(FakeResponse(200, b'x' * (64 * 1024 + 1)))
    with pytest.raises(ValueError): reader().get('alice', '/items')


def test_lockout_and_repeated_server_errors_halt(mocked_wire):
    events, responses = mocked_wire
    responses.extendleft([FakeResponse(500, b''), FakeResponse(500, b'')])
    client = reader()
    client.get('alice', '/items'); client.get('alice', '/items')
    with pytest.raises(ValueError): client.get('alice', '/items')
    assert sum(e[0] == 'connect' for e in events) == 2


def test_requires_literal_organizer_ip_and_valid_private_credentials(mocked_wire):
    from canarygate.network.guarded_httpx import GuardedHTTPXRunner
    data = load_authorized_scope(SCOPE).model_dump()
    data['organizer_ip'] = None; data['approved_resolver'] = 'organizer_approved_system'
    scope = load_authorized_scope(__import__('yaml').safe_dump(data))
    with pytest.raises(ValueError): GuardedHTTPXRunner(scope, {'alice': 'token-alice'})
    scope = load_authorized_scope(SCOPE)
    for tokens in ({'eve': 'token'}, {'alice': 'bad\r\nX-Evil: x'}, {'alice': ''}):
        with pytest.raises(ValueError): GuardedHTTPXRunner(scope, tokens)
    assert not mocked_wire[0]


def test_connection_failure_halts_and_does_not_retry(mocked_wire, monkeypatch):
    events, _ = mocked_wire
    def fail(self, target):
        self.events.append(('connect', target))
        raise OSError('synthetic failure')
    monkeypatch.setattr(FakeSocket, 'connect', fail)
    client = reader()
    with pytest.raises(ValueError, match='halted'): client.get('alice', '/items')
    with pytest.raises(ValueError, match='halted'): client.get('alice', '/items')
    assert sum(e[0] == 'connect' for e in events) == 1
    assert ('close-socket',) in events


def test_rate_limit_halts_before_next_socket(mocked_wire):
    events, responses = mocked_wire
    responses.appendleft(FakeResponse(429, b''))
    client = reader()
    assert client.get('alice', '/items').status_code == 429
    with pytest.raises(ValueError, match='halted'): client.get('alice', '/items')
    assert sum(e[0] == 'connect' for e in events) == 1


def test_ip_v6_pinning_and_tls_hostname(mocked_wire):
    events, _ = mocked_wire
    from canarygate.network.guarded_httpx import GuardedHTTPXRunner
    scope = load_authorized_scope(SCOPE.replace('203.0.113.12', '2001:db8::12'))
    assert GuardedHTTPXRunner(scope, {'alice': 'token-alice'}).get('alice', '/items').status_code == 200
    assert ('socket', socket.AF_INET6, socket.SOCK_STREAM) in events
    assert ('connect', ('2001:db8::12', 443)) in events
    assert ('tls', 'api.organizer.example') in events


def test_secrets_and_raw_body_not_in_result_representation(mocked_wire):
    _, responses = mocked_wire
    responses.appendleft(FakeResponse(200, b'sensitive private body'))
    client = reader()
    result = client.get('alice', '/items')
    assert 'sensitive' not in repr(result) and 'token-alice' not in repr(result)
    assert 'token-alice' not in repr(client)


def test_http_is_blocked_before_connection(mocked_wire):
    from canarygate.network.guarded_httpx import GuardedHTTPXRunner
    scope = load_authorized_scope(SCOPE.replace('scheme: https', 'scheme: http'))
    with pytest.raises(ValueError): GuardedHTTPXRunner(scope, {'alice': 'token'})
    assert not mocked_wire[0]


def test_real_http_serialization_with_mocked_socket(monkeypatch):
    import io
    from canarygate.network import guarded_httpx
    wire = []
    class WireSocket:
        def settimeout(self, timeout): pass
        def do_handshake(self): pass
        def connect(self, address): wire.append(('connect', address))
        def sendall(self, data): wire.append(('sent', data))
        def makefile(self, mode):
            return io.BytesIO(b'HTTP/1.1 302 Found\r\nLocation: https://evil.invalid/\r\nContent-Length: 0\r\n\r\n')
        def close(self): pass
    class TLS:
        def wrap_socket(self, connection, *, server_hostname, do_handshake_on_connect=False):
            wire.append(('tls', server_hostname)); return connection
    monkeypatch.setattr(socket, 'socket', lambda *a: WireSocket())
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **k: pytest.fail('DNS invoked'))
    monkeypatch.setattr(guarded_httpx.ssl, 'create_default_context', lambda: TLS())
    response = reader().get('alice', '/items')
    assert response.status_code == 302 and response.content == b''
    assert [e for e in wire if e[0] == 'connect'] == [('connect', ('203.0.113.12', 443))]
    request = b''.join(e[1] for e in wire if e[0] == 'sent')
    assert request.startswith(b'GET /items HTTP/1.1\r\n')
    assert b'Host: api.organizer.example:443\r\n' in request
    assert b'Authorization: Bearer token-alice\r\n' in request
    assert b'evil.invalid' not in request


def test_sequential_execution_and_budget_under_concurrency(mocked_wire, monkeypatch):
    import threading
    import time
    active = 0
    max_active = 0
    mutex = threading.Lock()
    original = FakeHTTP.request
    def tracked(self, method, path, *, headers):
        nonlocal active, max_active
        with mutex:
            active += 1
            max_active = max(max_active, active)
        time.sleep(0.01)
        try:
            original(self, method, path, headers=headers)
        finally:
            with mutex: active -= 1
    monkeypatch.setattr(FakeHTTP, 'request', tracked)
    client = reader()
    def attempt(_):
        try: return client.get('alice', '/items').status_code
        except ValueError: return None
    with ThreadPoolExecutor(max_workers=6) as pool:
        assert list(pool.map(attempt, range(6))).count(200) == 3
    assert max_active == 1


def test_oversized_response_halts(mocked_wire):
    events, responses = mocked_wire
    responses.appendleft(FakeResponse(200, b'x' * (64 * 1024 + 1)))
    client = reader()
    with pytest.raises(ValueError): client.get('alice', '/items')
    with pytest.raises(ValueError): client.get('alice', '/items')
    assert sum(e[0] == 'connect' for e in events) == 1


@pytest.mark.parametrize('hostname,expect_success', [('api.organizer.example', True), ('wrong.example', False)])
def test_real_tls_certificate_verification_over_socketpair(monkeypatch, hostname, expect_success):
    """Exercises real TLS, but the only socket is an in-process connected pair."""
    import ssl
    import threading
    from pathlib import Path
    from canarygate.network import guarded_httpx

    fixtures = Path(__file__).parents[1] / 'fixtures' / 'tls'
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(fixtures / 'test-cert.pem', fixtures / 'test-key.pem')
    client_context = ssl.create_default_context(cafile=str(fixtures / 'test-cert.pem'))
    assert client_context.check_hostname and client_context.verify_mode == ssl.CERT_REQUIRED
    client_sock, server_sock = socket.socketpair()
    wire = []

    def server():
        try:
            with server_context.wrap_socket(server_sock, server_side=True) as peer:
                request = peer.recv(16384)
                wire.append(request)
                peer.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}')
        except (OSError, ssl.SSLError):
            pass  # expected when the client rejects the certificate

    worker = threading.Thread(target=server, daemon=True)
    worker.start()
    class FakeConnect:
        def __getattr__(self, name): return getattr(client_sock, name)
        def connect(self, address):
            assert address == ('203.0.113.12', 443)
    monkeypatch.setattr(socket, 'socket', lambda *args: FakeConnect())
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *args, **kwargs: pytest.fail('DNS invoked'))
    monkeypatch.setattr(guarded_httpx.ssl, 'create_default_context', lambda: client_context)
    from canarygate.network.guarded_httpx import GuardedHTTPXRunner
    scope = load_authorized_scope(SCOPE.replace('api.organizer.example', hostname))
    try:
        instance = GuardedHTTPXRunner(scope, {'alice': 'token-alice'})
        if expect_success:
            assert instance.get('alice', '/items').content == b'{}'
        else:
            with pytest.raises(ValueError): instance.get('alice', '/items')
            with pytest.raises(ValueError, match='halted'): instance.get('alice', '/items')
    finally:
        worker.join(timeout=5)
        client_sock.close()
        server_sock.close()
    assert not worker.is_alive()
    if expect_success:
        assert wire and b'Host: api.organizer.example:443\r\n' in wire[0]
    else:
        assert not wire


def test_tls_setup_failure_halts_without_exposing_exception_details(mocked_wire, monkeypatch):
    from canarygate.network import guarded_httpx
    class BadTLS:
        def wrap_socket(self, *args, **kwargs):
            raise ValueError('internal diagnostic token-alice')
    monkeypatch.setattr(guarded_httpx.ssl, 'create_default_context', lambda: BadTLS())
    client = reader()
    with pytest.raises(ValueError) as error:
        client.get('alice', '/items')
    assert 'token-alice' not in str(error.value)
    with pytest.raises(ValueError, match='halted'): client.get('alice', '/items')
    assert sum(e[0] == 'connect' for e in mocked_wire[0]) == 1


def test_tls_key_logging_is_disabled_before_handshake(mocked_wire, monkeypatch):
    from canarygate.network import guarded_httpx
    class TLSWithKeyLog:
        keylog_filename = '/tmp/should-not-receive-session-secrets'
        def wrap_socket(self, connection, *, server_hostname, do_handshake_on_connect=False):
            assert self.keylog_filename is None
            return connection
    context = TLSWithKeyLog()
    monkeypatch.setattr(guarded_httpx.ssl, 'create_default_context', lambda: context)
    assert reader().get('alice', '/items').status_code == 200


def test_direct_httpx_transport_replaces_all_untrusted_headers(mocked_wire):
    import httpx
    from canarygate.network.guarded_httpx import GuardedHTTPXTransport
    events, _ = mocked_wire
    transport = GuardedHTTPXTransport(load_authorized_scope(SCOPE), {'alice': 'token-alice'})
    request = httpx.Request('GET', 'https://api.organizer.example/items',
                            headers={'Host': 'evil.invalid', 'Authorization': 'Bearer attacker',
                                     'Cookie': 'session=secret', 'X-Forwarded-Host': 'evil.invalid'},
                            extensions={'canary_actor': 'alice'})
    assert transport.handle_request(request).status_code == 200
    headers = next(e[3] for e in events if e[0] == 'request')
    assert headers['Host'] == 'api.organizer.example:443'
    assert headers['Authorization'] == 'Bearer token-alice'
    assert 'Cookie' not in headers and 'X-Forwarded-Host' not in headers


def test_httpx_redirect_cannot_follow_even_with_insecure_caller_configuration(mocked_wire):
    import httpx
    from canarygate.network.guarded_httpx import GuardedHTTPXTransport
    events, responses = mocked_wire
    responses.appendleft(FakeResponse(302, b''))
    transport = GuardedHTTPXTransport(load_authorized_scope(SCOPE), {'alice': 'token-alice'})
    with httpx.Client(transport=transport, follow_redirects=True, trust_env=False) as client:
        result = client.get('https://api.organizer.example/items', extensions={'canary_actor': 'alice'})
    assert result.status_code == 302
    assert sum(e[0] == 'connect' for e in events) == 1


def test_streaming_request_body_fails_before_socket(mocked_wire):
    import httpx
    from canarygate.network.guarded_httpx import GuardedHTTPXTransport
    transport = GuardedHTTPXTransport(load_authorized_scope(SCOPE), {'alice': 'token-alice'})
    request = httpx.Request('GET', 'https://api.organizer.example/items', content=iter([b'payload']),
                            extensions={'canary_actor': 'alice'})
    with pytest.raises(ValueError): transport.handle_request(request)
    assert not any(e[0] == 'socket' for e in mocked_wire[0])


def test_shared_run_budget_across_two_httpx_runners(mocked_wire):
    from canarygate.guard.run_guard import RunSafetyGuard
    from canarygate.network.guarded_httpx import GuardedHTTPXRunner
    scope = load_authorized_scope(SCOPE)
    guard = RunSafetyGuard(scope)
    one = GuardedHTTPXRunner(scope, {'alice': 'token-alice'}, run_guard=guard)
    two = GuardedHTTPXRunner(scope, {'alice': 'token-alice'}, run_guard=guard)
    one.get('alice', '/items'); two.get('alice', '/items'); one.get('alice', '/items')
    with pytest.raises(ValueError): two.get('alice', '/items')
    assert sum(e[0] == 'connect' for e in mocked_wire[0]) == 3
    assert guard.remaining == 0


def test_shared_run_guard_serializes_all_runners(mocked_wire, monkeypatch):
    import threading
    import time
    from canarygate.guard.run_guard import RunSafetyGuard
    from canarygate.network.guarded_httpx import GuardedHTTPXRunner
    scope = load_authorized_scope(SCOPE)
    guard = RunSafetyGuard(scope)
    clients = [GuardedHTTPXRunner(scope, {'alice': 'token-alice'}, run_guard=guard) for _ in range(3)]
    active = maximum = 0
    mutex = threading.Lock()
    original = FakeHTTP.request
    def tracked(self, method, path, *, headers):
        nonlocal active, maximum
        with mutex:
            active += 1
            maximum = max(active, maximum)
        time.sleep(0.01)
        try:
            return original(self, method, path, headers=headers)
        finally:
            with mutex: active -= 1
    monkeypatch.setattr(FakeHTTP, 'request', tracked)
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(lambda c: c.get('alice', '/items').status_code, clients)) == [200, 200, 200]
    assert maximum == 1


def test_rate_limit_halts_all_runners_in_same_run(mocked_wire):
    from canarygate.guard.run_guard import RunSafetyGuard
    from canarygate.network.guarded_httpx import GuardedHTTPXRunner
    scope = load_authorized_scope(SCOPE)
    guard = RunSafetyGuard(scope)
    one = GuardedHTTPXRunner(scope, {'alice': 'token-alice'}, run_guard=guard)
    two = GuardedHTTPXRunner(scope, {'alice': 'token-alice'}, run_guard=guard)
    mocked_wire[1].appendleft(FakeResponse(429, b''))
    assert one.get('alice', '/items').status_code == 429
    with pytest.raises(ValueError, match='halted'): two.get('alice', '/items')
    assert sum(e[0] == 'connect' for e in mocked_wire[0]) == 1


def test_run_guard_rejects_different_scope_before_network(mocked_wire):
    from canarygate.guard.run_guard import RunSafetyGuard
    from canarygate.network.guarded_httpx import GuardedHTTPXRunner
    original = load_authorized_scope(SCOPE)
    different = load_authorized_scope(SCOPE.replace('203.0.113.12', '203.0.113.13'))
    with pytest.raises(ValueError):
        GuardedHTTPXRunner(different, {'alice': 'token-alice'}, run_guard=RunSafetyGuard(original))
    assert not mocked_wire[0]


def test_repeated_server_errors_across_runners_share_halt(mocked_wire):
    from canarygate.guard.run_guard import RunSafetyGuard
    from canarygate.network.guarded_httpx import GuardedHTTPXRunner
    scope = load_authorized_scope(SCOPE)
    guard = RunSafetyGuard(scope)
    clients = [GuardedHTTPXRunner(scope, {'alice': 'token-alice'}, run_guard=guard) for _ in range(2)]
    mocked_wire[1].extendleft([FakeResponse(500, b''), FakeResponse(503, b'')])
    for c in clients: assert c.get('alice', '/items').status_code >= 500
    with pytest.raises(ValueError, match='halted'): clients[0].get('alice', '/items')
    assert sum(e[0] == 'connect' for e in mocked_wire[0]) == 2


def test_failed_connection_halts_other_runners(mocked_wire, monkeypatch):
    from canarygate.guard.run_guard import RunSafetyGuard
    from canarygate.network.guarded_httpx import GuardedHTTPXRunner
    scope = load_authorized_scope(SCOPE)
    guard = RunSafetyGuard(scope)
    one, two = [GuardedHTTPXRunner(scope, {'alice': 'token-alice'}, run_guard=guard) for _ in range(2)]
    def failure(self, address):
        self.events.append(('connect', address))
        raise OSError('failed')
    monkeypatch.setattr(FakeSocket, 'connect', failure)
    with pytest.raises(ValueError): one.get('alice', '/items')
    with pytest.raises(ValueError, match='halted'): two.get('alice', '/items')
    assert sum(e[0] == 'connect' for e in mocked_wire[0]) == 1


def test_invalid_scope_copy_cannot_construct_run_guard():
    from canarygate.guard.run_guard import RunSafetyGuard
    bad = load_authorized_scope(SCOPE).model_copy(update={'request_budget': 0})
    with pytest.raises(ValueError): RunSafetyGuard(bad)


@pytest.mark.parametrize('stall', ['handshake', 'headers', 'body', 'drip'])
def test_absolute_network_deadline_interrupts_slow_peer(monkeypatch, stall):
    """In-process socketpair only: a slow TLS peer must not evade the deadline."""
    import ssl
    import threading
    import time
    from pathlib import Path
    from canarygate.network import guarded_httpx
    fixtures = Path(__file__).parents[1] / 'fixtures' / 'tls'
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(fixtures / 'test-cert.pem', fixtures / 'test-key.pem')
    client_context = ssl.create_default_context(cafile=str(fixtures / 'test-cert.pem'))
    client_sock, server_sock = socket.socketpair()
    stop = threading.Event()
    calls = []
    def server():
        try:
            if stall == 'handshake':
                stop.wait(1.8)
            with server_context.wrap_socket(server_sock, server_side=True) as peer:
                peer.recv(16384)
                if stall == 'headers':
                    peer.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n')
                    stop.wait(1.8)
                    peer.sendall(b'\r\n{}')
                elif stall == 'drip':
                    for byte in b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}':
                        peer.sendall(bytes([byte]))
                        if stop.wait(0.03): break
                else:
                    peer.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{')
                    stop.wait(1.8)
                    peer.sendall(b'}')
        except (OSError, ssl.SSLError):
            pass
    worker = threading.Thread(target=server, daemon=True)
    worker.start()
    class FakeConnect:
        def __getattr__(self, name): return getattr(client_sock, name)
        def connect(self, address): calls.append(address)
    monkeypatch.setattr(socket, 'socket', lambda *args: FakeConnect())
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *args, **kwargs: pytest.fail('DNS invoked'))
    monkeypatch.setattr(guarded_httpx.ssl, 'create_default_context', lambda: client_context)
    monkeypatch.setattr(guarded_httpx, 'TOTAL_DEADLINE_SECONDS', 0.15, raising=False)
    client = reader()
    start = time.monotonic()
    try:
        with pytest.raises(ValueError, match='halted'): client.get('alice', '/items')
        assert time.monotonic() - start < 1.2
        with pytest.raises(ValueError, match='halted'): client.get('alice', '/items')
        assert calls == [('203.0.113.12', 443)]
    finally:
        stop.set()
        client_sock.close()
        server_sock.close()
        worker.join(timeout=2)
    assert not worker.is_alive()


def test_guarded_login_binds_exact_operation_and_keeps_secrets_out_of_result(mocked_wire, monkeypatch):
    from canarygate.network.guarded_httpx import GuardedHTTPXRunner
    from canarygate.accounts.login_config import LoginConfig
    monkeypatch.setenv('CANARY_ALICE_PASSWORD', 'synthetic-password-123')
    config = LoginConfig(method='POST', path='/login', username_field='username',
                         password_field='password', token_field='access_token',
                         password_env={'alice': 'CANARY_ALICE_PASSWORD'})
    mocked_wire[1].appendleft(FakeResponse(200, b'{"access_token":"signed-token-alice"}'))
    client = GuardedHTTPXRunner(load_authorized_scope(SCOPE), {}, login_config=config)
    result = client.login('alice')
    assert result.status_code == 200 and result.json() == {'token_obtained': True, 'identity_verified': False}
    assert b'signed-token-alice' not in result.content
    assert 'synthetic-password-123' not in repr(result) and 'signed-token-alice' not in repr(result)
    request = next(e for e in mocked_wire[0] if e[0] == 'request')
    assert request[1:3] == ('POST', '/login')
    assert request[3]['Content-Type'] == 'application/json'
    assert 'Authorization' not in request[3]
    assert __import__('json').loads(request[4]) == {'username': 'alice', 'password': 'synthetic-password-123'}
    assert client.get('alice', '/items').status_code == 200
    reads = [e for e in mocked_wire[0] if e[0] == 'request' and e[1] == 'GET']
    assert reads[0][3]['Authorization'] == 'Bearer signed-token-alice'


@pytest.mark.parametrize('body', [b'{}', b'{"access_token":""}', b'{"access_token":"bad\\r\\nX: x"}',
                                  b'{"access_token":"first","access_token":"second"}', b'{'])
def test_invalid_login_response_never_establishes_identity(mocked_wire, monkeypatch, body):
    from canarygate.network.guarded_httpx import GuardedHTTPXRunner
    from canarygate.accounts.login_config import LoginConfig
    monkeypatch.setenv('CANARY_ALICE_PASSWORD', 'synthetic-password')
    config = LoginConfig(method='POST', path='/login', username_field='username',
                         password_field='password', token_field='access_token',
                         password_env={'alice': 'CANARY_ALICE_PASSWORD'})
    mocked_wire[1].appendleft(FakeResponse(200, body))
    client = GuardedHTTPXRunner(load_authorized_scope(SCOPE), {}, login_config=config)
    response = client.login('alice')
    assert response.json() == {'token_obtained': False, 'identity_verified': False}
    with pytest.raises(ValueError): client.get('alice', '/items')
    assert sum(e[0] == 'connect' for e in mocked_wire[0]) == 1


def test_login_cannot_retry_or_use_unapproved_user_or_path(mocked_wire, monkeypatch):
    from canarygate.network.guarded_httpx import GuardedHTTPXRunner
    from canarygate.accounts.login_config import LoginConfig
    from canarygate.guard.run_guard import RunSafetyGuard
    monkeypatch.setenv('CANARY_ALICE_PASSWORD', 'synthetic-password')
    cfg = LoginConfig(method='POST', path='/login', username_field='username',
                      password_field='password', token_field='token',
                      password_env={'alice': 'CANARY_ALICE_PASSWORD'})
    scope = load_authorized_scope(SCOPE)
    guard = RunSafetyGuard(scope)
    first = GuardedHTTPXRunner(scope, {}, login_config=cfg, run_guard=guard)
    second = GuardedHTTPXRunner(scope, {}, login_config=cfg, run_guard=guard)
    mocked_wire[1].appendleft(FakeResponse(401, b'{"token":"not-for-client"}'))
    assert first.login('alice').json() == {'token_obtained': False, 'identity_verified': False}
    with pytest.raises(ValueError): second.login('alice')
    with pytest.raises(ValueError): first.login('bob')
    assert sum(e[0] == 'connect' for e in mocked_wire[0]) == 1


@pytest.mark.parametrize('change', [
    {'path': '/other'}, {'method': 'GET'}, {'username_field': 'password'},
    {'password_env': {'alice': 'PATH'}}, {'password_env': {'eve': 'CANARY_EVE_PASSWORD'}},
])
def test_invalid_login_config_fails_before_socket(mocked_wire, change):
    from canarygate.network.guarded_httpx import GuardedHTTPXRunner
    from canarygate.accounts.login_config import LoginConfig
    data = {'method': 'POST', 'path': '/login', 'username_field': 'username', 'password_field': 'password',
            'token_field': 'token', 'password_env': {'alice': 'CANARY_ALICE_PASSWORD'}}
    data.update(change)
    with pytest.raises(ValueError): GuardedHTTPXRunner(load_authorized_scope(SCOPE), {}, login_config=LoginConfig(**data))
    assert not mocked_wire[0]


def test_missing_password_blocks_without_connection_and_can_be_retried_after_setup(mocked_wire, monkeypatch):
    from canarygate.network.guarded_httpx import GuardedHTTPXRunner
    from canarygate.accounts.login_config import LoginConfig
    monkeypatch.delenv('CANARY_ALICE_PASSWORD', raising=False)
    cfg = LoginConfig(method='POST', path='/login', username_field='username', password_field='password',
                      token_field='token', password_env={'alice': 'CANARY_ALICE_PASSWORD'})
    client = GuardedHTTPXRunner(load_authorized_scope(SCOPE), {}, login_config=cfg)
    with pytest.raises(ValueError): client.login('alice')
    assert not mocked_wire[0]
    monkeypatch.setenv('CANARY_ALICE_PASSWORD', 'synthetic-password')
    mocked_wire[1].appendleft(FakeResponse(200, b'{"token":"valid-token"}'))
    assert client.login('alice').json() == {'token_obtained': True, 'identity_verified': False}


def test_rejected_login_retry_does_not_consume_additional_budget(mocked_wire, monkeypatch):
    from canarygate.network.guarded_httpx import GuardedHTTPXRunner
    from canarygate.accounts.login_config import LoginConfig
    from canarygate.guard.run_guard import RunSafetyGuard
    monkeypatch.setenv('CANARY_ALICE_PASSWORD', 'synthetic-password')
    cfg = LoginConfig(method='POST', path='/login', username_field='username', password_field='password',
                      token_field='token', password_env={'alice': 'CANARY_ALICE_PASSWORD'})
    scope = load_authorized_scope(SCOPE); guard = RunSafetyGuard(scope)
    client = GuardedHTTPXRunner(scope, {}, login_config=cfg, run_guard=guard)
    mocked_wire[1].appendleft(FakeResponse(401, b''))
    client.login('alice')
    assert guard.remaining == 2
    with pytest.raises(ValueError): client.login('alice')
    assert guard.remaining == 2


def test_direct_login_requests_cannot_override_payload_or_scope(mocked_wire, monkeypatch):
    import httpx
    from canarygate.network.guarded_httpx import GuardedHTTPXTransport
    from canarygate.accounts.login_config import LoginConfig
    monkeypatch.setenv('CANARY_ALICE_PASSWORD', 'synthetic-password')
    cfg = LoginConfig(method='POST', path='/login', username_field='username', password_field='password',
                      token_field='token', password_env={'alice': 'CANARY_ALICE_PASSWORD'})
    transport = GuardedHTTPXTransport(load_authorized_scope(SCOPE), {}, login_config=cfg)
    for request in [
        httpx.Request('POST', 'https://api.organizer.example/login', content=b'{"username":"evil"}', extensions={'canary_actor': 'alice'}),
        httpx.Request('POST', 'https://api.organizer.example/login?next=evil', extensions={'canary_actor': 'alice'}),
        httpx.Request('POST', 'https://evil.invalid/login', extensions={'canary_actor': 'alice'}),
        httpx.Request('POST', 'https://api.organizer.example/login', extensions={'canary_actor': 'bob'}),
    ]:
        with pytest.raises(ValueError): transport.handle_request(request)
    assert not mocked_wire[0]


def test_login_config_cannot_include_passwords_or_recipe_target():
    from canarygate.accounts.login_config import LoginConfig
    data = {'method': 'POST', 'path': '/login', 'username_field': 'username', 'password_field': 'password',
            'token_field': 'token', 'password_env': {'alice': 'CANARY_ALICE_PASSWORD'}}
    for extra in ({'base_url': 'https://other.invalid'}, {'password': 'synthetic-secret'}):
        with pytest.raises(ValueError): LoginConfig(**data, **extra)


def test_password_echo_is_not_accepted_as_a_bearer_token(mocked_wire, monkeypatch):
    from canarygate.network.guarded_httpx import GuardedHTTPXRunner
    from canarygate.accounts.login_config import LoginConfig
    monkeypatch.setenv('CANARY_ALICE_PASSWORD', 'synthetic-password')
    config = LoginConfig(method='POST', path='/login', username_field='username', password_field='password',
                         token_field='token', password_env={'alice': 'CANARY_ALICE_PASSWORD'})
    mocked_wire[1].appendleft(FakeResponse(200, b'{"token":"synthetic-password"}'))
    client = GuardedHTTPXRunner(load_authorized_scope(SCOPE), {}, login_config=config)
    result = client.login('alice')
    assert result.json() == {'token_obtained': False, 'identity_verified': False}
    with pytest.raises(ValueError): client.get('alice', '/items')


def test_login_redirect_halts_all_other_accounts_without_returning_response_body(mocked_wire, monkeypatch):
    from canarygate.network.guarded_httpx import GuardedHTTPXRunner
    from canarygate.accounts.login_config import LoginConfig
    monkeypatch.setenv('CANARY_ALICE_PASSWORD', 'synthetic-password')
    monkeypatch.setenv('CANARY_BOB_PASSWORD', 'another-password')
    config = LoginConfig(method='POST', path='/login', username_field='username', password_field='password',
                         token_field='token', password_env={'alice': 'CANARY_ALICE_PASSWORD', 'bob': 'CANARY_BOB_PASSWORD'})
    mocked_wire[1].appendleft(FakeResponse(302, b'secret-body'))
    client = GuardedHTTPXRunner(load_authorized_scope(SCOPE), {}, login_config=config)
    result = client.login('alice')
    assert result.status_code == 302 and result.json() == {'token_obtained': False, 'identity_verified': False}
    assert b'secret-body' not in result.content
    with pytest.raises(ValueError, match='halted'): client.login('bob')
    assert sum(e[0] == 'connect' for e in mocked_wire[0]) == 1


def test_guarded_login_actual_tls_and_http_framing_over_socketpair(monkeypatch):
    import ssl
    import threading
    from pathlib import Path
    from canarygate.network import guarded_httpx
    from canarygate.accounts.login_config import LoginConfig
    fixtures = Path(__file__).parents[1] / 'fixtures' / 'tls'
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(fixtures / 'test-cert.pem', fixtures / 'test-key.pem')
    client_context = ssl.create_default_context(cafile=str(fixtures / 'test-cert.pem'))
    client_sock, server_sock = socket.socketpair()
    observed = []
    def server():
        try:
            with server_context.wrap_socket(server_sock, server_side=True) as peer:
                data = b''
                while b'\r\n\r\n' not in data:
                    chunk = peer.recv(4096)
                    if not chunk: return
                    data += chunk
                head, body = data.split(b'\r\n\r\n', 1)
                lengths = [line.split(b':', 1)[1].strip() for line in head.split(b'\r\n')
                           if line.lower().startswith(b'content-length:')]
                assert len(lengths) == 1
                length = int(lengths[0])
                while len(body) < length:
                    chunk = peer.recv(4096)
                    if not chunk: return
                    body += chunk
                observed.append((head, body))
                payload = b'{"token":"synthetic-valid-token"}'
                peer.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(payload)).encode() +
                             b'\r\nConnection: close\r\n\r\n' + payload)
        except (OSError, ssl.SSLError):
            pass
    worker = threading.Thread(target=server, daemon=True); worker.start()
    class FakeConnect:
        def __getattr__(self, name): return getattr(client_sock, name)
        def connect(self, address): assert address == ('203.0.113.12', 443)
    monkeypatch.setattr(socket, 'socket', lambda *args: FakeConnect())
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *args, **kwargs: pytest.fail('DNS invoked'))
    monkeypatch.setattr(guarded_httpx.ssl, 'create_default_context', lambda: client_context)
    monkeypatch.setenv('CANARY_ALICE_PASSWORD', 'synthetic-password')
    config = LoginConfig(method='POST', path='/login', username_field='username', password_field='password',
                         token_field='token', password_env={'alice': 'CANARY_ALICE_PASSWORD'})
    try:
        client = guarded_httpx.GuardedHTTPXRunner(load_authorized_scope(SCOPE), {}, login_config=config)
        response = client.login('alice')
        assert response.json() == {'token_obtained': True, 'identity_verified': False}
        assert b'synthetic-valid-token' not in response.content
    finally:
        worker.join(timeout=3)
        client_sock.close(); server_sock.close()
    assert not worker.is_alive() and len(observed) == 1
    headers, body = observed[0]
    assert headers.startswith(b'POST /login HTTP/1.1\r\n')
    assert b'Host: api.organizer.example:443\r\n' in headers + b'\r\n'
    assert b'Authorization:' not in headers
    assert __import__('json').loads(body) == {'username': 'alice', 'password': 'synthetic-password'}


def test_identity_check_observes_explicit_profile_without_exposing_body(mocked_wire):
    from canarygate.accounts.identity_check import observe_identity
    from canarygate.network.guarded_httpx import GuardedHTTPXRunner
    scope = load_authorized_scope(SCOPE + '\n - {method: GET, path: /profile, classification: READ_ONLY}\n')
    runner = GuardedHTTPXRunner(scope, {'alice': 'token-alice'})
    mocked_wire[1].appendleft(FakeResponse(200, b'{"username":"alice","secret":"synthetic-private"}'))
    result = observe_identity(runner, actor='alice', path='/profile', identity_field='username')
    assert result.status == 'MATCHED' and result.account == 'alice'
    assert 'synthetic-private' not in repr(result) and 'token-alice' not in repr(result)
    assert sum(e[0] == 'request' for e in mocked_wire[0]) == 1


@pytest.mark.parametrize('status,body', [
    (401, b'{"username":"alice"}'), (200, b'{}'), (200, b'{"username":null}'),
    (200, b'{"username":""}'), (200, b'[]'), (200, b'not-json'),
    (200, b'{"username":"alice","username":"alice"}'),
])
def test_identity_check_cannot_verify_ambiguous_profile(mocked_wire, status, body):
    from canarygate.accounts.identity_check import observe_identity
    from canarygate.network.guarded_httpx import GuardedHTTPXRunner
    scope = load_authorized_scope(SCOPE + '\n - {method: GET, path: /profile, classification: READ_ONLY}\n')
    mocked_wire[1].appendleft(FakeResponse(status, body))
    result = observe_identity(GuardedHTTPXRunner(scope, {'alice': 'token-alice'}),
                             actor='alice', path='/profile', identity_field='username')
    assert result.status != 'MATCHED'


def test_observed_identity_mismatch_halts_run(mocked_wire):
    from canarygate.accounts.identity_check import observe_identity
    from canarygate.network.guarded_httpx import GuardedHTTPXRunner
    scope = load_authorized_scope(SCOPE + '\n - {method: GET, path: /profile, classification: READ_ONLY}\n')
    runner = GuardedHTTPXRunner(scope, {'alice': 'token-alice'})
    mocked_wire[1].appendleft(FakeResponse(200, b'{"username":"bob"}'))
    result = observe_identity(runner, actor='alice', path='/profile', identity_field='username')
    assert result.status == 'MISMATCH'
    with pytest.raises(ValueError, match='halted'): runner.get('alice', '/items')
    assert sum(e[0] == 'connect' for e in mocked_wire[0]) == 1


@pytest.mark.parametrize('actor,path,field', [
    ('eve', '/profile', 'username'), ('alice', '/other', 'username'),
    ('alice', '/profile?foo=1', 'username'), ('alice', '/profile', 'a.b'),
])
def test_identity_check_skips_invalid_setup_without_socket(mocked_wire, actor, path, field):
    from canarygate.accounts.identity_check import observe_identity
    from canarygate.network.guarded_httpx import GuardedHTTPXRunner
    scope = load_authorized_scope(SCOPE + '\n - {method: GET, path: /profile, classification: READ_ONLY}\n')
    runner = GuardedHTTPXRunner(scope, {'alice': 'token-alice'})
    result = observe_identity(runner, actor=actor, path=path, identity_field=field)
    assert result.status == 'SKIPPED'
    assert not any(e[0] == 'socket' for e in mocked_wire[0])


def test_guarded_login_then_explicit_profile_observation(mocked_wire, monkeypatch):
    from canarygate.accounts.identity_check import observe_identity
    from canarygate.accounts.login_config import LoginConfig
    from canarygate.network.guarded_httpx import GuardedHTTPXRunner
    monkeypatch.setenv('CANARY_ALICE_PASSWORD', 'synthetic-password')
    cfg = LoginConfig(method='POST', path='/login', username_field='username', password_field='password',
                      token_field='token', password_env={'alice': 'CANARY_ALICE_PASSWORD'})
    scope = load_authorized_scope(SCOPE + '\n - {method: GET, path: /profile, classification: READ_ONLY}\n')
    runner = GuardedHTTPXRunner(scope, {}, login_config=cfg)
    mocked_wire[1].appendleft(FakeResponse(200, b'{"username":"alice"}'))
    mocked_wire[1].appendleft(FakeResponse(200, b'{"token":"synthetic-token"}'))
    assert runner.login('alice').json() == {'token_obtained': True, 'identity_verified': False}
    observation = observe_identity(runner, actor='alice', path='/profile', identity_field='username')
    assert observation.status == 'MATCHED'
    requests = [e for e in mocked_wire[0] if e[0] == 'request']
    assert [e[1] for e in requests] == ['POST', 'GET']
    assert requests[1][3]['Authorization'] == 'Bearer synthetic-token'


def test_identity_mismatch_halts_other_runners_in_same_run(mocked_wire):
    from canarygate.accounts.identity_check import observe_identity
    from canarygate.guard.run_guard import RunSafetyGuard
    from canarygate.network.guarded_httpx import GuardedHTTPXRunner
    scope = load_authorized_scope(SCOPE + '\n - {method: GET, path: /profile, classification: READ_ONLY}\n')
    guard = RunSafetyGuard(scope)
    one, two = [GuardedHTTPXRunner(scope, {'alice': 'token-alice'}, run_guard=guard) for _ in range(2)]
    mocked_wire[1].appendleft(FakeResponse(200, b'{"username":"bob"}'))
    assert observe_identity(one, actor='alice', path='/profile', identity_field='username').status == 'MISMATCH'
    with pytest.raises(ValueError, match='halted'): two.get('alice', '/items')


def test_identity_pair_requires_distinct_tokens_and_two_matching_profiles(mocked_wire):
    from canarygate.accounts.identity_check import observe_identity_pair
    from canarygate.network.guarded_httpx import GuardedHTTPXRunner
    scope = load_authorized_scope(SCOPE + '\n - {method: GET, path: /profile, classification: READ_ONLY}\n')
    runner = GuardedHTTPXRunner(scope, {'alice': 'token-alice', 'bob': 'token-bob'})
    mocked_wire[1].appendleft(FakeResponse(200, b'{"username":"bob"}'))
    mocked_wire[1].appendleft(FakeResponse(200, b'{"username":"alice"}'))
    result = observe_identity_pair(runner, actor_a='alice', actor_b='bob', path='/profile', identity_field='username')
    assert result.status == 'MATCHED_PAIR'
    assert result.accounts == ('alice', 'bob')
    assert 'token-alice' not in repr(result) and 'token-bob' not in repr(result)
    assert sum(e[0] == 'request' for e in mocked_wire[0]) == 2


@pytest.mark.parametrize('accounts,tokens', [
    (('alice', 'alice'), {'alice': 'token-alice'}),
    (('alice', 'bob'), {'alice': 'same-token', 'bob': 'same-token'}),
    (('alice', 'bob'), {'alice': 'token-alice'}),
    (('alice', 'eve'), {'alice': 'token-alice'}),
])
def test_identity_pair_rejects_non_distinct_or_missing_accounts_before_network(mocked_wire, accounts, tokens):
    from canarygate.accounts.identity_check import observe_identity_pair
    from canarygate.network.guarded_httpx import GuardedHTTPXRunner
    scope = load_authorized_scope(SCOPE + '\n - {method: GET, path: /profile, classification: READ_ONLY}\n')
    runner = GuardedHTTPXRunner(scope, tokens)
    result = observe_identity_pair(runner, actor_a=accounts[0], actor_b=accounts[1], path='/profile', identity_field='username')
    assert result.status == 'SKIPPED'
    assert not mocked_wire[0]


def test_identity_pair_cannot_match_if_second_profile_is_ambiguous(mocked_wire):
    from canarygate.accounts.identity_check import observe_identity_pair
    from canarygate.network.guarded_httpx import GuardedHTTPXRunner
    scope = load_authorized_scope(SCOPE + '\n - {method: GET, path: /profile, classification: READ_ONLY}\n')
    runner = GuardedHTTPXRunner(scope, {'alice': 'token-alice', 'bob': 'token-bob'})
    mocked_wire[1].appendleft(FakeResponse(200, b'{}'))
    mocked_wire[1].appendleft(FakeResponse(200, b'{"username":"alice"}'))
    result = observe_identity_pair(runner, actor_a='alice', actor_b='bob', path='/profile', identity_field='username')
    assert result.status == 'INCONCLUSIVE'


def test_identity_pair_halts_when_second_profile_matches_other_account(mocked_wire):
    from canarygate.accounts.identity_check import observe_identity_pair
    from canarygate.network.guarded_httpx import GuardedHTTPXRunner
    scope = load_authorized_scope(SCOPE + '\n - {method: GET, path: /profile, classification: READ_ONLY}\n')
    runner = GuardedHTTPXRunner(scope, {'alice': 'token-alice', 'bob': 'token-bob'})
    mocked_wire[1].appendleft(FakeResponse(200, b'{"username":"alice"}'))
    mocked_wire[1].appendleft(FakeResponse(200, b'{"username":"alice"}'))
    result = observe_identity_pair(runner, actor_a='alice', actor_b='bob', path='/profile', identity_field='username')
    assert result.status == 'MISMATCH'
    with pytest.raises(ValueError, match='halted'): runner.get('alice', '/items')


def _discovery_runner(mocked_wire, *, budget=6):
    from canarygate.network.guarded_httpx import GuardedHTTPXRunner
    scope_text = SCOPE.replace('request_budget: 3', f'request_budget: {budget}')
    scope_text += '\n - {method: GET, path: /profile, classification: READ_ONLY}\n'
    return GuardedHTTPXRunner(load_authorized_scope(scope_text), {'alice': 'token-alice', 'bob': 'token-bob'})


def _queue_responses(mocked_wire, responses):
    for status, body in reversed(responses):
        mocked_wire[1].appendleft(FakeResponse(status, body))


def test_bounded_discovery_harvests_only_after_both_profile_controls(mocked_wire):
    from canarygate.seed.discovery import harvest_private_lists
    runner = _discovery_runner(mocked_wire)
    _queue_responses(mocked_wire, [(200, b'{"username":"alice"}'), (200, b'{"username":"bob"}'),
                                   (200, b'[{"id":"a-secret-id","owner":"alice"}]'),
                                   (200, b'[{"id":"b-secret-id","owner":"bob"}]')])
    result = harvest_private_lists(runner, actor_a='alice', actor_b='bob', profile_path='/profile',
                                   identity_field='username', list_path='/items', id_field='id',
                                   owner_field='owner', ownership_model='private')
    assert result.status == 'HARVESTED' and result.lists_disjoint is True
    assert result.ids_a == ('a-secret-id',) and result.ids_b == ('b-secret-id',)
    assert 'secret-id' not in repr(result) and 'token-alice' not in repr(result)
    requests = [e for e in mocked_wire[0] if e[0] == 'request']
    assert [(e[1], e[2]) for e in requests] == [('GET', '/profile'), ('GET', '/profile'), ('GET', '/items'), ('GET', '/items')]


@pytest.mark.parametrize('bad_body', [
    b'[]', b'{}', b'not-json', b'[{"id":"x","owner":"bob"}]',
    b'[{"id":"../escape","owner":"alice"}]',
    b'[{"id":"x","id":"x","owner":"alice"}]',
    b'[{"id":"x","owner":"alice"},{"id":"x","owner":"alice"}]',
])
def test_discovery_rejects_incomplete_or_ambiguous_owner_list(mocked_wire, bad_body):
    from canarygate.seed.discovery import harvest_private_lists
    runner = _discovery_runner(mocked_wire)
    _queue_responses(mocked_wire, [(200, b'{"username":"alice"}'), (200, b'{"username":"bob"}'), (200, bad_body)])
    result = harvest_private_lists(runner, actor_a='alice', actor_b='bob', profile_path='/profile',
                                   identity_field='username', list_path='/items', id_field='id',
                                   owner_field='owner', ownership_model='private')
    assert result.status == 'INCONCLUSIVE' and result.ids_a == () and result.ids_b == ()
    assert sum(e[0] == 'request' for e in mocked_wire[0]) == 3


def test_discovery_overlap_is_not_claimed_private_ownership(mocked_wire):
    from canarygate.seed.discovery import harvest_private_lists
    runner = _discovery_runner(mocked_wire)
    _queue_responses(mocked_wire, [(200, b'{"username":"alice"}'), (200, b'{"username":"bob"}'),
                                   (200, b'[{"id":"same","owner":"alice"}]'),
                                   (200, b'[{"id":"same","owner":"bob"}]')])
    result = harvest_private_lists(runner, actor_a='alice', actor_b='bob', profile_path='/profile',
                                   identity_field='username', list_path='/items', id_field='id',
                                   owner_field='owner', ownership_model='private')
    assert result.status == 'INCONCLUSIVE' and result.lists_disjoint is False
    assert result.ids_a == () and result.ids_b == ()


@pytest.mark.parametrize('model', ['shared', 'public', 'unknown'])
def test_discovery_skips_non_private_or_unknown_models_without_requests(mocked_wire, model):
    from canarygate.seed.discovery import harvest_private_lists
    result = harvest_private_lists(_discovery_runner(mocked_wire), actor_a='alice', actor_b='bob',
                                   profile_path='/profile', identity_field='username', list_path='/items',
                                   id_field='id', owner_field='owner', ownership_model=model)
    assert result.status == 'SKIPPED' and not mocked_wire[0]


def test_discovery_does_not_run_lists_if_identity_control_fails(mocked_wire):
    from canarygate.seed.discovery import harvest_private_lists
    runner = _discovery_runner(mocked_wire)
    _queue_responses(mocked_wire, [(200, b'{"username":"alice"}'), (200, b'{"username":"alice"}')])
    result = harvest_private_lists(runner, actor_a='alice', actor_b='bob', profile_path='/profile',
                                   identity_field='username', list_path='/items', id_field='id',
                                   owner_field='owner', ownership_model='private')
    assert result.status != 'HARVESTED'
    assert [(e[1], e[2]) for e in mocked_wire[0] if e[0] == 'request'] == [('GET', '/profile'), ('GET', '/profile')]


def test_discovery_rejects_oversized_list_without_truncating(mocked_wire):
    import json
    from canarygate.seed.discovery import harvest_private_lists
    runner = _discovery_runner(mocked_wire)
    many = json.dumps([{'id': f'x{i}', 'owner': 'alice'} for i in range(21)]).encode()
    _queue_responses(mocked_wire, [(200, b'{"username":"alice"}'), (200, b'{"username":"bob"}'), (200, many)])
    result = harvest_private_lists(runner, actor_a='alice', actor_b='bob', profile_path='/profile',
                                   identity_field='username', list_path='/items', id_field='id',
                                   owner_field='owner', ownership_model='private')
    assert result.status == 'INCONCLUSIVE' and result.ids_a == ()


def test_discovery_budget_exhaustion_exposes_no_partial_identifiers(mocked_wire):
    from canarygate.seed.discovery import harvest_private_lists
    runner = _discovery_runner(mocked_wire, budget=3)
    _queue_responses(mocked_wire, [(200, b'{"username":"alice"}'), (200, b'{"username":"bob"}'),
                                   (200, b'[{"id":"a-private-id","owner":"alice"}]')])
    result = harvest_private_lists(runner, actor_a='alice', actor_b='bob', profile_path='/profile',
                                   identity_field='username', list_path='/items', id_field='id',
                                   owner_field='owner', ownership_model='private')
    assert result.status == 'INCONCLUSIVE' and result.ids_a == () and 'a-private-id' not in repr(result)
    assert sum(e[0] == 'connect' for e in mocked_wire[0]) == 3


@pytest.mark.parametrize('list_path,id_field,owner_field', [
    ('/unlisted', 'id', 'owner'), ('/items?x=1', 'id', 'owner'),
    ('/items', 'owner', 'owner'), ('/items', 'id.name', 'owner'),
])
def test_discovery_invalid_setup_skips_before_profile_requests(mocked_wire, list_path, id_field, owner_field):
    from canarygate.seed.discovery import harvest_private_lists
    result = harvest_private_lists(_discovery_runner(mocked_wire), actor_a='alice', actor_b='bob',
                                   profile_path='/profile', identity_field='username', list_path=list_path,
                                   id_field=id_field, owner_field=owner_field, ownership_model='private')
    assert result.status == 'SKIPPED' and not mocked_wire[0]


def _ownership_runner(mocked_wire, *, budget=8, include_b=True):
    from canarygate.network.guarded_httpx import GuardedHTTPXRunner
    scope_text = SCOPE.replace('request_budget: 3', f'request_budget: {budget}')
    scope_text += '\n - {method: GET, path: /profile, classification: READ_ONLY}\n'
    scope_text += ' - {method: GET, path: /items/a-id, classification: READ_ONLY}\n'
    if include_b:
        scope_text += ' - {method: GET, path: /items/b-id, classification: READ_ONLY}\n'
    return GuardedHTTPXRunner(load_authorized_scope(scope_text), {'alice': 'token-alice', 'bob': 'token-bob'})


def _ownership_responses():
    return [(200, b'{"username":"alice"}'), (200, b'{"username":"bob"}'),
            (200, b'[{"id":"a-id","owner":"alice"}]'), (200, b'[{"id":"b-id","owner":"bob"}]'),
            (200, b'{"id":"a-id","owner":"alice","private_note":"alice private marker"}'),
            (200, b'{"id":"b-id","owner":"bob","private_note":"bob private marker"}')]


def test_owner_baselines_require_profiles_lists_and_scoped_detail_reads(mocked_wire):
    from canarygate.seed.ownership import observe_owner_baselines
    runner = _ownership_runner(mocked_wire)
    _queue_responses(mocked_wire, _ownership_responses())
    result = observe_owner_baselines(runner, actor_a='alice', actor_b='bob', profile_path='/profile',
                                    identity_field='username', list_path='/items', detail_template='/items/{id}',
                                    id_field='id', owner_field='owner', private_field='private_note', ownership_model='private')
    assert result.status == 'BASELINES_OBSERVED'
    assert result.ownership_verified is False  # still needs reviewed policy and independent live evidence
    assert 'private marker' not in repr(result) and 'a-id' not in repr(result) and 'b-id' not in repr(result)
    assert [(e[1], e[2]) for e in mocked_wire[0] if e[0] == 'request'] == [
        ('GET', '/profile'), ('GET', '/profile'), ('GET', '/items'), ('GET', '/items'),
        ('GET', '/items/a-id'), ('GET', '/items/b-id')]


@pytest.mark.parametrize('bad_b', [
    b'{"id":"b-id"}', b'{"id":"b-id","owner":"alice","private_note":"bob private marker"}',
    b'{"id":"other","owner":"bob","private_note":"bob private marker"}',
    b'{"id":"b-id","owner":"bob","private_note":"alice private marker"}',
    b'{"id":"b-id","owner":"bob","private_note":"[REDACTED]"}',
    b'{"id":"b-id","owner":"bob","private_note":"b-id"}',
    b'{"id":"b-id","owner":"bob","private_note":null}',
])
def test_owner_baselines_never_accept_missing_ambiguous_or_shared_private_data(mocked_wire, bad_b):
    from canarygate.seed.ownership import observe_owner_baselines
    runner = _ownership_runner(mocked_wire)
    responses = _ownership_responses(); responses[-1] = (200, bad_b)
    _queue_responses(mocked_wire, responses)
    result = observe_owner_baselines(runner, actor_a='alice', actor_b='bob', profile_path='/profile',
                                    identity_field='username', list_path='/items', detail_template='/items/{id}',
                                    id_field='id', owner_field='owner', private_field='private_note', ownership_model='private')
    assert result.status == 'INCONCLUSIVE' and result.ownership_verified is False


def test_owner_baselines_skip_unscoped_detail_before_detail_requests(mocked_wire):
    from canarygate.seed.ownership import observe_owner_baselines
    runner = _ownership_runner(mocked_wire, include_b=False)
    _queue_responses(mocked_wire, _ownership_responses()[:4])
    result = observe_owner_baselines(runner, actor_a='alice', actor_b='bob', profile_path='/profile',
                                    identity_field='username', list_path='/items', detail_template='/items/{id}',
                                    id_field='id', owner_field='owner', private_field='private_note', ownership_model='private')
    assert result.status == 'SKIPPED' and result.ownership_verified is False
    assert sum(e[0] == 'request' for e in mocked_wire[0]) == 4


@pytest.mark.parametrize('template', ['/items/{id}?x=1', '/items/../{id}', 'https://evil.invalid/{id}', '/items/{id}/{id}', '/items/%7Bid%7D'])
def test_owner_baselines_skip_ambiguous_detail_templates_without_requests(mocked_wire, template):
    from canarygate.seed.ownership import observe_owner_baselines
    runner = _ownership_runner(mocked_wire)
    result = observe_owner_baselines(runner, actor_a='alice', actor_b='bob', profile_path='/profile',
                                    identity_field='username', list_path='/items', detail_template=template,
                                    id_field='id', owner_field='owner', private_field='private_note', ownership_model='private')
    assert result.status == 'SKIPPED' and not mocked_wire[0]


@pytest.mark.parametrize('value', ['******', '****1234', '[MASKED]', '<redacted>', 'masked'])
def test_owner_baselines_reject_masked_private_markers(mocked_wire, value):
    import json
    from canarygate.seed.ownership import observe_owner_baselines
    runner = _ownership_runner(mocked_wire)
    responses = _ownership_responses()
    responses[-1] = (200, json.dumps({'id': 'b-id', 'owner': 'bob', 'private_note': value}).encode())
    _queue_responses(mocked_wire, responses)
    result = observe_owner_baselines(runner, actor_a='alice', actor_b='bob', profile_path='/profile',
                                    identity_field='username', list_path='/items', detail_template='/items/{id}',
                                    id_field='id', owner_field='owner', private_field='private_note', ownership_model='private')
    assert result.status == 'INCONCLUSIVE' and result.ownership_verified is False


@pytest.mark.parametrize('private_field', ['id', 'owner', 'status', 'ID', 'OWNER'])
def test_owner_baselines_never_treat_public_identifier_fields_as_private(mocked_wire, private_field):
    from canarygate.seed.ownership import observe_owner_baselines
    runner = _ownership_runner(mocked_wire)
    result = observe_owner_baselines(runner, actor_a='alice', actor_b='bob', profile_path='/profile',
                                    identity_field='username', list_path='/items', detail_template='/items/{id}',
                                    id_field='record_key', owner_field='owner_name', private_field=private_field,
                                    ownership_model='private')
    assert result.status == 'SKIPPED' and not mocked_wire[0]


def test_owner_baseline_rejects_value_derived_from_public_resource_id(mocked_wire):
    import json
    from canarygate.seed.ownership import observe_owner_baselines
    runner = _ownership_runner(mocked_wire)
    responses = _ownership_responses()
    responses[-1] = (200, json.dumps({'id': 'b-id', 'owner': 'bob', 'private_note': 'record b-id'}).encode())
    _queue_responses(mocked_wire, responses)
    result = observe_owner_baselines(runner, actor_a='alice', actor_b='bob', profile_path='/profile',
                                    identity_field='username', list_path='/items', detail_template='/items/{id}',
                                    id_field='id', owner_field='owner', private_field='private_note', ownership_model='private')
    assert result.status == 'INCONCLUSIVE' and result.ownership_verified is False


def test_owner_observation_cannot_be_constructed_as_verified():
    from canarygate.seed.ownership import OwnerBaselineObservation
    with pytest.raises(TypeError):
        OwnerBaselineObservation('BASELINES_OBSERVED', 'not a verification', ownership_verified=True)
