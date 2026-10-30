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
    def connect(self, target): self.events.append(('connect', target))
    def close(self): self.events.append(('close-socket',))


class FakeResponse:
    def __init__(self, status, body): self.status, self.body = status, body
    def read(self, maximum): return self.body[:maximum]


class FakeHTTP:
    def __init__(self, events, responses):
        self.events, self.responses, self.sock = events, responses, None
    def request(self, method, path, *, headers):
        self.events.append(('request', method, path, headers.copy()))
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
        def wrap_socket(self, connection, *, server_hostname):
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
        def connect(self, address): wire.append(('connect', address))
        def sendall(self, data): wire.append(('sent', data))
        def makefile(self, mode):
            return io.BytesIO(b'HTTP/1.1 302 Found\r\nLocation: https://evil.invalid/\r\nContent-Length: 0\r\n\r\n')
        def close(self): pass
    class TLS:
        def wrap_socket(self, connection, *, server_hostname):
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
        def wrap_socket(self, connection, *, server_hostname):
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
