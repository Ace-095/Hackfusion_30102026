"""New single HTTPX boundary: these tests must never open network sockets."""
import importlib.util
import socket

import httpx
import pytest


@pytest.fixture
def scope():
    from canarygate.scope.authorized import load_authorized_scope
    return load_authorized_scope('''
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
operations:
 - {method: GET, path: /items, classification: READ_ONLY}
 - {method: GET, path: /erase, classification: DESTRUCTIVE}
 - {method: POST, path: /login, classification: AUTHENTICATION}
''')


@pytest.fixture
def forbid_network(monkeypatch):
    calls = []
    def no_socket(*a, **k):
        calls.append('socket')
        pytest.fail('a rejected request reached socket creation')
    monkeypatch.setattr(socket, 'socket', no_socket)
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **k: pytest.fail('DNS invoked'))
    return calls


def test_old_experimental_reader_is_not_a_second_execution_path():
    with pytest.raises(ImportError, match='removed'):
        importlib.import_module('canarygate.network.pinned_reader')


def test_httpx_transport_is_the_guarded_boundary(scope, forbid_network):
    from canarygate.network.guarded_httpx import GuardedHTTPXTransport
    transport = GuardedHTTPXTransport(scope, {'alice': 'alice-token'})
    assert isinstance(transport, httpx.BaseTransport)
    for request in [
        httpx.Request('GET', 'https://api.organizer.example/items'), # actor absent
        httpx.Request('GET', 'https://evil.invalid/items', extensions={'canary_actor': 'alice'}),
        httpx.Request('GET', 'https://api.organizer.example:444/items', extensions={'canary_actor': 'alice'}),
        httpx.Request('GET', 'https://api.organizer.example/erase', extensions={'canary_actor': 'alice'}),
        httpx.Request('POST', 'https://api.organizer.example/login', extensions={'canary_actor': 'alice'}),
        httpx.Request('GET', 'https://api.organizer.example/items?q=1', extensions={'canary_actor': 'alice'}),
        httpx.Request('GET', 'https://api.organizer.example/items', content=b'data', extensions={'canary_actor': 'alice'}),
        httpx.Request('GET', 'https://user:pass@api.organizer.example/items', extensions={'canary_actor': 'alice'}),
    ]:
        with pytest.raises(ValueError): transport.handle_request(request)
    assert not forbid_network
