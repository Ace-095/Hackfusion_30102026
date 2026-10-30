"""Production path must remain disabled until live safety review is complete."""
import socket

import pytest

from canarygate.accounts.login_config import LoginConfig
from canarygate.network.guarded_httpx import GuardedHTTPXRunner
from canarygate.scope.authorized import load_authorized_scope

SCOPE = '''
mode: competition
scheme: https
hostname: api.organizer.example
port: 443
organizer_ip: 203.0.113.12
written_authorization_reference: organizer-approval
allowed_methods: [GET, POST]
request_budget: 3
accounts:
 - {account: alice, role: user}
operations:
 - {method: GET, path: /items, classification: READ_ONLY}
 - {method: POST, path: /login, classification: AUTHENTICATION}
'''


def test_live_get_is_disabled_before_socket_or_dns(monkeypatch):
    monkeypatch.setattr(socket, 'socket', lambda *a, **kw: pytest.fail('socket created'))
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **kw: pytest.fail('DNS invoked'))
    runner = GuardedHTTPXRunner(load_authorized_scope(SCOPE), {'alice': 'synthetic-token'})
    with pytest.raises(ValueError, match='disabled'):
        runner.get('alice', '/items')


def test_live_login_is_disabled_before_socket_or_dns(monkeypatch):
    monkeypatch.setattr(socket, 'socket', lambda *a, **kw: pytest.fail('socket created'))
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **kw: pytest.fail('DNS invoked'))
    monkeypatch.setenv('CANARY_ALICE_PASSWORD', 'synthetic-password')
    config = LoginConfig(method='POST', path='/login', username_field='username', password_field='password',
                         token_field='token', password_env={'alice': 'CANARY_ALICE_PASSWORD'})
    runner = GuardedHTTPXRunner(load_authorized_scope(SCOPE), {}, login_config=config)
    with pytest.raises(ValueError, match='disabled'):
        runner.login('alice')


def test_direct_transport_call_cannot_bypass_disabled_gate(monkeypatch):
    import httpx
    from canarygate.guard.run_guard import RunSafetyGuard
    from canarygate.network.guarded_httpx import GuardedHTTPXTransport
    monkeypatch.setattr(socket, 'socket', lambda *a, **kw: pytest.fail('socket created'))
    monkeypatch.setenv('CANARYGATE_LIVE_ENABLED', '1')
    scope = load_authorized_scope(SCOPE)
    guard = RunSafetyGuard(scope)
    transport = GuardedHTTPXTransport(scope, {'alice': 'synthetic-token'}, run_guard=guard)
    req = httpx.Request('GET', scope.origin + '/items', extensions={'canary_actor': 'alice'})
    with pytest.raises(ValueError, match='disabled'):
        transport.handle_request(req)
    assert guard.remaining == 3
