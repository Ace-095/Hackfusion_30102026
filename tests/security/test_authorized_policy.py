"""Preflight policy decisions only: no policy result enables network traffic."""
import pytest

from canarygate.scope.authorized import load_authorized_scope

SCOPE = """
mode: competition
scheme: https
hostname: api.example.test
port: 443
organizer_ip: 192.0.2.10
written_authorization_reference: AUTH-001
allowed_methods: [GET, POST, PUT, PATCH, DELETE]
request_budget: 2
accounts:
  - {account: alice, role: user}
operations:
  - {method: GET, path: /items, classification: READ_ONLY}
  - {method: POST, path: /login, classification: AUTHENTICATION}
  - {method: GET, path: /danger, classification: DESTRUCTIVE}
  - {method: DELETE, path: /items, classification: DESTRUCTIVE}
  - {method: PUT, path: /items, classification: DESTRUCTIVE}
  - {method: PATCH, path: /items, classification: DESTRUCTIVE}
  - {method: POST, path: /items, classification: STATE_CHANGING, creation_authorization_reference: CREATE-001}
"""


def policy():
    from canarygate.guard.authorized_preflight import AuthorizedPreflight
    return AuthorizedPreflight(load_authorized_scope(SCOPE))


def test_exact_read_and_login_decisions_share_budget():
    guard = policy()
    assert guard.check('alice', 'GET', 'https://api.example.test:443/items') == 'READ_ONLY'
    assert guard.check('alice', 'POST', 'https://api.example.test:443/login') == 'AUTHENTICATION'
    with pytest.raises(ValueError):
        guard.check('alice', 'GET', 'https://api.example.test:443/items')


@pytest.mark.parametrize('actor,method,url', [
    ('bob', 'GET', 'https://api.example.test:443/items'),
    ('alice', 'get', 'https://api.example.test:443/items'),
    ('alice', 'GET', 'https://api.example.test/items'),
    ('alice', 'GET', 'https://api.example.test:443/items?x=1'),
    ('alice', 'GET', 'https://api.example.test:443/a/../items'),
    ('alice', 'GET', 'https://api.example.test:443/%69tems'),
    ('alice', 'GET', 'https://api.example.test:443/items#fragment'),
    ('alice', 'GET', 'https://api.example.test.evil:443/items'),
    ('alice', 'GET', 'https://api.example.test:443/danger'),
    ('alice', 'DELETE', 'https://api.example.test:443/items'),
    ('alice', 'PUT', 'https://api.example.test:443/items'),
    ('alice', 'PATCH', 'https://api.example.test:443/items'),
    ('alice', 'POST', 'https://api.example.test:443/items'),
    ('alice', 'POST', 'https://api.example.test:443/other'),
])
def test_fail_closed_without_consuming_budget(actor, method, url):
    guard = policy()
    with pytest.raises(ValueError):
        guard.check(actor, method, url)
    assert guard.remaining == 2


def test_no_dns_or_socket_when_checking(monkeypatch):
    import socket
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **k: pytest.fail('DNS invoked'))
    monkeypatch.setattr(socket.socket, 'connect', lambda *a, **k: pytest.fail('network invoked'))
    assert policy().check('alice', 'GET', 'https://api.example.test:443/items') == 'READ_ONLY'


def test_copied_unvalidated_scope_cannot_bypass_validation():
    from canarygate.guard.authorized_preflight import AuthorizedPreflight
    bad = load_authorized_scope(SCOPE).model_copy(update={'request_budget': -1})
    with pytest.raises(ValueError):
        AuthorizedPreflight(bad)


def test_concurrent_decisions_cannot_overspend_budget():
    from concurrent.futures import ThreadPoolExecutor
    guard = policy()
    def attempt(_):
        try:
            return guard.check('alice', 'GET', 'https://api.example.test:443/items')
        except ValueError:
            return None
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt, range(25)))
    assert results.count('READ_ONLY') == 2
    assert guard.remaining == 0
