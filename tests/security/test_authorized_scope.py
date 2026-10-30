"""Test-first validation of written scope data; no live traffic is enabled."""
import socket

import pytest
import yaml

SCOPE = '''
mode: competition
scheme: https
hostname: api.organizer.example
port: 443
written_authorization_reference: organizer-test-reference
organizer_ip: 203.0.113.12
allowed_methods: [GET, POST]
request_budget: 20
accounts:
  - {account: alice, role: user}
  - {account: bob, role: user}
operations:
  - {method: POST, path: /login, classification: AUTHENTICATION}
  - {method: GET, path: /items, classification: READ_ONLY}
'''


def _load(text):
    from canarygate.scope.authorized import load_authorized_scope
    return load_authorized_scope(text)


def test_organizer_scope_is_immutable_bounded_and_never_resolves(monkeypatch):
    def prohibited(*args, **kwargs):
        raise AssertionError('scope validation attempted network or DNS')
    monkeypatch.setattr(socket, 'getaddrinfo', prohibited)
    monkeypatch.setattr(socket, 'gethostbyname', prohibited)
    monkeypatch.setattr(socket.socket, 'connect', prohibited)
    scope = _load(SCOPE)
    assert scope.origin == 'https://api.organizer.example:443'
    assert scope.organizer_ip == '203.0.113.12'
    assert scope.accounts[0].account == 'alice' and scope.accounts[0].role == 'user'
    assert scope.operations[0].classification == 'AUTHENTICATION'
    with pytest.raises((TypeError, AttributeError, ValueError)):
        scope.operations += (scope.operations[0],)


def test_explicit_approved_resolver_is_accepted_but_never_invoked(monkeypatch):
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **k: pytest.fail('DNS was invoked'))
    data = yaml.safe_load(SCOPE)
    del data['organizer_ip']
    data['approved_resolver'] = 'organizer_approved_system'
    result = _load(yaml.safe_dump(data))
    assert result.approved_resolver == 'organizer_approved_system'
    assert result.organizer_ip is None


@pytest.mark.parametrize('change', [
    {'hostname': '*.organizer.example'}, {'hostname': 'https://api.organizer.example'},
    {'organizer_ip': '203.0.113.0/24'}, {'organizer_ip': 'fe80::1%eth0'},
    {'port': '443'}, {'request_budget': 0}, {'request_budget': 100001},
    {'mode': 'fixture'}, {'written_authorization_reference': ''},
    {'approved_resolver': 'public_dns'}, {'base_url': 'https://attacker.invalid'},
])
def test_invalid_scope_fields_fail_closed(change):
    data = yaml.safe_load(SCOPE)
    data.update(change)
    with pytest.raises(ValueError):
        _load(yaml.safe_dump(data))


def test_scope_requires_explicit_destination_approval_without_dns_fallback():
    data = yaml.safe_load(SCOPE)
    del data['organizer_ip']
    with pytest.raises(ValueError):
        _load(yaml.safe_dump(data))


@pytest.mark.parametrize('operation', [
    {'method': 'GET', 'path': '/items', 'classification': 'UNKNOWN'},
    {'method': 'GET', 'path': '/items', 'classification': 'STATE_CHANGING'},
    {'method': 'DELETE', 'path': '/items', 'classification': 'READ_ONLY'},
    {'method': 'POST', 'path': '/login', 'classification': 'READ_ONLY'},
    {'method': 'GET', 'path': '/login', 'classification': 'AUTHENTICATION'},
    {'method': 'GET', 'path': '/../admin', 'classification': 'READ_ONLY'},
    {'method': 'GET', 'path': '/items?x=1', 'classification': 'READ_ONLY'},
    {'method': 'POST', 'path': '/create', 'classification': 'STATE_CHANGING'},
])
def test_invalid_or_unauthorized_operations_are_rejected(operation):
    data = yaml.safe_load(SCOPE)
    data['operations'].append(operation)
    with pytest.raises(ValueError):
        _load(yaml.safe_dump(data))


def test_explicit_written_creation_authorization_can_be_recorded_but_not_executed():
    data = yaml.safe_load(SCOPE)
    data['operations'].append({'method': 'POST', 'path': '/items', 'classification': 'STATE_CHANGING',
                               'creation_authorization_reference': 'organizer-create-approval'})
    scope = _load(yaml.safe_dump(data))
    assert scope.operations[-1].creation_authorization_reference == 'organizer-create-approval'
    # This module only validates scope data. It has no transport or request API.
    assert not hasattr(scope, 'request')


def test_duplicate_keys_aliases_and_credential_fields_are_rejected():
    for text in (SCOPE + '\nport: 444\n', SCOPE + '\nextra: &x [*x]\n'):
        with pytest.raises(ValueError):
            _load(text)
    data = yaml.safe_load(SCOPE)
    data['accounts'][0]['password'] = 'never-store-password'
    with pytest.raises(ValueError):
        _load(yaml.safe_dump(data))
    data = yaml.safe_load(SCOPE)
    data['accounts'][0]['token'] = 'never-store-token'
    with pytest.raises(ValueError):
        _load(yaml.safe_dump(data))


def test_duplicate_accounts_operations_and_multiple_login_operations_rejected():
    for kind in ('account', 'operation', 'login'):
        data = yaml.safe_load(SCOPE)
        if kind == 'account':
            data['accounts'].append({'account': 'alice', 'role': 'admin'})
        elif kind == 'operation':
            data['operations'].append(data['operations'][-1].copy())
        else:
            data['operations'].append({'method': 'POST', 'path': '/login2', 'classification': 'AUTHENTICATION'})
        with pytest.raises(ValueError):
            _load(yaml.safe_dump(data))


def test_invalid_yaml_and_oversized_scope_are_rejected():
    with pytest.raises(ValueError):
        _load('!!python/object/apply:os.system ["echo unsafe"]')
    with pytest.raises(ValueError):
        _load('x' * (64 * 1024 + 1))


@pytest.mark.parametrize('address', ['0.0.0.0', '::', '224.0.0.1', 'ff02::1', '255.255.255.255', '::ffff:224.0.0.1'])
def test_non_unicast_destination_addresses_are_not_accepted(address):
    data = yaml.safe_load(SCOPE)
    data['organizer_ip'] = address
    with pytest.raises(ValueError):
        _load(yaml.safe_dump(data))


def test_literal_hostname_cannot_conflict_with_organizer_ip():
    data = yaml.safe_load(SCOPE)
    data['hostname'] = '203.0.113.13'
    with pytest.raises(ValueError):
        _load(yaml.safe_dump(data))


def test_destructive_classification_is_only_metadata_and_does_not_create_a_transport():
    data = yaml.safe_load(SCOPE)
    data['operations'].append({'method': 'GET', 'path': '/erase', 'classification': 'DESTRUCTIVE'})
    scope = _load(yaml.safe_dump(data))
    assert scope.operations[-1].classification == 'DESTRUCTIVE'
    assert not hasattr(scope, 'request')


@pytest.mark.parametrize('hostname', ['0.0.0.0', '224.0.0.1', '::', 'ff02::1'])
def test_non_unicast_literal_hostname_fails_even_with_approved_resolver(hostname):
    data = yaml.safe_load(SCOPE)
    data['hostname'] = hostname
    data.pop('organizer_ip')
    data['approved_resolver'] = 'organizer_approved_system'
    with pytest.raises(ValueError):
        _load(yaml.safe_dump(data))
