"""Offline validation-plan checks; never invoke either independent application."""
from pathlib import Path
import socket

import httpx
import pytest
import yaml

from canarygate.guard.safety_guard import GuardRejected
from canarygate.network.guarded_httpx import _network_execution_enabled
from canarygate.offline.runner import FixtureRunner
from canarygate.offline.scan import fixture_recipe, run_fixture
from canarygate.offline.target import FixtureTarget
from canarygate.scope.loader import FixtureScope, fixture_scope
from canarygate.seed.recipe import validate_fixture_recipe
from canarygate.seed.registry import collect_fixture_ownership
from canarygate.spec.parser import parse_inventory

ROOT = Path(__file__).resolve().parents[2]
PROFILES = ROOT / 'docs' / 'validation' / 'profiles'


@pytest.mark.parametrize('name', ['vampi', 'crapi'])
def test_preparation_profiles_cannot_supply_target_or_authorization(name):
    profile = yaml.safe_load((PROFILES / f'{name}.yaml').read_text(encoding='utf-8'))
    assert profile['status'] == 'planning_only'
    assert profile['authorization'] == 'not_recorded'
    assert profile['execution_enabled'] is False
    assert profile['scope_authority'] == 'separate_organizer_authorized_scope'
    assert profile['target'] is None
    assert profile['account_a_password_env'] == 'CANARY_USER_A_PASSWORD'
    assert profile['account_b_password_env'] == 'CANARY_USER_B_PASSWORD'
    assert profile['candidate_login']['classification'] == 'AUTHENTICATION'
    assert profile['candidate_discovery']['classification'] == 'READ_ONLY'
    assert profile['candidate_detail']['classification'] == 'READ_ONLY'
    assert len(profile['source_revision']) == 40
    assert _network_execution_enabled() is False
    # A preparation profile is not a valid runnable fixture recipe or scope.
    with pytest.raises(ValueError):
        validate_fixture_recipe(profile)
    with pytest.raises(ValueError):
        FixtureScope.model_validate(profile)


def test_documented_vampi_database_reset_get_is_destructive():
    profile = yaml.safe_load((PROFILES / 'vampi.yaml').read_text(encoding='utf-8'))
    assert profile['never_execute'][0] == {'method': 'GET', 'path': '/createdb', 'classification': 'DESTRUCTIVE'}
    data = fixture_scope().model_dump(mode='json')
    data['operations'].append(profile['never_execute'][0])
    scope = FixtureScope.model_validate(data)
    calls = []
    runner = FixtureRunner(lambda request: calls.append(request) or httpx.Response(200), scope=scope)
    try:
        with pytest.raises(GuardRejected):
            runner.request('alice', 'GET', scope.origin + '/createdb', token='fixture-token-alice')
        assert not calls and runner.requests_sent == 0
    finally:
        runner.close()


@pytest.mark.parametrize('name,login,listing,detail', [
    ('vampi', '/users/v1/login', '/books/v1', '/books/v1/{book_title}'),
    ('crapi', '/identity/api/auth/login', '/identity/api/v2/vehicle/vehicles', '/identity/api/v2/vehicle/{vehicleId}/location'),
])
def test_reduced_synthetic_openapi_inventory(name, login, listing, detail):
    # A small synthetic document exercises common parser shapes, not the real lab.
    spec = f'''openapi: 3.0.1
info: {{title: synthetic, version: '1'}}
paths:
  {login}:
    post:
      security: []
      responses: {{'200': {{description: ok}}}}
  {listing}:
    get:
      security: [{{bearerAuth: []}}]
      responses: {{'200': {{description: ok}}}}
  {detail}:
    get:
      security: [{{bearerAuth: []}}]
      responses: {{'200': {{description: ok}}}}
'''
    inv = {(e['method'], e['path']): e for e in parse_inventory(spec)}
    assert inv[('POST', login)]['expected_access'] == 'public'
    assert inv[('GET', listing)]['expected_access'] == 'authenticated'
    assert inv[('GET', detail)]['expected_access'] == 'authenticated'  # not owner-only policy


@pytest.mark.parametrize('shape', ['global_wrapped_list', 'global_flat_list', 'nested_owner'])
def test_unsupported_external_style_discovery_never_verifies(shape):
    target = FixtureTarget()
    def handle(request):
        if request.url.path == '/items':
            if shape == 'global_wrapped_list':
                return httpx.Response(200, json={'Books': [{'id':'alice-item','owner':'alice'}, {'id':'bob-item','owner':'bob'}]})
            if shape == 'global_flat_list':
                return httpx.Response(200, json=[{'id':'alice-item','owner':'alice'}, {'id':'bob-item','owner':'bob'}])
            actor = request.headers['Authorization'].removeprefix('Bearer fixture-token-')
            return httpx.Response(200, json=[{'id': f'{actor}-item', 'owner': {'email': actor}}])
        return target.handle(request)
    runner = FixtureRunner(handle)
    resource = validate_fixture_recipe(fixture_recipe()).setup.resources['items']
    try:
        outcome = collect_fixture_ownership(runner, resource_type='items', resource=resource,
                  accounts=('alice', 'bob'), tokens={'alice':'fixture-token-alice','bob':'fixture-token-bob'})
        assert outcome.ownership_status != 'SUCCESS'
        assert not any(item.ownership_verified for item in outcome.entries)
    finally:
        runner.close()


def test_profiles_do_not_change_fixture_network_isolation(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('Unexpected DNS or network connection')
    monkeypatch.setattr(socket.socket, 'connect', forbidden)
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
    run = run_fixture()
    assert run['mode'] == 'fixture' and run['constraints']['network_transport_enabled'] is False
    assert run['constraints']['external_requests_executed'] == 0


def test_candidate_mappings_are_not_destinations_or_scope_grants():
    for name in ('vampi', 'crapi'):
        profile = yaml.safe_load((PROFILES / f'{name}.yaml').read_text(encoding='utf-8'))
        assert not {'base_url', 'hostname', 'port', 'organizer_ip', 'approved_resolver', 'written_authorization_reference'} & set(profile)
        for key in ('candidate_login', 'candidate_discovery', 'candidate_detail'):
            operation = profile[key]
            assert operation['path'].startswith('/') and '://' not in operation['path']
            assert '?' not in operation['path'] and '#' not in operation['path']
        assert profile['policy']['source'] != 'declared'
