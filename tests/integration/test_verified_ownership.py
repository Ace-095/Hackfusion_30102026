"""Test-first ownership registry tests: fixture transport only, no BOLA checks."""
from copy import deepcopy

import httpx
import pytest

from canarygate.models.ownership import OwnedResource
from canarygate.offline.runner import FixtureRunner
from canarygate.offline.scan import fixture_recipe, run_fixture
from canarygate.offline.target import FixtureTarget
from canarygate.seed.recipe import validate_fixture_recipe
from canarygate.scope.loader import fixture_scope


def resource(model='private'):
    data = deepcopy(fixture_recipe())
    data['setup']['resources']['items']['ownership_model'] = model
    return validate_fixture_recipe(data).setup.resources['items']


def collect(runner, *, model='private', accounts=('alice', 'bob'), tokens=None):
    from canarygate.seed.registry import collect_fixture_ownership
    if tokens is None:
        tokens = {'alice': 'fixture-token-alice', 'bob': 'fixture-token-bob'}
    return collect_fixture_ownership(runner, resource_type='items', resource=resource(model),
                                     accounts=accounts, tokens=tokens)


def test_private_ownership_registry_uses_scoped_lists_and_owner_reads():
    runner = FixtureRunner(FixtureTarget().handle)
    try:
        result = collect(runner)
        assert result.ownership_status == 'SUCCESS'
        assert all(isinstance(item, OwnedResource) for item in result.entries)
        assert [(r.resource_id, r.owner, r.ownership_model, r.ownership_verified, r.origin)
                for r in result.entries] == [
                    ('alice-item', 'alice', 'private', True, 'harvested'),
                    ('bob-item', 'bob', 'private', True, 'harvested')]
        assert all(r.canary is None for r in result.entries)
        assert runner.requests_sent == 4 and runner.guard.blocked == 0
    finally:
        runner.close()


@pytest.mark.parametrize('owner', ['alice', 'bob'])
def test_owner_denied_or_incorrect_baseline_is_unverified(owner):
    target = FixtureTarget()
    def handler(request):
        if request.url.path == f'/items/{owner}-item':
            return httpx.Response(403, json={'error': 'denied'})
        return target.handle(request)
    runner = FixtureRunner(handler)
    try:
        result = collect(runner)
        assert result.ownership_status != 'SUCCESS'
        assert all(not item.ownership_verified for item in result.entries)
        assert not any(req for req in result.entries if req.ownership_verified)
    finally:
        runner.close()


def test_other_account_list_includes_peer_resource_is_never_verified():
    runner = FixtureRunner(FixtureTarget(cross_list_leak=True).handle)
    try:
        result = collect(runner)
        assert result.ownership_status != 'SUCCESS'
        assert all(not item.ownership_verified for item in result.entries)
        assert runner.requests_sent == 2  # No detail reads after isolation fails.
    finally:
        runner.close()


@pytest.mark.parametrize('model', ['shared', 'public'])
def test_shared_or_public_resources_are_recorded_but_never_private_verified(model):
    runner = FixtureRunner(FixtureTarget().handle)
    try:
        result = collect(runner, model=model)
        assert result.entries and all(r.ownership_model == model for r in result.entries)
        assert all(not item.ownership_verified for item in result.entries)
        assert result.ownership_status != 'SUCCESS'
    finally:
        runner.close()


@pytest.mark.parametrize('accounts,tokens', [
    (('alice',), {'alice': 'fixture-token-alice'}),
    (('alice', 'alice'), {'alice': 'fixture-token-alice'}),
    (('alice', 'bob'), {'alice': 'fixture-token-alice'}),
])
def test_missing_second_account_or_token_fails_before_requests(accounts, tokens):
    runner = FixtureRunner(FixtureTarget().handle)
    try:
        result = collect(runner, accounts=accounts, tokens=tokens)
        assert result.ownership_status != 'SUCCESS'
        assert all(not r.ownership_verified for r in result.entries)
        assert runner.requests_sent == 0
    finally:
        runner.close()


@pytest.mark.parametrize('mode', ['missing-id', 'duplicate-id', 'unexpected-shape', 'pagination', 'failed-discovery'])
def test_ambiguous_or_incomplete_lists_never_verify_ownership(mode):
    target = FixtureTarget()
    def handler(request):
        if request.url.path == '/items' and request.headers.get('Authorization') == 'Bearer fixture-token-bob':
            if mode == 'missing-id': return httpx.Response(200, json=[{'owner': 'bob'}])
            if mode == 'duplicate-id': return httpx.Response(200, json=[{'id':'bob-item','owner':'bob'}, {'id':'bob-item','owner':'bob'}])
            if mode == 'unexpected-shape': return httpx.Response(200, json={'items': []})
            if mode == 'pagination': return httpx.Response(200, json=[{'id': 'bob-item', 'owner': 'bob'}], headers={'Link': '</items?page=2>; rel="next"'})
            return httpx.Response(500)
        return target.handle(request)
    runner = FixtureRunner(handler)
    try:
        result = collect(runner)
        assert result.ownership_status != 'SUCCESS'
        assert all(not r.ownership_verified for r in result.entries)
    finally:
        runner.close()


def test_scope_guard_rejection_prevents_detail_and_never_verifies():
    scope = fixture_scope().model_copy(update={'operations': [op for op in fixture_scope().operations if op.path != '/items/bob-item']})
    target = FixtureTarget()
    runner = FixtureRunner(target.handle, scope=scope)
    try:
        result = collect(runner)
        assert result.ownership_status != 'SUCCESS'
        assert all(not r.ownership_verified for r in result.entries)
        assert runner.guard.blocked == 1
    finally:
        runner.close()


def test_offline_scan_uses_verified_registry_before_bola(monkeypatch):
    import canarygate.seed.registry as registry
    seen = []
    original = registry.collect_fixture_ownership
    def audited(*args, **kwargs):
        result = original(*args, **kwargs)
        seen.append(result)
        return result
    monkeypatch.setattr(registry, 'collect_fixture_ownership', audited)
    run = run_fixture()
    assert len(seen) == 1
    assert all(item.ownership_verified for item in seen[0].entries)
    assert run['mode'] == 'fixture' and run['setup']['ownership_verification'] == 'SUCCESS'
    assert run['constraints']['network_transport_enabled'] is False


def test_resource_id_alone_cannot_serve_as_owner_field():
    from canarygate.seed.registry import collect_fixture_ownership
    target = FixtureTarget()
    runner = FixtureRunner(target.handle)
    bad = resource().model_copy(update={'ownership_field': 'id'})
    try:
        result = collect_fixture_ownership(
            runner, resource_type='items', resource=bad, accounts=('alice', 'bob'),
            tokens={'alice': 'fixture-token-alice', 'bob': 'fixture-token-bob'})
        assert result.ownership_status != 'SUCCESS'
        assert not result.entries and runner.requests_sent == 0
    finally:
        runner.close()


def test_state_changing_recipe_rejected_before_any_requests():
    from canarygate.seed.registry import collect_fixture_ownership
    target = FixtureTarget()
    bad = resource().model_copy(update={'discovery': resource().discovery.model_copy(update={'method': 'POST', 'path': '/login'})})
    runner = FixtureRunner(target.handle)
    try:
        result = collect_fixture_ownership(runner, resource_type='items', resource=bad,
                    accounts=('alice', 'bob'), tokens={'alice':'fixture-token-alice','bob':'fixture-token-bob'})
        assert result.ownership_status != 'SUCCESS' and runner.requests_sent == 0
    finally:
        runner.close()


@pytest.mark.parametrize('mode', ['duplicate-json-keys', 'wrong-owner', 'wrong-id', 'redirect', 'oversized'])
def test_ambiguous_owner_detail_never_verifies(mode):
    target = FixtureTarget()
    def handler(request):
        if request.url.path == '/items/bob-item':
            if mode == 'duplicate-json-keys':
                return httpx.Response(200, content=b'{"id":"bob-item","owner":"alice","owner":"bob"}')
            if mode == 'wrong-owner': return httpx.Response(200, json={'id': 'bob-item', 'owner': 'alice'})
            if mode == 'wrong-id': return httpx.Response(200, json={'id': 'alice-item', 'owner': 'bob'})
            if mode == 'redirect': return httpx.Response(302, headers={'Location': 'https://outside.invalid/'})
            return httpx.Response(200, content=b'X' * (64 * 1024 + 1))
        return target.handle(request)
    runner = FixtureRunner(handler)
    try:
        result = collect(runner)
        assert result.ownership_status != 'SUCCESS'
        assert not any(r.ownership_verified for r in result.entries)
        assert runner.requests_sent == 4
    finally:
        runner.close()


def test_registry_requires_fixture_runner_and_does_not_emit_raw_values_in_repr():
    from canarygate.seed.registry import collect_fixture_ownership
    runner = FixtureRunner(FixtureTarget().handle)
    try:
        result = collect(runner)
        assert 'synthetic-bob-private-canary' not in repr(result)
        assert 'fixture-token-bob' not in repr(result)
        refused = collect_fixture_ownership(object(), resource_type='items', resource=resource(),
                    accounts=('alice', 'bob'), tokens={'alice':'fixture-token-alice','bob':'fixture-token-bob'})
        assert refused.ownership_status != 'SUCCESS'
    finally:
        runner.close()


def test_ownership_status_is_independent_of_private_disclosure_marker():
    # Owner-readable and excluded from the peer's list still establishes fixture
    # ownership, but the existing synthetic disclosure check cannot run.
    result = run_fixture(FixtureTarget(owner_sees_canary=False))
    assert result['setup']['ownership_verification'] == 'SUCCESS'
    assert result['verdict'] == 'SKIPPED'
    assert result['evidence']['disclosure'] is None


def test_non_json_nan_in_list_is_not_valid_discovery():
    target = FixtureTarget()
    def handler(request):
        if request.url.path == '/items' and request.headers.get('Authorization') == 'Bearer fixture-token-bob':
            return httpx.Response(200, content=b'[{"id":"bob-item","owner":"bob","x":NaN}]')
        return target.handle(request)
    runner = FixtureRunner(handler)
    try:
        result = collect(runner)
        assert result.ownership_status != 'SUCCESS'
        assert not any(r.ownership_verified for r in result.entries)
    finally:
        runner.close()
