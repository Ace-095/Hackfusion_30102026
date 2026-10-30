"""Adversarial fixture-only tests for two-part read-BOLA evidence."""
from dataclasses import replace
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from canarygate.api.app import create_app
from canarygate.models.result import Result
from canarygate.offline.runner import FixtureRunner
from canarygate.offline.scan import fixture_recipe, run_fixture
from canarygate.offline.target import FixtureTarget
from canarygate.seed.recipe import validate_fixture_recipe
from canarygate.seed.registry import collect_fixture_ownership


@pytest.fixture
def observed():
    runner = FixtureRunner(FixtureTarget().handle)
    resource = validate_fixture_recipe(fixture_recipe()).setup.resources['items']
    registry = collect_fixture_ownership(runner, resource_type='items', resource=resource,
                 accounts=('alice', 'bob'), tokens={'alice': 'fixture-token-alice', 'bob': 'fixture-token-bob'})
    response = runner.request('alice', 'GET', runner.scope.origin + '/items/bob-item', token='fixture-token-alice')
    yield registry, resource, response
    runner.close()


def evaluate(observed, **changes):
    from canarygate.oracles.read_bola import evaluate_read_bola
    ownership, resource, response = observed
    args = dict(ownership=ownership, resource_type='items', resource=resource, actor='alice', owner='bob',
                response=response, expected_access='owner-only', expected_source='synthetic fixture policy')
    args.update(changes)
    result = evaluate_read_bola(**args)
    assert isinstance(result, Result) and result.verdict_reason
    assert isinstance(result.checklist, dict) and result.checklist
    assert all(type(value) is bool for value in result.checklist.values())
    assert 'synthetic-bob-private-canary' not in repr(result)
    assert 'fixture-token' not in repr(result)
    return result


def changed_response(original, status=200, *, body=None, content=None, request=None):
    if content is not None:
        return httpx.Response(status, content=content, request=request or original.request)
    return httpx.Response(status, json=body, request=request or original.request)


def test_confirmed_requires_both_evidence_parts(observed):
    result = evaluate(observed)
    assert result.verdict == 'CONFIRMED'
    for key in ('ownership_verified', 'owner_baseline', 'private_baseline', 'attacker_request',
                'response_checked', 'private_disclosure', 'policy_denies_access'):
        assert result.checklist[key] is True


@pytest.mark.parametrize('body', [{'id': 'bob-item'}, {}, {'id':'bob-item','owner':'bob','private_note':'different'},
                                  {'id':'alice-item','owner':'alice','private_note':'synthetic-bob-private-canary'}])
def test_success_without_unambiguous_private_disclosure_is_inconclusive(observed, body):
    result = evaluate(observed, response=changed_response(observed[2], body=body))
    assert result.verdict == 'INCONCLUSIVE'
    assert not result.checklist['private_disclosure']


@pytest.mark.parametrize('mode', ['failed', 'missing', 'wrong-identity'])
def test_owner_baseline_failure_is_inconclusive(observed, mode):
    reg, resource, response = observed
    baselines = dict(reg.baselines)
    if mode == 'missing': baselines.pop('bob')
    elif mode == 'failed': baselines['bob'] = (changed_response(baselines['bob'][0], 403, body={'error':'forbidden'}), {})
    else:
        original = baselines['bob'][0]
        req = httpx.Request('GET', original.request.url, headers={'Authorization': 'Bearer fixture-token-alice'})
        baselines['bob'] = (changed_response(original, body=baselines['bob'][1], request=req), baselines['bob'][1])
    result = evaluate(observed, ownership=replace(reg, baselines=baselines))
    assert result.verdict == 'INCONCLUSIVE'
    assert not result.checklist['owner_baseline']


def test_unverified_ownership_is_inconclusive(observed):
    reg = observed[0]
    entries = tuple(e.model_copy(update={'ownership_verified': False}) for e in reg.entries)
    result = evaluate(observed, ownership=replace(reg, entries=entries))
    assert result.verdict == 'INCONCLUSIVE'
    assert not result.checklist['ownership_verified']


@pytest.mark.parametrize('changes', [
    {'expected_access':'unknown'}, {'expected_access':'authenticated'},
    {'expected_source':'unknown'}, {'expected_source':''},
])
def test_unknown_or_untrusted_access_policy_cannot_confirm(observed, changes):
    result = evaluate(observed, **changes)
    assert result.verdict != 'CONFIRMED' and not result.checklist['policy_denies_access']


@pytest.mark.parametrize('model', ['shared', 'public'])
def test_nonprivate_resources_cannot_auto_confirm(observed, model):
    reg, resource, _ = observed
    entries = tuple(e.model_copy(update={'ownership_model': model}) for e in reg.entries)
    result = evaluate(observed, ownership=replace(reg, entries=entries), resource=resource.model_copy(update={'ownership_model': model}))
    assert result.verdict != 'CONFIRMED'


@pytest.mark.parametrize('status,content', [(200, b''), (200, b'garbage'), (200, b'{"private_note":"x","private_note":"y"}'),
                                           (404, b'{"error":"not found"}'), (401, b'{"error":"token rejected"}')])
def test_empty_and_ambiguous_responses_are_inconclusive(observed, status, content):
    assert evaluate(observed, response=changed_response(observed[2], status, content=content)).verdict == 'INCONCLUSIVE'


def test_incorrect_actor_identity_or_target_not_confirmed(observed):
    response = observed[2]
    for actor, request in [
        ('bob', response.request),
        ('alice', httpx.Request('GET', response.request.url, headers={'Authorization':'Bearer fixture-token-bob'})),
        ('alice', httpx.Request('GET', 'https://fixture.invalid/items/alice-item', headers={'Authorization':'Bearer fixture-token-alice'})),
        ('alice', httpx.Request('GET', 'https://other.invalid/items/bob-item', headers={'Authorization':'Bearer fixture-token-alice'})),
    ]:
        result = evaluate(observed, actor=actor, response=changed_response(response, body={'id':'bob-item','owner':'bob','private_note':'synthetic-bob-private-canary'}, request=request))
        assert result.verdict == 'INCONCLUSIVE'


def test_missing_disclosure_evidence_inconclusive(observed):
    result = evaluate(observed, response=None)
    assert result.verdict == 'INCONCLUSIVE' and not result.checklist['response_checked']


def test_verified_denial_requires_checked_body_and_expected_denial(observed):
    denied = changed_response(observed[2], 403, body={'error':'forbidden'})
    result = evaluate(observed, response=denied)
    assert result.verdict == 'SAFE' and result.checklist['response_checked'] and result.checklist['verified_denial']
    assert evaluate(observed, response=denied, expected_access='unknown').verdict != 'SAFE'


@pytest.mark.parametrize('body', [{}, {'error':'forbidden','private_note':'synthetic-bob-private-canary'},
                                  {'error':'forbidden','data':{'private_note':'synthetic-bob-private-canary'}}])
def test_403_body_with_missing_or_extra_data_is_not_safe(observed, body):
    assert evaluate(observed, response=changed_response(observed[2], 403, body=body)).verdict != 'SAFE'


def test_fixture_scanner_calls_oracle_and_persists_checklist(monkeypatch, tmp_path):
    import canarygate.oracles.read_bola as oracle
    seen = []
    original = oracle.evaluate_read_bola
    def audited(**kwargs):
        result = original(**kwargs)
        seen.append(result)
        return result
    monkeypatch.setattr(oracle, 'evaluate_read_bola', audited)
    with TestClient(create_app(tmp_path / 'db.sqlite3')) as client:
        run = client.post('/api/scan').json()
        assert run['verdict'] == 'CONFIRMED' and seen[-1].verdict == 'CONFIRMED'
        assert run['bola_checklist'] == seen[-1].checklist
        stored = client.get('/api/scan/' + run['id']).json()
        assert stored['bola_checklist'] == run['bola_checklist']
        assert 'fixture-token' not in json.dumps(stored) and 'synthetic-bob-private-canary' not in json.dumps(stored)
        html = client.get('/api/reports/' + run['id'] + '?format=html')
        assert html.status_code == 200 and 'Read-BOLA evidence checklist' in html.text
        assert 'private_disclosure' in html.text and 'synthetic-bob-private-canary' not in html.text


def test_scanner_skipped_verdict_has_checklist():
    run = run_fixture(FixtureTarget(cross_list_leak=True))
    assert run['verdict'] == 'SKIPPED'
    assert isinstance(run['bola_checklist'], dict) and not run['bola_checklist']['ownership_verified']


def test_legacy_stored_run_without_checklist_remains_readable(tmp_path):
    import hashlib
    import sqlite3
    from canarygate.database.store import FixtureStore
    from canarygate.evidence.redaction import canonical_json
    store = FixtureStore(tmp_path / 'legacy.sqlite3')
    store.initialize()
    run = store.save(run_fixture())
    run.pop('bola_checklist')
    payload = canonical_json(run)
    checksum = hashlib.sha256(payload.encode()).hexdigest()
    with sqlite3.connect(str(store.path)) as conn:
        conn.execute('UPDATE fixture_runs SET payload = ?, sha256 = ? WHERE run_id = ?', (payload, checksum, run['id']))
    loaded = store.get(run['id'])
    assert loaded['bola_checklist'] == {}  # Not recorded, not retroactively inferred.
    assert loaded['verdict'] == run['verdict']


@pytest.mark.parametrize('marker', ['', '   ', '[REDACTED]', 'masked', '****', 'bob-item', 'reflected:bob-item'])
def test_masked_empty_or_identifier_baseline_cannot_confirm(observed, marker):
    reg, resource, cross = observed
    old = reg.baselines['bob'][0]
    baselines = dict(reg.baselines)
    body = {'id':'bob-item', 'owner':'bob', 'private_note':marker}
    baselines['bob'] = (changed_response(old, body=body), body)
    new_resource = resource.model_copy(update={'known_owner_canary': marker})
    attacker = changed_response(cross, body=body)
    decision = evaluate(observed, ownership=replace(reg, baselines=baselines), resource=new_resource, response=attacker)
    assert decision.verdict == 'INCONCLUSIVE' and not decision.checklist['private_baseline']


def test_checklist_comes_from_oracle_for_denied_and_ambiguous_fixture_reads():
    class Target(FixtureTarget):
        def __init__(self, mode):
            super().__init__()
            self.mode = mode
        def handle(self, request):
            if request.url.path == '/items/bob-item' and request.headers.get('Authorization') == 'Bearer fixture-token-alice':
                if self.mode == 'leaky403':
                    return httpx.Response(403, json={'error':'forbidden', 'private_note':self.canary})
                return httpx.Response(200, json={'id':'bob-item', 'owner':'bob'})
            return super().handle(request)
    for mode in ('leaky403', 'metadata'):
        run = run_fixture(Target(mode))
        assert run['verdict'] == 'INCONCLUSIVE'
        assert run['bola_checklist']['response_checked']
        assert not run['bola_checklist']['verified_denial']
        assert not run['bola_checklist']['private_disclosure']
    denied = run_fixture(FixtureTarget(attacker_access='deny'))
    assert denied['verdict'] == 'SAFE' and denied['bola_checklist']['verified_denial']


def test_denial_body_matching_owner_private_value_is_not_safe(observed):
    reg, resource, original = observed
    baselines = dict(reg.baselines)
    body = {'id':'bob-item', 'owner':'bob', 'private_note':'forbidden'}
    baselines['bob'] = (changed_response(baselines['bob'][0], body=body), body)
    decision = evaluate(observed, ownership=replace(reg, baselines=baselines),
                        resource=resource.model_copy(update={'known_owner_canary':'forbidden'}),
                        response=changed_response(original, 403, body={'error':'forbidden'}))
    assert decision.verdict != 'SAFE'
    assert not decision.checklist['verified_denial']
