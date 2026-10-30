"""Test-first bounded generic fixture mappings, oracle and reports. No lab traffic."""
import json
import socket

import httpx
import pytest
from fastapi.testclient import TestClient

from canarygate.api.app import create_app
from canarygate.offline.runner import FixtureRunner
from canarygate.offline.scan import fixture_recipe, run_fixture
from canarygate.offline.target import FixtureTarget
from canarygate.scope.loader import fixture_scope
from canarygate.seed.recipe import validate_fixture_recipe
from canarygate.seed.registry import collect_fixture_ownership


def mapped_recipe(pages=2):
    recipe = fixture_recipe()
    resource = recipe['setup']['resources']['items']
    resource.update(id_field='meta.id', ownership_field='meta.owner', private_field='content.secret',
                    list_field='data.items', pagination={'next_field':'data.next', 'parameter':'page', 'max_pages':pages})
    return recipe


class NestedTarget(FixtureTarget):
    def __init__(self, *, mode='vulnerable', list_mode='normal'):
        super().__init__()
        self.mode, self.list_mode = mode, list_mode

    def handle(self, request):
        auth = request.headers.get('Authorization', '')
        actor = {'Bearer fixture-token-alice':'alice', 'Bearer fixture-token-bob':'bob'}.get(auth)
        path = request.url.path
        if actor and path == '/items':
            if request.url.query == b'page=2':
                items = [{'meta': {'id': actor + '-extra', 'owner':actor}}]
                if self.list_mode == 'peer-on-second-page' and actor == 'alice':
                    items.append({'meta': {'id': 'bob-item', 'owner': 'bob'}})
                next_page = '2' if self.list_mode == 'cycle' else None
            else:
                items = [{'meta': {'id':actor + '-item', 'owner':actor}}]
                next_page = {'missing': None, 'offscope':'3', 'url':'https://outside.invalid/x'}.get(self.list_mode, '2')
            data = {'items':items, 'next':next_page}
            if self.list_mode == 'missing': data.pop('next')
            return httpx.Response(200, json={'data':data})
        if actor and path in ('/items/alice-item','/items/bob-item'):
            owner = path.split('/')[-1].split('-')[0]
            if actor != owner and self.mode == 'secure':
                return httpx.Response(403, json={'error':'forbidden'})
            if actor != owner and self.mode == 'metadata':
                return httpx.Response(200, json={'meta':{'id':owner+'-item','owner':owner}})
            if actor != owner and self.mode == 'suspicious':
                return httpx.Response(200, json={'content': {'secret':'synthetic-bob-private-canary'}})
            note = 'synthetic-bob-private-canary' if owner == 'bob' else 'synthetic-alice-private-note'
            return httpx.Response(200, json={'meta':{'id':owner+'-item','owner':owner}, 'content':{'secret':note}})
        return super().handle(request)


def test_nested_paginated_end_to_end_confirms_and_secured_denial():
    vulnerable = run_fixture(NestedTarget(), recipe=mapped_recipe())
    assert vulnerable['verdict'] == 'CONFIRMED'
    assert vulnerable['bola_checklist']['ownership_verified']
    assert vulnerable['bola_checklist']['private_disclosure']
    assert vulnerable['constraints']['network_transport_enabled'] is False
    secure = run_fixture(NestedTarget(mode='secure'), recipe=mapped_recipe())
    assert secure['verdict'] == 'SAFE' and secure['bola_checklist']['verified_denial']
    assert run_fixture(NestedTarget(mode='metadata'), recipe=mapped_recipe())['verdict'] == 'INCONCLUSIVE'


def test_suspected_private_marker_without_identity_not_confirmed():
    result = run_fixture(NestedTarget(mode='suspicious'), recipe=mapped_recipe())
    assert result['verdict'] == 'SUSPECTED'
    assert result['bola_checklist']['ownership_verified']
    assert not result['bola_checklist']['private_disclosure']
    assert result['reason']


@pytest.mark.parametrize('mode', ['peer-on-second-page', 'cycle', 'missing', 'offscope', 'url'])
def test_incomplete_paginated_discovery_never_verifies(mode):
    result = run_fixture(NestedTarget(list_mode=mode), recipe=mapped_recipe())
    assert result['verdict'] == 'SKIPPED'
    assert result['setup']['ownership_verification'] != 'SUCCESS'
    assert result['constraints']['requests_sent'] <= 8
    assert result['constraints']['external_requests_executed'] == 0


def test_page_limit_and_budget_fail_closed():
    # A next token on the final allowed page is incomplete, not isolation proof.
    result = run_fixture(NestedTarget(), recipe=mapped_recipe(pages=1))
    assert result['verdict'] == 'SKIPPED' and result['setup']['ownership_verification'] != 'SUCCESS'
    data = fixture_scope().model_dump(mode='json')
    runner = FixtureRunner(NestedTarget().handle, budget=2, scope=type(fixture_scope()).model_validate(data))
    resource = validate_fixture_recipe(mapped_recipe()).setup.resources['items']
    try:
        result = collect_fixture_ownership(runner, resource_type='items', resource=resource,
                  accounts=('alice','bob'), tokens={'alice':'fixture-token-alice','bob':'fixture-token-bob'})
        assert result.ownership_status != 'SUCCESS' and not any(e.ownership_verified for e in result.entries)
        assert runner.requests_sent == 2
    finally:
        runner.close()


@pytest.mark.parametrize('selector', ['meta..id','meta.*','meta[0].id','meta.id.more.deep.than.eight.levels.allowed.extra', '../owner'])
def test_unsafe_selector_rejected(selector):
    recipe = mapped_recipe()
    recipe['setup']['resources']['items']['ownership_field'] = selector
    with pytest.raises(ValueError):
        validate_fixture_recipe(recipe)


def test_all_five_verdicts_and_redacted_fixture_reports_without_network(monkeypatch, tmp_path):
    def forbidden(*args, **kwargs): raise AssertionError('network connection or DNS attempted')
    with TestClient(create_app(tmp_path/'pipeline.sqlite3')) as client:
        monkeypatch.setattr(socket.socket, 'connect', forbidden)
        monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
        run = client.post('/api/scan').json()
        assert run['verdict'] == 'CONFIRMED'
        report_json = client.get('/api/reports/'+run['id']).text
        html = client.get('/api/reports/'+run['id']+'?format=html').text
        obs = client.get('/api/scan/'+run['id']+'/observations').text
        for text in (json.dumps(run), report_json, html, obs):
            assert 'fixture-token-' not in text and 'synthetic-bob-private-canary' not in text
        assert 'ownership' in html and 'disclosure' in html and 'CONFIRMED' in html
        assert run_fixture(FixtureTarget(attacker_access='deny'))['verdict'] == 'SAFE'
        assert run_fixture(FixtureTarget(attacker_access='metadata'))['verdict'] == 'INCONCLUSIVE'
        assert run_fixture(FixtureTarget(cross_list_leak=True))['verdict'] == 'SKIPPED'
        assert run_fixture(NestedTarget(mode='suspicious'), recipe=mapped_recipe())['verdict'] == 'SUSPECTED'


def test_forged_model_copy_cannot_bypass_pagination_bound():
    resource = validate_fixture_recipe(mapped_recipe()).setup.resources['items']
    bad = resource.model_copy(update={'pagination':resource.pagination.model_copy(update={'max_pages':1000})})
    runner = FixtureRunner(NestedTarget().handle)
    try:
        result = collect_fixture_ownership(runner, resource_type='items', resource=bad,
                     accounts=('alice','bob'), tokens={'alice':'fixture-token-alice','bob':'fixture-token-bob'})
        assert result.ownership_status != 'SUCCESS' and runner.requests_sent == 0
    finally:
        runner.close()


@pytest.mark.parametrize('change', ['unknown-policy', 'unverified', 'wrong-id', 'wrong-owner', 'non200'])
def test_suspicious_marker_never_bypasses_prerequisites(change):
    from dataclasses import replace
    from canarygate.oracles.read_bola import evaluate_read_bola
    target = FixtureTarget()
    runner = FixtureRunner(target.handle)
    resource = validate_fixture_recipe(fixture_recipe()).setup.resources['items']
    reg = collect_fixture_ownership(runner, resource_type='items', resource=resource,
                    accounts=('alice','bob'), tokens={'alice':'fixture-token-alice','bob':'fixture-token-bob'})
    try:
        original = runner.request('alice','GET',runner.scope.origin+'/items/bob-item',token='fixture-token-alice')
        body = {'private_note':'synthetic-bob-private-canary'}
        status = 200
        policy = 'owner-only'
        if change == 'unknown-policy': policy = 'unknown'
        if change == 'unverified': reg = replace(reg, ownership_status='FAILED')
        if change == 'wrong-id': body['id'] = 'alice-item'
        if change == 'wrong-owner': body['owner'] = 'alice'
        if change == 'non200': status = 403
        resp = httpx.Response(status, json=body, request=original.request)
        decision = evaluate_read_bola(ownership=reg, resource_type='items', resource=resource,
                   actor='alice', owner='bob', response=resp, expected_access=policy, expected_source='synthetic fixture policy')
        assert decision.verdict == 'INCONCLUSIVE' and not decision.checklist['private_disclosure']
    finally:
        runner.close()


def test_nested_pipeline_persists_redacted_observations_json_and_html(monkeypatch, tmp_path):
    import importlib
    app_module = importlib.import_module('canarygate.api.app')
    original = run_fixture
    def nested_scan(*, observation_sink):
        return original(NestedTarget(), recipe=mapped_recipe(), observation_sink=observation_sink)
    monkeypatch.setattr(app_module, 'run_fixture', nested_scan)
    with TestClient(create_app(tmp_path/'nested.sqlite3')) as client:
        result = client.post('/api/scan')
        assert result.status_code == 201
        run = result.json()
        assert run['verdict'] == 'CONFIRMED'
        responses = [result.text, client.get('/api/scan/'+run['id']).text,
                     client.get('/api/scan/'+run['id']+'/observations').text,
                     client.get('/api/reports/'+run['id']+'?include_observations=true').text,
                     client.get('/api/reports/'+run['id']+'?format=html').text,
                     client.get('/api/findings').text, client.get('/api/matrix').text]
        for text in responses:
            assert 'fixture-token-' not in text
            assert 'synthetic-bob-private-canary' not in text
            assert 'synthetic-alice-private-note' not in text
        assert 'CONFIRMED' in responses[4]


@pytest.mark.parametrize('mode', ['duplicate-across-pages', 'pagination-header', 'oversized-list'])
def test_pagination_rejects_duplicates_headers_and_item_overflow(mode):
    class BadPage(NestedTarget):
        def handle(self, request):
            if request.url.path == '/items' and request.headers.get('Authorization','').startswith('Bearer fixture-token-'):
                actor = request.headers['Authorization'].removeprefix('Bearer fixture-token-')
                if mode == 'oversized-list':
                    rows = [{'meta':{'id':f'{actor}-{i}', 'owner':actor}} for i in range(257)]
                    return httpx.Response(200, json={'data':{'items':rows, 'next':None}})
                if mode == 'pagination-header':
                    return httpx.Response(200, headers={'Link':'<https://outside.invalid>; rel="next"'},
                                          json={'data':{'items':[{'meta':{'id':actor+'-item','owner':actor}}], 'next':None}})
                return httpx.Response(200, json={'data':{'items':[{'meta':{'id':actor+'-item','owner':actor}}],
                                                          'next':'2' if not request.url.query else None}})
            return super().handle(request)
    result = run_fixture(BadPage(), recipe=mapped_recipe())
    assert result['setup']['ownership_verification'] != 'SUCCESS'
    assert result['verdict'] == 'SKIPPED' and result['constraints']['external_requests_executed'] == 0


def test_nested_secret_material_never_appears_in_fixture_outputs_or_storage(monkeypatch, tmp_path, caplog):
    import importlib
    app_module = importlib.import_module('canarygate.api.app')
    secrets = ('OTHER_SECRET_7f42', 'COOKIE_SECRET_4aa2', 'fixture-token-alice', 'fixture-token-bob',
               'synthetic-bob-private-canary', 'synthetic-alice-private-note')
    class SecretTarget(NestedTarget):
        def handle(self, request):
            response = super().handle(request)
            if request.url.path.startswith('/items') and response.status_code == 200:
                body = response.json()
                if isinstance(body, dict):
                    body['debug'] = {'password': secrets[0], 'raw': secrets[0]}
                    return httpx.Response(200, json=body, headers={'Set-Cookie':'session='+secrets[1]})
            return response
    def nested_scan(*, observation_sink):
        return run_fixture(SecretTarget(), recipe=mapped_recipe(), observation_sink=observation_sink)
    monkeypatch.setattr(app_module, 'run_fixture', nested_scan)
    db = tmp_path/'redaction.sqlite3'
    with TestClient(create_app(db)) as client:
        response = client.post('/api/scan')
        assert response.status_code == 201 and response.json()['verdict'] == 'CONFIRMED'
        run_id = response.json()['id']
        paths = [f'/api/scan/{run_id}', f'/api/scan/{run_id}/observations', f'/api/reports/{run_id}',
                 f'/api/reports/{run_id}?include_observations=true', f'/api/reports/{run_id}?format=html',
                 '/api/findings', '/api/matrix', '/api/setup/status']
        rendered = [response.text] + [client.get(path).text for path in paths]
        for text in rendered + [caplog.text]:
            assert not any(secret in text for secret in secrets)
    raw_db = db.read_bytes()
    assert all(secret.encode() not in raw_db for secret in secrets)


def test_wrapped_list_without_explicit_completeness_cannot_verify():
    recipe = mapped_recipe()
    del recipe['setup']['resources']['items']['pagination']
    with pytest.raises(ValueError):
        validate_fixture_recipe(recipe)


def test_conflicting_has_more_metadata_cannot_verify():
    class Conflicting(NestedTarget):
        def handle(self, request):
            if request.url.path == '/items' and request.headers.get('Authorization','').startswith('Bearer fixture-token-'):
                actor = request.headers['Authorization'].removeprefix('Bearer fixture-token-')
                return httpx.Response(200, json={'data':{'items':[{'meta':{'id':actor+'-item','owner':actor}}],
                                                       'next':None, 'has_more':True}})
            return super().handle(request)
    result = run_fixture(Conflicting(), recipe=mapped_recipe())
    assert result['verdict'] == 'SKIPPED'
    assert result['setup']['ownership_verification'] != 'SUCCESS'


@pytest.mark.parametrize('continuation,expected', [(None,'SUCCESS'), ('5','FAILED')])
def test_four_page_hard_cap_and_scoped_queries(continuation, expected):
    scope_data = fixture_scope().model_dump(mode='json')
    for number in (3, 4, 5):
        scope_data['operations'].append({'method':'GET','path':'/items','query':f'page={number}','classification':'READ_ONLY'})
    calls = []
    target = NestedTarget()
    def handler(request):
        calls.append((request.url.path, request.url.query))
        if request.url.path == '/items':
            actor = request.headers['Authorization'].removeprefix('Bearer fixture-token-')
            page = int(request.url.params.get('page', '1'))
            token = str(page + 1) if page < 4 else continuation
            identifier = actor+'-item' if page == 1 else f'{actor}-extra-{page}'
            return httpx.Response(200, json={'data':{'items':[{'meta':{'id':identifier,'owner':actor}}], 'next':token}})
        return target.handle(request)
    runner = FixtureRunner(handler, scope=type(fixture_scope()).model_validate(scope_data))
    try:
        resource = validate_fixture_recipe(mapped_recipe(pages=4)).setup.resources['items']
        result = collect_fixture_ownership(runner, resource_type='items', resource=resource,
                      accounts=('alice','bob'), tokens={'alice':'fixture-token-alice','bob':'fixture-token-bob'})
        if expected == 'SUCCESS':
            assert result.ownership_status == 'SUCCESS'
        else:
            assert result.ownership_status != 'SUCCESS'
        assert not any(query == b'page=5' for _,query in calls)
        assert runner.requests_sent <= 10
    finally:
        runner.close()


@pytest.mark.parametrize('mode,list_mode,expected', [
    ('vulnerable','normal','CONFIRMED'), ('suspicious','normal','SUSPECTED'),
    ('secure','normal','SAFE'), ('metadata','normal','INCONCLUSIVE'),
    ('vulnerable','peer-on-second-page','SKIPPED'),
])
def test_all_verdicts_persist_in_nested_fixture_reports(monkeypatch, tmp_path, mode, list_mode, expected):
    import importlib
    app_module = importlib.import_module('canarygate.api.app')
    monkeypatch.setattr(app_module, 'run_fixture', lambda *, observation_sink: run_fixture(
        NestedTarget(mode=mode, list_mode=list_mode), recipe=mapped_recipe(), observation_sink=observation_sink))
    with TestClient(create_app(tmp_path/f'{expected}.sqlite3')) as client:
        result = client.post('/api/scan')
        assert result.status_code == 201
        run = result.json()
        assert run['verdict'] == expected and run['reason'] and run['bola_checklist']
        report = client.get('/api/reports/'+run['id']).json()
        html = client.get('/api/reports/'+run['id']+'?format=html').text
        assert report['verdict'] == expected and report['bola_checklist'] == run['bola_checklist']
        assert expected in html
