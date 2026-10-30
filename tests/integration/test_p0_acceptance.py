"""Test-first P0 regression cases using only the in-process fixture."""
import importlib
import json
import socket
from html.parser import HTMLParser

import httpx
import pytest
from fastapi.testclient import TestClient

from canarygate.offline.scan import run_fixture
from canarygate.offline.target import FixtureTarget


def checks(run):
    return {check['id']: check for check in run['checks']}


@pytest.mark.parametrize('body', [b'{"private_note":"synthetic-alice-private-note"}',
                                  b'{"error":"denied","data":{"private_note":"synthetic-alice-private-note"}}',
                                  b'{bad-json', b'{"error":"denied","error":"again"}'])
def test_auth_denial_with_unchecked_or_leaking_body_is_not_safe(body):
    class Target(FixtureTarget):
        def handle(self, request):
            if request.url.path == '/items/alice-item' and request.headers.get('Authorization') != 'Bearer fixture-token-alice':
                return httpx.Response(401, content=body)
            return super().handle(request)
    run = run_fixture(Target())
    for name in ('AUTHN-01','AUTHN-02','AUTHN-03'):
        assert checks(run)[name]['verdict'] == 'INCONCLUSIVE'
        assert checks(run)[name]['evidence']['status_code'] == 401
    assert 'synthetic-alice-private-note' not in json.dumps(run)


def test_debug_header_is_detected_without_storing_value():
    class Target(FixtureTarget):
        def handle(self, request):
            response = super().handle(request)
            if request.url.path == '/search': response.headers['X-Debug-Token'] = 'debug-secret-7f42'
            return response
    result = checks(run_fixture(Target()))['DISC-05']
    assert result['verdict'] == 'CONFIRMED'
    assert result['evidence']['checklist']['disclosure_signature'] == 'debug_header'
    assert result['remediation'] and 'debug-secret-7f42' not in json.dumps(result)


def test_public_endpoint_check_is_scoped_and_not_just_http_200():
    from canarygate.offline.auth_checks import run_public_check
    from canarygate.offline.runner import FixtureRunner
    from canarygate.offline.scan import _summary
    from canarygate.scope.loader import FixtureScope, fixture_scope
    data = fixture_scope().model_dump(mode='json')
    data['operations'].append({'method':'GET','path':'/public-health','classification':'READ_ONLY','auth_probes':['missing']})
    scope = FixtureScope.model_validate(data)
    inventory = [{'method':'GET','path':'/public-health','expected_access':'public','parameters':[],
                  'security':[], 'expected_source':'openapi.operation.security'}]
    def execute(body, status=200, endpoints=inventory, scoped=scope):
        calls=[]
        runner=FixtureRunner(lambda req: calls.append(req) or httpx.Response(status,json=body),scope=scoped)
        try:
            item=run_public_check(runner, actor='alice', role='user', endpoints=endpoints, summary=_summary)
            return item,calls
        finally: runner.close()
    safe,calls=execute({'status':'ok','service':'fixture'})
    assert safe['verdict']=='SAFE' and safe['evidence']['status_code']==200
    assert len(calls)==1 and 'authorization' not in calls[0].headers
    assert execute({})[0]['verdict']=='INCONCLUSIVE'
    assert execute({'status':'ok','service':'fixture'},403)[0]['verdict']=='INCONCLUSIVE'
    no_policy,calls=execute({'status':'ok','service':'fixture'},endpoints=[])
    assert no_policy['verdict']=='SKIPPED' and not calls
    blocked,calls=execute({'status':'ok','service':'fixture'},scoped=fixture_scope())
    assert blocked['verdict']=='SKIPPED' and not calls


SECTION_KEYS = {'executive_summary','scope_accounts_seeding','endpoint_inventory','findings',
                'secured_endpoints','skipped_and_inconclusive','authorization_matrix',
                'manual_interventions_and_inferences','constraint_checklist'}


@pytest.mark.parametrize('target,expected', [
    (FixtureTarget(), 'CONFIRMED'), (FixtureTarget(attacker_access='deny'), 'SAFE'),
    (FixtureTarget(attacker_access='metadata'), 'INCONCLUSIVE'),
    (FixtureTarget(cross_list_leak=True), 'SKIPPED'),
])
def test_nine_section_html_json_consistency_and_coverage(monkeypatch,tmp_path,target,expected):
    app = importlib.import_module('canarygate.api.app')
    monkeypatch.setattr(app, 'run_fixture', lambda *, observation_sink: run_fixture(target,observation_sink=observation_sink))
    def forbidden(*args, **kwargs): raise AssertionError('external networking attempted')
    with TestClient(app.create_app(tmp_path/'results.sqlite3')) as client:
        monkeypatch.setattr(socket.socket, 'connect', forbidden)
        monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
        run=client.post('/api/scan').json()
        result=client.get(f"/api/reports/{run['id']}?view=sections")
        assert result.status_code == 200
        report=result.json()
        assert set(report['sections']) == SECTION_KEYS
        sections=report['sections']
        assert sections['executive_summary']['bola_verdict'] == expected
        assert sections['authorization_matrix']['cells'][0]['verdict'] == expected
        assert sections['authorization_matrix']['coverage'] == 'partial_fixture'
        assert sections['constraint_checklist'] == run['constraints']
        assert sections['manual_interventions_and_inferences']['status'] == 'NOT_RECORDED'
        if expected in ('CONFIRMED', 'SAFE', 'INCONCLUSIVE'):
            assert all(any(item['id'] == name and item['evidence']['checklist']['denial_body_checked'] is True
                           for item in sections['secured_endpoints'])
                       for name in ('AUTHN-01', 'AUTHN-02', 'AUTHN-03'))
        html=client.get(f"/api/reports/{run['id']}?format=html").text
        for heading in ('Executive summary','Scope and rules of engagement','Endpoint inventory',
                        'Findings and remediation','Secured endpoints that passed','Skipped and inconclusive tests',
                        'Authorization matrix','Manual interventions and inferred items','constraint checklist'):
            assert heading in html
        class SectionParser(HTMLParser):
            def __init__(self):
                super().__init__(); self.tag = None; self.heading = ''; self.buffer = ''; self.seen = {}
            def handle_starttag(self, tag, attrs):
                if tag in ('h2', 'pre'): self.tag = tag; self.buffer = ''
            def handle_data(self, data):
                if self.tag: self.buffer += data
            def handle_endtag(self, tag):
                if self.tag != tag: return
                if tag == 'h2': self.heading = self.buffer
                elif tag == 'pre':
                    try: self.seen[self.heading] = json.loads(self.buffer)
                    except ValueError: pass
                self.tag = None
        parser=SectionParser(); parser.feed(html)
        for title, key in (
            ('Executive summary','executive_summary'), ('Scope and rules of engagement, accounts and seeding','scope_accounts_seeding'),
            ('Endpoint inventory (OpenAPI authentication requirements only)','endpoint_inventory'),
            ('Findings and remediation','findings'), ('Secured endpoints that passed','secured_endpoints'),
            ('Skipped and inconclusive tests','skipped_and_inconclusive'),
            ('Authorization matrix (partial fixture coverage)','authorization_matrix'),
            ('Manual interventions and inferred items','manual_interventions_and_inferences'),
            ('Fixture constraint checklist','constraint_checklist')):
            assert parser.seen[title] == sections[key]
        assert expected in html
        if expected == 'SAFE': assert sections['secured_endpoints']
        else: assert not any(item['category']=='Authorization' for item in sections['secured_endpoints'])
        if expected in ('SKIPPED','INCONCLUSIVE'):
            assert any(item['id']=='READ-BOLA' and item['verdict']==expected and item['reason'] for item in sections['skipped_and_inconclusive'])
        for text in (result.text,html):
            assert 'fixture-token-' not in text and 'synthetic-bob-private-canary' not in text


def test_legacy_safe_verdict_without_checklist_is_not_reclassified_as_secured():
    from canarygate.report.fixture import build_fixture_sections
    run = run_fixture(FixtureTarget(attacker_access='deny'))
    run['bola_checklist'] = {}  # Historical row; evidence checklist was not recorded.
    sections = build_fixture_sections(run)
    assert not any(item['category']=='Authorization' for item in sections['secured_endpoints'])
    assert sections['authorization_matrix']['cells'][0]['verdict'] == 'SAFE'
    assert sections['authorization_matrix']['coverage'] == 'partial_fixture'


def test_auth_denial_that_contains_the_private_marker_is_not_safe_even_if_empty_json():
    from canarygate.offline.auth_checks import run_auth_checks
    from canarygate.offline.runner import FixtureRunner
    runner = FixtureRunner(lambda request: httpx.Response(401, content=b'{}'))
    try:
        result = run_auth_checks(runner, actor='alice', role='user', path='/items/alice-item',
                    token='opaque', private_field='private_note', baseline='{}',
                    summary=lambda *args, **kwargs: {'status_code':401})
        assert all(item['verdict'] != 'SAFE' for item in result[:3])
    finally:
        runner.close()


def test_debug_signal_is_retained_and_redacted_in_stored_sections(monkeypatch,tmp_path):
    app = importlib.import_module('canarygate.api.app')
    class Target(FixtureTarget):
        def handle(self,request):
            response=super().handle(request)
            if request.url.path == '/search': response.headers['X-Debug-Token']='dont-persist-this-debug-value'
            return response
    monkeypatch.setattr(app,'run_fixture',lambda *,observation_sink: run_fixture(Target(), observation_sink=observation_sink))
    with TestClient(app.create_app(tmp_path/'debug.sqlite3')) as client:
        run=client.post('/api/scan').json()
        assert checks(run)['DISC-05']['evidence']['checklist']['disclosure_signature']=='debug_header'
        sections=client.get('/api/reports/'+run['id']+'?view=sections').json()
        assert any(item['id']=='DISC-05' for item in sections['sections']['findings']['Disclosure'])
        html=client.get('/api/reports/'+run['id']+'?format=html').text
        assert 'debug_header' in html
        assert 'dont-persist-this-debug-value' not in json.dumps(sections)+html


def test_guard_budget_block_is_reported_in_both_formats_without_fabricating_a_verdict(monkeypatch,tmp_path):
    app = importlib.import_module('canarygate.api.app')
    scan = importlib.import_module('canarygate.offline.scan')
    from canarygate.offline.runner import FixtureRunner
    monkeypatch.setattr(scan, 'FixtureRunner', lambda handler: FixtureRunner(handler, budget=2))
    with TestClient(app.create_app(tmp_path/'limited.sqlite3')) as client:
        def forbidden(*args,**kwargs): raise AssertionError('external networking attempted')
        monkeypatch.setattr(socket.socket,'connect',forbidden)
        monkeypatch.setattr(socket,'getaddrinfo',forbidden)
        run=client.post('/api/scan').json()
        assert run['verdict']=='SKIPPED'
        assert run['constraints']['requests_sent']==2 and run['constraints']['blocked_by_guard'] > 0
        sections=client.get('/api/reports/'+run['id']+'?view=sections').json()['sections']
        assert sections['constraint_checklist']['blocked_by_guard'] > 0
        assert any(item['id']=='READ-BOLA' and item['reason'] for item in sections['skipped_and_inconclusive'])
        html=client.get('/api/reports/'+run['id']+'?format=html').text
        assert 'blocked_by_guard' in html and run['reason'] in html


def test_section_report_schema_is_advertised_and_incompatible_views_fail(monkeypatch,tmp_path):
    app = importlib.import_module('canarygate.api.app')
    with TestClient(app.create_app(tmp_path/'schema.sqlite3')) as client:
        schema=client.get('/openapi.json').json()
        response_schema=schema['paths']['/api/reports/{run_id}']['get']['responses']['200']['content']['application/json']['schema']
        assert any(item.get('$ref','').endswith('/FixtureSectionReport') for item in response_schema['anyOf'])
        run=client.post('/api/scan').json()
        assert client.get('/api/reports/'+run['id']+'?view=sections&include_observations=true').status_code==400


def test_auth_secure_section_requires_recorded_denial_body_check():
    from canarygate.report.fixture import build_fixture_sections
    run=run_fixture()
    auth=[c for c in run['checks'] if c['id'] in ('AUTHN-01','AUTHN-02','AUTHN-03')]
    assert all(c['evidence']['checklist'].get('denial_body_checked') is True for c in auth)
    assert all(any(item['id']==c['id'] for item in build_fixture_sections(run)['secured_endpoints']) for c in auth)
    for c in auth:
        c['evidence']['checklist'].pop('denial_body_checked')
    secured=build_fixture_sections(run)['secured_endpoints']
    assert all(not any(item['id']==c['id'] for item in secured) for c in auth)
