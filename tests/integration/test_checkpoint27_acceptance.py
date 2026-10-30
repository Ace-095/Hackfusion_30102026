"""Synthetic offline acceptance outcomes through persistence and both reports."""
import importlib
import json
import socket

import httpx
import pytest
from fastapi.testclient import TestClient

from canarygate.offline.scan import fixture_recipe, run_fixture
from canarygate.offline.target import FixtureTarget


class CrossBody(FixtureTarget):
    def handle(self,request):
        if request.url.path=='/items/bob-item' and request.headers.get('Authorization')=='Bearer fixture-token-alice':
            return httpx.Response(403,json={'error':'forbidden','detail':{'private_note':'synthetic-bob-private-canary'}})
        return super().handle(request)


class BadBaseline(FixtureTarget):
    def handle(self,request):
        if request.url.path=='/items/bob-item' and request.headers.get('Authorization')=='Bearer fixture-token-bob':
            return httpx.Response(200,content=b'{malformed')
        return super().handle(request)


class Paged(FixtureTarget):
    def handle(self,request):
        if request.url.path=='/items':
            actor={'Bearer fixture-token-alice':'alice','Bearer fixture-token-bob':'bob'}.get(request.headers.get('Authorization'))
            if actor:
                return httpx.Response(200,json={'data':[{'id':actor+'-item','owner':actor}], 'next':'2'})
        return super().handle(request)


def limit_recipe():
    recipe=fixture_recipe()
    recipe['setup']['resources']['items'].update(list_field='data',pagination={'next_field':'next','parameter':'page','max_pages':1})
    return recipe


@pytest.mark.parametrize('target,recipe,expected',[
    (FixtureTarget(),None,'CONFIRMED'),
    (FixtureTarget(attacker_access='deny'),None,'SAFE'),
    (FixtureTarget(attacker_access='metadata'),None,'INCONCLUSIVE'),
    (CrossBody(),None,'INCONCLUSIVE'),
    (BadBaseline(),None,'SKIPPED'),
    (FixtureTarget(bob_login=False),None,'SKIPPED'),
    (Paged(),limit_recipe(),'SKIPPED'),
])
def test_offline_acceptance_scenarios_persist_in_json_and_html(monkeypatch,tmp_path,target,recipe,expected):
    app=importlib.import_module('canarygate.api.app')
    monkeypatch.setattr(app,'run_fixture',lambda *,observation_sink:run_fixture(target,recipe=recipe,observation_sink=observation_sink))
    with TestClient(app.create_app(tmp_path/'acceptance.sqlite3')) as client:
        def forbidden(*args,**kwargs): raise AssertionError('network attempted')
        monkeypatch.setattr(socket.socket,'connect',forbidden)
        monkeypatch.setattr(socket,'getaddrinfo',forbidden)
        run=client.post('/api/scan').json()
        assert run['verdict']==expected and run['reason'] and run['mode']=='fixture'
        report=client.get('/api/reports/'+run['id']+'?view=sections').json()['sections']
        html=client.get('/api/reports/'+run['id']+'?format=html').text
        assert report['executive_summary']['bola_verdict']==expected and expected in html
        assert report['authorization_matrix']['cells'][0]['verdict']==expected
        assert report['constraint_checklist']['external_requests_executed']==0
        if expected=='CONFIRMED':
            assert run['evidence']['ownership'] and run['evidence']['disclosure']
            assert run['bola_checklist']['ownership_verified'] and run['bola_checklist']['private_disclosure']
            assert next(c for c in run['checks'] if c['id']=='AUTHN-01')['verdict']=='SAFE'
        if expected=='SAFE':
            assert run['bola_checklist']['verified_denial'] and report['secured_endpoints']
        if expected=='INCONCLUSIVE':
            assert not run['bola_checklist']['private_disclosure'] and not run['bola_checklist']['verified_denial']
        for output in (json.dumps(run),json.dumps(report),html):
            assert 'fixture-token-' not in output and 'synthetic-bob-private-canary' not in output
