"""Fixture persistence/export redaction; no real network or live credentials."""
import importlib
import json
import socket

import httpx
from fastapi.testclient import TestClient

from canarygate.offline.scan import run_fixture
from canarygate.offline.target import FixtureTarget


def test_nested_headers_cookies_tokens_errors_and_debug_do_not_reach_outputs_or_sqlite(monkeypatch,tmp_path,caplog):
    secrets=('nested-access-908','nested-refresh-127','nested-password-461','nested-api-key-753',
             'header-cookie-317','debug-header-619','debug-error-853','synthetic-bob-private-canary',
             'fixture-token-alice','fixture-token-bob')
    class Target(FixtureTarget):
        def handle(self,request):
            response=super().handle(request)
            if request.url.path in ('/items/alice-item','/items/bob-item') and response.status_code==200:
                body=response.json()
                body['nested']=[{'accessToken':secrets[0], 'next':[{'refresh_token':secrets[1]},
                    {'passwordHash':secrets[2]}, {'X-Api-Key':secrets[3]}]}]
                body['debug_error']='Authorization: Bearer '+secrets[6]
                response=httpx.Response(200,json=body,headers={'Set-Cookie':'sid='+secrets[4], 'X-Debug-Info':secrets[5]})
            if request.url.path=='/search':
                response.headers['X-Debug-Info']=secrets[5]
            return response
    app=importlib.import_module('canarygate.api.app')
    monkeypatch.setattr(app,'run_fixture',lambda *,observation_sink:run_fixture(Target(),observation_sink=observation_sink))
    db=tmp_path/'redaction.sqlite3'
    with TestClient(app.create_app(db)) as client:
        def forbidden(*args, **kwargs): raise AssertionError('external networking attempted')
        monkeypatch.setattr(socket.socket,'connect',forbidden)
        monkeypatch.setattr(socket,'getaddrinfo',forbidden)
        run=client.post('/api/scan').json()
        assert run['verdict']=='CONFIRMED' and run['bola_checklist']['private_disclosure'] is True
        assert run['evidence']['ownership']['status_code']==200 and run['evidence']['disclosure']['status_code']==200
        assert any(c['id']=='DISC-05' and c['verdict']=='CONFIRMED' for c in run['checks'])
        outputs=[json.dumps(run),client.get('/api/reports/'+run['id']+'?view=sections').text,
                 client.get('/api/reports/'+run['id']+'?format=html').text,
                 client.get('/api/scan/'+run['id']+'/observations').text,caplog.text]
    raw=db.read_bytes()
    for secret in secrets:
        assert all(secret not in text for text in outputs)
        assert secret.encode() not in raw
    assert 'private_disclosure' in outputs[1] and 'ownership_verified' in outputs[2]
