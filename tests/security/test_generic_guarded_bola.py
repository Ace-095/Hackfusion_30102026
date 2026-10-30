"""Generic guarded-runner/oracle contract: fake HTTP/TLS/socket only, no real network."""
import json
import socket
from dataclasses import replace

import httpx
import pytest

from canarygate.network import guarded_httpx
from canarygate.scope.authorized import load_authorized_scope
from canarygate.seed.recipe import Resource

SCOPE = '''
mode: competition
scheme: https
hostname: mock.invalid
port: 443
organizer_ip: 192.0.2.7
written_authorization_reference: synthetic-test-only
allowed_methods: [GET]
request_budget: 12
accounts:
 - {account: account-a, role: user}
 - {account: account-b, role: user}
operations:
 - {method: GET, path: /profile, classification: READ_ONLY}
 - {method: GET, path: /records, classification: READ_ONLY}
 - {method: GET, path: /records/ra, classification: READ_ONLY}
 - {method: GET, path: /records/rb, classification: READ_ONLY}
'''


@pytest.fixture
def environment(monkeypatch):
    events=[]
    behavior={'mode':'vulnerable', 'profile':'ok', 'lists':'ok', 'baselines':'ok'}
    monkeypatch.setattr(guarded_httpx, '_network_execution_enabled', lambda: True)
    def dns(*args,**kwargs): pytest.fail('DNS attempted')
    monkeypatch.setattr(socket, 'getaddrinfo', dns)
    monkeypatch.setattr(socket, 'gethostbyname', dns)
    class FakeSocket:
        def settimeout(self, timeout): pass
        def connect(self, address): events.append(('fake-connect',address))
        def do_handshake(self): pass
        def shutdown(self,*args): pass
        def close(self): pass
    class FakeTLS:
        keylog_filename=None
        def wrap_socket(self, sock, **kwargs): return sock
    class Reply:
        def __init__(self,status,body, headers=None): self.status=status; self.body=json.dumps(body).encode(); self.headers=headers or {}
        def read(self,limit): return self.body[:limit]
        def getheader(self,name,default=None): return self.headers.get(name.lower(),default)
    class FakeHTTP:
        def __init__(self): self.sock=None; self.request_data=None
        def request(self, method, path, *, headers, body=None):
            actor={'Bearer temporary-a':'account-a','Bearer temporary-b':'account-b'}.get(headers.get('Authorization'))
            self.request_data=(method,path,actor); events.append(('request',method,path,actor))
        def getresponse(self):
            _,path,actor=self.request_data
            if path == '/profile':
                if behavior['profile']=='nan':
                    reply=Reply(200, {}); reply.body=b'{\"identity\":\"account-a\",\"value\":NaN}'; return reply
                return Reply(200, {'identity': 'account-a' if behavior['profile']=='mismatch' else actor})
            if path == '/records':
                if behavior['lists']=='ambiguous': return Reply(200, {'records':[]})
                rid={'account-a':'ra','account-b':'rb'}[actor]
                if behavior['lists']=='paginated':
                    return Reply(200, {'records':[{'id':rid,'owner':actor}], 'next':'2'})
                if behavior['lists']=='header':
                    return Reply(200, [{'id':rid,'owner':actor}], {'link':'sensitive-pagination-link'})
                return Reply(200, [{'id':rid,'owner':actor}])
            owner={'/records/ra':'account-a','/records/rb':'account-b'}[path]
            rid={'account-a':'ra','account-b':'rb'}[owner]
            if actor == owner and behavior['baselines']=='unknown-owner':
                return Reply(200, {'id':rid,'confidential':{'value':'owner-private-B'}})
            if actor != owner:
                if behavior['mode']=='denied': return Reply(403, {'error':'forbidden'})
                if behavior['mode']=='malformed-denial': return Reply(403, {'error':'forbidden','secret':'owner-private-B'})
                if behavior['mode']=='missing': return Reply(200, {'id':rid,'owner':owner})
            return Reply(200, {'id':rid,'owner':owner,'confidential':{'value':'owner-private-A' if owner=='account-a' else 'owner-private-B'}})
        def close(self): pass
    monkeypatch.setattr(socket,'socket',lambda *args: FakeSocket())
    monkeypatch.setattr(guarded_httpx.ssl,'create_default_context',lambda: FakeTLS())
    monkeypatch.setattr(guarded_httpx.http.client,'HTTPConnection',lambda *args,**kwargs: FakeHTTP())
    runner=guarded_httpx.GuardedHTTPXRunner(load_authorized_scope(SCOPE), {'account-a':'temporary-a','account-b':'temporary-b'})
    resource=Resource.model_validate({'discovery':{'method':'GET','path':'/records'},
       'detail':{'method':'GET','path':'/records/{id}'},'id_field':'id','ownership_field':'owner',
       'ownership_model':'private','private_field':'confidential.value'})
    yield runner,resource,behavior,events
    runner.close()


def collect(environment, resource=None):
    from canarygate.seed.registry import collect_guarded_ownership
    runner,original,_,_=environment
    return collect_guarded_ownership(runner, resource_type='records', resource=resource or original,
             accounts=('account-a','account-b'), profile_path='/profile', identity_field='identity')


def evaluate(environment, ownership, response, resource=None, **kwargs):
    from canarygate.oracles.read_bola import evaluate_read_bola
    runner,original,_,_=environment
    args=dict(ownership=ownership, resource_type='records', resource=resource or original,
              actor='account-a', owner='account-b', response=response, expected_access='owner-only',
              expected_source='synthetic fixture policy')
    args.update(kwargs)
    return evaluate_read_bola(**args)


@pytest.mark.parametrize('mode,verdict', [('vulnerable','CONFIRMED'),('denied','SAFE'),
                                            ('missing','INCONCLUSIVE'),('malformed-denial','INCONCLUSIVE')])
def test_generic_guarded_runner_feeds_same_oracle(environment,mode,verdict,monkeypatch):
    import canarygate.oracles.read_bola as oracle
    runner,resource,behavior,events=environment
    behavior['mode']=mode
    ownership=collect(environment)
    assert ownership.ownership_status=='SUCCESS'
    response=runner.get('account-a','/records/rb')
    seen=[]; original=oracle.evaluate_read_bola
    def spy(**kw):
        result=original(**kw); seen.append(result); return result
    monkeypatch.setattr(oracle,'evaluate_read_bola',spy)
    result=evaluate(environment,ownership,response)
    assert seen==[result] and result.verdict==verdict and result.verdict_reason
    assert result.checklist['ownership_verified'] and result.checklist['owner_baseline']
    assert result.checklist['private_disclosure'] is (verdict=='CONFIRMED')
    assert result.checklist['verified_denial'] is (verdict=='SAFE')
    assert len([e for e in events if e[0]=='request'])==7  # profiles, lists, owner reads, cross read
    assert 'owner-private-B' not in repr(result)+repr(ownership)


def test_missing_unverified_or_shared_evidence_cannot_confirm_or_be_safe(environment):
    runner,resource,behavior,events=environment
    ownership=collect(environment)
    response=runner.get('account-a','/records/rb')
    assert evaluate(environment,ownership,None).verdict=='INCONCLUSIVE'
    assert evaluate(environment,replace(ownership,baselines={}),response).verdict=='INCONCLUSIVE'
    assert evaluate(environment,replace(ownership,ownership_status='FAILED'),response).verdict=='INCONCLUSIVE'
    assert evaluate(environment,ownership,response,expected_access='unknown').verdict=='INCONCLUSIVE'
    for model in ('shared','public'):
        changed=resource.model_copy(update={'ownership_model':model})
        assert evaluate(environment,ownership,response,resource=changed).verdict=='INCONCLUSIVE'
    assert evaluate(environment,ownership,response,owner='nobody').verdict=='INCONCLUSIVE'


def test_profile_mismatch_and_ambiguous_list_cannot_verify(environment):
    runner,_,behavior,events=environment
    behavior['profile']='mismatch'
    assert collect(environment).ownership_status != 'SUCCESS'
    assert [e[2] for e in events if e[0]=='request']==['/profile','/profile']


def test_generic_response_attestation_rejects_forged_and_mutated_responses(environment):
    runner,_,_,_=environment
    ownership=collect(environment)
    genuine=runner.get('account-a','/records/rb')
    forged=httpx.Response(genuine.status_code,content=genuine.content,request=genuine.request)
    assert evaluate(environment,ownership,forged).verdict=='INCONCLUSIVE'
    genuine._content=b'{"error":"forbidden"}'
    genuine.status_code=403
    assert evaluate(environment,ownership,genuine).verdict=='INCONCLUSIVE'


def test_fixture_and_generic_oracle_use_same_public_entry_point(environment,monkeypatch):
    import canarygate.oracles.read_bola as oracle
    from canarygate.offline.scan import run_fixture
    calls=[]; original=oracle.evaluate_read_bola
    def spy(**kw):
        result=original(**kw); calls.append(result.verdict); return result
    monkeypatch.setattr(oracle,'evaluate_read_bola',spy)
    assert run_fixture()['verdict']=='CONFIRMED'
    ownership=collect(environment)
    response=environment[0].get('account-a','/records/rb')
    assert evaluate(environment,ownership,response).verdict=='CONFIRMED'
    assert calls[-1]=='CONFIRMED' and calls.count('CONFIRMED')>=2


def test_generic_oracle_rejects_caller_constructed_registry_and_changed_entries(environment):
    from canarygate.seed.registry import FixtureOwnershipResult
    runner,_,_,_=environment
    ownership=collect(environment)
    response=runner.get('account-a','/records/rb')
    forged=FixtureOwnershipResult(entries=ownership.entries, resource_status='SUCCESS', ownership_status='SUCCESS',
            ids=dict(ownership.ids), baselines=dict(ownership.baselines), source_runner=runner,
            identity_accounts=('account-a','account-b'))
    assert evaluate(environment,forged,response).verdict=='INCONCLUSIVE'
    ownership.entries[0].origin='supplied'  # frozen dataclass does not freeze nested models
    assert evaluate(environment,ownership,response).verdict=='INCONCLUSIVE'


def test_halted_runner_and_invalid_actor_fail_closed_without_crash(environment):
    runner,_,_,_=environment
    ownership=collect(environment)
    response=runner.get('account-a','/records/rb')
    assert evaluate(environment,ownership,response,owner=[]).verdict=='INCONCLUSIVE'
    runner.halt()
    assert evaluate(environment,ownership,response).verdict=='INCONCLUSIVE'


def test_hidden_pagination_header_cannot_prove_list_completeness(environment):
    runner,_,behavior,events=environment
    behavior['lists']='header'
    ownership=collect(environment)
    assert ownership.ownership_status!='SUCCESS'
    assert [e[2] for e in events if e[0]=='request']==['/profile','/profile','/records']
    assert 'sensitive-pagination-link' not in repr(ownership)


def test_generic_pagination_limit_fails_closed_without_unscoped_second_page(environment):
    runner,resource,behavior,events=environment
    behavior['lists']='paginated'
    resource=Resource.model_validate({**resource.model_dump(), 'list_field':'records','pagination':{'next_field':'next','parameter':'page','max_pages':1}})
    result=collect(environment, resource)
    assert result.ownership_status!='SUCCESS'
    assert not any(e[2].startswith('/records?') for e in events if e[0]=='request')


def test_unknown_owner_baseline_and_ambiguous_list_fail_closed(environment):
    runner,_,behavior,events=environment
    behavior['baselines']='unknown-owner'
    result=collect(environment)
    assert result.ownership_status != 'SUCCESS'
    assert not any(e.ownership_verified for e in result.entries)
    assert not any(e[2] == '/records/rb' and e[3] == 'account-a' for e in events if e[0]=='request')


def test_nonfinite_profile_is_not_identity_evidence(environment):
    _,_,behavior,events=environment
    behavior['profile']='nan'
    result=collect(environment)
    assert result.ownership_status!='SUCCESS'
    assert [e[2] for e in events if e[0]=='request']==['/profile']


def test_guard_blocked_discovery_never_reaches_mock_transport(environment):
    _,resource,_,events=environment
    changed=Resource.model_validate({**resource.model_dump(), 'discovery':{'method':'GET','path':'/not-in-scope'}})
    result=collect(environment, changed)
    assert result.ownership_status!='SUCCESS'
    assert [e[2] for e in events if e[0]=='request']==['/profile','/profile']


def test_guarded_ownership_evidence_is_bound_to_the_collected_recipe(environment):
    runner,resource,_,_=environment
    ownership=collect(environment)
    response=runner.get('account-a','/records/rb')
    changed=resource.model_copy(update={'known_owner_canary':'owner-private-B'})
    assert evaluate(environment,ownership,response,resource=changed).verdict=='INCONCLUSIVE'
