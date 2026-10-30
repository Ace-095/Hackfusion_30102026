"""End-to-end offline scenario scan: API, persistence, reports, adversarial no-bypass."""
import json
import socket

import httpx
import pytest
from fastapi.testclient import TestClient

from canarygate.api.app import create_app
from canarygate.scan import scenarios
from canarygate.scan.generic import run_generic_scan
from canarygate.scan.offline import OfflineGuardedRunner
from canarygate.scan.transcript import OfflineTranscript, TranscriptEntry


def client(path):
    return TestClient(create_app(path))


def start(client, scenario_id):
    response = client.post('/api/scenario-scans', json={'scenario_id': scenario_id})
    assert response.status_code == 201, response.text
    return response.json()


def no_network(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('network or DNS attempted by an offline scan')
    monkeypatch.setattr(socket.socket, 'connect', forbidden)
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)


@pytest.mark.parametrize('scenario_id,verdict', [
    ('synthetic-vulnerable', 'CONFIRMED'),
    ('synthetic-secure', 'SAFE'),
    ('synthetic-metadata', 'INCONCLUSIVE'),
    ('synthetic-leaky-denial', 'INCONCLUSIVE'),
    ('synthetic-pagination-limit', 'SKIPPED'),
    ('synthetic-guard-block', 'SKIPPED'),
])
def test_scenario_verdicts_survive_the_application(monkeypatch, tmp_path, scenario_id, verdict):
    no_network(monkeypatch)
    with client(tmp_path / 'scenario.sqlite3') as api:
        run = start(api, scenario_id)
        stored = api.get('/api/scenario-scans/' + run['id'])
        assert stored.status_code == 200 and stored.json() == run
        assert run['verdict'] == verdict and run['mode'] == 'offline_scenario'
        assert run['transport'] == 'offline_transcript' and run['network_transport_enabled'] is False
        assert run['constraints']['network_transport_enabled'] is False
        assert run['constraints']['external_requests_executed'] == 0
        assert run['constraints']['destructive_requests_executed'] == 0
        assert set(run['checklist']) == {
            'private_resource', 'distinct_accounts', 'ownership_verified', 'owner_baseline',
            'private_baseline', 'attacker_request', 'response_checked', 'private_disclosure',
            'policy_denies_access', 'verified_denial'}
        assert all(type(value) is bool for value in run['checklist'].values())
        if verdict == 'CONFIRMED':
            assert all(value for key, value in run['checklist'].items() if key != 'verified_denial')
            assert run['checklist']['verified_denial'] is False
            assert run['setup']['ownership_verification'] == 'SUCCESS'
            assert run['evidence']['ownership']['status_code'] == 200
            assert run['evidence']['disclosure']['status_code'] == 200
            assert run['evidence']['ownership']['checklist']['both_owner_baselines'] is True
            assert run['evidence']['ownership']['checklist']['cross_list_isolation'] is True
            assert run['evidence']['disclosure']['checklist']['private_disclosure'] is True
            assert run['constraints']['requests_sent'] == 7
            assert run['remediation']
        elif verdict == 'SAFE':
            assert run['checklist']['verified_denial'] is True
            assert run['checklist']['private_disclosure'] is False
            assert run['evidence']['disclosure']['status_code'] == 403
        elif scenario_id in ('synthetic-metadata', 'synthetic-leaky-denial'):
            assert run['checklist']['response_checked'] is True
            assert run['checklist']['private_disclosure'] is False
            assert run['checklist']['verified_denial'] is False
            assert run['evidence']['disclosure'] is not None
        elif scenario_id == 'synthetic-pagination-limit':
            assert run['setup']['ownership_verification'] != 'SUCCESS'
            assert run['constraints']['requests_sent'] <= 3
        elif scenario_id == 'synthetic-guard-block':
            assert run['setup']['ownership_verification'] == 'SUCCESS'
            assert run['constraints']['blocked_by_guard'] >= 1
            assert run['evidence']['disclosure'] is None
        assert len(run['transcript_sha256']) == 64
        text = json.dumps(run)
        for secret in ('synthetic-alpha-private', 'synthetic-beta-private', 'offline-token-account-a'):
            assert secret not in text
    raw = (tmp_path / 'scenario.sqlite3').read_bytes()
    for secret in ('synthetic-alpha-private', 'synthetic-beta-private', 'offline-token-account-a'):
        assert secret.encode() not in raw


def test_confirmed_scan_is_explained_consistently_in_both_reports(monkeypatch, tmp_path):
    no_network(monkeypatch)
    with client(tmp_path / 'report.sqlite3') as api:
        run = start(api, 'synthetic-vulnerable')
        sections_response = api.get('/api/scenario-scans/' + run['id'] + '/report?view=sections')
        assert sections_response.status_code == 200
        report = sections_response.json()
        sections = report['sections']
        assert report['mode'] == 'offline_scenario' and report['run_id'] == run['id'] == report['id']
        assert sections['executive_summary']['verdict'] == 'CONFIRMED'
        assert sections['executive_summary']['scenario_id'] == 'synthetic-vulnerable'
        assert sections['bola_evidence']['checklist'] == run['checklist']
        assert sections['bola_evidence']['ownership'] == run['evidence']['ownership']
        assert sections['bola_evidence']['disclosure'] == run['evidence']['disclosure']
        assert sections['outcome']['verdict'] == run['verdict'] and sections['outcome']['remediation'] == run['remediation']
        assert sections['scope_and_accounts']['origin'] == 'https://offline.invalid:443'
        assert sections['constraints'] == run['constraints']
        html = api.get('/api/scenario-scans/' + run['id'] + '/report?format=html')
        assert html.status_code == 200
        text = html.text
        for expected in ('CONFIRMED', 'Read-BOLA', 'ownership_verified', 'both_owner_baselines',
                         'cross_list_isolation', 'owner_baseline', 'attacker_request', 'response_checked',
                         'private_disclosure', 'account-a', 'account-b', '/records/{id}',
                         'offline scenario policy', 'offline_transcript'):
            assert expected in text, expected
        for secret in ('synthetic-beta-private', 'offline-token-account-a'):
            assert secret not in text and secret not in json.dumps(report)


def test_secure_scan_reports_checked_denial_and_skipped_scan_reports_reason(monkeypatch, tmp_path):
    no_network(monkeypatch)
    with client(tmp_path / 'outcomes.sqlite3') as api:
        safe = start(api, 'synthetic-secure')
        text = api.get('/api/scenario-scans/' + safe['id'] + '/report?format=html').text
        assert 'SAFE' in text and 'verified_denial' in text and '403' in text
        skipped = start(api, 'synthetic-pagination-limit')
        sections = api.get('/api/scenario-scans/' + skipped['id'] + '/report?view=sections').json()['sections']
        assert sections['executive_summary']['verdict'] == 'SKIPPED'
        assert sections['outcome']['reason'] and sections['outcome']['skipped_or_inconclusive'] is True
        assert sections['bola_evidence']['disclosure'] is None


def test_scenario_runs_survive_restart_and_detect_tampering(monkeypatch, tmp_path):
    no_network(monkeypatch)
    database = tmp_path / 'restart.sqlite3'
    with client(database) as api:
        run = start(api, 'synthetic-vulnerable')
    with client(database) as api:
        restored = api.get('/api/scenario-scans/' + run['id']).json()
        assert restored['verdict'] == 'CONFIRMED' and restored['evidence'] == run['evidence']
    import sqlite3
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE scenario_runs SET payload = replace(payload, 'CONFIRMED', 'SAFE')")
    with client(database) as api:
        assert api.get('/api/scenario-scans/' + run['id']).status_code == 500


@pytest.mark.parametrize('payload', [
    {'scenario_id': 'unknown-scenario'}, {'scenario_id': 'synthetic-vulnerable', 'target': 'https://evil.invalid'},
    {'scenario_id': ''}, {'scenario_id': 7},
])
def test_api_rejects_unknown_or_widened_requests(monkeypatch, tmp_path, payload):
    no_network(monkeypatch)
    with client(tmp_path / 'reject.sqlite3') as api:
        response = api.post('/api/scenario-scans', json=payload)
        assert response.status_code in (404, 422), response.text
        assert api.get('/api/scenario-scans/missing').status_code == 404


def test_safety_cannot_be_bypassed_by_direct_runner_or_plan_construction(monkeypatch, tmp_path):
    no_network(monkeypatch)
    plan = scenarios.build_scenario('synthetic-vulnerable')
    runner = OfflineGuardedRunner(plan.scope, {'account-a': 'offline-token-account-a',
                                               'account-b': 'offline-token-account-b'}, plan.transcript)
    try:
        for actor, path in [('account-a', '/records/rc'), ('account-a', '/records?x=1'),
                            ('account-a', '/records/../profile'), ('eve', '/records'),
                            ('account-a', '/records/rb#fragment')]:
            with pytest.raises(ValueError):
                runner.get(actor, path)
        assert runner.stats()['requests_sent'] == 0
        assert runner.stats()['blocked_by_guard'] == 5
        assert runner.get('account-a', '/records/ra').status_code == 200
        assert runner.stats()['requests_sent'] == 1
    finally:
        runner.close()
    with pytest.raises(ValueError):
        OfflineTranscript(entries=(TranscriptEntry(actor='account-a', method='GET', path='/records',
                                                   status=302, body={}),))
    with pytest.raises(ValueError):
        OfflineTranscript(entries=(TranscriptEntry(actor='account-a', method='GET', path='/records',
                                                   status=200, body=[]),) * 2)
    unscoped = OfflineTranscript(entries=(TranscriptEntry(actor='eve', method='GET', path='/records',
                                                          status=200, body=[]),))
    with pytest.raises(ValueError):
        OfflineGuardedRunner(plan.scope, {'account-a': 'offline-token-account-a',
                                          'account-b': 'offline-token-account-b'}, unscoped)
    with pytest.raises(ValueError):
        run_generic_scan(object(), plan)


def test_transcript_entries_must_match_scoped_operations():
    plan = scenarios.build_scenario('synthetic-vulnerable')
    bad = OfflineTranscript(entries=(TranscriptEntry(actor='account-a', method='GET', path='/not-scoped',
                                                     status=200, body={}),))
    with pytest.raises(ValueError):
        OfflineGuardedRunner(plan.scope, {'account-a': 'offline-token-account-a',
                                          'account-b': 'offline-token-account-b'}, bad)


def test_same_orchestrator_runs_over_mocked_httpx_boundary(monkeypatch, tmp_path):
    """The orchestrator is transport-agnostic; the HTTPX boundary stays disabled in production."""
    from canarygate.network import guarded_httpx
    from canarygate.scope.authorized import load_authorized_scope
    plan = scenarios.build_scenario('synthetic-vulnerable')
    bodies = {(entry.actor, entry.path): entry.body for entry in plan.transcript.entries}
    statuses = {(entry.actor, entry.path): entry.status for entry in plan.transcript.entries}
    monkeypatch.setattr(guarded_httpx, '_network_execution_enabled', lambda: True)
    def dns(*args, **kwargs):
        raise AssertionError('DNS attempted')
    monkeypatch.setattr(socket, 'getaddrinfo', dns)
    monkeypatch.setattr(socket, 'gethostbyname', dns)
    class FakeSocket:
        def settimeout(self, value): pass
        def connect(self, address): pass
        def do_handshake(self): pass
        def close(self): pass
    class FakeTLS:
        keylog_filename = None
        def wrap_socket(self, sock, **kwargs): return sock
    class Reply:
        def __init__(self, status, body): self.status = status; self.body = json.dumps(body).encode(); self.headers = {}
        def read(self, limit): return self.body[:limit]
        def getheader(self, name, default=None): return self.headers.get(name.lower(), default)
    class FakeHTTP:
        def __init__(self): self.sock = None; self.actor = self.path = None
        def request(self, method, path, *, headers, body=None):
            actor = {'Bearer offline-token-account-a': 'account-a',
                     'Bearer offline-token-account-b': 'account-b'}.get(headers.get('Authorization'))
            self.actor, self.path = actor, path
        def getresponse(self):
            return Reply(statuses[(self.actor, self.path)], bodies[(self.actor, self.path)])
        def close(self): pass
    monkeypatch.setattr(socket, 'socket', lambda *args: FakeSocket())
    monkeypatch.setattr(guarded_httpx.ssl, 'create_default_context', lambda: FakeTLS())
    monkeypatch.setattr(guarded_httpx.http.client, 'HTTPConnection', lambda *args, **kwargs: FakeHTTP())
    runner = guarded_httpx.GuardedHTTPXRunner(
        load_authorized_scope(json.dumps(plan.scope.model_dump(mode='json'))),
        {'account-a': 'offline-token-account-a', 'account-b': 'offline-token-account-b'})
    try:
        result = run_generic_scan(runner, plan)
    finally:
        runner.close()
    assert result['verdict'] == 'CONFIRMED'
    assert result['checklist']['private_disclosure'] is True
    assert result['evidence']['ownership']['status_code'] == 200
    assert result['transport'] == 'guarded_httpx_disabled'
    # Only recorded-transcript runs may be persisted by this offline workflow.
    from canarygate.database.scenario_store import ScenarioStore
    from canarygate.scan.models import ScenarioRun
    with pytest.raises(ValueError):
        ScenarioRun.model_validate(result)
    store = ScenarioStore(tmp_path / 'httpx-not-persistable.sqlite3')
    store.initialize()
    with pytest.raises(ValueError):
        store.save(result)
