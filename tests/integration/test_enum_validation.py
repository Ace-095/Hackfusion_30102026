"""Test-first cases for one explicitly scoped synthetic enum probe."""
from importlib.resources import files
import socket

import httpx
import pytest
from fastapi.testclient import TestClient

from canarygate.api.app import create_app
from canarygate.database.store import FixtureStore
from canarygate.offline.scan import _summary, inventory, run_fixture
from canarygate.offline.target import FixtureTarget


class EnumFixture(FixtureTarget):
    def __init__(self, behavior="strict", **kwargs):
        super().__init__(**kwargs)
        self.behavior = behavior
        self.requests = []

    def handle(self, request):
        self.requests.append(request)
        if request.url.path == "/search" and request.url.query == b"limit=9":
            if self.behavior == "accept":
                return httpx.Response(200, json={"results": []})
            if self.behavior == "ambiguous":
                return httpx.Response(400, json={"error": "invalid value"})
            if self.behavior == "redirect":
                return httpx.Response(302, headers={"Location": "https://outside.invalid"})
            if self.behavior == "oversized":
                return httpx.Response(400, content=b'x' * 65537)
            if self.behavior == "lockout":
                return httpx.Response(423, json={'error': 'account locked'})
            if self.behavior == "traceback":
                return httpx.Response(400, json={"error": "Traceback (most recent call last): invalid limit"})
            return httpx.Response(400, json={"error": "Invalid limit"})
        return super().handle(request)


def checks(run):
    return {item['id']: item for item in run['checks']}


@pytest.mark.parametrize('behavior,expected,status', [
    ('strict', 'SAFE', 400), ('accept', 'SUSPECTED', 200),
    ('ambiguous', 'INCONCLUSIVE', 400), ('redirect', 'INCONCLUSIVE', 302),
    ('oversized', 'INCONCLUSIVE', None),
])
def test_enum_result_uses_actual_response_and_stays_offline(behavior, expected, status, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('unexpected network or DNS')
    monkeypatch.setattr(socket.socket, 'connect', forbidden)
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
    target = EnumFixture(behavior)
    result = run_fixture(target)
    item = checks(result)['INPUT-03']
    assert item['verdict'] == expected
    assert result['constraints']['network_transport_enabled'] is False
    assert result['constraints']['redirects_followed'] == 0
    assert result['constraints']['requests_sent'] == 16
    sent = [request for request in target.requests if request.url.query == b'limit=9']
    assert len(sent) == 1 and sent[0].method == 'GET' and sent[0].url.path == '/search'
    assert sent[0].headers['Authorization'] == 'Bearer fixture-token-alice'
    if status is None:
        assert item['evidence'] is None
    else:
        assert item['evidence']['status_code'] == status
        assert item['evidence']['checklist']['input_case'] == 'invalid_enum_limit'
        assert item['evidence']['checklist']['valid_control_observed'] is True
    assert 'fixture-token-alice' not in str(result)


def test_enum_probe_is_skipped_if_schema_or_control_is_missing():
    from canarygate.offline.input_checks import run_input_checks
    from canarygate.offline.runner import FixtureRunner
    endpoints = inventory()
    search = next(ep for ep in endpoints if ep['path'] == '/search' and ep['method'] == 'GET')
    search['parameters'][0]['schema'].pop('enum', None)
    calls = []
    fixture = EnumFixture()
    runner = FixtureRunner(lambda request: calls.append(request) or fixture.handle(request))
    spec = files('canarygate.offline').joinpath('fixture.yaml').read_text(encoding='utf-8')
    try:
        result = {item['id']: item for item in run_input_checks(
            runner, actor='alice', role='user', token='fixture-token-alice',
            endpoints=endpoints, summary=_summary, spec_text=spec)}
        assert result['INPUT-03']['verdict'] == 'SKIPPED'
        assert all(req.url.query != b'limit=9' for req in calls)
        assert result['DISC-01']['verdict'] == 'SAFE'  # Four applicable responses inspected.
    finally:
        runner.close()
    calls = []
    runner = FixtureRunner(lambda req: calls.append(req) or httpx.Response(400, json={'error': 'Invalid limit'}))
    try:
        result = {item['id']: item for item in run_input_checks(
            runner, actor='alice', role='user', token='fixture-token-alice',
            endpoints=inventory(), summary=_summary, spec_text=spec)}
        assert result['INPUT-03']['verdict'] == 'SKIPPED'
        assert len(calls) == 1 and calls[0].url.query == b'limit=1'
    finally:
        runner.close()


def test_scope_and_budget_block_enum_before_transport_and_do_not_claim_full_coverage():
    from canarygate.offline.input_checks import run_input_checks
    from canarygate.offline.runner import FixtureRunner
    from canarygate.scope.loader import FixtureScope, fixture_scope
    data = fixture_scope().model_dump(mode='json')
    data['operations'] = [op for op in data['operations'] if op.get('query') != 'limit=9']
    calls = []
    target = EnumFixture()
    runner = FixtureRunner(lambda request: calls.append(request) or target.handle(request), scope=FixtureScope.model_validate(data))
    try:
        result = {item['id']: item for item in run_input_checks(
            runner, actor='alice', role='user', token='fixture-token-alice', endpoints=inventory(), summary=_summary)}
        assert result['INPUT-03']['verdict'] == 'SKIPPED'
        assert all(request.url.query != b'limit=9' for request in calls)
        assert result['DISC-01']['verdict'] == 'INCONCLUSIVE'
    finally:
        runner.close()
    calls = []
    runner = FixtureRunner(lambda request: calls.append(request) or target.handle(request), budget=4)
    try:
        result = {item['id']: item for item in run_input_checks(
            runner, actor='alice', role='user', token='fixture-token-alice', endpoints=inventory(), summary=_summary)}
        assert result['INPUT-03']['verdict'] == 'SKIPPED'
        assert len(calls) == 4 and all(request.url.query != b'limit=9' for request in calls)
        assert result['DISC-01']['verdict'] == 'INCONCLUSIVE'
    finally:
        runner.close()


def test_enum_response_is_also_inspected_for_disclosure():
    result = checks(run_fixture(EnumFixture('traceback')))
    assert result['INPUT-03']['verdict'] == 'INCONCLUSIVE'
    assert result['DISC-01']['verdict'] == 'CONFIRMED'
    assert result['DISC-01']['evidence']['checklist']['input_case'] == 'invalid_enum_limit'
    assert 'Traceback (most recent call last)' not in str(result)


def test_enum_evidence_and_five_response_coverage_survive_persistence(tmp_path):
    db = tmp_path / 'fixture.sqlite3'
    store = FixtureStore(db)
    store.initialize()
    run = store.save(run_fixture(EnumFixture()))
    with TestClient(create_app(db)) as client:
        restored = client.get(f'/api/scan/{run["id"]}').json()
        found = checks(restored)
        assert found['INPUT-03']['verdict'] == 'SAFE'
        assert found['INPUT-03']['evidence']['checklist']['input_case'] == 'invalid_enum_limit'
        assert found['DISC-03']['evidence']['checklist']['inspected_fixture_responses'] == 5
        html = client.get(f'/api/reports/{run["id"]}?format=html').text
        assert 'INPUT-03' in html and 'fixture-token-alice' not in html
    assert b'fixture-token-alice' not in db.read_bytes()


def test_fixture_target_accepts_declared_enum_values_and_rejects_invalid_values():
    spec = inventory()
    search = next(ep for ep in spec if ep['path'] == '/search' and ep['method'] == 'GET')
    choices = search['parameters'][0]['schema']['enum']
    assert choices == [1, 2, 3]
    target = FixtureTarget()
    headers = {'Authorization': 'Bearer fixture-token-alice'}
    # Exercise the in-process handler directly: these are not outbound requests
    # and the runner still blocks the unscoped 2/3 query variants.
    for value in choices:
        response = target.handle(httpx.Request('GET', f'https://fixture.invalid/search?limit={value}', headers=headers))
        assert response.status_code == 200
    for value in (9, 999):
        response = target.handle(httpx.Request('GET', f'https://fixture.invalid/search?limit={value}', headers=headers))
        assert response.status_code == 400


@pytest.mark.parametrize('change', [
    {'enum': [True, 2, 3]}, {'enum': [1, 9]}, {'enum': [2, 3]},
    {'enum': []}, {'enum': '1,2,3'}, {'minimum': True},
])
def test_ambiguous_or_inapplicable_enum_is_skipped_without_probe(change):
    from canarygate.offline.input_checks import run_input_checks
    from canarygate.offline.runner import FixtureRunner
    endpoints = inventory()
    search = next(ep for ep in endpoints if ep['path'] == '/search' and ep['method'] == 'GET')
    search['parameters'][0]['schema'].update(change)
    calls = []
    target = EnumFixture()
    runner = FixtureRunner(lambda request: calls.append(request) or target.handle(request))
    try:
        found = {item['id']: item for item in run_input_checks(
            runner, actor='alice', role='user', token='fixture-token-alice', endpoints=endpoints, summary=_summary)}
        assert found['INPUT-03']['verdict'] == 'SKIPPED'
        assert all(req.url.query != b'limit=9' for req in calls)
    finally:
        runner.close()


def test_lockout_on_enum_probe_halts_later_enumeration_and_is_inconclusive():
    target = EnumFixture('lockout')
    run = run_fixture(target)
    found = checks(run)
    assert found['INPUT-03']['verdict'] == 'INCONCLUSIVE'
    assert found['DISC-01']['verdict'] == 'INCONCLUSIVE'
    assert found['DISC-06']['verdict'] == 'SKIPPED'
    assert run['constraints']['halted_reason'] == 'account lockout or rate limit'
    assert run['constraints']['requests_sent'] == 15
    assert all(request.url.path != '/items/nonexistent-item' for request in target.requests)
