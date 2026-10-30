"""Test-first DISC-06 scenarios; every request stays in the offline fixture."""
import hashlib
import json
import socket

import httpx
import pytest
from fastapi.testclient import TestClient

from canarygate.api.app import create_app
from canarygate.database.store import FixtureStore
from canarygate.offline.scan import run_fixture
from canarygate.offline.target import FixtureTarget


class EnumerationFixture(FixtureTarget):
    def __init__(self, behavior="uniform", **kwargs):
        super().__init__(**kwargs)
        self.behavior = behavior
        self.requests = []

    def handle(self, request):
        self.requests.append(request)
        if request.url.path == "/items/nonexistent-item":
            assert "Authorization" not in request.headers
            if self.behavior == "status":
                return httpx.Response(404, json={"error": "fixture-response-secret-should-not-leak"})
            if self.behavior == "body":
                return httpx.Response(401, json={"error": "fixture-response-secret-should-not-leak"})
            if self.behavior == "redirect":
                return httpx.Response(302, headers={"Location": "https://outside.invalid"})
            if self.behavior == "error":
                return httpx.Response(500)
            if self.behavior == "rate_limit":
                return httpx.Response(429)
            if self.behavior == "lockout":
                return httpx.Response(423)
            if self.behavior == "oversized":
                return httpx.Response(401, content=b'x' * 65537)
            return httpx.Response(401)
        return super().handle(request)


def check(run):
    return next(item for item in run["checks"] if item["id"] == "DISC-06")


@pytest.mark.parametrize("behavior,verdict,probe_status", [
    ("uniform", "SAFE", 401),
    ("status", "SUSPECTED", 404),
    ("body", "SUSPECTED", 401),
    ("redirect", "INCONCLUSIVE", 302),
    ("error", "INCONCLUSIVE", 500),
    ("rate_limit", "INCONCLUSIVE", 429),
    ("lockout", "INCONCLUSIVE", 423),
    ("oversized", "INCONCLUSIVE", None),
])
def test_known_synthetic_resource_comparison_uses_real_guarded_responses(behavior, verdict, probe_status, monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError("fixture tried to use network or DNS")
    monkeypatch.setattr(socket.socket, "connect", no_network)
    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    target = EnumerationFixture(behavior)
    run = run_fixture(target)
    result = check(run)
    assert result["verdict"] == verdict
    assert run["verdict"] == "CONFIRMED"  # Independent read-BOLA fixture remains unchanged.
    assert run["constraints"]["requests_sent"] == 16
    missing = [req for req in target.requests if req.url.path == "/items/nonexistent-item"]
    assert len(missing) == 1 and missing[0].method == "GET"
    assert "Authorization" not in missing[0].headers
    assert run["constraints"]["redirects_followed"] == 0
    assert run["constraints"]["network_transport_enabled"] is False
    if behavior in {"rate_limit", "lockout"}:
        assert run["constraints"]["halted_reason"] == "account lockout or rate limit"
    assert "fixture-response-secret-should-not-leak" not in json.dumps(run)
    if probe_status is not None:
        evidence = result["evidence"]
        assert evidence["status_code"] == probe_status
        assert evidence["checklist"]["baseline_status"] == 401
        if verdict in {"SAFE", "SUSPECTED"}:
            assert evidence["checklist"]["responses_differ"] is (verdict == "SUSPECTED")
        canonical = {key: value for key, value in evidence.items() if key not in {"sha256", "redacted"}}
        assert evidence["sha256"] == hashlib.sha256(json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def test_missing_or_accepted_denial_baseline_never_issues_enumeration_probe():
    for target in (EnumerationFixture(auth_behavior="bypass"), EnumerationFixture(auth_behavior="empty"),
                   EnumerationFixture(auth_behavior="redirect"), EnumerationFixture(bob_login=False),
                   EnumerationFixture(validation_behavior="lockout")):
        result = check(run_fixture(target))
        assert result["verdict"] == "SKIPPED"
        assert result["evidence"] is None
        assert all(req.url.path != "/items/nonexistent-item" for req in target.requests)


def test_scope_and_budget_block_before_transport():
    from canarygate.offline.enumeration import run_enumeration_check
    from canarygate.offline.runner import FixtureRunner
    from canarygate.offline.scan import _summary
    from canarygate.scope.loader import FixtureScope, fixture_scope

    data = fixture_scope().model_dump(mode="json")
    data["operations"] = [op for op in data["operations"] if op["path"] != "/items/nonexistent-item"]
    scope = FixtureScope.model_validate(data)
    calls = []
    runner = FixtureRunner(lambda req: calls.append(req) or httpx.Response(401), scope=scope)
    baseline = httpx.Response(401, request=httpx.Request("GET", scope.origin + "/items/alice-item"))
    try:
        result = run_enumeration_check(runner, actor="alice", role="user", baseline=baseline,
                                       owner_verified=True, summary=_summary)
        assert result["verdict"] == "SKIPPED" and result["evidence"] is None
        assert calls == [] and runner.requests_sent == 0
    finally:
        runner.close()


def test_enumeration_evidence_is_persisted_redacted_and_retrievable(tmp_path):
    db = tmp_path / "fixture.sqlite3"
    store = FixtureStore(db)
    store.initialize()
    result = store.save(run_fixture(EnumerationFixture("body")))
    with TestClient(create_app(db)) as client:
        restored = client.get(f"/api/scan/{result['id']}").json()
        assert check(restored)["verdict"] == "SUSPECTED"
        assert check(restored)["evidence"]["checklist"] == {"baseline_status": 401, "responses_differ": True}
        html = client.get(f"/api/reports/{result['id']}?format=html").text
        assert "DISC-06" in html and "fixture-response-secret-should-not-leak" not in html
    assert b"fixture-response-secret-should-not-leak" not in db.read_bytes()


def test_matching_responses_report_exactly_what_was_compared():
    result = check(run_fixture(EnumerationFixture("uniform")))
    assert result["verdict"] == "SAFE"
    assert "status, content-type and body" in result["reason"]


def test_budget_and_unverified_baseline_fail_closed_before_comparison():
    from canarygate.offline.enumeration import run_enumeration_check
    from canarygate.offline.runner import FixtureRunner
    from canarygate.offline.scan import _summary

    calls = []
    runner = FixtureRunner(lambda req: calls.append(req) or httpx.Response(401), budget=1)
    try:
        baseline = runner.request("alice", "GET", runner.scope.origin + "/items/alice-item", auth_probe="missing")
        result = run_enumeration_check(runner, actor="alice", role="user", baseline=baseline,
                                       owner_verified=False, summary=_summary)
        assert result["verdict"] == "SKIPPED" and len(calls) == 1
        result = run_enumeration_check(runner, actor="alice", role="user", baseline=baseline,
                                       owner_verified=True, summary=_summary)
        assert result["verdict"] == "SKIPPED" and "budget" in result["reason"]
        assert len(calls) == 1 and runner.requests_sent == 1
    finally:
        runner.close()


def test_new_exact_scope_entry_rejects_other_auth_probe_variants():
    from canarygate.guard.safety_guard import GuardRejected
    from canarygate.offline.runner import FixtureRunner
    calls = []
    runner = FixtureRunner(lambda req: calls.append(req) or httpx.Response(401))
    try:
        for probe in ("malformed", "wrong_scheme"):
            with pytest.raises(GuardRejected):
                runner.request("alice", "GET", runner.scope.origin + "/items/nonexistent-item", auth_probe=probe)
        assert calls == [] and runner.requests_sent == 0
    finally:
        runner.close()


def test_authenticated_or_wrong_path_baselines_are_not_used():
    from canarygate.offline.enumeration import run_enumeration_check
    from canarygate.offline.runner import FixtureRunner
    from canarygate.offline.scan import _summary
    calls = []
    runner = FixtureRunner(lambda req: calls.append(req) or httpx.Response(401))
    try:
        for path, headers in (("/items/alice-item", {"Authorization": "Bearer fixture-token-alice"}),
                              ("/items/bob-item", {}), ("/items/alice-item?x=1", {})):
            request = httpx.Request("GET", runner.scope.origin + path, headers=headers)
            result = run_enumeration_check(runner, actor="alice", role="user",
                                           baseline=httpx.Response(401, request=request),
                                           owner_verified=True, summary=_summary)
            assert result["verdict"] == "SKIPPED"
        assert calls == [] and runner.requests_sent == 0
    finally:
        runner.close()


def test_missing_auth_probe_does_not_inherit_a_fixture_login_cookie():
    from canarygate.offline.runner import FixtureRunner
    calls = []
    def handler(request):
        calls.append(request)
        if request.url.path == "/login":
            return httpx.Response(200, json={"token": "fixture-token-alice"},
                                  headers={"Set-Cookie": "session=synthetic-secret; Path=/"})
        return httpx.Response(401)
    runner = FixtureRunner(handler)
    try:
        runner.request("alice", "POST", runner.scope.origin + "/login", json_body={"account": "alice"})
        runner.request("alice", "GET", runner.scope.origin + "/items/alice-item", auth_probe="missing")
        assert "Cookie" not in calls[1].headers
        assert len(runner._client.cookies) == 0
    finally:
        runner.close()


def test_cookie_or_proxy_auth_baseline_is_not_an_unauthenticated_control():
    from canarygate.offline.enumeration import run_enumeration_check
    from canarygate.offline.runner import FixtureRunner
    from canarygate.offline.scan import _summary
    calls = []
    runner = FixtureRunner(lambda req: calls.append(req) or httpx.Response(401))
    try:
        for header in ({"Cookie": "session=secret"}, {"Proxy-Authorization": "Basic secret"}):
            baseline = httpx.Response(401, request=httpx.Request("GET", runner.scope.origin + "/items/alice-item", headers=header))
            result = run_enumeration_check(runner, actor="alice", role="user", baseline=baseline,
                                           owner_verified=True, summary=_summary)
            assert result["verdict"] == "SKIPPED"
        assert not calls
    finally:
        runner.close()
