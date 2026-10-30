"""Test-first scenarios for bounded, fixture-only disclosure inspection."""
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


class DisclosureFixture(FixtureTarget):
    def __init__(self, scenario):
        super().__init__()
        self.scenario = scenario

    def handle(self, request):
        response = super().handle(request)
        if request.url.path != "/search":
            return response
        # Modify only the valid control. Every other bounded fixture response
        # remains real and goes through the guard and MockTransport.
        if request.url.query != b"limit=1":
            return response
        if self.scenario == "sensitive":
            return httpx.Response(200, json={"results": [{"profile": {"password_hash": "sensitive-value-never-store"}}]})
        if self.scenario == "redacted":
            return httpx.Response(200, json={"results": [{"password_hash": "[REDACTED]"}]})
        if self.scenario == "excess":
            return httpx.Response(200, json={"results": [], "id": "unapproved-id-must-not-leak"})
        if self.scenario == "not_json":
            return httpx.Response(200, text="not-json")
        return response


def by_id(run):
    return {check["id"]: check for check in run["checks"]}


def test_normal_fixture_has_complete_sampled_disclosure_coverage():
    run = run_fixture()
    checks = by_id(run)
    for check_id in ("DISC-03", "DISC-04"):
        assert checks[check_id]["verdict"] == "SAFE"
        assert checks[check_id]["evidence"]["checklist"]["inspected_fixture_responses"] == 4
    assert run["constraints"]["requests_sent"] == 14  # Reuse the existing probes.


@pytest.mark.parametrize("scenario,disc03,disc04", [
    ("sensitive", "CONFIRMED", "SAFE"),
    ("redacted", "SAFE", "SAFE"),
    ("excess", "SAFE", "SUSPECTED"),
    ("not_json", "INCONCLUSIVE", "INCONCLUSIVE"),
])
def test_actual_response_contents_drive_disclosure_verdicts_without_leaking(scenario, disc03, disc04, monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError("fixture attempted network or DNS")
    monkeypatch.setattr(socket.socket, "connect", no_network)
    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    run = run_fixture(DisclosureFixture(scenario))
    found = by_id(run)
    assert found["DISC-03"]["verdict"] == disc03
    assert found["DISC-04"]["verdict"] == disc04
    assert run["constraints"]["network_transport_enabled"] is False
    serialized = json.dumps(run)
    assert "sensitive-value-never-store" not in serialized
    assert "unapproved-id-must-not-leak" not in serialized
    for name in ("DISC-03", "DISC-04"):
        evidence = found[name]["evidence"]
        if evidence:
            canonical = {key: value for key, value in evidence.items() if key not in ("sha256", "redacted")}
            assert evidence["sha256"] == hashlib.sha256(json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def test_partial_fixture_coverage_never_proves_absence():
    checks = by_id(run_fixture(FixtureTarget(validation_behavior="lockout")))
    assert checks["DISC-03"]["verdict"] == "INCONCLUSIVE"
    assert checks["DISC-04"]["verdict"] == "INCONCLUSIVE"
    checks = by_id(run_fixture(FixtureTarget(bob_login=False)))
    assert checks["DISC-03"]["verdict"] == checks["DISC-04"]["verdict"] == "SKIPPED"


def test_redacted_evidence_survives_persistence_and_report(tmp_path):
    db = tmp_path / "fixture.sqlite3"
    store = FixtureStore(db)
    store.initialize()
    sensitive = store.save(run_fixture(DisclosureFixture("sensitive")))
    excess = store.save(run_fixture(DisclosureFixture("excess")))
    with TestClient(create_app(db)) as client:
        for run, check_id, verdict in ((sensitive, "DISC-03", "CONFIRMED"), (excess, "DISC-04", "SUSPECTED")):
            restored = client.get(f"/api/scan/{run['id']}").json()
            assert by_id(restored)[check_id]["verdict"] == verdict
            html = client.get(f"/api/reports/{run['id']}?format=html").text
            assert check_id in html
            assert "sensitive-value-never-store" not in html
            assert "unapproved-id-must-not-leak" not in html
    assert b"sensitive-value-never-store" not in db.read_bytes()
    assert b"unapproved-id-must-not-leak" not in db.read_bytes()


@pytest.mark.parametrize("phase", ["control", "probe"])
def test_excessively_nested_fixture_json_is_inconclusive_not_a_crash(phase):
    class NestedFixture(FixtureTarget):
        def handle(self, request):
            if request.url.path == "/search" and (
                    (phase == "control" and request.url.query == b"limit=1") or
                    (phase == "probe" and request.url.query == b"limit=999")):
                body = b'{"results":[],"nested":' + b'[' * 1100 + b'0' + b']' * 1100 + b'}'
                return httpx.Response(200, content=body, headers={"Content-Type": "application/json"})
            return super().handle(request)
    result = run_fixture(NestedFixture())
    found = by_id(result)
    assert result["verdict"] == "CONFIRMED"  # independent BOLA evidence remains valid
    assert found["DISC-03"]["verdict"] == "INCONCLUSIVE"
    assert found["DISC-04"]["verdict"] == "INCONCLUSIVE"
    if phase == "probe":
        assert found["INPUT-04"]["verdict"] == "SUSPECTED"


def test_nested_discovery_json_is_skipped_without_crashing_observation_capture():
    class NestedDiscovery(FixtureTarget):
        def handle(self, request):
            if request.url.path == "/items":
                return httpx.Response(200, content=b'[' * 1100 + b'0' + b']' * 1100,
                                      headers={"Content-Type": "application/json"})
            return super().handle(request)
    observations = []
    result = run_fixture(NestedDiscovery(), observation_sink=observations)
    assert result["verdict"] == "SKIPPED"
    assert result["setup"]["resources"] == "FAILED"
    assert len(observations) == 1 and observations[0]["assertions"]["own_resource_identified"] is None
