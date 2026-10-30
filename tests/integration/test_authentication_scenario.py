"""AUTHN workflow through the real application: API, SQLite, JSON and HTML.

All responses are recorded synthetic data. Sockets and DNS are patched to fail,
so a passing test cannot have contacted a real authentication endpoint.
"""
import json
import socket
from contextlib import contextmanager

import pytest
from fastapi.testclient import TestClient

from canarygate.api.app import create_app
from canarygate.scan import auth_scenarios
from canarygate.scan.auth_generic import run_authentication_scan
from canarygate.scan.auth_runner import OfflineAuthRunner

CHECKS = ("AUTHN-01", "AUTHN-02", "AUTHN-03", "AUTHN-04a", "AUTHN-04b",
          "AUTHN-05", "AUTHN-06", "AUTHN-08")

EXPECTED = {
    "synthetic-jwt-secure": {
        "AUTHN-01": "SAFE", "AUTHN-02": "SAFE", "AUTHN-03": "SAFE",
        "AUTHN-04a": "SAFE", "AUTHN-04b": "SAFE", "AUTHN-05": "SAFE",
        "AUTHN-06": "SAFE", "AUTHN-08": "SKIPPED"},
    "synthetic-jwt-sub-confirmed": {
        "AUTHN-01": "SAFE", "AUTHN-02": "SAFE", "AUTHN-03": "SAFE",
        "AUTHN-04a": "CONFIRMED", "AUTHN-04b": "SAFE", "AUTHN-05": "SAFE",
        "AUTHN-06": "SAFE", "AUTHN-08": "SKIPPED"},
    "synthetic-jwt-role-confirmed": {
        "AUTHN-01": "SAFE", "AUTHN-02": "SAFE", "AUTHN-03": "SAFE",
        "AUTHN-04a": "SAFE", "AUTHN-04b": "CONFIRMED", "AUTHN-05": "SAFE",
        "AUTHN-06": "SAFE", "AUTHN-08": "SKIPPED"},
    "synthetic-jwt-no-observability": {
        "AUTHN-01": "INCONCLUSIVE", "AUTHN-02": "INCONCLUSIVE", "AUTHN-03": "INCONCLUSIVE",
        "AUTHN-04a": "INCONCLUSIVE", "AUTHN-04b": "INCONCLUSIVE", "AUTHN-05": "SUSPECTED",
        "AUTHN-06": "INCONCLUSIVE", "AUTHN-08": "SKIPPED"},
    "synthetic-jwt-opaque": {
        "AUTHN-01": "SAFE", "AUTHN-02": "SAFE", "AUTHN-03": "SAFE",
        "AUTHN-04a": "SKIPPED", "AUTHN-04b": "SKIPPED", "AUTHN-05": "SKIPPED",
        "AUTHN-06": "SKIPPED", "AUTHN-08": "SKIPPED"},
    "synthetic-api-key": {
        "AUTHN-01": "SAFE", "AUTHN-02": "SAFE", "AUTHN-03": "SAFE",
        "AUTHN-04a": "SKIPPED", "AUTHN-04b": "SKIPPED", "AUTHN-05": "SKIPPED",
        "AUTHN-06": "SKIPPED", "AUTHN-08": "SAFE"},
    "synthetic-api-key-accepted": {
        "AUTHN-01": "SAFE", "AUTHN-02": "SAFE", "AUTHN-03": "SAFE",
        "AUTHN-04a": "SKIPPED", "AUTHN-04b": "SKIPPED", "AUTHN-05": "SKIPPED",
        "AUTHN-06": "SKIPPED", "AUTHN-08": "CONFIRMED"},
}


def forbidden(*args, **kwargs):
    raise AssertionError("network or DNS attempted by an offline authentication scan")


@contextmanager
def offline_client(monkeypatch, path):
    # Windows asyncio creates a loopback socketpair while TestClient starts.
    with TestClient(create_app(path)) as api:
        with monkeypatch.context() as guard:
            guard.setattr(socket.socket, "connect", forbidden)
            guard.setattr(socket, "getaddrinfo", forbidden)
            yield api


def start(api, scenario_id):
    response = api.post("/api/authentication-scans", json={"scenario_id": scenario_id})
    assert response.status_code == 201, response.text
    return response.json()


def verdicts(run):
    return {check["id"]: check["verdict"] for check in run["checks"]}


@pytest.mark.parametrize("scenario_id", sorted(EXPECTED))
def test_authentication_verdicts_through_the_application(monkeypatch, tmp_path, scenario_id):
    with offline_client(monkeypatch, tmp_path / "auth.sqlite3") as api:
        run = start(api, scenario_id)
        stored = api.get("/api/authentication-scans/" + run["id"])
        assert stored.status_code == 200 and stored.json() == run
        assert run["mode"] == "offline_authentication"
        assert run["transport"] == "offline_transcript"
        assert run["network_transport_enabled"] is False
        assert run["claims_unverified"] is True
        assert run["signature_verification"] == "not_performed"
        assert run["constraints"]["network_transport_enabled"] is False
        assert run["constraints"]["external_requests_executed"] == 0
        assert run["constraints"]["destructive_requests_executed"] == 0
        assert [check["id"] for check in run["checks"]] == list(CHECKS)
        assert verdicts(run) == EXPECTED[scenario_id]
        summary = run["summary"]
        assert summary["total"] == len(CHECKS)
        assert sum(summary[key] for key in
                   ("confirmed", "suspected", "safe", "inconclusive", "skipped")) == len(CHECKS)
        for check in run["checks"]:
            assert check["category"] == "Authentication" and check["reason"]
            if check["verdict"] == "CONFIRMED":
                assert check["remediation"]
        assert len(run["transcript_sha256"]) == 64


def test_confirmed_authentication_findings_explain_observed_effect(monkeypatch, tmp_path):
    with offline_client(monkeypatch, tmp_path / "effect.sqlite3") as api:
        sub = start(api, "synthetic-jwt-sub-confirmed")
        check = {item["id"]: item for item in sub["checks"]}["AUTHN-04a"]
        assert check["evidence"]["identity_effect"] == "target"
        assert check["evidence"]["denial_body_checked"] is False
        assert "sub" in check["reason"] and "identity" in check["reason"].lower()

        role = start(api, "synthetic-jwt-role-confirmed")
        check = {item["id"]: item for item in role["checks"]}["AUTHN-04b"]
        assert check["evidence"]["capability"] == "granted"
        assert "admin" in check["reason"].lower()

        alg = start(api, "synthetic-jwt-no-observability")
        checks = {item["id"]: item for item in alg["checks"]}
        assert checks["AUTHN-05"]["verdict"] == "SUSPECTED"
        assert checks["AUTHN-04a"]["evidence"]["identity_effect"] == "unobserved"


def test_skipped_checks_stay_explicit_and_never_become_safe(monkeypatch, tmp_path):
    with offline_client(monkeypatch, tmp_path / "skip.sqlite3") as api:
        opaque = {item["id"]: item for item in start(api, "synthetic-jwt-opaque")["checks"]}
        for check_id in ("AUTHN-04a", "AUTHN-04b", "AUTHN-05"):
            assert opaque[check_id]["verdict"] == "SKIPPED"
            assert opaque[check_id]["reason"] == auth_scenarios.JWT_SKIP_REASON
        assert opaque["AUTHN-06"]["reason"] == auth_scenarios.NO_LOGOUT_REASON
        assert opaque["AUTHN-08"]["reason"] == auth_scenarios.API_KEY_SKIP_REASON

        api_key = {item["id"]: item for item in start(api, "synthetic-api-key")["checks"]}
        assert api_key["AUTHN-04a"]["reason"] == auth_scenarios.JWT_SKIP_REASON
        assert api_key["AUTHN-06"]["reason"] == auth_scenarios.NO_LOGOUT_REASON
        assert api_key["AUTHN-08"]["verdict"] == "SAFE"


def test_inconclusive_results_do_not_claim_absence_of_vulnerability(monkeypatch, tmp_path):
    with offline_client(monkeypatch, tmp_path / "inconclusive.sqlite3") as api:
        run = start(api, "synthetic-jwt-no-observability")
        checks = {item["id"]: item for item in run["checks"]}
        assert checks["AUTHN-04b"]["verdict"] == "INCONCLUSIVE"
        assert "admin" in checks["AUTHN-04b"]["reason"].lower()
        assert checks["AUTHN-06"]["verdict"] == "INCONCLUSIVE"
        assert run["summary"]["inconclusive"] == 6 and run["summary"]["safe"] == 0


def test_reports_project_every_check_consistently(monkeypatch, tmp_path):
    with offline_client(monkeypatch, tmp_path / "report.sqlite3") as api:
        run = start(api, "synthetic-jwt-sub-confirmed")
        response = api.get("/api/authentication-scans/" + run["id"] + "/report?view=sections")
        assert response.status_code == 200
        report = response.json()
        assert report["mode"] == "offline_authentication"
        assert report["run_id"] == run["id"] == report["id"]
        sections = report["sections"]
        assert set(sections) == {"executive_summary", "scope_and_accounts", "authentication_checks",
                                 "outcome", "claims_policy", "constraints", "limitations"}
        assert sections["authentication_checks"] == run["checks"]
        assert sections["executive_summary"]["summary"] == run["summary"]
        assert sections["claims_policy"]["claims_unverified"] is True
        assert sections["claims_policy"]["signature_verification"] == "not_performed"
        assert "decoding" in sections["claims_policy"]["statement"].lower()

        html = api.get("/api/authentication-scans/" + run["id"] + "/report?format=html")
        assert html.status_code == 200
        text = html.text
        for expected in ("AUTHN-04a", "CONFIRMED", "AUTHN-05", "SAFE", "SKIPPED",
                         "account-a", "/profile", "offline_transcript",
                         "claims are not verified"):
            assert expected in text, expected


def test_credentials_never_reach_storage_or_reports(monkeypatch, tmp_path):
    database = tmp_path / "secrets.sqlite3"
    with offline_client(monkeypatch, database) as api:
        runs = [start(api, scenario) for scenario in
                ("synthetic-jwt-sub-confirmed", "synthetic-api-key-accepted")]
        sections = [api.get(f"/api/authentication-scans/{run['id']}/report?view=sections").json()
                    for run in runs]
        html = "".join(api.get(f"/api/authentication-scans/{run['id']}/report?format=html").text
                       for run in runs)
    payload = json.dumps(runs) + json.dumps(sections) + html
    raw = database.read_bytes()
    for secret in (auth_scenarios.account_token("account-a"), auth_scenarios.account_token("account-b"),
                   auth_scenarios.API_KEY_VALID, auth_scenarios.API_KEY_INVALID):
        assert secret not in payload
        assert secret.encode() not in raw
    assert "eyJ" not in payload
    for run in runs:
        for check in run["checks"]:
            assert "authorization" not in json.dumps(check).lower()


def test_runs_survive_restart_and_tampering_fails_closed(monkeypatch, tmp_path):
    database = tmp_path / "restart-auth.sqlite3"
    with offline_client(monkeypatch, database) as api:
        run = start(api, "synthetic-jwt-role-confirmed")
    with offline_client(monkeypatch, database) as api:
        restored = api.get("/api/authentication-scans/" + run["id"]).json()
        assert restored["checks"] == run["checks"]
    import sqlite3
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE authentication_runs SET payload = replace(payload, 'CONFIRMED', 'SAFE')")
    with offline_client(monkeypatch, database) as api:
        assert api.get("/api/authentication-scans/" + run["id"]).status_code == 500


@pytest.mark.parametrize("payload", [
    {"scenario_id": "unknown-scenario"},
    {"scenario_id": "synthetic-jwt-secure", "target": "https://evil.invalid"},
    {"scenario_id": "synthetic-jwt-secure", "token": "attacker-supplied"},
    {"scenario_id": ""},
])
def test_api_rejects_unknown_or_widened_requests(monkeypatch, tmp_path, payload):
    with offline_client(monkeypatch, tmp_path / "reject-auth.sqlite3") as api:
        response = api.post("/api/authentication-scans", json=payload)
        assert response.status_code in (404, 422), response.text
        assert api.get("/api/authentication-scans/missing").status_code == 404


def test_direct_construction_and_unscoped_probes_fail_closed(monkeypatch, tmp_path):
    plan = auth_scenarios.build_auth_scenario("synthetic-jwt-secure")
    with pytest.raises(ValueError):
        run_authentication_scan(object(), plan)
    runner = auth_scenarios.runner_for(plan)
    try:
        with pytest.raises(ValueError):
            runner.probe("account-a", "/admin/users", "jwt_sub")
        with pytest.raises(ValueError):
            runner.probe("account-a", "/profile", "api_key_invalid")
        with pytest.raises(ValueError):
            runner.authenticate("account-a", "/admin/users")
        assert runner.stats()["requests_sent"] == 0
        assert runner.stats()["blocked_by_guard"] == 3
    finally:
        runner.close()


def test_authentication_orchestrator_marks_failures_inconclusive():
    plan = auth_scenarios.build_auth_scenario("synthetic-jwt-secure")
    runner = auth_scenarios.runner_for(plan)
    def broken(*args, **kwargs):
        raise RuntimeError("unexpected failure")
    runner.probe = broken
    try:
        run = run_authentication_scan(runner, plan)
    finally:
        runner.close()
    assert run["status"] == "failed"
    assert all(check["verdict"] in ("INCONCLUSIVE", "SKIPPED") for check in run["checks"])
    assert run["summary"]["confirmed"] == 0
    assert {check["id"] for check in run["checks"] if check["verdict"] == "INCONCLUSIVE"}
