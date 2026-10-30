"""INPUT-05/06/07 and DISC-01..06 through the real application.

All responses are recorded synthetic data. Sockets and DNS are patched to fail
inside each client block, so a passing test cannot have contacted a real host.
"""
import json
import socket
import sqlite3
from contextlib import contextmanager

import pytest
from fastapi.testclient import TestClient

from canarygate.api.app import create_app
from canarygate.scan import validation_scenarios
from canarygate.scan.validation_generic import run_offline_validation

CHECKS = ("INPUT-05", "INPUT-06", "INPUT-07", "DISC-01", "DISC-02", "DISC-03", "DISC-04",
          "DISC-05", "DISC-06")

EXPECTED = {
    "synthetic-validation-secure": {check: "SAFE" for check in CHECKS},
    "synthetic-validation-weak": {
        "INPUT-05": "SUSPECTED", "INPUT-06": "SUSPECTED", "INPUT-07": "SUSPECTED",
        "DISC-01": "CONFIRMED", "DISC-02": "CONFIRMED", "DISC-03": "CONFIRMED",
        "DISC-04": "CONFIRMED", "DISC-05": "CONFIRMED", "DISC-06": "CONFIRMED"},
    "synthetic-validation-unobservable": {
        "INPUT-05": "INCONCLUSIVE", "INPUT-06": "INCONCLUSIVE", "INPUT-07": "SAFE",
        "DISC-01": "SAFE", "DISC-02": "SAFE", "DISC-03": "SAFE", "DISC-04": "SKIPPED",
        "DISC-05": "CONFIRMED", "DISC-06": "INCONCLUSIVE"},
    "synthetic-validation-malformed-responses": {
        "INPUT-05": "SUSPECTED", "INPUT-06": "INCONCLUSIVE", "INPUT-07": "INCONCLUSIVE",
        "DISC-01": "SAFE", "DISC-02": "SAFE", "DISC-03": "INCONCLUSIVE",
        "DISC-04": "INCONCLUSIVE", "DISC-05": "SAFE", "DISC-06": "INCONCLUSIVE"},
}


def forbidden(*args, **kwargs):
    raise AssertionError("network or DNS attempted by an offline validation scan")


@contextmanager
def offline_client(monkeypatch, path):
    # Windows asyncio creates a loopback socketpair while TestClient starts.
    with TestClient(create_app(path)) as api:
        with monkeypatch.context() as guard:
            guard.setattr(socket.socket, "connect", forbidden)
            guard.setattr(socket, "getaddrinfo", forbidden)
            yield api


def start(api, scenario_id):
    response = api.post("/api/validation-scans", json={"scenario_id": scenario_id})
    assert response.status_code == 201, response.text
    return response.json()


def verdicts(run):
    return {check["id"]: check["verdict"] for check in run["checks"]}


@pytest.mark.parametrize("scenario_id", sorted(EXPECTED))
def test_validation_verdicts_through_the_application(monkeypatch, tmp_path, scenario_id):
    with offline_client(monkeypatch, tmp_path / "validation.sqlite3") as api:
        run = start(api, scenario_id)
        stored = api.get("/api/validation-scans/" + run["id"])
        assert stored.status_code == 200 and stored.json() == run
        assert run["mode"] == "offline_validation"
        assert run["status"] == "completed"
        assert run["transport"] == "offline_transcript"
        assert run["network_transport_enabled"] is False
        assert run["policy_source"] == "offline validation scenario policy"
        assert [check["id"] for check in run["checks"]] == list(CHECKS)
        assert verdicts(run) == EXPECTED[scenario_id]
        summary = run["summary"]
        assert summary["total"] == len(CHECKS)
        assert summary["executed"] == len(CHECKS) - summary["skipped"]
        if scenario_id == "synthetic-validation-unobservable":
            assert summary["skipped"] == 1 and summary["executed"] == 8
        assert sum(summary[key] for key in
                   ("confirmed", "suspected", "safe", "inconclusive", "skipped")) == len(CHECKS)
        assert run["requests_sent"] > 0
        assert run["blocked_by_guard"] == 0
        assert 0 <= run["budget_remaining"] < run["scope"]["request_budget"]
        assert len(run["transcript_sha256"]) == 64
        for check in run["checks"]:
            assert check["reason"] and check["category"] in {"Input validation", "Information disclosure"}
            assert (check["category"] == "Input validation") == check["id"].startswith("INPUT")
            if check["verdict"] == "CONFIRMED":
                assert check["remediation"]
            if check["verdict"] in {"SAFE", "CONFIRMED", "SUSPECTED"}:
                assert check["evidence"]


def test_input_checks_execute_declared_probes_and_record_their_status(monkeypatch, tmp_path):
    with offline_client(monkeypatch, tmp_path / "probes.sqlite3") as api:
        run = start(api, "synthetic-validation-weak")
        checks = {check["id"]: check for check in run["checks"]}
        assert checks["INPUT-05"]["request_probes"] == ["extra_property"]
        assert checks["INPUT-06"]["request_probes"] == ["malformed_json"]
        assert checks["INPUT-07"]["request_probes"] == ["special_characters"]
        assert checks["INPUT-05"]["evidence"]["status"] == 200
        assert checks["INPUT-06"]["evidence"]["status"] == 200
        assert checks["INPUT-07"]["evidence"]["status"] == 200
        assert checks["INPUT-05"]["evidence"]["path"] == "/login"
        assert checks["INPUT-05"]["verdict"] == "SUSPECTED"


def test_disclosure_checks_rest_on_recorded_read_evidence(monkeypatch, tmp_path):
    with offline_client(monkeypatch, tmp_path / "disclosure.sqlite3") as api:
        run = start(api, "synthetic-validation-weak")
        checks = {check["id"]: check for check in run["checks"]}
        assert checks["DISC-01"]["evidence"] == {"path": "/errors/trace", "status": 500}
        assert checks["DISC-02"]["evidence"] == {"path": "/errors/internal", "status": 400}
        assert checks["DISC-03"]["evidence"] == {"path": "/profile", "status": 200,
                                                 "signals": ["name", "pattern"]}
        assert checks["DISC-04"]["evidence"]["excess_fields"] is True
        assert checks["DISC-06"]["evidence"] == {"known_status": 403, "unknown_status": 404}
        assert checks["DISC-05"]["verdict"] == "CONFIRMED"


def test_malformed_or_hostile_responses_never_read_as_safe(monkeypatch, tmp_path):
    with offline_client(monkeypatch, tmp_path / "hostile.sqlite3") as api:
        run = start(api, "synthetic-validation-malformed-responses")
        checks = {check["id"]: check for check in run["checks"]}
        assert checks["INPUT-06"]["verdict"] == "INCONCLUSIVE"
        assert checks["INPUT-07"]["verdict"] == "INCONCLUSIVE"
        assert checks["DISC-03"]["verdict"] == "INCONCLUSIVE"
        assert checks["DISC-04"]["verdict"] == "INCONCLUSIVE"
        assert checks["DISC-06"]["verdict"] == "INCONCLUSIVE"


def test_report_sections_and_html_explain_every_check(monkeypatch, tmp_path):
    with offline_client(monkeypatch, tmp_path / "report.sqlite3") as api:
        run = start(api, "synthetic-validation-weak")
        sections = api.get(f"/api/validation-scans/{run['id']}/report?view=sections")
        assert sections.status_code == 200
        body = sections.json()
        assert body["mode"] == "offline_validation" and body["run_id"] == run["id"]
        assert body["sections"]["executive_summary"]["live_target_contacted"] is False
        assert body["sections"]["outcome"]["confirmed"] == ["DISC-01", "DISC-02", "DISC-03",
                                                            "DISC-04", "DISC-05", "DISC-06"]
        assert body["sections"]["outcome"]["statement"]
        assert [check["id"] for check in body["sections"]["check_results"]] == list(CHECKS)
        assert body["sections"]["scope_and_accounts"]["accounting"]["requests_sent"] == run["requests_sent"]
        html = api.get(f"/api/validation-scans/{run['id']}/report?format=html")
        assert html.status_code == 200
        page = html.text
        assert "not live testing" in page and "network transport enabled: False" in page
        for check in CHECKS:
            assert check in page
        assert "synthetic-digest" not in page and "offline-valid-credential" not in page
        assert "eyJhbGciOiJIUzI1NiJ9" not in page


def test_sensitive_values_are_redacted_before_persistence(monkeypatch, tmp_path):
    database = tmp_path / "redaction.sqlite3"
    with offline_client(monkeypatch, database) as api:
        run = start(api, "synthetic-validation-weak")
        stored = api.get("/api/validation-scans/" + run["id"]).json()
        assert stored == run
        assert "synthetic-digest" not in json.dumps(stored)
        assert "eyJhbGciOiJIUzI1NiJ9" not in json.dumps(stored)
        assert "offline-valid-credential" not in json.dumps(stored)
        assert "offline-validation-token" not in json.dumps(stored)
    raw = database.read_bytes()
    assert b"synthetic-digest" not in raw
    assert b"eyJhbGciOiJIUzI1NiJ9" not in raw
    assert b"offline-valid-credential" not in raw
    assert b"Traceback (most recent call last)" not in raw


def test_tampered_validation_run_is_rejected(monkeypatch, tmp_path):
    database = tmp_path / "tamper.sqlite3"
    with offline_client(monkeypatch, database) as api:
        run = start(api, "synthetic-validation-secure")
    with sqlite3.connect(str(database)) as conn:
        payload = conn.execute("SELECT payload FROM validation_runs WHERE run_id = ?",
                               (run["id"],)).fetchone()[0]
        tampered = json.loads(payload)
        tampered["checks"][0]["verdict"] = "SAFE"
        tampered["checks"][0]["reason"] = "tampered"
        conn.execute("UPDATE validation_runs SET payload = ? WHERE run_id = ?",
                     (json.dumps(tampered), run["id"]))
        conn.commit()
    with offline_client(monkeypatch, database) as api:
        response = api.get("/api/validation-scans/" + run["id"])
        assert response.status_code == 500
        assert "integrity" in response.json()["detail"]


def test_unknown_scenarios_and_runs_fail_closed(monkeypatch, tmp_path):
    with offline_client(monkeypatch, tmp_path / "errors.sqlite3") as api:
        assert api.post("/api/validation-scans", json={"scenario_id": "synthetic-missing"}).status_code == 404
        assert api.post("/api/validation-scans", json={"scenario_id": "Bad Id"}).status_code == 422
        assert api.post("/api/validation-scans", json={"scenario_id": "synthetic-validation-secure",
                                                       "target": "http://example.com"}).status_code == 422
        run = start(api, "synthetic-validation-secure")
        assert api.get("/api/validation-scans/00000000-0000-0000-0000-000000000000").status_code == 404
        assert api.get("/api/validation-scans/not-a-run").status_code == 404
        assert api.get(f"/api/validation-scans/{run['id']}/report?view=nope").status_code == 400
        assert api.get(f"/api/validation-scans/{run['id']}/report?format=xml").status_code == 400


def test_scope_without_declared_probes_cannot_run_the_validation_flow():
    plan = validation_scenarios.build_validation_scenario("synthetic-validation-secure")
    runner = validation_scenarios.runner_for(plan)
    broken_scope = validation_scenarios.scope_without_input_probes()
    with pytest.raises(ValueError):
        type(runner)(broken_scope, {"account-a": "token-a", "account-b": "token-b"},
                     plan.reads, plan.probes, config=validation_scenarios.config_for(plan))


def test_every_scenario_reports_completed_enforced_accounting():
    for scenario_id in validation_scenarios.SCENARIO_IDS:
        plan = validation_scenarios.build_validation_scenario(scenario_id)
        run = run_offline_validation(plan, validation_scenarios.runner_for(plan))
        assert run.requests_sent + run.budget_remaining == plan.scope.request_budget
        assert run.blocked_by_guard == 0
        assert run.summary.executed == 9 - run.summary.skipped
