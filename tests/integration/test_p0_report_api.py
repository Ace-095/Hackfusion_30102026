"""Frozen nine-section report and authorization matrix through the real application.

Every run is a bundled offline synthetic scenario; sockets and DNS are patched to
fail inside each client block.
"""
import socket
from contextlib import contextmanager

import pytest
from fastapi.testclient import TestClient

from canarygate.api.app import create_app
from canarygate.report.p0 import P0_SECTION_KEYS

KINDS = {
    "scenario": ("/api/scenario-scans", "synthetic-vulnerable", 1),
    "authentication": ("/api/authentication-scans", "synthetic-jwt-sub-confirmed", 8),
    "validation": ("/api/validation-scans", "synthetic-validation-weak", 9),
}


def forbidden(*args, **kwargs):
    raise AssertionError("network or DNS attempted by an offline report run")


@contextmanager
def offline_client(monkeypatch, path):
    # Windows asyncio creates a loopback socketpair while TestClient starts.
    with TestClient(create_app(path)) as api:
        with monkeypatch.context() as guard:
            guard.setattr(socket.socket, "connect", forbidden)
            guard.setattr(socket, "getaddrinfo", forbidden)
            yield api


def start(api, kind, scenario_id=None):
    base, default, _ = KINDS[kind]
    response = api.post(base, json={"scenario_id": scenario_id or default})
    assert response.status_code == 201, response.text
    return response.json()


def p0(api, kind, run_id, **params):
    base, _, _ = KINDS[kind]
    return api.get(f"{base}/{run_id}/report", params={"view": "p0", **params})


@pytest.mark.parametrize("kind", sorted(KINDS))
def test_frozen_nine_sections_are_available_for_every_run_kind(monkeypatch, tmp_path, kind):
    with offline_client(monkeypatch, tmp_path / f"{kind}.sqlite3") as api:
        run = start(api, kind)
        response = p0(api, kind, run["id"])
        assert response.status_code == 200, response.text
        report = response.json()
        assert report["run_kind"] == kind and report["run_id"] == run["id"]
        assert report["mode"] == {"scenario": "offline_scenario",
                                  "authentication": "offline_authentication",
                                  "validation": "offline_validation"}[kind]
        sections = report["sections"]
        assert tuple(sections) == P0_SECTION_KEYS
        assert sum(sections["executive_summary"]["verdict_counts"].values()) == KINDS[kind][2]
        assert len([item for items in sections["findings"].values() for item in items]) == KINDS[kind][2]
        assert sections["executive_summary"]["live_target_contacted"] is False
        assert sections["executive_summary"]["network_transport_enabled"] is False
        assert sections["constraint_checklist"]["network_transport_enabled"] is False
        assert sections["scope_and_rules"]["seeding_rung"].startswith("NOT_APPLICABLE")
        assert sections["manual_interventions_and_inferences"]["status"] == "RECORDED"
        assert len(sections["scope_and_rules"]["scope_sha256"]) == 64


def test_report_explains_each_confirmed_authentication_finding(monkeypatch, tmp_path):
    with offline_client(monkeypatch, tmp_path / "auth-report.sqlite3") as api:
        run = start(api, "authentication")
        sections = p0(api, "authentication", run["id"]).json()["sections"]
        findings = {item["id"]: item for item in sections["findings"]["Authentication"]}
        confirmed = findings["AUTHN-04a"]
        assert confirmed["verdict"] == "CONFIRMED" and confirmed["severity"] == "Medium"
        assert confirmed["remediation_key"] == "token_validation" and confirmed["remediation"]
        assert confirmed["observed"].startswith("status 200")
        assert confirmed["expectation_source"].startswith("frozen section 8")
        assert confirmed["curl"].endswith('"Authorization: Bearer $TOKEN_A"')
        assert findings["AUTHN-08"]["verdict"] == "SKIPPED"
        skipped = {item["id"] for item in sections["skipped_and_inconclusive"]}
        assert "AUTHN-08" in skipped


def test_report_groups_validation_findings_and_maps_severity(monkeypatch, tmp_path):
    with offline_client(monkeypatch, tmp_path / "validation-report.sqlite3") as api:
        run = start(api, "validation")
        sections = p0(api, "validation", run["id"]).json()["sections"]
        assert set(sections["findings"]) == {"Authentication", "Authorization",
                                             "Input validation", "Disclosure"}
        input_findings = {item["id"]: item for item in sections["findings"]["Input validation"]}
        disclosure = {item["id"]: item for item in sections["findings"]["Disclosure"]}
        assert input_findings["INPUT-05"]["verdict"] == "SUSPECTED"
        assert input_findings["INPUT-05"]["severity"] is None
        assert disclosure["DISC-03"]["severity"] == "Medium"
        assert disclosure["DISC-03"]["remediation_key"] == "excessive_data_exposure"
        assert len(sections["secured_endpoints"]) >= 0
        assert sections["authorization_matrix"]["coverage"]["rows"] == 0
        assert "Untested cells are marked hatched" in sections["authorization_matrix"]["coverage"]["statement"]


def test_html_report_shows_all_five_verdicts_and_every_section(monkeypatch, tmp_path):
    with offline_client(monkeypatch, tmp_path / "html-report.sqlite3") as api:
        run = start(api, "validation")
        response = p0(api, "validation", run["id"], format="html")
        assert response.status_code == 200
        page = response.text
        for verdict in ("CONFIRMED", "SUSPECTED", "SAFE", "INCONCLUSIVE", "SKIPPED"):
            assert verdict in page
        for heading in ("1. Executive summary", "2. Scope and rules of engagement",
                        "3. Endpoint inventory", "4. Findings by category",
                        "5. Secured endpoints that passed", "6. Skipped and inconclusive tests",
                        "7. Authorization matrix", "8. Manual interventions and inferred items",
                        "9. Constraint checklist"):
            assert heading in page
        assert "not live testing" in page and "No live target was contacted" in page
        assert "synthetic-digest" not in page and "eyJhbGciOiJIUzI1NiJ9" not in page


def test_authorization_matrix_aggregates_stored_runs_and_keeps_gaps_visible(monkeypatch, tmp_path):
    with offline_client(monkeypatch, tmp_path / "matrix.sqlite3") as api:
        vulnerable = start(api, "scenario", "synthetic-vulnerable")
        secure = start(api, "scenario", "synthetic-secure")
        start(api, "authentication")
        start(api, "validation")
        response = api.get("/api/authorization-matrix")
        assert response.status_code == 200, response.text
        matrix = response.json()
        assert matrix["columns"] == ["anonymous", "own_resource", "other_account_resource", "role"]
        assert matrix["live_target_contacted"] is False
        records = next(row for row in matrix["rows"] if row["path"] == "/records/{id}")
        cells = {cell["column"]: cell for cell in records["cells"]}
        other = cells["other_account_resource"]
        assert other["tested"] is True and other["state"] == "red"
        assert "synthetic-vulnerable" in other["source_ref"] and "synthetic-secure" in other["source_ref"]
        assert "|" in other["reason"]
        assert cells["anonymous"]["tested"] is False and cells["anonymous"]["state"] == "hatched"
        assert matrix["coverage"]["untested"] > 0
        assert any(row["path"] == "/login" for row in matrix["rows"])
        assert "partial" in matrix["coverage"]["statement"].lower()
        assert matrix["coverage"]["not_contributing"]["validation_runs"] == 1
        assert sum(matrix["verdict_counts"].values()) > 0
        assert matrix["verdict_counts"]["CONFIRMED"] >= 1
        # The two scenario runs disagree on purpose: the worse observation wins.
        assert vulnerable["id"] != secure["id"]


def test_matrix_reports_clean_coverage_when_the_only_run_is_secure(monkeypatch, tmp_path):
    with offline_client(monkeypatch, tmp_path / "secure-matrix.sqlite3") as api:
        start(api, "scenario", "synthetic-secure")
        matrix = api.get("/api/authorization-matrix").json()
        records = next(row for row in matrix["rows"] if row["path"] == "/records/{id}")
        cells = {cell["column"]: cell for cell in records["cells"]}
        assert cells["other_account_resource"]["state"] == "green"
        assert cells["other_account_resource"]["verdict"] == "SAFE"
        assert matrix["coverage"]["by_state"]["hatched"] >= 1
        assert matrix["coverage"]["by_state"]["grey"] == 1
        assert matrix["coverage"]["tested"] < matrix["coverage"]["cells"]


def test_p0_view_rejects_unknown_requests_and_never_leaks_secrets(monkeypatch, tmp_path):
    with offline_client(monkeypatch, tmp_path / "guards.sqlite3") as api:
        run = start(api, "scenario")
        base, _, _ = KINDS["scenario"]
        assert api.get(f"{base}/{run['id']}/report?view=everything").status_code == 400
        assert api.get(f"{base}/00000000-0000-0000-0000-000000000000/report?view=p0").status_code == 404
        report = p0(api, "scenario", run["id"]).json()
        text = str(report)
        for secret in ("synthetic-alpha-private", "synthetic-beta-private", "fixture-token",
                       "offline-opaque-token", "eyJhbGciOiJIUzI1NiJ9"):
            assert secret not in text
        findings = report["sections"]["findings"]["Authorization"]
        assert findings and findings[0]["curl"].endswith('Bearer $TOKEN_A"')
        assert "TOKEN_A" in findings[0]["curl"]
