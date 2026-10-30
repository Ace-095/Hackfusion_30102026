"""Real read-BOLA validation against a running TargetLab through the application.

The lab is served over TLS on 127.0.0.1 with an ephemeral port. The application
can only reach it because the scope mode is ``local_lab``; nothing leaves the
machine. The lab's declared ground truth is compared only after the verdicts.
"""
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

import targetlab
import targetlab.testing as lab_server
from canarygate.api.app import create_app
from canarygate.database.lab_bola_store import LabBolaStore
from canarygate.scan.lab_bola_scenarios import EXPECTED_VERDICTS
from targetlab.app import create_lab_app

FORBIDDEN = ("lab-token-mallapa", "lab-token-sakshi", "mallapa-lab-password", "sakshi-lab-password",
             "targetlab-mallapa-private-marker", "targetlab-sakshi-private-marker")


class Recording:
    """Serve the real lab and remember which paths were requested."""

    def __init__(self):
        self.paths = []
        app = create_lab_app()

        @app.middleware("http")
        async def record(request, call_next):
            self.paths.append(request.url.path)
            return await call_next(request)

        self.app = app


@pytest.fixture()
def lab():
    with lab_server.LabTlsServer() as server:
        yield server


@pytest.fixture()
def client(tmp_path, lab, monkeypatch):
    monkeypatch.setenv("CANARYGATE_TARGETLAB_CA", str(lab_server.TARGETLAB_CERT))
    database = tmp_path / "lab-bola.sqlite3"
    with TestClient(create_app(database)) as api:
        api.database_path = database
        yield api


def start(api, port, **extra):
    response = api.post("/api/lab-bola-scans", json={"port": port, **extra})
    assert response.status_code == 201, response.text
    return response.json()


def test_real_bola_is_confirmed_both_directions_and_the_secure_route_is_safe(client, lab):
    run = start(client, lab.port)
    assert run["mode"] == "targetlab_bola"
    assert run["verdict"] == "CONFIRMED"
    assert run["transport"]["destination"] == "127.0.0.1"
    assert run["transport"]["network_transport_enabled"] is True
    assert run["transport"]["live_target_contacted"] is False
    checks = {check["id"]: check for check in run["checks"]}
    assert [(check_id, checks[check_id]["verdict"]) for check_id in sorted(checks)] == [
        ("LAB-BOLA-01", "SAFE"), ("LAB-BOLA-02", "SAFE"),
        ("LAB-BOLA-03", "CONFIRMED"), ("LAB-BOLA-04", "CONFIRMED"),
        ("LAB-BOLA-05", "SAFE"), ("LAB-BOLA-06", "SAFE")]
    assert checks["LAB-BOLA-03"]["status"] == 200
    assert checks["LAB-BOLA-03"]["checklist"]["private_disclosure"] is True
    assert checks["LAB-BOLA-03"]["checklist"]["ownership_verified"] is True
    assert checks["LAB-BOLA-03"]["checklist"]["owner_baseline"] is True
    assert checks["LAB-BOLA-03"]["checklist"]["policy_denies_access"] is True
    assert checks["LAB-BOLA-03"]["remediation"] and checks["LAB-BOLA-05"]["remediation"] is None
    assert checks["LAB-BOLA-05"]["status"] == 403
    assert checks["LAB-BOLA-05"]["checklist"]["verified_denial"] is True
    assert run["summary"] == {"total": 6, "confirmed": 2, "safe": 4, "suspected": 0,
                              "inconclusive": 0, "skipped": 0}
    assert run["constraints"]["requests_sent"] == 18
    assert run["constraints"]["budget_remaining"] == 2
    assert run["constraints"]["blocked_by_guard"] == 0
    assert client.get(f"/api/lab-bola-scans/{run['id']}").json()["id"] == run["id"]


def test_the_scanner_never_requests_the_lab_ground_truth(tmp_path, monkeypatch):
    """The answer key must not be reachable, let alone consulted."""
    recording = Recording()
    monkeypatch.setenv("CANARYGATE_TARGETLAB_CA", str(lab_server.TARGETLAB_CERT))
    with lab_server.LabTlsServer(app=recording.app) as lab:
        with TestClient(create_app(tmp_path / "no-ground-truth.sqlite3")) as api:
            run = start(api, lab.port)
    assert run["verdict"] == "CONFIRMED"
    assert "/lab/ground-truth" not in recording.paths
    assert not any(path.startswith("/lab/") for path in recording.paths)
    # The routes that were used are exactly the declared ones.
    assert set(recording.paths) <= {"/login", "/profile", "/records", "/records/MKT-2026-041",
                                    "/records/BRD-2026-018", "/records/BRD-2026-018/secure", "/records/MKT-2026-041/secure"}
    assert "/records/BRD-2026-018" in recording.paths and "/records/BRD-2026-018/secure" in recording.paths


def test_ground_truth_is_scored_after_the_verdicts_and_cannot_change_them(client, lab,
                                                                         monkeypatch):
    run = start(client, lab.port)
    assert run["ground_truth"]["matched"] == 6
    assert run["ground_truth"]["mismatched"] == 0
    assert run["ground_truth"]["used_as_decision_input"] is False
    assert run["ground_truth"]["evaluated_after_verdicts"] is True
    baseline = [check["verdict"] for check in run["checks"]]

    import canarygate.scan.lab_bola as module

    # Corrupt the declared table: the comparison changes, the verdicts do not.
    monkeypatch.setattr(module, "EXPECTED_VERDICTS",
                        {check_id: "SKIPPED" for check_id in EXPECTED_VERDICTS})
    second = start(client, lab.port)
    assert [check["verdict"] for check in second["checks"]] == baseline
    assert second["ground_truth"]["matched"] == 0
    assert second["ground_truth"]["mismatched"] == 6


def test_p0_report_is_the_frozen_nine_sections_and_explains_the_finding(client, lab):
    run = start(client, lab.port)
    report = client.get(f"/api/lab-bola-scans/{run['id']}/report",
                        params={"view": "p0"}).json()
    sections = report["sections"]
    assert report["mode"] == "targetlab_bola"
    assert list(sections) == ["executive_summary", "scope_and_rules", "endpoint_inventory",
                              "findings", "secured_endpoints", "skipped_and_inconclusive",
                              "authorization_matrix", "manual_interventions_and_inferences",
                              "constraint_checklist"]
    findings = {item["id"]: item for items in sections["findings"].values() for item in items}
    assert len(findings) == 6
    confirmed = findings["LAB-BOLA-03"]
    assert confirmed["verdict"] == "CONFIRMED" and confirmed["severity"] == "High"
    assert confirmed["category"] == "Authorization"
    assert confirmed["remediation_key"] == "bola" and confirmed["remediation"]
    assert confirmed["expected"] and confirmed["observed"] and confirmed["expectation_source"]
    assert confirmed["verified_owner"].startswith("sakshi")
    assert confirmed["curl"].count("$TOKEN_") == 1
    assert findings["LAB-BOLA-05"]["verdict"] == "SAFE"
    assert {item["id"] for item in sections["secured_endpoints"]} == {"LAB-BOLA-05", "LAB-BOLA-06"}
    assert sections["executive_summary"]["network_transport_enabled"] is True
    assert sections["executive_summary"]["live_target_contacted"] is False
    assert sections["constraint_checklist"]["loopback_lab_contacted"] is True
    inferences = sections["manual_interventions_and_inferences"]["inferences"]
    assert any(item["item"] == "ground_truth_independence" for item in inferences)
    matrix = sections["authorization_matrix"]
    cells = {(row["endpoint"], cell["column"]): cell
             for row in matrix["rows"] for cell in row["cells"]}
    assert cells[("GET /records/{id}", "other_account_resource")]["state"] == "red"
    assert cells[("GET /records/{id}", "other_account_resource")]["verdict"] == "CONFIRMED"
    assert cells[("GET /records/{id}/secure", "other_account_resource")]["state"] == "green"
    assert cells[("GET /records/{id}/secure", "other_account_resource")]["verdict"] == "SAFE"
    assert "lab_bola:" in cells[("GET /records/{id}", "other_account_resource")]["source_ref"]


def test_html_reports_label_the_run_as_controlled_validation(client, lab):
    run = start(client, lab.port)
    page = client.get(f"/api/lab-bola-scans/{run['id']}/report", params={"format": "html"}).text
    assert "Controlled validation, not live validation" in page
    assert "LAB-BOLA-03" in page and "CONFIRMED" in page
    assert "127.0.0.1" in page
    p0_page = client.get(f"/api/lab-bola-scans/{run['id']}/report",
                         params={"view": "p0", "format": "html"}).text
    assert "LAB-BOLA-03" in p0_page and "Authorization" in p0_page


def test_aggregate_matrix_contains_the_lab_cells_and_stays_partial(client, lab):
    run = start(client, lab.port)
    matrix = client.get("/api/authorization-matrix").json()
    assert matrix["coverage"]["scope"] == "partial_offline"
    cells = {(row["endpoint"], cell["column"]): cell
             for row in matrix["rows"] for cell in row["cells"]}
    red = cells[("GET /records/{id}", "other_account_resource")]
    assert red["state"] == "red" and "lab_bola:" in red["source_ref"]
    green = cells[("GET /records/{id}/secure", "other_account_resource")]
    assert green["state"] == "green"
    assert matrix["coverage"]["untested"] > 0
    assert run["id"]


def test_no_credentials_markers_or_bodies_are_stored(client, lab):
    run = start(client, lab.port)
    sections = client.get(f"/api/lab-bola-scans/{run['id']}/report",
                          params={"view": "sections"}).text
    p0 = client.get(f"/api/lab-bola-scans/{run['id']}/report", params={"view": "p0"}).text
    page = client.get(f"/api/lab-bola-scans/{run['id']}/report", params={"format": "html"}).text
    raw = client.database_path.read_bytes().decode("utf-8", errors="ignore")
    combined = "\n".join((json.dumps(run), sections, p0, page, raw))
    for secret in FORBIDDEN:
        assert secret not in combined, secret[:24]
    assert "$TOKEN_" in combined  # reproducibility uses placeholders only


def test_runs_survive_restart_and_tampering_is_rejected(client, lab):
    run = start(client, lab.port)
    path = client.database_path
    with TestClient(create_app(path)) as restarted:
        again = restarted.get(f"/api/lab-bola-scans/{run['id']}").json()
        assert again["verdict"] == "CONFIRMED"
        assert again["ground_truth"]["matched"] == 6
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE lab_bola_runs SET payload = replace(payload, "
                           "'\"verdict\":\"CONFIRMED\"', '\"verdict\":\"SAFE\"')")
        connection.commit()
    with TestClient(create_app(path), raise_server_exceptions=False) as tampered:
        assert tampered.get(f"/api/lab-bola-scans/{run['id']}").status_code == 500


def test_budget_exhaustion_never_fabricates_a_verdict(client, lab):
    run = start(client, lab.port, request_budget=16)
    verdicts = [check["verdict"] for check in run["checks"]]
    assert run["constraints"]["requests_sent"] == 16
    assert run["constraints"]["budget_remaining"] == 0
    assert run["constraints"]["blocked_by_guard"] >= 1
    assert verdicts.count("SKIPPED") >= 1
    assert run["verdict"] in {"CONFIRMED", "INCONCLUSIVE", "SKIPPED"}


def test_missing_ca_and_unreachable_lab_store_nothing(tmp_path, monkeypatch, lab):
    # "Missing" means missing from this process, not from the developer's shell:
    # tests/conftest.py clears every CANARYGATE_* variable before each test.
    database = tmp_path / "unreachable.sqlite3"
    with TestClient(create_app(database)) as api:
        assert api.post("/api/lab-bola-scans", json={"port": lab.port}).status_code == 400
    monkeypatch.setenv("CANARYGATE_TARGETLAB_CA", str(lab_server.TARGETLAB_CERT))
    with TestClient(create_app(database)) as api:
        response = api.post("/api/lab-bola-scans", json={"port": lab_server.free_port()})
        assert response.status_code == 502
    assert LabBolaStore(database).list() == []


def test_an_untrusted_certificate_is_refused(tmp_path, monkeypatch, lab):
    monkeypatch.setenv("CANARYGATE_TARGETLAB_CA", str(lab_server.OTHER_CERT))
    database = tmp_path / "bad-ca.sqlite3"
    with TestClient(create_app(database)) as api:
        response = api.post("/api/lab-bola-scans", json={"port": lab.port})
        assert response.status_code == 502
    assert LabBolaStore(database).list() == []


@pytest.mark.parametrize("payload", [{"port": 80}, {"port": 8765, "request_budget": 4},
                                     {"port": 8765, "hostname": "example.com"},
                                     {"port": 8765, "request_budget": 100}])
def test_invalid_scan_requests_are_rejected(client, payload):
    assert client.post("/api/lab-bola-scans", json=payload).status_code == 422


def test_the_workflow_reuses_the_single_bola_oracle():
    """No second oracle: the workflow imports the shared one and nothing else."""
    import canarygate.scan.lab_bola as module

    source = open(module.__file__, encoding="utf-8").read()
    assert "from canarygate.oracles.read_bola import evaluate_read_bola" in source
    assert "from canarygate.seed.registry import collect_guarded_ownership" in source
    for forbidden in ("def evaluate_read_bola", "def collect_guarded_ownership",
                      "private_disclosure =", "verdict_reason ="):
        assert forbidden not in source, forbidden
