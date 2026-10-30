"""Real HTTPS control-interaction (SCI) validation through the application.

The lab is served over TLS on 127.0.0.1 with an ephemeral port. A CONFIRMED
verdict requires the deny → rejected-login → leak sequence, both individual
controls passing, and the leaked marker matching an independently collected
owner baseline.
"""
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

import targetlab.testing as lab_server
from canarygate.api.app import create_app
from canarygate.database.lab_sci_store import LabSciStore
from canarygate.scan.lab_sci_scenarios import DENIAL_BODY, REJECTION_BODY

FORBIDDEN = ("lab-token-mallapa", "lab-token-sakshi", "lab-token-harsha",
             "mallapa-lab-password", "sakshi-lab-password", "harsha-lab-password",
             "targetlab-mallapa-private-marker", "targetlab-sakshi-private-marker",
             "targetlab-harsha-private-marker", "targetlab-trace-marker")


class Recording:
    """Serve the real lab and remember which paths were requested."""

    def __init__(self):
        from targetlab.app import create_lab_app

        self.paths = []
        app = create_lab_app()

        @app.middleware("http")
        async def record(request, call_next):
            self.paths.append((request.method, request.url.path))
            return await call_next(request)

        self.app = app


@pytest.fixture()
def lab():
    with lab_server.LabTlsServer() as server:
        yield server


@pytest.fixture()
def client(tmp_path, lab, monkeypatch):
    monkeypatch.setenv("CANARYGATE_TARGETLAB_CA", str(lab_server.TARGETLAB_CERT))
    database = tmp_path / "lab-sci.sqlite3"
    with TestClient(create_app(database)) as api:
        api.database_path = database
        yield api


def start(api, port, **extra):
    response = api.post("/api/lab-sci-scans", json={"port": port, **extra})
    assert response.status_code == 201, response.text
    return response.json()


def test_the_real_interaction_is_confirmed_from_verified_evidence(client, lab):
    run = start(client, lab.port)
    assert run["mode"] == "targetlab_sci"
    assert run["integration_origin"] == "loopback_lab"
    assert run["network_transport_enabled"] is True
    assert run["transport"]["destination"] == "127.0.0.1"
    assert run["transport"]["live_target_contacted"] is False
    assert run["transport"]["tls_verification"] == "pinned_test_ca_with_hostname_check"
    assert run["interaction_kind"] == "AUTHN+AUTHZ"
    assert run["controls"] == ["Authentication", "Authorization"]
    assert run["policy_source"] == "targetlab declared interaction policy"

    baselines = {item["id"]: item for item in run["baselines"]}
    assert set(baselines) == {"SCI-AUTHZ", "SCI-AUTHN"}
    assert baselines["SCI-AUTHZ"]["control"] == "Authorization"
    assert baselines["SCI-AUTHZ"]["endpoint"] == "GET /records/{id}/guarded"
    assert baselines["SCI-AUTHZ"]["verdict"] == "SAFE"
    assert baselines["SCI-AUTHZ"]["evidence"]["status"] == 403
    assert baselines["SCI-AUTHN"]["control"] == "Authentication"
    assert baselines["SCI-AUTHN"]["endpoint"] == "POST /login"
    assert baselines["SCI-AUTHN"]["probe"] == "wrong_password"
    assert baselines["SCI-AUTHN"]["verdict"] == "SAFE"
    assert baselines["SCI-AUTHN"]["evidence"]["status"] == 401

    combined = run["combined"]
    assert combined["endpoint"] == "GET /records/{id}/guarded"
    assert combined["action"] == "get_after"
    assert combined["executed"] is True and combined["permitted"] is True
    assert combined["verified"] is True
    assert combined["status"] == 200
    assert combined["impact"] == "private_data"

    assert run["verdict"] == "CONFIRMED"
    assert run["attribution"] == "interaction_induced"
    assert run["remediation_key"] == "sci_authentication" and run["remediation"]
    assert all(run["checklist"].values())

    assert run["disclosure"]["owner_baseline_collected"] is True
    assert run["disclosure"]["marker_matches_owner_baseline"] is True
    assert run["disclosure"]["marker_withheld"] is True
    assert run["disclosure"]["owner"] == "sakshi" and run["disclosure"]["actor"] == "mallapa"
    assert run["ownership"]["status"] == "SUCCESS"
    assert run["ownership"]["cross_list_isolated"] is True
    assert run["requests_sent"] == 11 and run["budget_remaining"] == 5
    assert run["blocked_by_guard"] == 0
    assert client.get(f"/api/lab-sci-scans/{run['id']}").json()["verdict"] == "CONFIRMED"


def test_the_scanner_never_requests_the_lab_ground_truth(tmp_path, monkeypatch):
    recording = Recording()
    monkeypatch.setenv("CANARYGATE_TARGETLAB_CA", str(lab_server.TARGETLAB_CERT))
    with lab_server.LabTlsServer(app=recording.app) as lab:
        with TestClient(create_app(tmp_path / "no-answer-key.sqlite3")) as api:
            run = start(api, lab.port)
    assert run["verdict"] == "CONFIRMED"
    paths = [path for _, path in recording.paths]
    assert not any(path.startswith("/lab/") for path in paths)
    assert set(recording.paths) <= {("POST", "/login"), ("GET", "/profile"), ("GET", "/records"),
                                    ("GET", "/records/MKT-2026-041/guarded"), ("GET", "/records/BRD-2026-018/guarded")}
    # The exact declared sequence: two logins, then the interaction on the guarded route.
    # sakshi's owner baseline, then mallapa's denial, then mallapa's combined read
    assert recording.paths.count(("GET", "/records/BRD-2026-018/guarded")) == 3
    assert recording.paths.count(("POST", "/login")) == 3


def test_ground_truth_evaluation_cannot_change_the_stored_run(client, lab, monkeypatch):
    run = start(client, lab.port)
    before = client.get(f"/api/lab-sci-scans/{run['id']}").content
    report = client.get(f"/api/lab-sci-scans/{run['id']}/report",
                        params={"view": "sections"}).json()
    assert report["sections"]["evaluation"]["total"] == 1
    assert report["sections"]["evaluation"]["matched"] == 1
    assert report["sections"]["evaluation"]["used_as_decision_input"] is False

    import canarygate.scan.lab_sci_scenarios as scenarios

    monkeypatch.setattr(scenarios, "EXPECTED",
                        {key: "SAFE" for key in scenarios.EXPECTED})
    after = client.get(f"/api/lab-sci-scans/{run['id']}").content
    assert after == before  # stored verdict and evidence are byte-identical
    changed = client.get(f"/api/lab-sci-scans/{run['id']}/report",
                         params={"view": "sections"}).json()
    assert changed["sections"]["evaluation"]["matched"] == 0
    assert changed["sections"]["decision"]["verdict"] == "CONFIRMED"


def test_the_reset_proof_is_separate_and_does_not_change_the_primary_run(client, lab):
    run = start(client, lab.port)
    stored = client.get(f"/api/lab-sci-scans/{run['id']}").content
    response = client.post("/api/lab-sci-resets", json={"port": lab.port})
    assert response.status_code == 201, response.text
    proof = response.json()
    assert proof["mode"] == "targetlab_sci_reset"
    assert proof["status"] == "proven"
    checks = {item["id"]: item for item in proof["checks"]}
    assert checks["RESET-01"]["status"] == 403 and checks["RESET-01"]["passed"] is True
    assert checks["RESET-02"]["status"] == 401 and checks["RESET-02"]["passed"] is True
    assert checks["RESET-03"]["status"] == 200 and checks["RESET-03"]["passed"] is True
    assert checks["RESET-04"]["status"] == 403 and checks["RESET-04"]["passed"] is True
    assert proof["isolation"]["runners"] == 2
    assert proof["isolation"]["state"] == "fresh_run_clears_the_condition"
    assert proof["disclosure"]["marker_matches_owner_baseline"] is True
    assert proof["disclosure"]["marker_withheld"] is True
    assert proof["requests"]["total"] == 8
    assert proof["requests"]["runner_a"] == 7 and proof["requests"]["runner_b"] == 1
    assert client.get(f"/api/lab-sci-resets/{proof['id']}").json()["status"] == "proven"
    attached = client.get(f"/api/lab-sci-scans/{run['id']}/report",
                          params={"view": "sections", "reset": proof["id"]}).json()
    assert attached["sections"]["reset_verification"]["status"] == "proven"
    assert len(attached["sections"]["reset_verification"]["checks"]) == 4
    assert client.get(f"/api/lab-sci-scans/{run['id']}/report",
                      params={"view": "sections", "reset": "0" * 8}).status_code == 404
    # The primary run is untouched: same bytes, same verdict.
    assert client.get(f"/api/lab-sci-scans/{run['id']}").content == stored


def test_repeated_runs_are_deterministic_and_state_independent(client, lab):
    first = start(client, lab.port)
    second = start(client, lab.port)
    assert first["verdict"] == second["verdict"] == "CONFIRMED"
    assert [item["verdict"] for item in first["baselines"]] == \
        [item["verdict"] for item in second["baselines"]]
    assert first["combined"]["status"] == second["combined"]["status"] == 200
    assert first["requests_sent"] == second["requests_sent"] == 11


def test_p0_report_projects_the_interaction_into_the_frozen_nine_sections(client, lab):
    run = start(client, lab.port)
    report = client.get(f"/api/lab-sci-scans/{run['id']}/report",
                        params={"view": "p0"}).json()
    assert report["mode"] == "targetlab_sci"
    sections = report["sections"]
    assert list(sections) == ["executive_summary", "scope_and_rules", "endpoint_inventory",
                              "findings", "secured_endpoints", "skipped_and_inconclusive",
                              "authorization_matrix", "manual_interventions_and_inferences",
                              "constraint_checklist"]
    findings = [item for items in sections["findings"].values() for item in items]
    assert len(findings) == 1
    finding = findings[0]
    assert finding["id"] == "SCI-01" and finding["category"] == "Authorization"
    assert finding["verdict"] == "CONFIRMED" and finding["severity"] == "High"
    assert finding["remediation_key"] == "sci_authentication"
    assert finding["finding_kind"] == "interaction"
    assert finding["interaction"]["kind"] == "AUTHN+AUTHZ"
    assert finding["interaction"]["attribution"] == "interaction_induced"
    assert [item["id"] for item in finding["interaction"]["baselines"]] == ["SCI-AUTHZ",
                                                                           "SCI-AUTHN"]
    assert finding["expected"] and finding["observed"] and finding["expectation_source"]
    assert sections["executive_summary"]["network_transport_enabled"] is True
    assert sections["executive_summary"]["live_target_contacted"] is False
    assert sections["constraint_checklist"]["loopback_lab_contacted"] is True
    inferences = sections["manual_interventions_and_inferences"]["inferences"]
    assert any(item["item"] == "ground_truth_independence" for item in inferences)
    interventions = sections["manual_interventions_and_inferences"]["interventions"]
    assert any(item["item"] == "sci_baselines" for item in interventions)
    assert any(item["item"] == "reset_verification" for item in interventions)
    matrix = sections["authorization_matrix"]
    cells = {(row["endpoint"], cell["column"]): cell
             for row in matrix["rows"] for cell in row["cells"]}
    guarded = cells[("GET /records/{id}/guarded", "other_account_resource")]
    assert guarded["state"] == "red" and guarded["verdict"] == "CONFIRMED"
    assert guarded["source_ref"].startswith("lab_sci:")


def test_the_aggregate_matrix_includes_the_lab_sci_cell(client, lab):
    start(client, lab.port)
    matrix = client.get("/api/authorization-matrix").json()
    cells = {(row["endpoint"], cell["column"]): cell
             for row in matrix["rows"] for cell in row["cells"]}
    guarded = cells[("GET /records/{id}/guarded", "other_account_resource")]
    assert guarded["state"] == "red" and "lab_sci:" in guarded["source_ref"]
    assert matrix["coverage"]["scope"] == "partial_offline"


def test_no_credentials_markers_or_bodies_are_stored(client, lab):
    run = start(client, lab.port)
    proof = client.post("/api/lab-sci-resets", json={"port": lab.port}).json()
    sections = client.get(f"/api/lab-sci-scans/{run['id']}/report",
                          params={"view": "sections"}).text
    p0 = client.get(f"/api/lab-sci-scans/{run['id']}/report", params={"view": "p0"}).text
    page = client.get(f"/api/lab-sci-scans/{run['id']}/report", params={"format": "html"}).text
    assert "control interaction" in page and "Controlled validation" in page
    raw = client.database_path.read_bytes().decode("utf-8", errors="ignore")
    combined = "\n".join((json.dumps(run), json.dumps(proof), sections, p0, page, raw))
    for secret in FORBIDDEN:
        assert secret not in combined, secret[:24]
    assert "$TOKEN_" in combined


def test_runs_survive_restart_and_tampering_is_rejected(client, lab):
    run = start(client, lab.port)
    proof = client.post("/api/lab-sci-resets", json={"port": lab.port}).json()
    path = client.database_path
    with TestClient(create_app(path)) as restarted:
        assert restarted.get(f"/api/lab-sci-scans/{run['id']}").json()["verdict"] == "CONFIRMED"
        assert restarted.get(f"/api/lab-sci-resets/{proof['id']}").json()["status"] == "proven"
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE lab_sci_runs SET payload = replace(payload, "
                           "'\"verdict\":\"CONFIRMED\"', '\"verdict\":\"SAFE\"')")
        connection.commit()
    with TestClient(create_app(path), raise_server_exceptions=False) as tampered:
        assert tampered.get(f"/api/lab-sci-scans/{run['id']}").status_code == 500


def test_budget_exhaustion_never_confirms(client, lab):
    run = start(client, lab.port, request_budget=8)
    assert run["verdict"] != "CONFIRMED"
    assert run["blocked_by_guard"] >= 1
    assert run["budget_remaining"] == 0
    assert run["combined"]["executed"] is False
    assert [item["verdict"] for item in run["baselines"]].count("CONFIRMED") == 0
    assert run["status"] in {"completed", "failed"}


def test_missing_ca_and_unreachable_lab_store_nothing(tmp_path, monkeypatch, lab):
    database = tmp_path / "unreachable.sqlite3"
    with TestClient(create_app(database)) as api:
        assert api.post("/api/lab-sci-scans", json={"port": lab.port}).status_code == 400
        assert api.post("/api/lab-sci-resets", json={"port": lab.port}).status_code == 400
    monkeypatch.setenv("CANARYGATE_TARGETLAB_CA", str(lab_server.TARGETLAB_CERT))
    with TestClient(create_app(database)) as api:
        assert api.post("/api/lab-sci-scans",
                        json={"port": lab_server.free_port()}).status_code == 502
    assert LabSciStore(database).list() == []


def test_a_redirect_is_refused_rather_than_followed(tmp_path, monkeypatch):
    monkeypatch.setenv("CANARYGATE_TARGETLAB_CA", str(lab_server.TARGETLAB_CERT))
    database = tmp_path / "redirect.sqlite3"
    with lab_server.CountingTlsServer(redirect=True) as server:
        with TestClient(create_app(database)) as api:
            assert api.post("/api/lab-sci-scans", json={"port": server.port}).status_code == 502
        # One request only: the redirect was never followed.
        assert server.hits == 1
    assert LabSciStore(database).list() == []


def test_an_untrusted_certificate_is_refused(tmp_path, monkeypatch, lab):
    monkeypatch.setenv("CANARYGATE_TARGETLAB_CA", str(lab_server.OTHER_CERT))
    database = tmp_path / "bad-ca.sqlite3"
    with TestClient(create_app(database)) as api:
        assert api.post("/api/lab-sci-scans", json={"port": lab.port}).status_code == 502
    assert LabSciStore(database).list() == []


@pytest.mark.parametrize("payload", [{"port": 80}, {"port": 8765, "request_budget": 4},
                                     {"port": 8765, "hostname": "example.com"},
                                     {"port": 8765, "request_budget": 100}])
def test_invalid_scan_requests_are_rejected(client, payload):
    assert client.post("/api/lab-sci-scans", json=payload).status_code == 422


def test_the_workflow_reuses_the_single_sci_engine():
    import canarygate.scan.lab_sci as module

    source = open(module.__file__, encoding="utf-8").read()
    assert "from canarygate.oracles.interaction import" in source
    assert "decide(" in source
    for forbidden in ("def decide", "def credential_rejection_decision",
                      "def is_checked_denial", "EXPECTED"):
        assert forbidden not in source, forbidden
    assert DENIAL_BODY and REJECTION_BODY


def test_each_ordered_pair_runs_its_own_real_interaction(client, lab):
    """Any ordered pair of demo accounts reaches the same flaw with its own asset.

    The three pairs are the ones the demo catalog declares; each must confirm with
    the disclosure attributed to the selected owner and no other account's marker.
    """
    markers = {"mallapa": "targetlab-mallapa-private-marker",
               "sakshi": "targetlab-sakshi-private-marker",
               "harsha": "targetlab-harsha-private-marker"}
    pairs = (("mallapa", "sakshi"), ("sakshi", "harsha"), ("harsha", "mallapa"))
    for actor, owner in pairs:
        run = start(client, lab.port, actor=actor, owner=owner)
        assert run["verdict"] == "CONFIRMED", (actor, owner, run["reason"])
        assert run["disclosure"]["actor"] == actor
        assert run["disclosure"]["owner"] == owner
        assert run["disclosure"]["marker_matches_owner_baseline"] is True
        assert run["disclosure"]["marker_withheld"] is True
        payload = json.dumps(run)
        assert markers[owner] not in payload
        for other, marker in markers.items():
            if other != owner:
                assert marker not in payload
        assert run["ownership"]["status"] == "SUCCESS"
        assert run["scope"]["accounts"] if "accounts" in run["scope"] else True
        assert run["requests_sent"] == 11 and run["blocked_by_guard"] == 0


def test_the_reset_proof_follows_the_selected_pair(client, lab):
    proof = client.post("/api/lab-sci-resets",
                        json={"port": lab.port, "actor": "harsha", "owner": "mallapa"}).json()
    assert proof["status"] == "proven"
    assert proof["disclosure"]["actor"] == "harsha"
    assert proof["disclosure"]["owner"] == "mallapa"
    assert proof["disclosure"]["marker_matches_owner_baseline"] is True
    assert "targetlab-mallapa-private-marker" not in json.dumps(proof)


def test_a_selection_without_two_distinct_provisioned_accounts_is_rejected(client, lab):
    """A pair that cannot be a cross-account read is refused before any request."""
    for payload in ({"actor": "mallapa", "owner": "mallapa"},
                    {"actor": "mallapa", "owner": "nobody"},
                    {"actor": "admin", "owner": "sakshi"}):
        response = client.post("/api/lab-sci-scans", json={"port": lab.port, **payload})
        assert response.status_code == 400, (payload, response.text)
