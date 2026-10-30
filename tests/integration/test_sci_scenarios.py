"""SCI end to end: combined interactions executed through the real application.

Every case is a bundled synthetic offline scenario; sockets and DNS are patched to
fail inside each client block, so a combined exchange that tried to reach the
network would fail the test rather than silently pass.
"""
import json
import socket
from contextlib import contextmanager

import pytest
from fastapi.testclient import TestClient

from canarygate.api.app import create_app
from canarygate.evidence.redaction import REDACTED, redact

SENTINEL = "sci-interaction-secret-value"

CASES = {
    "synthetic-sci-authz-input-confirmed": ("CONFIRMED", "interaction_induced", "AUTHZ+INPUT_VALIDATION"),
    "synthetic-sci-authz-input-secure": ("SAFE", "no_failure", "AUTHZ+INPUT_VALIDATION"),
    "synthetic-sci-individual-failure": ("INCONCLUSIVE", "individual_failure", "AUTHZ+INPUT_VALIDATION"),
    "synthetic-sci-incomplete-baseline": ("INCONCLUSIVE", "incomplete_baseline", "AUTHZ+INPUT_VALIDATION"),
    "synthetic-sci-unpermitted": ("SKIPPED", "not_permitted", "AUTHZ+INPUT_VALIDATION"),
    "synthetic-sci-budget-exhausted": ("SKIPPED", "not_permitted", "AUTHZ+INPUT_VALIDATION"),
    "synthetic-sci-secret-redaction": ("CONFIRMED", "interaction_induced", "AUTHZ+INPUT_VALIDATION"),
    "synthetic-sci-variation": ("SUSPECTED", "no_demonstrated_impact", "AUTHZ+INPUT_VALIDATION"),
    "synthetic-sci-authn-authz": ("CONFIRMED", "interaction_induced", "AUTHN+AUTHZ"),
    "synthetic-sci-input-disclosure": ("CONFIRMED", "interaction_induced",
                                       "INPUT_VALIDATION+INFORMATION_DISCLOSURE"),
}


def forbidden(*args, **kwargs):
    raise AssertionError("network or DNS attempted by an offline SCI run")


@contextmanager
def offline_client(monkeypatch, path):
    with TestClient(create_app(path)) as api:
        with monkeypatch.context() as guard:
            guard.setattr(socket.socket, "connect", forbidden)
            guard.setattr(socket, "getaddrinfo", forbidden)
            yield api


def start(api, scenario_id):
    response = api.post("/api/interaction-scans", json={"scenario_id": scenario_id})
    assert response.status_code == 201, response.text
    return response.json()


@pytest.mark.parametrize("scenario_id,expected", sorted(CASES.items()))
def test_interaction_scenarios_execute_through_the_application(monkeypatch, tmp_path, scenario_id, expected):
    verdict, attribution, kind = expected
    with offline_client(monkeypatch, tmp_path / "sci.sqlite3") as api:
        run = start(api, scenario_id)
        assert run["verdict"] == verdict
        assert run["attribution"] == attribution
        assert run["interaction_kind"] == kind
        assert run["mode"] == "offline_interaction"
        assert run["network_transport_enabled"] is False
        assert run["status"] == "completed"
        assert len(run["baselines"]) >= 2
        assert all(item["verdict"] in {"CONFIRMED", "SUSPECTED", "SAFE", "INCONCLUSIVE", "SKIPPED"}
                   for item in run["baselines"])
        assert run["combined"]["executed"] in {True, False}
        assert len(run["transcript_sha256"]) == 64
        assert api.get(f"/api/interaction-scans/{run['id']}").json()["id"] == run["id"]


def test_confirmed_interaction_explains_both_baselines_and_redacts_the_secret(monkeypatch, tmp_path):
    db = tmp_path / "sci-explain.sqlite3"
    with offline_client(monkeypatch, db) as api:
        run = start(api, "synthetic-sci-secret-redaction")
        assert run["verdict"] == "CONFIRMED"
        assert run["remediation_key"] == "sci_authorization" and run["remediation"]
        assert all(item["evidence_sha256"] and len(item["evidence_sha256"]) == 64
                   for item in run["baselines"])
        combined = run["combined"]
        assert combined["status"] == 200 and combined["impact"] == "privileged_data"
        assert combined["verified"] is True
        assert all(value is True for value in run["checklist"].values())
        report = api.get(f"/api/interaction-scans/{run['id']}/report",
                         params={"view": "sections"}).json()
        assert report["mode"] == "offline_interaction"
        sections = report["sections"]
        assert sections["decision"]["verdict"] == "CONFIRMED"
        assert [item["id"] for item in sections["baselines"]] == ["AUTHZ-01", "INPUT-07"]
        html = api.get(f"/api/interaction-scans/{run['id']}/report",
                       params={"format": "html"}).text
        assert "CONFIRMED" in html and "interaction" in html.lower()
        p0 = api.get(f"/api/interaction-scans/{run['id']}/report", params={"view": "p0"}).json()
        findings = [item for items in p0["sections"]["findings"].values() for item in items]
        assert len(findings) == 1
        finding = findings[0]
        assert finding["finding_kind"] == "interaction"
        assert finding["interaction"]["kind"] == "AUTHZ+INPUT_VALIDATION"
        assert finding["interaction"]["attribution"] == "interaction_induced"
        assert len(finding["interaction"]["baselines"]) == 2
        assert finding["interaction"]["combined"]["impact"] == "privileged_data"
        for document in (json.dumps(run), json.dumps(sections), json.dumps(p0), html,
                         api.get("/api/authorization-matrix").text):
            assert SENTINEL not in document
    assert SENTINEL.encode() not in db.read_bytes()
    # Redaction is real, not merely an absence: the same sentinel sitting under a
    # non-sensitive key is rewritten, so no report path can echo it back.
    assert redact({"email": SENTINEL}) == {"email": REDACTED}
    assert redact({"note": f"user {SENTINEL} seen"}) == {"note": f"user {REDACTED} seen"}


def test_unpermitted_interaction_is_blocked_by_the_guard_not_simulated(monkeypatch, tmp_path):
    with offline_client(monkeypatch, tmp_path / "sci-blocked.sqlite3") as api:
        run = start(api, "synthetic-sci-unpermitted")
        assert run["verdict"] == "SKIPPED"
        assert run["combined"]["executed"] is False
        assert run["combined"]["permitted"] is False
        assert run["blocked_by_guard"] >= 1
        assert "scope" in run["reason"].lower() or "guard" in run["reason"].lower()
        assert api.get(f"/api/interaction-scans/{run['id']}/report",
                       params={"view": "p0"}).json()["sections"]["skipped_and_inconclusive"]


def test_budget_exhaustion_is_reported_and_never_confirmed(monkeypatch, tmp_path):
    with offline_client(monkeypatch, tmp_path / "sci-budget.sqlite3") as api:
        run = start(api, "synthetic-sci-budget-exhausted")
        assert run["verdict"] == "SKIPPED"
        assert "budget" in (run["reason"] + run["combined"]["observed"]).lower()
        assert run["budget_remaining"] == 0
        assert run["verdict"] != "CONFIRMED"


def test_individual_failure_keeps_the_individual_finding_and_blocks_sci(monkeypatch, tmp_path):
    with offline_client(monkeypatch, tmp_path / "sci-individual.sqlite3") as api:
        run = start(api, "synthetic-sci-individual-failure")
        assert run["verdict"] == "INCONCLUSIVE"
        assert run["attribution"] == "individual_failure"
        failing = [item for item in run["baselines"] if item["verdict"] == "CONFIRMED"]
        assert failing and failing[0]["id"] == "AUTHZ-01"
        assert "AUTHZ-01" in run["reason"]
        assert run["remediation_key"] is None


@pytest.mark.parametrize("scenario_id", ["synthetic-sci-authz-input-confirmed",
                                         "synthetic-sci-authn-authz",
                                         "synthetic-sci-input-disclosure"])
def test_interaction_findings_are_distinguishable_in_the_matrix(monkeypatch, tmp_path, scenario_id):
    with offline_client(monkeypatch, tmp_path / f"{scenario_id}.sqlite3") as api:
        run = start(api, scenario_id)
        matrix = api.get("/api/authorization-matrix").json()
        assert matrix["coverage"]["scope"] == "partial_offline"
        sources = [cell["source_ref"] for row in matrix["rows"] for cell in row["cells"]]
        if run["interaction_kind"] == "INPUT_VALIDATION+INFORMATION_DISCLOSURE":
            # A disclosure interaction makes no authorization claim, so it must not
            # appear as a matrix verdict; the endpoint stays visible as untested.
            assert not any("interaction:" in item for item in sources)
            assert matrix["coverage"]["untested"] > 0
        else:
            assert any("interaction:" in item for item in sources)
            assert matrix["verdict_counts"]["CONFIRMED"] >= 1
        assert matrix["coverage"]["statement"]


def test_runs_survive_restart_and_tampered_payloads_are_rejected(monkeypatch, tmp_path):
    import sqlite3

    db = tmp_path / "sci-restart.sqlite3"
    with offline_client(monkeypatch, db) as api:
        run = start(api, "synthetic-sci-authz-input-confirmed")
    with TestClient(create_app(db)) as api:
        assert api.get(f"/api/interaction-scans/{run['id']}").status_code == 200
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE interaction_runs SET payload = ? WHERE run_id = ?",
                     (json.dumps({**run, "verdict": "SAFE"}), run["id"]))
    with TestClient(create_app(db)) as api:
        assert api.get(f"/api/interaction-scans/{run['id']}").status_code == 500


def test_api_rejects_unknown_scenarios_and_widened_payloads(monkeypatch, tmp_path):
    with offline_client(monkeypatch, tmp_path / "sci-errors.sqlite3") as api:
        assert api.post("/api/interaction-scans", json={"scenario_id": "nope"}).status_code == 404
        assert api.post("/api/interaction-scans", json={
            "scenario_id": "synthetic-sci-authz-input-confirmed", "target": "https://example.com"
        }).status_code == 422
        assert api.get("/api/interaction-scans/00000000-0000-0000-0000-000000000000"
                       ).status_code == 404
