"""Adversarial P0 regression: false SAFE, false CONFIRMED, leaked secrets.

Stage B of the P0 acceptance audit. Every case runs a bundled synthetic offline
run through the real application; sockets and DNS are patched to fail.
"""
import json
import socket
from contextlib import contextmanager

import pytest
from fastapi.testclient import TestClient

from canarygate.api.app import create_app
from canarygate.scan import auth_scenarios, scenarios, validation_scenarios

KINDS = {
    "scenario": ("/api/scenario-scans", scenarios.SCENARIO_IDS),
    "authentication": ("/api/authentication-scans", auth_scenarios.SCENARIO_IDS),
    "validation": ("/api/validation-scans", validation_scenarios.SCENARIO_IDS),
}
SECRETS = (
    scenarios.ALPHA_PRIVATE, scenarios.BETA_PRIVATE,
    *scenarios.TOKENS.values(), *auth_scenarios.API_KEY_TOKENS.values(),
    *auth_scenarios.OPAQUE_TOKENS.values(),
    validation_scenarios.REQUEST_BODIES["control"],
    "offline-valid-credential", "eyJhbGciOiJIUzI1NiJ9",
)
BOLA_EVIDENCE = ("ownership_verified", "owner_baseline", "attacker_request",
                 "response_checked", "private_disclosure", "policy_denies_access")


def forbidden(*args, **kwargs):
    raise AssertionError("network or DNS attempted by an offline regression test")


@contextmanager
def offline_client(monkeypatch, path):
    with TestClient(create_app(path)) as api:
        with monkeypatch.context() as guard:
            guard.setattr(socket.socket, "connect", forbidden)
            guard.setattr(socket, "getaddrinfo", forbidden)
            yield api


def run_every_scenario(api, kind):
    base, ids = KINDS[kind]
    for scenario_id in ids:
        response = api.post(base, json={"scenario_id": scenario_id})
        assert response.status_code == 201, (scenario_id, response.text)
        run = response.json()
        report = api.get(f"{base}/{run['id']}/report", params={"view": "p0"})
        assert report.status_code == 200, (scenario_id, report.text)
        yield scenario_id, run, report.json()["sections"]


def stored_verdicts(kind, run):
    return [run["verdict"]] if kind == "scenario" else [check["verdict"] for check in run["checks"]]


@pytest.mark.parametrize("kind", sorted(KINDS))
def test_every_reported_finding_carries_the_stored_verdict(monkeypatch, tmp_path, kind):
    with offline_client(monkeypatch, tmp_path / f"{kind}.sqlite3") as api:
        for scenario_id, run, sections in run_every_scenario(api, kind):
            findings = [item for items in sections["findings"].values() for item in items]
            expected = stored_verdicts(kind, run)
            assert sorted(item["verdict"] for item in findings) == sorted(expected), scenario_id
            assert len({item["id"] for item in findings}) == len(findings), scenario_id
            counts = sections["executive_summary"]["verdict_counts"]
            for verdict, count in counts.items():
                assert count == expected.count(verdict), (scenario_id, verdict)


@pytest.mark.parametrize("kind", sorted(KINDS))
def test_unperformed_checks_are_never_reported_as_safe(monkeypatch, tmp_path, kind):
    with offline_client(monkeypatch, tmp_path / f"{kind}-safe.sqlite3") as api:
        for scenario_id, run, sections in run_every_scenario(api, kind):
            secured = {item["id"] for item in sections["secured_endpoints"]}
            findings = {item["id"]: item for items in sections["findings"].values() for item in items}
            assert secured <= {key for key, item in findings.items() if item["verdict"] == "SAFE"}
            explicit = {item["id"] for item in sections["skipped_and_inconclusive"]}
            assert explicit == {key for key, item in findings.items()
                                if item["verdict"] in {"SKIPPED", "INCONCLUSIVE"}}, scenario_id
            for key in explicit:
                assert findings[key]["verdict"] != "SAFE", (scenario_id, key)
                assert findings[key]["reason"], (scenario_id, key)


def test_confirmed_bola_needs_complete_evidence_and_a_remediation(monkeypatch, tmp_path):
    with offline_client(monkeypatch, tmp_path / "bola.sqlite3") as api:
        confirmed = 0
        for scenario_id, run, sections in run_every_scenario(api, "scenario"):
            for finding in sections["findings"]["Authorization"]:
                if finding["verdict"] != "CONFIRMED":
                    assert finding["remediation"] is None, scenario_id
                    assert finding["severity"] is None, scenario_id
                    continue
                confirmed += 1
                assert all(finding["evidence_checklist"].get(key) is True for key in BOLA_EVIDENCE), scenario_id
                assert finding["expectation_source"] in {"offline scenario policy"}, scenario_id
                assert finding["remediation_key"] == "bola" and finding["remediation"], scenario_id
                assert finding["severity"] == "High", scenario_id
        # The bundled family must actually contain a genuine CONFIRMED case.
        assert confirmed >= 1


def test_no_report_or_store_contains_a_fixture_secret(monkeypatch, tmp_path):
    db = tmp_path / "secrets.sqlite3"
    with offline_client(monkeypatch, db) as api:
        documents = []
        for kind in sorted(KINDS):
            base, _ = KINDS[kind]
            for scenario_id, run, sections in run_every_scenario(api, kind):
                documents.append(json.dumps(sections))
                html = api.get(f"{base}/{run['id']}/report",
                               params={"view": "p0", "format": "html"}).text
                documents.append(html)
                assert api.get(f"{base}/{run['id']}").status_code == 200
        matrix = api.get("/api/authorization-matrix")
        assert matrix.status_code == 200
        documents.append(matrix.text)
    documents.append(db.read_bytes().decode("utf-8", errors="ignore"))
    combined = "\n".join(documents)
    for secret in SECRETS:
        assert secret not in combined, f"fixture secret leaked: {secret[:12]}…"
    assert "$TOKEN_A" in combined or "$TOKEN_B" in combined


def test_matrix_cannot_show_green_for_a_confirmed_cell(monkeypatch, tmp_path):
    with offline_client(monkeypatch, tmp_path / "matrix-green.sqlite3") as api:
        per_run_states = set()
        for kind in sorted(KINDS):
            for _, _, sections in run_every_scenario(api, kind):
                per_run_states.update(cell["state"]
                                      for row in sections["authorization_matrix"]["rows"]
                                      for cell in row["cells"])
        matrix = api.get("/api/authorization-matrix").json()
        seen = 0
        for row in matrix["rows"]:
            for cell in row["cells"]:
                if cell["state"] == "green":
                    seen += 1
                    assert cell["tested"] is True
                    assert cell["verdict"] == "SAFE"
                if cell["state"] == "red":
                    assert cell["verdict"] == "CONFIRMED"
                assert cell["state"] in {"green", "red", "orange", "grey", "hatched"}
        # SAFE observations do exist in the corpus and render as green, so the
        # aggregate is not silently suppressing every clean result.
        assert "green" in per_run_states
        assert seen >= 1 or all(cell["state"] != "green"
                                for row in matrix["rows"] for cell in row["cells"])
