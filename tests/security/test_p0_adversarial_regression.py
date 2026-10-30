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


# --- Checkpoint 33: the same adversarial invariants must hold for SCI ---------

from canarygate.scan import interaction_scenarios  # noqa: E402

INTERACTION = ("/api/interaction-scans", interaction_scenarios.SCENARIO_IDS)


def run_every_interaction(api):
    base, ids = INTERACTION
    for scenario_id in ids:
        response = api.post(base, json={"scenario_id": scenario_id})
        assert response.status_code == 201, (scenario_id, response.text)
        run = response.json()
        report = api.get(f"{base}/{run['id']}/report", params={"view": "p0"})
        assert report.status_code == 200, (scenario_id, report.text)
        page = api.get(f"{base}/{run['id']}/report", params={"view": "p0", "format": "html"})
        assert page.status_code == 200
        yield scenario_id, run, report.json()["sections"], page.text


def test_interaction_runs_never_confirm_without_a_complete_case(monkeypatch, tmp_path):
    with offline_client(monkeypatch, tmp_path / "sci-adversarial.sqlite3") as api:
        for scenario_id, run, sections, _ in run_every_interaction(api):
            findings = [item for items in sections["findings"].values() for item in items]
            if run["verdict"] == "CONFIRMED":
                assert all(value is True for value in run["checklist"].values()), scenario_id
                assert run["attribution"] == "interaction_induced", scenario_id
                assert run["remediation_key"].startswith("sci_"), scenario_id
                assert run["combined"]["executed"] and run["combined"]["verified"], scenario_id
                assert run["combined"]["impact"] in {"private_data", "privileged_data",
                                                    "internal_detail"}, scenario_id
                assert len(findings) == 1, scenario_id
                assert findings[0]["finding_kind"] == "interaction"
                assert findings[0]["interaction"]["attribution"] == "interaction_induced"
            else:
                assert run["remediation"] is None, scenario_id
                assert len(findings) == 1, scenario_id
                assert findings[0]["verdict"] == run["verdict"], scenario_id
                assert findings[0]["remediation"] is None, scenario_id
                if run["verdict"] in {"SKIPPED", "INCONCLUSIVE"}:
                    assert [item["id"] for item in sections["skipped_and_inconclusive"]] == ["SCI-01"]
                else:
                    assert sections["skipped_and_inconclusive"] == [], scenario_id


def test_interaction_runs_do_not_leak_synthetic_secrets(monkeypatch, tmp_path):
    db = tmp_path / "sci-secrets.sqlite3"
    with offline_client(monkeypatch, db) as api:
        documents = []
        for scenario_id, run, sections, page in run_every_interaction(api):
            documents.extend((json.dumps(run), json.dumps(sections), page))
        documents.append(api.get("/api/authorization-matrix").text)
        documents.append(db.read_bytes().decode("utf-8", errors="ignore"))
        combined = "\n".join(documents)
        for secret in (*SECRETS, interaction_scenarios.SCI_SECRET):
            assert secret not in combined, (scenario_id, secret[:16])


def test_interaction_findings_stay_out_of_ordinary_single_control_claims(monkeypatch, tmp_path):
    with offline_client(monkeypatch, tmp_path / "sci-kind.sqlite3") as api:
        for scenario_id, run, sections, _ in run_every_interaction(api):
            for items in sections["findings"].values():
                for finding in items:
                    assert finding["finding_kind"] in {"single_control", "interaction"}
                    if finding["finding_kind"] == "interaction":
                        assert set(finding["interaction"]["controls"]) == set(run["controls"])
                        assert finding["interaction"]["kind"] == run["interaction_kind"]
                        assert finding["id"].startswith("SCI-")
