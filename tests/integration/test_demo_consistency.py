"""Checkpoint 38: the demo and the reporting surfaces must agree, every time.

These tests are the acceptance criteria for the stabilization checkpoint. They
run the four judge-demo stages from a clean start against a real loopback lab,
then compare what every surface says about the same evidence: the stored run, the
sections report, the frozen nine-section report, the HTML page and the
authorization matrix.

The negative tests matter as much as the positive ones: a checker that cannot
detect a tampered surface proves nothing about the untampered ones.
"""
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import targetlab.testing as lab_server
from canarygate.api.app import create_app

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import demo_kit  # noqa: E402


@pytest.fixture()
def lab():
    with lab_server.LabTlsServer() as server:
        yield server


@pytest.fixture()
def client(tmp_path, lab, monkeypatch):
    monkeypatch.setenv("CANARYGATE_TARGETLAB_CA", str(lab_server.TARGETLAB_CERT))
    database = tmp_path / "demo.sqlite3"
    with TestClient(create_app(database)) as api:
        api.database_path = database
        yield api


def demo(client, lab):
    return demo_kit.run_demo(client, port=lab.port)


# --------------------------------------------------------------- the four stages
def test_the_four_demo_stages_run_from_a_clean_start_and_agree(client, lab):
    bundle = demo(client, lab)
    assert [stage["id"] for stage in bundle["stages"]] == ["bola", "bola_secure", "sci", "reset"]
    verdicts = {stage["id"]: stage["verdict"] for stage in bundle["stages"]}
    assert verdicts == {"bola": "CONFIRMED", "bola_secure": "SAFE",
                        "sci": "CONFIRMED", "reset": "proven"}
    assert bundle["problems"] == [], "\n".join(str(item) for item in bundle["problems"])
    assert bundle["surfaces_checked"] >= 8
    assert bundle["invariants_checked"] >= 40


def test_the_demo_is_repeatable_and_state_independent(tmp_path, lab, monkeypatch):
    monkeypatch.setenv("CANARYGATE_TARGETLAB_CA", str(lab_server.TARGETLAB_CERT))
    summaries = []
    for index in range(2):
        with TestClient(create_app(tmp_path / f"repeat-{index}.sqlite3")) as api:
            summaries.append(demo_kit.run_demo(api, port=lab.port)["summary"])
    assert summaries[0] == summaries[1]
    assert summaries[0]["stages"]["bola"]["requests_sent"] == 18
    assert summaries[0]["stages"]["sci"]["requests_sent"] == 11
    assert summaries[0]["stages"]["reset"]["requests_sent"] == 8


def test_each_stage_reports_the_numbers_the_demo_claims(client, lab):
    bundle = demo(client, lab)
    stages = {stage["id"]: stage for stage in bundle["stages"]}
    bola = stages["bola"]
    assert bola["checks"]["LAB-BOLA-03"] == "CONFIRMED"
    assert bola["checks"]["LAB-BOLA-04"] == "CONFIRMED"
    assert bola["statuses"]["LAB-BOLA-03"] == 200
    assert bola["statuses"]["LAB-BOLA-05"] == 403
    assert stages["bola_secure"]["checks"]["LAB-BOLA-05"] == "SAFE"
    assert stages["bola_secure"]["checks"]["LAB-BOLA-06"] == "SAFE"
    sci = stages["sci"]
    assert sci["attribution"] == "interaction_induced"
    assert sci["baselines"] == {"SCI-AUTHZ": "SAFE", "SCI-AUTHN": "SAFE"}
    assert (sci["statuses"]["SCI-AUTHZ"], sci["statuses"]["SCI-AUTHN"],
            sci["combined_status"]) == (403, 401, 200)
    assert stages["reset"]["statuses"] == [403, 401, 200, 403]


# ------------------------------------------------------- evidence integrity
def test_no_evidence_is_missing_duplicated_or_contradictory(client, lab):
    bundle = demo(client, lab)
    assert demo_kit.check_evidence_integrity(bundle) == []
    # Every check appears exactly once in its run, in its report and in the matrix.
    bola = next(stage for stage in bundle["stages"] if stage["id"] == "bola")
    assert len(bola["checks"]) == 6
    assert len(set(bola["digests"].values())) == 6
    sci = next(stage for stage in bundle["stages"] if stage["id"] == "sci")
    assert len(set(sci["digests"].values())) == 2


def test_the_checker_detects_a_tampered_surface(client, lab):
    bundle = demo(client, lab)
    bola = next(stage for stage in bundle["stages"] if stage["id"] == "bola")
    # 1. The nine-section report disagrees with the stored verdict.
    tampered = json.loads(json.dumps(bola["p0"]))
    for items in tampered["sections"]["findings"].values():
        for finding in items:
            if finding["id"] == "LAB-BOLA-03":
                finding["verdict"] = "SAFE"
    problems = demo_kit.compare_surfaces(bola, p0=tampered)
    assert any(problem.code == "p0-verdict-mismatch" for problem in problems), problems
    # 2. The sections report disagrees with the request accounting.
    tampered = json.loads(json.dumps(bola["sections"]))
    tampered["sections"]["constraints"]["requests_sent"] = 3
    problems = demo_kit.compare_surfaces(bola, sections=tampered)
    assert any(problem.code == "accounting-mismatch" for problem in problems), problems
    # 3. A finding disappears from the report.
    tampered = json.loads(json.dumps(bola["p0"]))
    for items in tampered["sections"]["findings"].values():
        items[:] = [item for item in items if item["id"] != "LAB-BOLA-06"]
    problems = demo_kit.compare_surfaces(bola, p0=tampered)
    assert any(problem.code == "p0-finding-missing" for problem in problems), problems
    # 4. Two checks share one evidence digest.
    tampered = json.loads(json.dumps(bola["run"]))
    tampered["checks"][1]["evidence_sha256"] = tampered["checks"][0]["evidence_sha256"]
    problems = demo_kit.compare_surfaces(bola, run=tampered)
    assert any(problem.code == "duplicate-evidence-digest" for problem in problems), problems


def test_the_matrix_cell_must_match_the_stored_verdict(client, lab):
    bundle = demo(client, lab)
    sci = next(stage for stage in bundle["stages"] if stage["id"] == "sci")
    tampered = json.loads(json.dumps(sci["matrix"]))
    for row in tampered["rows"]:
        for cell in row["cells"]:
            if "guarded" in row["endpoint"] and cell["column"] == "other_account_resource":
                cell["verdict"] = "SAFE"
                cell["state"] = "green"
    problems = demo_kit.compare_surfaces(sci, matrix=tampered)
    assert any(problem.code == "matrix-verdict-mismatch" for problem in problems), problems


def test_the_database_row_must_hash_to_its_payload(client, lab):
    demo(client, lab)
    path = client.database_path
    with sqlite3.connect(path) as connection:
        row = connection.execute("SELECT run_id, payload, sha256 FROM lab_bola_runs").fetchone()
        assert row is not None
        payload = json.loads(row[1])
        assert payload["verdict"] == "CONFIRMED"
        payload["verdict"] = "SAFE"
        connection.execute("UPDATE lab_bola_runs SET payload = ? WHERE run_id = ?",
                           (json.dumps(payload, sort_keys=True), row[0]))
        connection.commit()
    problems = demo_kit.check_database_integrity(path)
    assert any(problem.code == "database-hash-mismatch" for problem in problems), problems


# ------------------------------------------------------------ safety recheck
def test_no_surface_claims_live_validation_or_leaks_a_secret(client, lab):
    bundle = demo(client, lab)
    assert demo_kit.check_honesty_and_redaction(bundle) == []
    raw = client.database_path.read_bytes().decode("utf-8", errors="ignore")
    for secret in demo_kit.LAB_SECRETS:
        assert secret not in raw, secret[:20]
    for stage in bundle["stages"]:
        assert stage["transport"]["destination"] == "127.0.0.1"
        assert stage["transport"]["tls_verification"] == "pinned_test_ca_with_hostname_check"
        assert stage["transport"]["redirects"] == "refused"
        assert stage["transport"]["retries"] == "none"
        assert stage["transport"]["dns"] == "not_used"
        assert stage["transport"]["live_target_contacted"] is False
        assert stage["requests_sent"] <= stage["request_budget"]


def test_the_static_safety_sweep_passes_on_this_repository():
    problems = demo_kit.safety_sweep(ROOT)
    assert problems == [], "\n".join(str(item) for item in problems)


def test_the_sweep_detects_a_forbidden_pattern(tmp_path):
    planted = tmp_path / "canarygate" / "network"
    planted.mkdir(parents=True)
    (planted / "bad.py").write_text("import httpx\nhttpx.get('https://x', verify=False)\n",
                                    encoding="utf-8")
    problems = demo_kit.safety_sweep(tmp_path)
    assert any(problem.code == "forbidden-verify-disabled" for problem in problems), problems


# ------------------------------------------------------------------ the CLI
def test_the_demo_script_runs_from_a_clean_start_and_exits_zero(tmp_path):
    database = tmp_path / "cli.sqlite3"
    result = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "demo.py"), "--database", str(database),
         "--json", str(tmp_path / "summary.json")],
        cwd=str(ROOT), capture_output=True, text=True, timeout=300)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "STAGE 1" in result.stdout and "STAGE 4" in result.stdout
    assert "ALL CONSISTENCY CHECKS PASSED" in result.stdout
    summary = json.loads((tmp_path / "summary.json").read_text())
    assert summary["ok"] is True
    assert summary["stages"]["bola"]["verdict"] == "CONFIRMED"
    assert summary["stages"]["reset"]["verdict"] == "proven"
    assert summary["problems"] == []


def test_the_consistency_audit_reports_a_clean_store(client, lab, tmp_path):
    demo(client, lab)
    result = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "consistency_audit.py"),
         "--database", str(client.database_path), "--json", str(tmp_path / "audit.json")],
        cwd=str(ROOT), capture_output=True, text=True, timeout=300)
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads((tmp_path / "audit.json").read_text())
    assert report["ok"] is True
    assert report["runs_checked"] == 3  # bola, sci, reset proof
    assert report["problems"] == []
