"""Cross-component consistency: runner results, storage, API, both reports, matrix.

Stage C of the P0 acceptance audit. Every run is a bundled synthetic offline run;
sockets and DNS are patched to fail inside each client block.
"""
import socket
from contextlib import contextmanager

import pytest
from fastapi.testclient import TestClient

from canarygate.api.app import create_app

KINDS = {
    "scenario": ("/api/scenario-scans", "synthetic-vulnerable"),
    "authentication": ("/api/authentication-scans", "synthetic-jwt-sub-confirmed"),
    "validation": ("/api/validation-scans", "synthetic-validation-weak"),
}

# Worse wins: red > orange > green > grey > hatched. A per-run report may never
# look worse than the aggregate that contains it.
STATE_RANK = {"red": 4, "orange": 3, "green": 2, "grey": 1, "hatched": 0}


def forbidden(*args, **kwargs):
    raise AssertionError("network or DNS attempted by an offline consistency test")


@contextmanager
def offline_client(monkeypatch, path):
    with TestClient(create_app(path)) as api:
        with monkeypatch.context() as guard:
            guard.setattr(socket.socket, "connect", forbidden)
            guard.setattr(socket, "getaddrinfo", forbidden)
            yield api


def start(api, kind):
    base, scenario_id = KINDS[kind]
    response = api.post(base, json={"scenario_id": scenario_id})
    assert response.status_code == 201, response.text
    return response.json()


def p0(api, kind, run_id):
    base, _ = KINDS[kind]
    response = api.get(f"{base}/{run_id}/report", params={"view": "p0"})
    assert response.status_code == 200, response.text
    return response.json()


def stored_verdicts(kind, run):
    if kind == "scenario":
        return [run["verdict"]]
    return [check["verdict"] for check in run["checks"]]


def test_legacy_and_p0_reports_never_share_a_run_or_a_claim(monkeypatch, tmp_path):
    with offline_client(monkeypatch, tmp_path / "consistency.sqlite3") as api:
        fixture = api.post("/api/scan").json()
        scenario = start(api, "scenario")

        legacy = api.get(f"/api/reports/{fixture['id']}")
        assert legacy.status_code == 200
        assert legacy.json()["mode"] == "fixture"
        assert api.get(f"/api/reports/{scenario['id']}").status_code == 404

        assert api.get(f"/api/scenario-scans/{fixture['id']}/report",
                       params={"view": "p0"}).status_code == 404
        assert p0(api, "scenario", scenario["id"])["run_kind"] == "scenario"

        html = api.get(f"/api/reports/{fixture['id']}", params={"format": "html"}).text
        # The legacy page is a fixture reproduction, not the frozen contract.
        assert "frozen nine sections" not in html
        assert legacy.json().get("sections") is None

        report = p0(api, "scenario", scenario["id"])
        assert report["mode"] == "offline_scenario"
        assert report["sections"]["executive_summary"]["run_kind"] == "scenario"
        assert "fixture" not in report["mode"]


@pytest.mark.parametrize("kind", sorted(KINDS))
def test_report_counts_are_derived_from_the_stored_run(monkeypatch, tmp_path, kind):
    with offline_client(monkeypatch, tmp_path / f"{kind}-counts.sqlite3") as api:
        run = start(api, kind)
        report = p0(api, kind, run["id"])["sections"]
        counts = report["executive_summary"]["verdict_counts"]
        assert sum(counts.values()) == report["executive_summary"]["finding_count"]
        expected = stored_verdicts(kind, run)
        for verdict in counts:
            assert counts[verdict] == expected.count(verdict)
        findings = [item for items in report["findings"].values() for item in items]
        assert len(findings) == len(expected)
        assert sorted(item["verdict"] for item in findings) == sorted(expected)
        # Every non-SAFE, non-CONFIRMED result is listed explicitly, never dropped.
        explicit = len(report["skipped_and_inconclusive"])
        assert explicit == counts["SKIPPED"] + counts["INCONCLUSIVE"]
        # Secured endpoints only ever contain results that really are SAFE.
        safe_ids = {item["id"] for items in report["findings"].values()
                    for item in items if item["verdict"] == "SAFE"}
        assert {item["id"] for item in report["secured_endpoints"]} <= safe_ids


def test_report_matrix_never_looks_worse_than_the_aggregate(monkeypatch, tmp_path):
    with offline_client(monkeypatch, tmp_path / "matrix.sqlite3") as api:
        runs = {kind: start(api, kind) for kind in sorted(KINDS)}
        aggregate = api.get("/api/authorization-matrix").json()
        assert aggregate["coverage"]["rows"] > 0
        indexed = {(row["endpoint"], cell["column"]): cell
                   for row in aggregate["rows"] for cell in row["cells"]}
        assert len(indexed) == aggregate["coverage"]["cells"]
        endpoints = {row["endpoint"] for row in aggregate["rows"]}

        for kind, run in runs.items():
            matrix = p0(api, kind, run["id"])["sections"]["authorization_matrix"]
            for row in matrix["rows"]:
                assert row["endpoint"] in endpoints
                for cell in row["cells"]:
                    merged = indexed[(row["endpoint"], cell["column"])]
                    assert STATE_RANK[merged["state"]] >= STATE_RANK[cell["state"]], (
                        f"aggregate hid {kind} severity for {row['endpoint']} {cell['column']}")
                    if cell["state"] != "hatched":
                        assert merged["tested"] is True


def test_matrix_coverage_maths_holds_and_every_gap_is_explained(monkeypatch, tmp_path):
    with offline_client(monkeypatch, tmp_path / "coverage.sqlite3") as api:
        for kind in sorted(KINDS):
            start(api, kind)
        matrix = api.get("/api/authorization-matrix").json()
        coverage = matrix["coverage"]
        assert coverage["cells"] == coverage["rows"] * len(matrix["columns"])
        assert coverage["tested"] + coverage["untested"] == coverage["cells"]
        assert sum(coverage["by_state"].values()) == coverage["cells"]
        assert coverage["scope"] == "partial_offline"
        assert "not evidence of correct behaviour" in coverage["statement"]
        for row in matrix["rows"]:
            assert [cell["column"] for cell in row["cells"]] == matrix["columns"]
            for cell in row["cells"]:
                if cell["state"] == "hatched":
                    assert cell["tested"] is False and cell["verdict"] is None
                    assert cell["reason"]
                else:
                    assert cell["tested"] is True and cell["reason"]
                    assert (cell["verdict"] is None) == (cell["state"] == "grey")
