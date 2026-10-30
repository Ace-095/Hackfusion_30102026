"""The 3x3 TargetLab matrix, assembled from real loopback-TLS scans.

The lab is the real server on 127.0.0.1 with the pinned test CA. Every assertion
compares a matrix cell with the stored run it claims to come from; the matrix is
never allowed to invent a cell, merge two runs into one, or turn a missing result
into SAFE.
"""
import json

import pytest
from fastapi.testclient import TestClient

import targetlab.testing as lab_server
from canarygate.api.app import create_app

PAIRS = (("mallapa", "sakshi"), ("sakshi", "harsha"), ("harsha", "mallapa"))
ASSETS = {"mallapa": "MKT-2026-041", "sakshi": "BRD-2026-018", "harsha": "ADS-2026-027"}


@pytest.fixture()
def lab():
    with lab_server.LabTlsServer() as server:
        yield server


@pytest.fixture()
def client(tmp_path, lab, monkeypatch):
    monkeypatch.setenv("CANARYGATE_TARGETLAB_CA", str(lab_server.TARGETLAB_CERT))
    with TestClient(create_app(tmp_path / "matrix.sqlite3")) as api:
        yield api


def run_pair(api, port, actor, owner):
    response = api.post("/api/lab-bola-scans",
                        json={"port": port, "actor": actor, "owner": owner})
    assert response.status_code == 201, response.text
    return response.json()


def matrix(api):
    response = api.get("/api/lab-matrix")
    assert response.status_code == 200, response.text
    return response.json()


def cell(payload, requester, asset):
    return next(item for item in payload["cells"]
                if item["requester"] == requester and item["asset_id"] == asset)


def test_an_empty_store_is_nine_untested_cells(client):
    payload = matrix(client)
    assert payload["mode"] == "targetlab_matrix"
    assert payload["derived_from"] == "stored_lab_bola_runs"
    assert len(payload["cells"]) == 9
    assert payload["summary"] == {
        "cells": 9, "tested": 0, "untested": 9, "confirmed": 0, "suspected": 0,
        "safe": 0, "inconclusive": 0, "skipped": 0, "runs_considered": 0,
        "ports": [], "lab_instances": 0, "stale_cells": 0, "duplicated_cells": 0}
    for item in payload["cells"]:
        assert item["state"] == "untested" and item["verdict"] is None
        assert item["evidence"] is None and item["secure"] is None


def test_three_coverage_runs_answer_all_nine_cells(client, lab):
    runs = {pair: run_pair(client, lab.port, *pair) for pair in PAIRS}
    payload = matrix(client)
    summary = payload["summary"]
    assert summary["tested"] == 9 and summary["untested"] == 0
    assert summary["confirmed"] == 6 and summary["safe"] == 3
    assert summary["suspected"] == summary["inconclusive"] == summary["skipped"] == 0
    assert summary["runs_considered"] == 3 and summary["ports"] == [lab.port]
    assert summary["lab_instances"] == 1 and summary["stale_cells"] == 0
    assert summary["duplicated_cells"] == 3

    for item in payload["cells"]:
        assert item["state"] == "tested"
        diagonal = item["requester"] == item["owner"]
        assert item["kind"] == ("legitimate_owner_request" if diagonal
                                else "cross_account_attempt")
        assert item["expected_access"] == "owner-only"
        if diagonal:
            assert item["verdict"] == "SAFE"
            # An owner reading their own asset is a baseline read, not a disclosure.
            assert item["actual_access"] == "own_record_returned"
            assert item["secure"] is None
            assert item["sources"] == 2 and len(item["superseded_runs"]) == 1
            assert item["evidence"]["remediation"] is None
        else:
            assert item["verdict"] == "CONFIRMED"
            assert item["actual_access"] == "private_record_returned"
            assert item["evidence"]["remediation"], "a confirmed cell carries the oracle repair"
            assert item["secure"]["verdict"] == "SAFE"
            assert item["secure"]["status"] == 403
            assert item["secure"]["verified_denial"] is True
            assert item["sources"] == 1 and item["superseded_runs"] == []

        # The cell points at a check that really exists in the stored run it names.
        stored = client.get(f"/api/lab-bola-scans/{item['evidence']['run_id']}").json()
        match = next(check for check in stored["checks"]
                     if check["id"] == item["evidence"]["check_id"])
        assert match["actor"] == item["requester"]
        expected_owner = item["requester"] if diagonal else item["owner"]
        assert match["owner"] == expected_owner
        assert match["verdict"] == item["verdict"]
        assert match["status"] == item["evidence"]["status"]
        assert match["evidence_sha256"] == item["evidence"]["evidence_sha256"]
        assert stored["id"] in {run["id"] for run in runs.values()}
        assert item["evidence"]["evidence_id"] == f"{stored['id']}#{match['id']}"
        assert item["evidence"]["lab_instance"] == lab.instance_id


def test_each_cross_cell_links_the_same_run_as_its_secure_counterpart(client, lab):
    run_pair(client, lab.port, *PAIRS[0])
    payload = matrix(client)
    for item in payload["cells"]:
        if item["secure"] is None:
            continue
        assert item["secure"]["run_id"] == item["evidence"]["run_id"]
        stored = client.get(f"/api/lab-bola-scans/{item['evidence']['run_id']}").json()
        secure = next(check for check in stored["checks"]
                      if check["id"] == item["secure"]["check_id"])
        assert secure["direction"] == "cross_account_secure"
        assert secure["actor"] == item["requester"] and secure["owner"] == item["owner"]
        assert secure["status"] == 403 and secure["verdict"] == "SAFE"


def test_a_repeated_run_is_visible_as_a_superseded_duplicate(client, lab):
    first = run_pair(client, lab.port, "mallapa", "sakshi")
    second = run_pair(client, lab.port, "mallapa", "sakshi")
    item = cell(matrix(client), "mallapa", ASSETS["sakshi"])
    assert item["sources"] == 2
    assert item["evidence"]["run_id"] == second["id"]
    assert item["superseded_runs"] == [first["id"]]
    # Both runs are still readable; the matrix did not delete or rewrite either.
    assert client.get(f"/api/lab-bola-scans/{first['id']}").status_code == 200
    assert client.get(f"/api/lab-bola-scans/{second['id']}").status_code == 200


def test_evidence_from_a_previous_lab_instance_is_marked_stale(client, lab):
    run_pair(client, lab.port, "mallapa", "sakshi")
    with lab_server.LabTlsServer() as second_lab:
        run_pair(client, second_lab.port, "sakshi", "harsha")
        payload = matrix(client)
    assert payload["summary"]["ports"] == sorted({lab.port, second_lab.port})
    # The first run answered four cells; one of them is re-answered by the newer run on
    # the newer instance, so three selected cells come from the older instance.
    assert payload["summary"]["stale_cells"] == 3
    old = cell(payload, "mallapa", ASSETS["sakshi"])
    fresh = cell(payload, "sakshi", ASSETS["harsha"])
    assert old["stale"] is True and old["evidence"]["port"] == lab.port
    assert fresh["stale"] is False and fresh["evidence"]["port"] == second_lab.port
    # Staleness is a label, not a verdict change.
    assert old["verdict"] == "CONFIRMED" and old["evidence"]["run_id"]


def test_the_matrix_never_touches_the_lab_or_its_ground_truth(client, lab):
    recording = Recording()
    with lab_server.LabTlsServer(app=recording.app) as recorded_lab:
        run_pair(client, recorded_lab.port, "mallapa", "sakshi")
    before = list(recording.paths)
    payload = matrix(client)
    assert payload["summary"]["tested"] == 4
    assert recording.paths == before, "reading the matrix must not send a request"
    assert "/lab/ground-truth" not in recording.paths
    assert not any(path.startswith("/lab/") for path in recording.paths)


def test_the_matrix_is_read_only_and_stable(client, lab):
    run = run_pair(client, lab.port, "mallapa", "sakshi")
    stored_before = client.get(f"/api/lab-bola-scans/{run['id']}").content
    first = matrix(client)
    second = matrix(client)
    assert json.dumps(first["cells"], sort_keys=True) == json.dumps(second["cells"],
                                                                   sort_keys=True)
    assert client.get(f"/api/lab-bola-scans/{run['id']}").content == stored_before


class Recording:
    """Serve the real lab and remember which paths were requested."""

    def __init__(self):
        from targetlab.app import create_lab_app

        self.paths = []
        app = create_lab_app()

        @app.middleware("http")
        async def record(request, call_next):
            self.paths.append(request.url.path)
            return await call_next(request)

        self.app = app
