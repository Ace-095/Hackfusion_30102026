import hashlib
import json
import socket
import sqlite3
from contextlib import closing
from importlib import import_module

from fastapi.testclient import TestClient

from canarygate.api.app import create_app
from canarygate.evidence.redaction import canonical_json


def test_scan_reports_survive_restart_and_store_no_fixture_credentials(tmp_path, monkeypatch):
    database = tmp_path / "fixture.sqlite3"
    def no_network(*args, **kwargs):
        raise AssertionError("fixture tried to reach a network or DNS")

    # Let Windows create its internal event-loop socketpair, then block all
    # scanner network and DNS access for the duration of each client session.
    with TestClient(create_app(database)) as client:
        with monkeypatch.context() as isolated:
            isolated.setattr(socket.socket, "connect", no_network)
            isolated.setattr(socket, "getaddrinfo", no_network)
            run = client.post("/api/scan").json()
            assert run["mode"] == "fixture" and run["verdict"] == "CONFIRMED"
            assert run["inventory"] and len(run["spec_hash"]) == 64
            assert client.get(f"/api/reports/{run['id']}").json() == run

    with TestClient(create_app(database)) as client:
        with monkeypatch.context() as isolated:
            isolated.setattr(socket.socket, "connect", no_network)
            isolated.setattr(socket, "getaddrinfo", no_network)
            assert client.get(f"/api/scan/{run['id']}").json() == run
            assert client.get(f"/api/reports/{run['id']}").json() == run
            assert "not live testing" in client.get(f"/api/reports/{run['id']}?format=html").text
            assert client.get("/api/setup/status").json()["setup"] == run["setup"]
            assert run["id"] in [entry["id"] for entry in client.get("/api/findings").json()["findings"]]
            assert run["id"] in [entry["id"] for entry in client.get("/api/matrix").json()["cells"]]

    assert database.exists()
    forbidden = (b"fixture-token-alice", b"fixture-token-bob", b"synthetic-alice-private-note",
                 b"synthetic-bob-private-canary", b"malformed-fixture", b"synthetic-fixture")
    for file in tmp_path.glob("fixture.sqlite3*"):
        content = file.read_bytes()
        assert all(secret not in content for secret in forbidden)


def test_report_uses_persisted_inventory_not_a_changed_current_spec(tmp_path, monkeypatch):
    database = tmp_path / "fixture.sqlite3"
    with TestClient(create_app(database)) as client:
        run = client.post("/api/scan").json()
    api = import_module("canarygate.api.app")
    monkeypatch.setattr(api, "inventory", lambda: [])
    with TestClient(create_app(database)) as client:
        assert client.get("/api/endpoints").json()["endpoints"] == []
        report = client.get(f"/api/reports/{run['id']}?format=html")
        assert report.status_code == 200 and "/items/{id}" in report.text
        assert client.get(f"/api/scan/{run['id']}").json()["inventory"] == run["inventory"]


def test_corrupt_report_is_not_served(tmp_path):
    database = tmp_path / "fixture.sqlite3"
    with TestClient(create_app(database)) as client:
        run = client.post("/api/scan").json()
    with closing(sqlite3.connect(database)) as conn, conn:
        conn.execute("UPDATE fixture_runs SET payload = ? WHERE run_id = ?", ('{"tampered":true}', run["id"]))
    with TestClient(create_app(database)) as client:
        response = client.get(f"/api/reports/{run['id']}")
        assert response.status_code == 500
        assert response.json()["detail"] == "Stored fixture data failed integrity verification"


def test_corrupt_evidence_is_rejected_even_when_report_hash_is_recomputed(tmp_path):
    database = tmp_path / "fixture.sqlite3"
    with TestClient(create_app(database)) as client:
        run = client.post("/api/scan").json()
    with closing(sqlite3.connect(database)) as conn, conn:
        payload = json.loads(conn.execute("SELECT payload FROM fixture_runs WHERE run_id = ?", (run["id"],)).fetchone()[0])
        payload["evidence"]["disclosure"]["status_code"] = 403
        changed = canonical_json(payload)
        checksum = hashlib.sha256(changed.encode()).hexdigest()
        conn.execute("UPDATE fixture_runs SET payload = ?, sha256 = ? WHERE run_id = ?", (changed, checksum, run["id"]))
    with TestClient(create_app(database)) as client:
        response = client.get(f"/api/scan/{run['id']}")
        assert response.status_code == 500
        assert response.json()["detail"] == "Stored fixture data failed integrity verification"


def test_storage_failure_returns_generic_error_without_secret_details(tmp_path, monkeypatch):
    application = create_app(tmp_path / "fixture.sqlite3")
    with TestClient(application) as client:
        def fail_save(*_):
            raise sqlite3.OperationalError("internal db message with secret-token")
        monkeypatch.setattr(application.state.store, "save", fail_save)
        response = client.post("/api/scan")
        assert response.status_code == 500
        assert response.json()["detail"] == "Fixture storage unavailable or invalid"
        assert "secret-token" not in response.text
        assert client.get("/api/findings").json()["findings"] == []


def test_sql_injection_like_run_id_cannot_read_or_delete_other_runs(tmp_path):
    with TestClient(create_app(tmp_path / "fixture.sqlite3")) as client:
        run = client.post("/api/scan").json()
        response = client.get("/api/scan/%27%20OR%201%3D1--")
        assert response.status_code == 404
        assert client.get(f"/api/scan/{run['id']}").json()["id"] == run["id"]


def test_unknown_stored_fields_fail_closed_even_with_valid_report_hash(tmp_path):
    database = tmp_path / "fixture.sqlite3"
    with TestClient(create_app(database)) as client:
        run = client.post("/api/scan").json()
    with closing(sqlite3.connect(database)) as conn, conn:
        payload = json.loads(conn.execute("SELECT payload FROM fixture_runs WHERE run_id = ?", (run["id"],)).fetchone()[0])
        payload["unexpected"] = "do-not-serve"
        changed = canonical_json(payload)
        checksum = hashlib.sha256(changed.encode()).hexdigest()
        conn.execute("UPDATE fixture_runs SET payload = ?, sha256 = ? WHERE run_id = ?", (changed, checksum, run["id"]))
    with TestClient(create_app(database)) as client:
        response = client.get(f"/api/scan/{run['id']}")
        assert response.status_code == 500
        assert "do-not-serve" not in response.text
