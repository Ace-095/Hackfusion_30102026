import hashlib
import json
import socket
import sqlite3

import pytest
from contextlib import closing

from fastapi.testclient import TestClient

from canarygate.api.app import create_app
from canarygate.database.store import FixtureStore
from canarygate.evidence.observations import prepare
from canarygate.evidence.redaction import canonical_json, digest
from canarygate.offline.scan import run_fixture
from canarygate.offline.target import FixtureTarget


def test_observation_api_and_report_bundle_survive_restart_without_network(tmp_path, monkeypatch):
    db = tmp_path / "fixture.sqlite3"
    def no_network(*args, **kwargs):
        raise AssertionError("fixture attempted network or DNS")
    with TestClient(create_app(db)) as client:
        with monkeypatch.context() as isolated:
            isolated.setattr(socket.socket, "connect", no_network)
            isolated.setattr(socket, "getaddrinfo", no_network)
            response = client.post("/api/scan")
            assert response.status_code == 201
            run = response.json()
            assert run["verdict"] == "CONFIRMED"
            page = client.get(f"/api/scan/{run['id']}/observations").json()
            assert page["mode"] == "fixture" and page["coverage"] == "RECORDED"
            observations = page["observations"]
            assert [(item["phase"], item["actor"]) for item in observations] == [
                ("discovery", "alice"), ("discovery", "bob"),
                ("owner_baseline", "alice"), ("owner_baseline", "bob"),
                ("cross_user_read", "alice")]
            for item in observations:
                summary = {key: value for key, value in item.items() if key not in {"sha256", "redacted"}}
                assert item["sha256"] == digest(summary)
                assert item["request"]["authorization"] == "[REDACTED]"
            assert observations[0]["response"]["items"] == [{"id": "alice-item", "owner": "alice", "private_field_present": False}]
            assert observations[1]["response"]["items"] == [{"id": "bob-item", "owner": "bob", "private_field_present": False}]
            assert observations[0]["assertions"]["peer_resource_excluded"] is True
            assert observations[1]["assertions"]["peer_resource_excluded"] is True
            assert observations[3]["assertions"]["canary_matches_recipe"] is True
            assert observations[4]["assertions"]["private_data_matches_owner_baseline"] is True
            assert observations[4]["response"]["item"]["private_field_present"] is True
            bundle = client.get(f"/api/reports/{run['id']}?include_observations=true").json()
            assert bundle == {"run": run, "observation_set": page}
            # The original JSON response remains backwards compatible.
            assert client.get(f"/api/reports/{run['id']}").json() == run
            html = client.get(f"/api/reports/{run['id']}?format=html").text
            assert "Ownership and cross-user observations" in html and "Local fixture reproduction" in html
            assert "starts a new local fixture scan" in html
            assert "fixture.invalid" not in html or "curl -sS -X POST &quot;https://fixture.invalid" not in html
            serialized = json.dumps(bundle) + html
            for secret in ("fixture-token-alice", "fixture-token-bob", "synthetic-bob-private-canary", "synthetic-alice-private-note"):
                assert secret not in serialized
    with TestClient(create_app(db)) as client:
        assert client.get(f"/api/scan/{run['id']}/observations").json() == page
        assert client.get(f"/api/reports/{run['id']}?include_observations=true").json() == bundle
    data = db.read_bytes()
    for secret in (b"fixture-token-alice", b"fixture-token-bob", b"synthetic-bob-private-canary", b"synthetic-alice-private-note"):
        assert secret not in data


def test_failed_ownership_and_denied_read_have_honest_observations(tmp_path):
    store = FixtureStore(tmp_path / "fixture.sqlite3")
    store.initialize()
    leaked = []
    skipped = run_fixture(FixtureTarget(cross_list_leak=True), observation_sink=leaked)
    assert skipped["verdict"] == "SKIPPED" and len(leaked) == 2
    assert leaked[0]["assertions"]["peer_resource_excluded"] is False
    assert not any(o["phase"] == "cross_user_read" for o in leaked)
    store.save(skipped, leaked)
    assert store.get_observations(skipped["id"]) == prepare(leaked)
    denied = []
    safe = run_fixture(FixtureTarget(attacker_access="deny"), observation_sink=denied)
    assert safe["verdict"] == "SAFE" and len(denied) == 5
    assert denied[-1]["response"]["status_code"] == 403
    assert denied[-1]["assertions"]["private_data_matches_owner_baseline"] is False
    missing = []
    assert run_fixture(FixtureTarget(bob_login=False), observation_sink=missing)["verdict"] == "SKIPPED"
    assert missing == []


def test_pre_checkpoint_database_stays_readable_and_marks_observations_missing(tmp_path):
    db = tmp_path / "fixture.sqlite3"
    store = FixtureStore(db)
    store.initialize()
    run = store.save(run_fixture())  # Same shape as a pre-checkpoint stored run.
    with closing(sqlite3.connect(db)) as conn, conn:
        conn.execute("DROP TABLE fixture_observation_sets")  # Simulate the earlier schema.
    with TestClient(create_app(db)) as client:
        assert client.get(f"/api/scan/{run['id']}").json() == run
        page = client.get(f"/api/scan/{run['id']}/observations").json()
        assert page == {"mode": "fixture", "run_id": run["id"], "coverage": "NOT_RECORDED", "observations": []}
        assert "Not recorded for this earlier fixture run" in client.get(f"/api/reports/{run['id']}?format=html").text
        assert client.get("/api/scan/not-a-run/observations").status_code == 404


@pytest.mark.parametrize("recompute", [False, True])
def test_tampered_observation_set_fails_closed_even_with_set_hash_recomputed(tmp_path, recompute):
    db = tmp_path / "fixture.sqlite3"
    with TestClient(create_app(db)) as client:
        run = client.post("/api/scan").json()
    with closing(sqlite3.connect(db)) as conn, conn:
        row = conn.execute("SELECT payload FROM fixture_observation_sets WHERE run_id=?", (run["id"],)).fetchone()
        observations = json.loads(row[0])
        observations[0]["assertions"]["peer_resource_excluded"] = False
        payload = canonical_json(observations)
        if recompute:
            conn.execute("UPDATE fixture_observation_sets SET payload=?, sha256=? WHERE run_id=?",
                         (payload, hashlib.sha256(payload.encode()).hexdigest(), run["id"]))
        else:
            conn.execute("UPDATE fixture_observation_sets SET payload=? WHERE run_id=?", (payload, run["id"]))
    with TestClient(create_app(db)) as client:
        for path in (f"/api/scan/{run['id']}/observations", f"/api/reports/{run['id']}?include_observations=true", f"/api/reports/{run['id']}?format=html"):
            response = client.get(path)
            assert response.status_code == 500
            assert response.json()["detail"] == "Stored fixture data failed integrity verification"
        # Existing base report remains independently verifiable.
        assert client.get(f"/api/reports/{run['id']}").json() == run


@pytest.mark.parametrize("behavior,status", [("unauthorized", 401), ("not_found", 404), ("metadata", 200), ("redirect", 302)])
def test_inconclusive_cross_user_response_is_not_fabricated_as_disclosure(behavior, status):
    observations = []
    run = run_fixture(FixtureTarget(attacker_access=behavior), observation_sink=observations)
    assert run["verdict"] == "INCONCLUSIVE"
    assert observations[-1]["phase"] == "cross_user_read"
    assert observations[-1]["response"]["status_code"] == status
    assert observations[-1]["assertions"]["private_data_matches_owner_baseline"] is False
    prepare(observations)


def test_partial_and_failed_baseline_observations_are_honest():
    no_resource = []
    result = run_fixture(FixtureTarget(alice_item_missing=True), observation_sink=no_resource)
    assert result["verdict"] == "SKIPPED"
    assert len(no_resource) == 1
    assert no_resource[0]["assertions"]["own_resource_identified"] is False
    assert no_resource[0]["assertions"]["peer_resource_excluded"] is None
    no_canary = []
    result = run_fixture(FixtureTarget(owner_sees_canary=False), observation_sink=no_canary)
    assert result["verdict"] == "SKIPPED"
    assert len(no_canary) == 4
    assert no_canary[-1]["assertions"]["owner_detail_matches"] is True
    assert no_canary[-1]["assertions"]["canary_matches_recipe"] is False
    assert all(item["phase"] != "cross_user_read" for item in no_canary)


def test_empty_recorded_set_and_jinja_html_autoescape(tmp_path):
    db = tmp_path / "fixture.sqlite3"
    store = FixtureStore(db)
    store.initialize()
    run = run_fixture()
    run["reason"] = '<script>alert("not executable")</script>'
    store.save(run, [])
    with TestClient(create_app(db)) as client:
        observations = client.get(f"/api/scan/{run['id']}/observations").json()
        assert observations["coverage"] == "RECORDED" and observations["observations"] == []
        html = client.get(f"/api/reports/{run['id']}?format=html").text
        assert '<script>alert(' not in html
        assert '&lt;script&gt;' in html
        assert "No observation claims are made" not in html


@pytest.mark.parametrize("table,path", [("fixture_runs", "report"), ("fixture_observation_sets", "observation")])
def test_non_ascii_checksum_corruption_returns_generic_error(tmp_path, table, path):
    db = tmp_path / "fixture.sqlite3"
    with TestClient(create_app(db)) as client:
        run = client.post("/api/scan").json()
    with closing(sqlite3.connect(db)) as conn, conn:
        conn.execute(f"UPDATE {table} SET sha256=? WHERE run_id=?", ("non-ascii-☃", run["id"]))
    endpoint = (f"/api/scan/{run['id']}" if path == "report" else f"/api/scan/{run['id']}/observations")
    with TestClient(create_app(db)) as client:
        response = client.get(endpoint)
        assert response.status_code == 500
        assert response.json()["detail"] == "Stored fixture data failed integrity verification"
