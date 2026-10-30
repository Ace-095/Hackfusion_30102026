"""TargetLab evidence scans through the real application over loopback HTTPS.

These are the first tests in the suite that open a socket: a real uvicorn server
serving TargetLab over TLS on 127.0.0.1 with an ephemeral port. Nothing leaves
the machine, and the application can only reach that address because the scope
mode is ``local_lab``.
"""
import json
import socket

import pytest
from fastapi.testclient import TestClient

import targetlab.testing as lab_server
from canarygate.api.app import create_app
from canarygate.database.lab_store import LabStore

FORBIDDEN_IN_OUTPUT = ("lab-token-alice", "lab-token-bob", "alice-lab-password",
                       "bob-lab-password", "targetlab-bob-private-marker",
                       "targetlab-alice-private-marker")


@pytest.fixture()
def lab():
    with lab_server.LabTlsServer() as server:
        yield server


@pytest.fixture()
def client(tmp_path, lab, monkeypatch):
    monkeypatch.setenv("CANARYGATE_TARGETLAB_CA", str(lab_server.TARGETLAB_CERT))
    database = tmp_path / "targetlab.sqlite3"
    with TestClient(create_app(database)) as api:
        api.database_path = database
        yield api


def start(api, port, **extra):
    payload = {"port": port, **extra}
    response = api.post("/api/lab-scans", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def test_scan_runs_through_the_application_and_collects_evidence(client, lab):
    run = start(client, lab.port)
    assert run["mode"] == "targetlab_https"
    assert run["status"] == "completed"
    assert run["transport"]["destination"] == "127.0.0.1"
    assert run["transport"]["network_transport_enabled"] is True
    assert run["transport"]["production_networking"] is False
    assert len(run["checks"]) == 7
    observations = {check["id"]: check["observation"] for check in run["checks"]}
    assert observations == {"LAB-01": "allowed_owner", "LAB-02": "allowed_owner",
                            "LAB-03": "allowed_owner", "LAB-04": "allowed_owner",
                            "LAB-05": "allowed_other", "LAB-06": "denied", "LAB-07": "denied"}
    assert run["summary"]["allowed"] == 5 and run["summary"]["denied"] == 2
    assert run["constraints"]["requests_sent"] == 9
    stored = client.get(f"/api/lab-scans/{run['id']}")
    assert stored.status_code == 200 and stored.json()["id"] == run["id"]


def test_report_sections_and_html_are_labeled_as_controlled_validation(client, lab):
    run = start(client, lab.port)
    sections = client.get(f"/api/lab-scans/{run['id']}/report",
                          params={"view": "sections"}).json()
    assert sections["mode"] == "targetlab_https"
    data = sections["sections"]
    assert set(data) == {"executive_summary", "scope_and_transport", "checks",
                         "constraints", "limitations"}
    assert len(data["checks"]) == 7
    assert data["scope_and_transport"]["destination"] == "127.0.0.1"
    assert data["scope_and_transport"]["redirects"] == "refused"
    assert data["scope_and_transport"]["dns"] == "not_used"
    page = client.get(f"/api/lab-scans/{run['id']}/report", params={"format": "html"}).text
    assert "Controlled validation, not live validation" in page
    assert "127.0.0.1" in page and "LAB-05" in page
    assert page.count("allowed_other") >= 1


def test_no_credentials_markers_or_bodies_are_stored_anywhere(client, lab):
    run = start(client, lab.port)
    sections = client.get(f"/api/lab-scans/{run['id']}/report",
                          params={"view": "sections"}).text
    page = client.get(f"/api/lab-scans/{run['id']}/report", params={"format": "html"}).text
    raw = client.database_path.read_bytes().decode("utf-8", errors="ignore")
    combined = "\n".join((json.dumps(run), sections, page, raw))
    for secret in FORBIDDEN_IN_OUTPUT:
        assert secret not in combined, secret[:20]


def test_runs_survive_restart_and_tampering_is_rejected(client, lab):
    run = start(client, lab.port)
    path = client.database_path
    with TestClient(create_app(path)) as restarted:
        assert restarted.get(f"/api/lab-scans/{run['id']}").status_code == 200
    import sqlite3
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE lab_runs SET payload = replace(payload, '\"status\":\"completed\"', "
                           "'\"status\":\"failed\"')")
        connection.commit()
    with TestClient(create_app(path), raise_server_exceptions=False) as tampered:
        assert tampered.get(f"/api/lab-scans/{run['id']}").status_code == 500


def test_missing_ca_configuration_is_refused_without_contacting_the_lab(tmp_path, lab):
    database = tmp_path / "no-ca.sqlite3"
    with TestClient(create_app(database)) as api:
        response = api.post("/api/lab-scans", json={"port": lab.port})
        assert response.status_code == 400
        assert "CANARYGATE_TARGETLAB_CA" in response.json()["detail"]
    assert LabStore(database).list() == []


def test_an_unreachable_lab_stores_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv("CANARYGATE_TARGETLAB_CA", str(lab_server.TARGETLAB_CERT))
    database = tmp_path / "unreachable.sqlite3"
    with TestClient(create_app(database)) as api:
        response = api.post("/api/lab-scans", json={"port": lab_server.free_port()})
        assert response.status_code == 502
    assert LabStore(database).list() == []


@pytest.mark.parametrize("payload", [{"port": 80}, {"port": 8765, "request_budget": 3},
                                     {"port": 8765, "hostname": "example.com"},
                                     {"port": "8765"}])
def test_invalid_scan_requests_are_rejected(client, payload):
    assert client.post("/api/lab-scans", json=payload).status_code == 422


def test_the_transport_refuses_a_scope_that_is_not_local_lab():
    from canarygate.network.targetlab import TargetLabRefused, TargetLabTransport
    from canarygate.scope.authorized import AuthorizedScope

    competition = AuthorizedScope.model_validate({
        "mode": "competition", "scheme": "https", "hostname": "api.organizer.example",
        "port": 443, "organizer_ip": "203.0.113.10",
        "written_authorization_reference": "competition-approval-001",
        "allowed_methods": ["GET"], "request_budget": 5,
        "accounts": [{"account": "account-a", "role": "user"}],
        "operations": [{"method": "GET", "path": "/profile", "classification": "READ_ONLY"}],
    })
    with pytest.raises(TargetLabRefused):
        TargetLabTransport(competition, ca_file=lab_server.TARGETLAB_CERT)


def test_rejected_requests_never_leave_the_process(lab, monkeypatch):
    """A refused path must not open a socket at all."""
    opened = []
    real_socket = socket.socket

    class SpySocket(real_socket):
        def connect(self, address):
            opened.append(address)
            return super().connect(address)

    with monkeypatch.context() as guard:
        guard.setattr(socket, "socket", SpySocket)
        from canarygate.network.targetlab import TargetLabRefused, TargetLabTransport
        from canarygate.scan.lab_scenarios import build_lab_scope

        transport = TargetLabTransport(build_lab_scope(lab.port),
                                       ca_file=lab_server.TARGETLAB_CERT)
        with pytest.raises(TargetLabRefused):
            transport.request("alice", "GET", "/lab/ground-truth", token="lab-token-alice")
    assert opened == []
