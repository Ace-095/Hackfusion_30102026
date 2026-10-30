"""Contract tests for targetlab, the deliberately vulnerable local test API.

TargetLab exists so CanaryGate can be validated against a real server whose
ground truth is known. These tests pin the ground truth itself: which endpoints
are deliberately broken, which are secure, and exactly what the interaction
sequence (deny -> reject -> leak) does. If the lab drifts, later live-validation
results become meaningless, so the drift must fail here first.

The lab is loopback-only and makes no outbound request; both are asserted.
"""
import json
import socket
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from targetlab.app import LOOPBACK_HOSTS, create_lab_app
from targetlab.state import ASSET_BY_OWNER, LAB_ACCOUNTS, PRIVATE_MARKERS, TRACE_MARKER

BASE_URL = "http://127.0.0.1"


@pytest.fixture()
def lab():
    with TestClient(create_lab_app(), base_url=BASE_URL) as client:
        yield client


def login(client, username, password=None):
    account = LAB_ACCOUNTS[username]
    response = client.post("/login", json={"username": username,
                                           "password": password or account["password"]})
    assert response.status_code == 200, response.text
    return response.json()["token"]


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def test_the_lab_documents_three_independent_accounts_with_private_markers():
    """The demo tenant is three colleagues, one private asset each.

    The accounts differ in which asset they own, not in the kind of grant they hold:
    every role is descriptive metadata and no route authorizes on it.
    """
    assert set(LAB_ACCOUNTS) == {"mallapa", "sakshi", "harsha"}
    for name, account in LAB_ACCOUNTS.items():
        assert account["password"] and account["token"] and account["title"]
        assert account["role"] not in {"admin", "user"}, "roles are descriptive, not capabilities"
    assert len({account["token"] for account in LAB_ACCOUNTS.values()}) == 3
    assert set(PRIVATE_MARKERS) == {"mallapa", "sakshi", "harsha"}
    assert len(set(PRIVATE_MARKERS.values())) == 3
    assert set(ASSET_BY_OWNER) == {"mallapa", "sakshi", "harsha"}
    assert len(set(ASSET_BY_OWNER.values())) == 3


def test_login_returns_identity_and_rejects_bad_credentials(lab):
    token = login(lab, "mallapa")
    profile = lab.get("/profile", headers=auth(token)).json()
    assert profile["identity"] == "mallapa"
    assert profile["role"] == LAB_ACCOUNTS["mallapa"]["role"] == "marketing_manager"
    bad = lab.post("/login", json={"username": "mallapa", "password": "wrong"})
    assert bad.status_code == 401
    assert "mallapa-lab-password" not in bad.text


def test_anonymous_access_is_rejected_everywhere_except_health_and_errors(lab):
    for path in ("/profile", "/records/MKT-2026-041", "/records/BRD-2026-018/secure", "/records/BRD-2026-018/guarded",
                 "/admin/users"):
        response = lab.get(path)
        assert response.status_code == 401, path
        assert response.json() == {"error": "unauthorized"}
    assert lab.get("/health").status_code == 200


def test_admin_endpoint_denies_both_accounts(lab):
    for name in ("mallapa", "sakshi"):
        assert lab.get("/admin/users", headers=auth(login(lab, name))).status_code == 403


def test_vulnerable_endpoint_leaks_another_accounts_private_marker(lab):
    """Deliberate BOLA: the unprotected record route returns any owner's record."""
    mallapa = login(lab, "mallapa")
    stolen = lab.get("/records/BRD-2026-018", headers=auth(mallapa))
    assert stolen.status_code == 200
    assert stolen.json()["owner"] == "sakshi"
    assert PRIVATE_MARKERS["sakshi"] in stolen.json()["private_note"]


def test_secure_endpoint_enforces_ownership_in_both_directions(lab):
    mallapa, sakshi = login(lab, "mallapa"), login(lab, "sakshi")
    denied = lab.get("/records/BRD-2026-018/secure", headers=auth(mallapa))
    assert denied.status_code == 403 and denied.json() == {"error": "forbidden"}
    assert PRIVATE_MARKERS["sakshi"] not in denied.text
    owned = lab.get("/records/BRD-2026-018/secure", headers=auth(sakshi))
    assert owned.status_code == 200 and PRIVATE_MARKERS["sakshi"] in owned.json()["private_note"]
    # Mallapa reading her own resource is allowed and leaks nothing of Sakshi's.
    own = lab.get("/records/MKT-2026-041/secure", headers=auth(mallapa))
    assert own.status_code == 200 and PRIVATE_MARKERS["sakshi"] not in own.text


def test_the_full_interaction_sequence_denies_rejects_then_leaks(lab):
    """The exact sequence CanaryGate must reproduce against a live server.

    1. Mallapa requests Sakshi's private resource: denied.
    2. Mallapa submits malformed input: rejected with a bounded error.
    3. (Scanner records both baselines - out of scope for the lab.)
    4. The authorized combined condition executes.
    5. The API returns Sakshi's private marker.
    """
    mallapa = login(lab, "mallapa")
    before = lab.get("/records/BRD-2026-018/guarded", headers=auth(mallapa))
    assert before.status_code == 403
    assert PRIVATE_MARKERS["sakshi"] not in before.text

    rejected = lab.post("/login", json={"username": "mallapa", "password": "x", "admin": True})
    assert rejected.status_code == 422
    assert rejected.json() == {"error": "invalid_request"}
    assert "admin" not in rejected.text

    after = lab.get("/records/BRD-2026-018/guarded", headers=auth(mallapa))
    assert after.status_code == 200
    assert after.json()["owner"] == "sakshi"
    assert PRIVATE_MARKERS["sakshi"] in after.json()["private_note"]


def test_the_interaction_flaw_is_scoped_to_the_failing_account(lab):
    mallapa, sakshi = login(lab, "mallapa"), login(lab, "sakshi")
    lab.post("/login", json={"username": "sakshi", "password": "x", "admin": True})
    # Sakshi's rejected login unlocks Sakshi's own guarded read, never Mallapa's.
    assert lab.get("/records/BRD-2026-018/guarded", headers=auth(mallapa)).status_code == 403
    assert lab.get("/records/MKT-2026-041/guarded", headers=auth(sakshi)).status_code == 200


def test_a_successful_login_clears_the_compatibility_state(lab):
    mallapa = login(lab, "mallapa")
    lab.post("/login", json={"username": "mallapa", "password": "x", "admin": True})
    assert lab.get("/records/BRD-2026-018/guarded", headers=auth(mallapa)).status_code == 200
    login(lab, "mallapa")
    assert lab.get("/records/BRD-2026-018/guarded", headers=auth(mallapa)).status_code == 403


def test_the_interaction_flaw_never_spreads_to_the_secure_endpoint(lab):
    mallapa = login(lab, "mallapa")
    lab.post("/login", json={"username": "mallapa", "password": "x", "admin": True})
    assert lab.get("/records/BRD-2026-018/secure", headers=auth(mallapa)).status_code == 403
    assert lab.get("/records/BRD-2026-018", headers=auth(mallapa)).status_code == 200


def test_harmless_response_variation_has_no_security_impact(lab):
    """A response may change shape without granting anything: case H of the SCI list."""
    mallapa = login(lab, "mallapa")
    assert lab.get("/diagnostics/banner").json() == {"banner": "stable"}
    lab.post("/login", json={"username": "mallapa", "password": "x", "admin": True})
    assert lab.get("/diagnostics/banner").json() == {"banner": "compatibility"}
    assert lab.get("/records/BRD-2026-018/secure", headers=auth(mallapa)).status_code == 403
    assert lab.get("/records/BRD-2026-018/guarded", headers=auth(mallapa)).json()["owner"] == "sakshi"


def test_verbose_error_endpoint_leaks_a_synthetic_trace(lab):
    response = lab.get("/errors/trace")
    assert response.status_code == 500
    assert TRACE_MARKER in response.text and "Traceback" in response.text


def test_openapi_documents_every_route_and_the_bearer_scheme(lab):
    schema = lab.get("/openapi.json").json()
    paths = set(schema["paths"])
    for path in ("/health", "/login", "/profile", "/admin/users", "/records/{record_id}",
                 "/records/{record_id}/secure", "/records/{record_id}/guarded",
                 "/errors/trace", "/diagnostics/banner"):
        assert path in paths, path
    schemes = schema["components"]["securitySchemes"]
    assert schemes["bearerAuth"]["scheme"] == "bearer"
    assert lab.get("/docs").status_code == 200


def test_host_header_must_be_loopback(lab):
    rejected = lab.get("/health", headers={"host": "example.com"})
    assert rejected.status_code == 403
    assert rejected.json() == {"error": "non_loopback_host_rejected"}
    assert lab.get("/health", headers={"host": "127.0.0.1:8765"}).status_code == 200
    assert "localhost" in LOOPBACK_HOSTS and "127.0.0.1" in LOOPBACK_HOSTS


def test_the_runner_refuses_to_bind_a_public_interface():
    from targetlab.__main__ import run

    with pytest.raises(SystemExit):
        run(["--host", "0.0.0.0", "--port", "8765"])
    with pytest.raises(SystemExit):
        run(["--host", "example.com", "--port", "8765"])


def test_the_lab_makes_no_outbound_connection(lab, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("targetlab attempted an outbound connection")

    with monkeypatch.context() as guard:
        guard.setattr(socket.socket, "connect", forbidden)
        guard.setattr(socket, "getaddrinfo", forbidden)
        mallapa = login(lab, "mallapa")
        assert lab.get("/records/MKT-2026-041", headers=auth(mallapa)).status_code == 200
        assert lab.get("/records/BRD-2026-018/guarded", headers=auth(mallapa)).status_code == 403


def test_the_scanner_never_imports_the_lab_package():
    """The scanner may contain a lab *transport*, but never import the lab app.

    Checkpoint 35 added `canarygate.network.targetlab`, which talks to the lab over
    loopback HTTPS. The lab's own code (accounts, records, flaw hooks) must stay out
    of the scanner so a scan can never be scored against in-process ground truth.
    """
    root = Path(__file__).resolve().parents[2]
    for path in (root / "canarygate").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "import targetlab" not in text, path
        assert "from targetlab" not in text, path


def test_the_lab_has_no_outbound_http_client():
    root = Path(__file__).resolve().parents[2] / "targetlab"
    for path in root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for module in ("import httpx", "import requests", "urllib.request", "http.client"):
            assert module not in text, (path, module)


def test_reports_and_errors_never_echo_the_credentials(lab):
    documents = []
    for name in ("mallapa", "sakshi"):
        token = login(lab, name)
        documents.append(lab.get("/profile", headers=auth(token)).text)
        documents.append(lab.post("/login", json={"username": name, "password": "nope"}).text)
    payload = "\n".join(documents)
    for account in LAB_ACCOUNTS.values():
        assert account["password"] not in payload
    assert json.dumps({"ok": True})  # keep the json import meaningful


def test_the_collection_route_is_owner_isolated_for_every_account(lab):
    """Discovery must be correct: each account sees exactly one record, its own."""
    for account in LAB_ACCOUNTS:
        listed = lab.get("/records", headers=auth(login(lab, account))).json()
        assert [item["id"] for item in listed] == [ASSET_BY_OWNER[account]]
        assert {item["owner"] for item in listed} == {account}
        # Cross-account isolation: no list mentions another account's record or marker.
        others = set(ASSET_BY_OWNER.values()) - {ASSET_BY_OWNER[account]}
        assert others.isdisjoint({item["id"] for item in listed})
        for other in set(PRIVATE_MARKERS) - {account}:
            assert PRIVATE_MARKERS[other] not in str(listed)


def test_the_collection_route_requires_a_credential(lab):
    assert lab.get("/records").status_code == 401
