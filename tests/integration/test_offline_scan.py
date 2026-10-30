import hashlib
import json
import socket

import pytest
from fastapi.testclient import TestClient

from canarygate.api.app import app
from canarygate.offline.scan import fixture_recipe, run_fixture
from canarygate.offline.target import FixtureTarget


def test_full_fixture_api_pipeline_cannot_open_network(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("real network access attempted")
    # Windows asyncio creates a loopback socketpair while TestClient starts.
    # Install the outbound guard only after that internal event loop exists;
    # every API request and scanner operation below remains guarded.
    with TestClient(app) as client:
        monkeypatch.setattr(socket.socket, "connect", forbidden)
        monkeypatch.setattr(socket, "getaddrinfo", forbidden)
        assert client.get("/api/health").json() == {"status": "ok", "mode": "fixture", "live_scanning": False}
        inventory = client.get("/api/endpoints").json()["endpoints"]
        assert any(e["path"] == "/items/{id}" and e["expected_access"] == "authenticated" for e in inventory)
        assert client.post("/api/spec/upload").status_code == 501
        response = client.post("/api/scan")
        assert response.status_code == 201
        run = response.json()
        assert run["mode"] == "fixture"
        assert run["verdict"] == "CONFIRMED"
        assert all(run["setup"][key] == "SUCCESS" for key in ("authentication", "resources", "ownership_verification", "bola_coverage"))
        assert run["setup"]["accounts"] == {"alice": "SUCCESS", "bob": "SUCCESS"}
        assert run["evidence"]["ownership"]["checklist"]["both_owner_baselines"]
        assert run["evidence"]["ownership"]["checklist"]["cross_list_isolation"]
        assert run["constraints"]["requests_sent"] == 10
        assert run["constraints"]["network_transport_enabled"] is False
        checks = {item["id"]: item for item in run["checks"]}
        assert [checks[name]["verdict"] for name in ("AUTHN-01", "AUTHN-02", "AUTHN-03")] == ["SAFE"] * 3
        assert all(checks[name]["verdict"] == "SKIPPED" for name in ("AUTHN-04a", "AUTHN-04b", "AUTHN-05"))
        assert "Token is not a supported JWT format" in checks["AUTHN-04a"]["reason"]
        assert all(checks[name]["evidence"]["status_code"] == 401 for name in ("AUTHN-01", "AUTHN-02", "AUTHN-03"))
        assert run["evidence"]["ownership"]["private_canary_matched"] is True
        assert run["evidence"]["disclosure"]["private_canary_matched"] is True
        for evidence in run["evidence"].values():
            summary = {key: value for key, value in evidence.items() if key not in {"sha256", "redacted"}}
            expected_hash = hashlib.sha256(json.dumps(summary, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            assert evidence["sha256"] == expected_hash
        assert client.get("/openapi.json").json()["components"]["schemas"]["FixtureRun"]["type"] == "object"
        # Default Swagger and ReDoc use external CDN assets, so they are disabled.
        assert client.get("/docs").status_code == 404
        assert client.get("/redoc").status_code == 404
        assert "fixture-token" not in json.dumps(run)
        assert "synthetic-bob-private-canary" not in json.dumps(run)
        assert client.get(f"/api/scan/{run['id']}").json() == run
        assert client.get(f"/api/reports/{run['id']}").json() == run
        html = client.get(f"/api/reports/{run['id']}?format=html")
        assert html.status_code == 200 and "not live testing" in html.text and "CONFIRMED" in html.text
        for section in ("Three setup gates", "ownership and disclosure evidence", "Authentication checks", "Secured endpoints", "constraint checklist"):
            assert section in html.text
        assert "fixture-token" not in html.text
        assert "synthetic-bob-private-canary" not in html.text
        assert run["id"] in [entry["id"] for entry in client.get("/api/findings").json()["findings"]]
        assert run["id"] in [entry["id"] for entry in client.get("/api/matrix").json()["cells"]]
        assert client.get("/api/setup/status").json()["setup"]["ownership_verification"] == "SUCCESS"
        assert client.get("/api/scan/unknown").status_code == 404
        assert client.get(f"/api/reports/{run['id']}?format=xml").status_code == 400


@pytest.mark.parametrize("target_options,recipe_change,expected", [
    ({"attacker_access": "metadata"}, {}, "INCONCLUSIVE"),
    ({"owner_sees_canary": False}, {}, "SKIPPED"),
    ({"cross_list_leak": True}, {}, "SKIPPED"),
    ({"alice_item_missing": True}, {}, "SKIPPED"),
    ({}, {"ownership_model": "shared"}, "SKIPPED"),
    ({}, {"ownership_model": "public"}, "SKIPPED"),
    ({}, {"expected_access": "unknown"}, "INCONCLUSIVE"),
    ({"bob_login": False}, {}, "SKIPPED"),
    ({"attacker_access": "deny"}, {}, "SAFE"),
    ({"attacker_access": "unauthorized"}, {}, "INCONCLUSIVE"),
    ({"attacker_access": "not_found"}, {}, "INCONCLUSIVE"),
    ({"attacker_access": "redirect"}, {}, "INCONCLUSIVE"),
    ({"canary": "wrong-value"}, {}, "SKIPPED"),
])
def test_verdict_depends_on_observed_evidence(target_options, recipe_change, expected):
    recipe = fixture_recipe()
    for key, value in recipe_change.items():
        if key == "ownership_model":
            recipe["setup"]["resources"]["items"][key] = value
        else:
            recipe["policy"][key] = value
    result = run_fixture(FixtureTarget(**target_options), recipe=recipe)
    assert result["verdict"] == expected
    assert result["mode"] == "fixture"
    if result["verdict"] == "SKIPPED":
        assert result["evidence"]["disclosure"] is None



def test_denied_read_still_has_independently_verified_owner():
    result = run_fixture(FixtureTarget(attacker_access="deny"))
    assert result["verdict"] == "SAFE"
    assert result["evidence"]["ownership"]["private_canary_matched"] is True
    assert result["evidence"]["disclosure"]["status_code"] == 403
    assert result["evidence"]["disclosure"]["private_canary_matched"] is False


def test_unknown_policy_cannot_be_confirmed_even_with_disclosure():
    recipe = fixture_recipe()
    recipe["policy"]["expected_access"] = "unknown"
    result = run_fixture(recipe=recipe)
    assert result["evidence"]["ownership"]["private_canary_matched"] is True
    assert result["evidence"]["disclosure"]["private_canary_matched"] is True
    assert result["verdict"] == "INCONCLUSIVE"
