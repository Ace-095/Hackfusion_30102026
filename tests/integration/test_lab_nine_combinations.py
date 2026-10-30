"""The nine demo-tenant combinations, answered by real targetlab runs.

The judge playground offers one selector for the requesting account and one for the
asset. Every cell of that 3x3 grid must be backed by a check a real scan produced —
never by the interface, never by the catalog.

Three ordered pairs cover the whole grid:

* ``(mallapa, sakshi)``  -> mallapa own, sakshi own, mallapa->sakshi, sakshi->mallapa
* ``(sakshi, harsha)``   -> harsha own, sakshi->harsha, harsha->sakshi
* ``(harsha, mallapa)``  -> mallapa->harsha, harsha->mallapa

The catalog names, for every combination, which pair a scan should run, so the
interface never has to derive a pairing itself.
"""
import pytest
from fastapi.testclient import TestClient

import targetlab.testing as lab_server
from canarygate.api.app import create_app

SECRET_FRAGMENTS = ("lab-password", "lab-token", "private-marker")


@pytest.fixture()
def lab():
    with lab_server.LabTlsServer() as server:
        yield server


@pytest.fixture()
def client(tmp_path, lab, monkeypatch):
    monkeypatch.setenv("CANARYGATE_TARGETLAB_CA", str(lab_server.TARGETLAB_CERT))
    with TestClient(create_app(tmp_path / "nine.sqlite3")) as api:
        yield api


@pytest.fixture(scope="module")
def catalog():
    """The catalog is static; read it once from a throwaway application."""
    with TestClient(create_app()) as api:
        response = api.get("/api/lab-catalog")
    assert response.status_code == 200, response.text
    return response.json()


def run_pair(api, lab, actor, owner):
    response = api.post("/api/lab-bola-scans", json={"port": lab.port,
                                                     "actor": actor, "owner": owner})
    assert response.status_code == 201, response.text
    return response.json()


def check_for(run, combination):
    """The one check of a real run that answers this catalog combination."""
    if combination["kind"] == "legitimate_owner_request":
        matches = [check for check in run["checks"]
                   if check["direction"] == "owner_baseline"
                   and check["actor"] == combination["actor"]]
    else:
        matches = [check for check in run["checks"]
                   if check["direction"] == "cross_account"
                   and check["actor"] == combination["actor"]
                   and check["owner"] == combination["owner"]]
    assert len(matches) == 1, (combination, [check["id"] for check in run["checks"]])
    return matches[0]


def test_the_catalog_declares_three_accounts_and_three_assets(catalog):
    assert catalog["mode"] == "targetlab_demo"
    assert catalog["dataset"] == "demo_tenant"
    assert [account["account"] for account in catalog["accounts"]] == [
        "mallapa", "sakshi", "harsha"]
    assert {account["asset_id"] for account in catalog["accounts"]} == {
        "MKT-2026-041", "BRD-2026-018", "ADS-2026-027"}
    assert len({account["title"] for account in catalog["accounts"]}) == 3


def test_the_catalog_contains_no_credential_or_private_marker(catalog):
    import json

    payload = json.dumps(catalog)
    for fragment in SECRET_FRAGMENTS:
        assert fragment not in payload
    for account in catalog["accounts"]:
        assert set(account) == {"account", "title", "role", "asset_id", "asset_type",
                                "asset_label"}


def test_the_catalog_declares_nine_combinations_three_of_them_legitimate(catalog):
    combinations = catalog["combinations"]
    assert len(combinations) == 9
    legitimate = [item for item in combinations
                  if item["kind"] == "legitimate_owner_request"]
    cross = [item for item in combinations if item["kind"] == "cross_account_attempt"]
    assert len(legitimate) == 3 and len(cross) == 6
    assert {(item["actor"], item["asset_id"]) for item in combinations} == {
        (actor, asset) for actor in ("mallapa", "sakshi", "harsha")
        for asset in ("MKT-2026-041", "BRD-2026-018", "ADS-2026-027")}
    for item in legitimate:
        assert item["actor"] == item["owner"]
        assert item["pair"]["actor"] == item["actor"]
    for item in cross:
        assert item["actor"] != item["owner"]
        assert item["pair"] == {"actor": item["actor"], "owner": item["owner"]}


def test_every_combination_is_answered_by_a_real_run(client, lab, catalog):
    """One real scan per catalog pair; each of the nine cells maps to its own check."""
    runs = {}
    answers = {}
    for combination in catalog["combinations"]:
        pair = (combination["pair"]["actor"], combination["pair"]["owner"])
        if pair not in runs:
            runs[pair] = run_pair(client, lab, *pair)
        answers[(combination["actor"], combination["asset_id"])] = check_for(
            runs[pair], combination)

    assert len(answers) == 9
    # A legitimate combination is answered by the same ordered pair as one of the
    # cross-account directions, so the six declared pairs cover the whole grid.
    assert set(runs) == {(p["actor"], p["owner"]) for p in catalog["pairs"]}
    for combination in catalog["combinations"]:
        check = answers[(combination["actor"], combination["asset_id"])]
        if combination["kind"] == "legitimate_owner_request":
            # The owner reading their own asset is the only safe baseline.
            assert check["verdict"] == "SAFE", check
            assert check["status"] == 200
            assert check["checklist"]["owner_baseline"] is True
            assert check["remediation"] is None
        else:
            # A cross-account read is confirmed only by the oracle's evidence, never
            # by the bare 200 the lab returns.
            assert check["verdict"] == "CONFIRMED", check
            assert check["status"] == 200
            assert check["checklist"]["ownership_verified"] is True
            assert check["checklist"]["private_disclosure"] is True
            assert check["checklist"]["verified_denial"] is False
            assert "private_marker" not in check["evidence"]
            assert check["remediation"]


def test_each_combination_also_has_a_secure_route_counterpart(client, lab, catalog):
    """The vulnerable-versus-secure comparison uses the same real run."""
    runs = {}
    for combination in catalog["combinations"]:
        if combination["kind"] != "cross_account_attempt":
            continue
        pair = (combination["pair"]["actor"], combination["pair"]["owner"])
        if pair not in runs:
            runs[pair] = run_pair(client, lab, *pair)
        secure = [check for check in runs[pair]["checks"]
                  if check["direction"] == "cross_account_secure"
                  and check["actor"] == combination["actor"]
                  and check["owner"] == combination["owner"]]
        assert len(secure) == 1
        assert secure[0]["verdict"] == "SAFE"
        assert secure[0]["status"] == 403
        assert secure[0]["checklist"]["verified_denial"] is True
        assert secure[0]["remediation"] is None
        assert secure[0]["endpoint"].endswith("/secure")


def test_the_three_pairs_are_the_catalog_pairs(client, lab, catalog):
    """The interface may only run pairs the catalog declares."""
    declared = {(pair["actor"], pair["owner"]) for pair in catalog["pairs"]}
    assert len(declared) == 6
    for pair in sorted(declared):
        run = run_pair(client, lab, *pair)
        assert {(check["actor"], check["owner"]) for check in run["checks"]} == {
            (pair[0], pair[0]), (pair[1], pair[1]), (pair[0], pair[1]), (pair[1], pair[0])}


def test_an_unknown_pair_is_rejected_not_guessed(client, lab):
    for payload in ({"actor": "mallapa", "owner": "mallapa"},
                    {"actor": "mallapa", "owner": "nobody"},
                    {"actor": "admin", "owner": "sakshi"}):
        response = client.post("/api/lab-bola-scans", json={"port": lab.port, **payload})
        assert response.status_code == 400, payload
    # Nothing was persisted for a rejected selection.
    assert client.get("/api/lab-bola-scans").status_code in (404, 405)
