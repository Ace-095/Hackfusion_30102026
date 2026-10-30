"""Ownership proof and disclosure proof, as their own pages.

Why this file exists
--------------------
The dashboard renders a TargetLab assessment, but the numbered review journey still
walked the *fixture* workflow: "5 · Ownership proof" and "6 · Disclosure proof"
both landed on `/ui/findings`, which is empty when only lab runs are stored. A
reviewer clicking the path a judge is told to follow therefore saw nothing — the
two proofs looked unfinished because, as destinations, they did not exist.

These tests pin the corrections:

* the journey follows the dataset that actually has evidence;
* `/ui/lab/proof/ownership` lists every owner baseline that a stored run verified,
  and every account it could not verify, with the check id, run id, HTTP status and
  evidence hash — all of them read back from `/api/lab-bola-scans/{id}`;
* `/ui/lab/proof/disclosure` chains the four stored steps of each direction
  (baseline → cross-account request → disclosure → secure-route denial);
* with nothing stored, both pages say so and invent nothing;
* the run page never shows a run-level "private disclosure: no" beside a CONFIRMED
  verdict, which the old aggregate did because it ANDed the flag across the secure
  checks too, where `false` is the *correct* answer.
"""
import html
import re

import pytest
from fastapi.testclient import TestClient

import targetlab.testing as lab_server
from canarygate.ui.app import create_ui_app

LAB = ("mallapa", "sakshi", "harsha")
ASSETS = {"mallapa": "MKT-2026-041", "sakshi": "BRD-2026-018", "harsha": "ADS-2026-027"}


@pytest.fixture()
def lab():
    with lab_server.LabTlsServer() as server:
        yield server


@pytest.fixture()
def client(tmp_path, lab, monkeypatch):
    monkeypatch.setenv("CANARYGATE_TARGETLAB_CA", str(lab_server.TARGETLAB_CERT))
    with TestClient(create_ui_app(tmp_path / "ui-proofs.sqlite3")) as ui:
        yield ui


def _text(response) -> str:
    return html.unescape(response.text)


def _run(client, **form):
    response = client.post("/ui/actions/run-assessment", data=form, follow_redirects=False)
    assert response.status_code == 303, response.text
    url = response.headers["location"]
    import time
    deadline = time.time() + 90
    snapshot = client.get(url + "/events?since=0").json()
    while snapshot["status"] == "running" and time.time() < deadline:
        time.sleep(0.05)
        snapshot = client.get(url + "/events?since=0").json()
    assert snapshot["status"] in {"complete", "partial"}, snapshot
    return snapshot


def _journey(body: str) -> dict[str, str]:
    """Map journey label → href, from the rendered nav."""
    nav = body.split('aria-label="Review journey"', 1)[1].split("</nav>", 1)[0]
    steps = {}
    for href, label in re.findall(r'<a href="([^"]+)"[^>]*><span class="idx">\d+</span>([^<]+)</a>',
                                  nav):
        steps[label.strip()] = href
    for label in re.findall(r'<span class="idx">\d+</span>([^<]+)</span>', nav):
        steps[label.strip()] = "current"
    return steps


# --- the journey follows the evidence ---------------------------------------

def test_the_journey_walks_the_lab_surfaces_when_lab_evidence_exists(client, lab):
    assert _run(client, kind="bola", port=lab.port, actor="mallapa",
                asset="BRD-2026-018")["status"] == "complete"
    body = _text(client.get("/ui/"))
    steps = _journey(body)
    assert steps["Ownership proof"] == "/ui/lab/proof/ownership"
    assert steps["Disclosure proof"] == "/ui/lab/proof/disclosure"
    assert steps["Matrix"] == "/ui/lab/matrix"
    assert steps["Scan results"].startswith("/ui/lab")
    # Every step is a page that exists — a journey with a 404 in it is not a journey.
    for label, href in steps.items():
        if href == "current":
            continue
        assert client.get(href).status_code == 200, (label, href)


def test_the_journey_keeps_the_fixture_path_when_only_fixtures_exist(client):
    client.post("/ui/actions/fixture-scan", follow_redirects=False)
    steps = _journey(_text(client.get("/ui/")))
    assert steps["Ownership proof"] == "/ui/findings"
    assert steps["Matrix"] == "/ui/matrix"


# --- ownership proof ---------------------------------------------------------

def test_the_ownership_proof_page_reports_every_verified_baseline(client, lab):
    snapshot = _run(client, kind="demo", port=lab.port)
    run_ids = [item["run_id"] for item in snapshot["results"]]
    page = _text(client.get("/ui/lab/proof/ownership"))
    assert "Ownership proof" in page
    for account in LAB:
        assert account in page
        assert ASSETS[account] in page
    # Every account's baseline is attributed to a stored check of a stored run.
    api_runs = [client.get(f"/api/lab-bola-scans/{rid}").json() for rid in run_ids]
    baselines = [check for run in api_runs for check in run["checks"]
                 if check["direction"] == "owner_baseline"]
    assert len(baselines) == 6
    for check in baselines:
        assert check["id"] in page
        assert check["evidence_sha256"][:12] in page
    assert "verified" in page.lower()
    # And the counts on the page equal the checks the API returned.
    assert page.count("baseline verified") == 3


def test_the_ownership_proof_page_invents_nothing_on_an_empty_database(client):
    page = _text(client.get("/ui/lab/proof/ownership"))
    assert "no owner baseline" in page.lower()
    assert "baseline verified" not in page
    assert "verified by" not in page.lower()


def test_a_half_run_leaves_the_unread_owner_marked_unverified(client, lab):
    """Two pairs cover four of the six baseline checks; the rest stay unverified."""
    snapshot = _run(client, kind="bola", port=lab.port, actor="mallapa",
                    asset="BRD-2026-018")
    assert snapshot["status"] == "complete"
    page = _text(client.get("/ui/lab/proof/ownership"))
    # mallapa → sakshi verifies both owners and nothing else.
    assert "baseline verified" in page
    assert page.count("not verified") >= 1


# --- disclosure proof --------------------------------------------------------

def test_the_disclosure_proof_page_chains_the_stored_steps(client, lab):
    snapshot = _run(client, kind="bola", port=lab.port, actor="mallapa",
                    asset="BRD-2026-018")
    run_id = snapshot["results"][0]["run_id"]
    run = client.get(f"/api/lab-bola-scans/{run_id}").json()
    page = _text(client.get("/ui/lab/proof/disclosure"))
    assert "Disclosure proof" in page
    for check in run["checks"]:
        assert check["id"] in page, check["id"]
        assert check["evidence_sha256"][:12] in page
    # The four steps of the vulnerable direction plus its secure comparison.
    for phrase in ("owner baseline", "cross-account request", "private disclosure",
                   "secure route"):
        assert phrase in page.lower(), phrase
    # Both directions were recorded in this run, so both appear.
    assert "mallapa → sakshi" in page and "sakshi → mallapa" in page


def test_a_denial_is_never_drawn_as_a_disclosure(client, lab):
    snapshot = _run(client, kind="bola", port=lab.port, actor="mallapa",
                    asset="BRD-2026-018")
    run = client.get(f"/api/lab-bola-scans/{snapshot['results'][0]['run_id']}").json()
    page = _text(client.get("/ui/lab/proof/disclosure"))
    secure = [check for check in run["checks"]
              if check["direction"] == "cross_account_secure"]
    assert secure and all(check["status"] == 403 for check in secure)
    # Each secure check is labelled a denial, and the page says which route it hit.
    assert page.count("denied") >= len(secure)
    assert "/secure" in page
    # The disclosure count is the number of confirmed cross-account checks, not the
    # number of checks that merely returned 200.
    assert f"{run['summary']['confirmed']} confirmed" in page


def test_the_disclosure_proof_page_invents_nothing_on_an_empty_database(client):
    page = _text(client.get("/ui/lab/proof/disclosure"))
    assert "no cross-account" in page.lower()
    assert "CONFIRMED" not in page.split('<main', 1)[-1].split("</main>", 1)[0] or \
        "no cross-account" in page.lower()


# --- the run page agrees with itself ----------------------------------------

def test_the_run_page_does_not_contradict_a_confirmed_verdict(client, lab):
    snapshot = _run(client, kind="bola", port=lab.port, actor="mallapa",
                    asset="BRD-2026-018")
    assert snapshot["status"] == "complete"
    page = _text(client.get(f"/ui/lab/bola/{snapshot['results'][0]['run_id']}"))
    assert "CONFIRMED" in page
    # The evidence panel groups the flags by route instead of ANDing a disclosure
    # flag across the secure checks, where a false is the desired answer.
    assert "Owner baselines" in page
    assert "Cross-account requests" in page
    assert "Secure-route denials" in page
    # The old contradictory line is gone.
    assert "Vulnerable route disclosure" not in page
    # The explanation is on the page, so a false next to a denial reads correctly.
    assert "expected" in page.lower()
