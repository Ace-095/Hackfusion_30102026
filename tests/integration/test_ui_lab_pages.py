"""The TargetLab workflows, driven through the HTML interface.

Every assertion compares what the page displays with what the JSON API returns for
the same stored run. The lab is the real TLS server on 127.0.0.1; nothing here
mocks a verdict, a status code or a transport error.
"""
import html
import re
import socket

import pytest
from fastapi.testclient import TestClient

import targetlab.testing as lab_server
from canarygate.ui.app import create_ui_app

FORBIDDEN = ("alice-lab-password", "bob-lab-password", "lab-token-alice", "lab-token-bob",
             "targetlab-alice-private-marker", "targetlab-bob-private-marker",
             "targetlab-trace-marker", "PRIVATE KEY")


@pytest.fixture()
def lab():
    with lab_server.LabTlsServer() as server:
        yield server


@pytest.fixture()
def client(tmp_path, lab, monkeypatch):
    monkeypatch.setenv("CANARYGATE_TARGETLAB_CA", str(lab_server.TARGETLAB_CERT))
    with TestClient(create_ui_app(tmp_path / "ui-lab.sqlite3")) as ui:
        yield ui


def _run_through_ui(client, action, port, **form):
    response = client.post(f"/ui/actions/{action}", data={"port": port, **form},
                           follow_redirects=False)
    assert response.status_code == 303, response.text
    return response.headers["location"]


def _text(response) -> str:
    """Page text with entities decoded, so backend strings compare literally."""
    return html.unescape(response.text)


def _closed_port() -> int:
    """A port that was just free: connecting to it is refused."""
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def _api_run(client, family, run_id):
    root = {"bola": "lab-bola-scans", "sci": "lab-sci-scans", "reset": "lab-sci-resets"}[family]
    key = "proof_id" if family == "reset" else "run_id"
    response = client.get(f"/api/{root}/{run_id}")
    assert response.status_code == 200, response.text
    return response.json()


# --------------------------------------------------------------------------- #
# Readiness and refusal
# --------------------------------------------------------------------------- #
def test_lab_page_states_readiness_and_offers_the_three_real_workflows(client):
    body = client.get("/ui/lab").text
    assert "TargetLab validation" in body
    assert "CANARYGATE_TARGETLAB_CA" in body
    # One form per workflow, each posting to a real action route.
    assert body.count("<form") == 3
    for action in ("lab-bola-scan", "lab-sci-scan", "lab-sci-reset"):
        assert f'action="/ui/actions/{action}"' in body
    # The page says what it is, and what the browser may not do.
    assert "Controlled validation, not live-target validation" in body
    assert "cannot choose a host, path, account" in body
    assert "No read-BOLA lab run stored yet" in body


def test_missing_ca_is_reported_as_a_refusal_not_a_result(tmp_path, lab, monkeypatch):
    monkeypatch.delenv("CANARYGATE_TARGETLAB_CA", raising=False)
    with TestClient(create_ui_app(tmp_path / "no-ca.sqlite3")) as ui:
        page = ui.get("/ui/lab")
        assert "is not set" in page.text
        assert "The lab transport is not ready" in page.text

        for action in ("lab-bola-scan", "lab-sci-scan", "lab-sci-reset"):
            response = ui.post(f"/ui/actions/{action}", data={"port": lab.port},
                               follow_redirects=False)
            assert response.status_code == 400, action
            assert "CANARYGATE_TARGETLAB_CA" in response.text
        # Nothing was stored by a refused request.
        assert ui.get("/api/lab-bola-scans/" + "0" * 8 + "-0000-0000-0000-" + "0" * 12
                      ).status_code == 404


@pytest.mark.parametrize("form", [
    {"port": "abc"},
    {"port": "80"},
    {"port": "70000"},
    {"port": "8765", "request_budget": "600"},
    {"port": "8765", "request_budget": "many"},
])
def test_invalid_form_values_are_rejected_before_any_connection(client, lab, form):
    response = client.post("/ui/actions/lab-bola-scan", data=form, follow_redirects=False)
    assert response.status_code == 422, form
    assert "port" in response.text.lower() or "budget" in response.text.lower()


def test_unreachable_lab_is_a_502_page_and_stores_nothing(client):
    response = client.post("/ui/actions/lab-bola-scan", data={"port": _closed_port()},
                           follow_redirects=False)
    assert response.status_code == 502
    assert "no evidence was stored" in response.text
    page = client.get("/ui/lab").text
    assert "No read-BOLA lab run stored yet" in page
    assert "/ui/lab/bola/" not in page          # no stored run is listed


def test_unknown_run_id_is_a_html_404(client):
    missing = "11111111-2222-3333-4444-555555555555"
    for path in (f"/ui/lab/bola/{missing}", f"/ui/lab/sci/{missing}", f"/ui/lab/reset/{missing}"):
        response = client.get(path)
        assert response.status_code == 404, path
        assert "not found" in response.text.lower()
    assert client.get("/ui/lab/unknown/" + missing).status_code == 404


# --------------------------------------------------------------------------- #
# Read-BOLA
# --------------------------------------------------------------------------- #
def test_bola_run_page_shows_the_verdicts_the_api_stored(client, lab):
    location = _run_through_ui(client, "lab-bola-scan", lab.port)
    run_id = location.rsplit("/", 1)[-1]
    api_run = _api_run(client, "bola", run_id)

    body = _text(client.get(location))
    assert api_run["verdict"] in body
    for check in api_run["checks"]:
        assert check["id"] in body
        assert check["verdict"] in body
    assert api_run["transport"]["destination"] in body
    assert str(api_run["transport"]["port"]) in body
    assert f"matched {api_run['ground_truth']['matched']}" in body
    assert api_run["ground_truth"]["statement"] in body
    assert "used_as_decision_input=" in body and "evaluated_after_verdicts=" in body
    # The page renders the summary counts the backend computed.
    assert str(api_run["constraints"]["requests_sent"]) in body
    assert "Destructive executed" in body


def test_bola_report_page_renders_the_backend_section_projection(client, lab):
    location = _run_through_ui(client, "lab-bola-scan", lab.port)
    run_id = location.rsplit("/", 1)[-1]
    sections = client.get(f"/api/lab-bola-scans/{run_id}/report?view=sections").json()["sections"]
    page = client.get(f"{location}/report")  # text compared after entity decoding
    assert page.status_code == 200
    assert page.text.count('class="report-section"') == len(sections)
    for key in sections:
        readable = key.replace("_", " ")
        assert readable.lower() in page.text.lower(), key
    # The report links back to the backend's own HTML and JSON.
    assert f"/api/lab-bola-scans/{run_id}/report?format=html" in page.text


def test_default_json_report_view_still_serves_the_run(client, lab):
    # Regression: the default (view=run) used to answer 500 because the response
    # model only allowed the section projection.
    location = _run_through_ui(client, "lab-bola-scan", lab.port)
    run_id = location.rsplit("/", 1)[-1]
    for path in (f"/api/lab-bola-scans/{run_id}/report",
                 f"/api/lab-bola-scans/{run_id}/report?view=run",
                 f"/api/lab-scans/{run_id}/report"):
        response = client.get(path)
        if path.startswith("/api/lab-scans/"):
            assert response.status_code == 404  # another family's store
            continue
        assert response.status_code == 200, path
        assert response.json()["id"] == run_id


# --------------------------------------------------------------------------- #
# Control interaction and reset
# --------------------------------------------------------------------------- #
def test_sci_page_shows_both_baselines_and_the_combined_action(client, lab):
    location = _run_through_ui(client, "lab-sci-scan", lab.port)
    run_id = location.rsplit("/", 1)[-1]
    api_run = _api_run(client, "sci", run_id)
    body = _text(client.get(location))

    assert api_run["verdict"] in body
    assert api_run["attribution"] in body
    for baseline in api_run["baselines"]:
        assert baseline["id"] in body
        assert baseline["verdict"] in body
        assert str(baseline["evidence"]["status"]) in body
    combined = api_run["combined"]
    assert str(combined["status"]) in body
    assert combined["impact"] in body
    assert combined["observed"] in body
    # The three statuses are the backend's evidence, not text the page wrote.
    statuses = {str(item["evidence"]["status"]) for item in api_run["baselines"]}
    statuses.add(str(combined["status"]))
    assert statuses == {"403", "401", "200"}
    assert "No reset proof recorded on this port" in body


def test_reset_proof_page_renders_every_check_the_api_stored(client, lab):
    location = _run_through_ui(client, "lab-sci-reset", lab.port)
    proof_id = location.rsplit("/", 1)[-1]
    api_proof = _api_run(client, "reset", proof_id)
    body = _text(client.get(location))

    assert api_proof["status"] in body
    for check in api_proof["checks"]:
        assert check["id"] in body
        assert str(check["expected_status"]) in body
        assert str(check["status"]) in body
    assert api_proof["isolation"]["why"][:40] in body
    # A reset proof has no section report; the UI says so with a 404 page.
    assert client.get(f"{location}/report").status_code == 404


def test_sci_page_links_the_reset_proof_from_the_same_port(client, lab):
    sci_location = _run_through_ui(client, "lab-sci-scan", lab.port)
    reset_location = _run_through_ui(client, "lab-sci-reset", lab.port)
    proof_id = reset_location.rsplit("/", 1)[-1]
    body = client.get(sci_location).text
    assert proof_id in body
    assert "separate two-runner scenario" in body


# --------------------------------------------------------------------------- #
# Surfaces and state
# --------------------------------------------------------------------------- #
def test_dashboard_shows_the_lab_verdicts_that_were_stored(client, lab):
    bola_location = _run_through_ui(client, "lab-bola-scan", lab.port)
    sci_location = _run_through_ui(client, "lab-sci-scan", lab.port)
    bola_id = bola_location.rsplit("/", 1)[-1]
    sci_id = sci_location.rsplit("/", 1)[-1]

    body = client.get("/ui/").text
    assert "TargetLab validation" in body
    assert bola_id[:8] in body and sci_id[:8] in body
    assert _api_run(client, "bola", bola_id)["verdict"] in body


def test_reports_page_lists_stored_lab_runs(client, lab):
    bola_location = _run_through_ui(client, "lab-bola-scan", lab.port)
    bola_id = bola_location.rsplit("/", 1)[-1]
    body = client.get("/ui/reports").text
    assert "TargetLab validation reports" in body
    assert bola_id[:8] in body


def test_htmx_submission_returns_a_fragment_naming_the_stored_run(client, lab):
    response = client.post("/ui/actions/lab-bola-scan", data={"port": lab.port},
                           headers={"HX-Request": "true"})
    assert response.status_code == 200
    body = response.text
    assert "<!doctype html>" not in body          # a fragment, not a page
    run_id = re.search(r"/ui/lab/bola/([0-9a-f-]{36})", body).group(1)
    assert client.get(f"/api/lab-bola-scans/{run_id}").status_code == 200


@pytest.mark.parametrize("action", ["lab-bola-scan", "lab-sci-scan", "lab-sci-reset"])
def test_no_lab_secret_reaches_the_browser(client, lab, action):
    location = _run_through_ui(client, action, lab.port)
    bodies = [client.get(location).text, client.get("/ui/lab").text,
              client.get("/ui/reports").text, client.get("/ui/").text]
    if action != "lab-sci-reset":
        bodies.append(client.get(f"{location}/report").text)
    text = "\n".join(bodies)
    for needle in FORBIDDEN:
        assert needle not in text, needle
