"""What the loading screen says when a run stops early.

CP43 streamed genuine progress, but every terminal state was drawn by
JavaScript: a judge who refreshed the page, opened a bookmark, or ran with
scripts off saw "Assessment in progress" forever and no reason for a stop.
This file pins the corrected contract:

* the server renders the terminal state, the reason and the next step;
* a demonstration that stored two of three runs is reported as **partial**,
  never as complete;
* nothing is announced as stored when the store is empty.

The lab is the real TLS server. Failures are real connection refusals, and the
partial case is produced by making one pair fail inside the same engine.
"""
import html
import re
import socket

import pytest
from fastapi.testclient import TestClient

import targetlab.testing as lab_server
from canarygate.ui import execution
from canarygate.ui.app import create_ui_app

FORBIDDEN = ("mallapa-lab-password", "sakshi-lab-password", "lab-token-mallapa",
             "lab-token-sakshi", "targetlab-mallapa-private-marker",
             "targetlab-sakshi-private-marker", "targetlab-trace-marker", "PRIVATE KEY")


@pytest.fixture()
def lab():
    with lab_server.LabTlsServer() as server:
        yield server


@pytest.fixture()
def client(tmp_path, lab, monkeypatch):
    monkeypatch.setenv("CANARYGATE_TARGETLAB_CA", str(lab_server.TARGETLAB_CERT))
    with TestClient(create_ui_app(tmp_path / "ui-outcomes.sqlite3")) as ui:
        yield ui


def _text(response) -> str:
    return html.unescape(response.text)


def _closed_port() -> int:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def _start(client, **form):
    response = client.post("/ui/actions/run-assessment", data=form,
                           follow_redirects=False)
    assert response.status_code == 303, response.text
    return response.headers["location"]


def _wait_for(client, url, timeout=60.0):
    import time
    deadline = time.time() + timeout
    snapshot = client.get(url + "/events?since=0").json()
    while snapshot["status"] == "running" and time.time() < deadline:
        time.sleep(0.05)
        snapshot = client.get(url + "/events?since=0").json()
    assert snapshot["status"] != "running", snapshot
    return snapshot


def _terminal_block(page: str) -> str:
    """The server-rendered terminal section, or '' when the page has none."""
    match = re.search(r'<section[^>]*data-terminal=.*?</section>', page, re.S)
    return match.group(0) if match else ""


# --- a completed run ---------------------------------------------------------

def test_a_completed_run_renders_its_result_without_javascript(client, lab):
    url = _start(client, kind="bola", port=lab.port, actor="mallapa",
                 asset="BRD-2026-018")
    snapshot = _wait_for(client, url)
    assert snapshot["status"] == "complete"
    run_id = snapshot["results"][0]["run_id"]

    page = _text(client.get(url))
    assert "<title>Assessment complete" in page
    block = _terminal_block(page)
    assert block, "the finished page must render a terminal section on the server"
    assert "hidden" not in block.split(">")[0], "the terminal section must be visible"
    assert "Assessment complete." in block
    assert "1 of 1 runs stored" in block
    # The link is real: it opens the stored run the transcript names.
    assert f"/ui/lab/bola/{run_id}" in block
    assert client.get(f"/ui/lab/bola/{run_id}").status_code == 200


def test_a_completed_demonstration_points_at_the_matrix(client, lab):
    url = _start(client, kind="demo", port=lab.port)
    snapshot = _wait_for(client, url)
    assert snapshot["status"] == "complete"
    assert len(snapshot["results"]) == 3
    page = _text(client.get(url))
    block = _terminal_block(page)
    assert "3 of 3 runs stored" in block
    assert "/ui/lab/matrix" in block
    assert snapshot["requests_sent"] == 54


# --- a refusal ---------------------------------------------------------------

def test_a_refused_run_explains_itself_on_the_server_render(client, lab):
    port = _closed_port()
    url = _start(client, kind="bola", port=port, actor="mallapa",
                 asset="BRD-2026-018")
    snapshot = _wait_for(client, url)
    assert snapshot["status"] == "failed"

    page = _text(client.get(url))
    assert "<title>Assessment stopped" in page
    block = _terminal_block(page)
    assert block, "a stopped run must render its reason on the server"
    assert "hidden" not in block.split(">")[0]
    assert "Assessment did not complete." in block
    # The backend's own sentence is shown, not a frontend invention.
    assert "No pair completed" in block
    # The next step names the port that was actually attempted and the real command.
    assert f"127.0.0.1:{port}" in block
    assert "python -m targetlab" in block
    # And it offers the same configuration again rather than starting over.
    assert 'action="/ui/actions/run-assessment"' in block
    assert f'value="{port}"' in block
    assert 'value="bola"' in block


def test_a_failure_carries_structured_metadata(client, lab):
    url = _start(client, kind="bola", port=_closed_port(), actor="mallapa",
                 asset="BRD-2026-018")
    snapshot = _wait_for(client, url)
    failure = snapshot["failure"]
    assert failure["reason"] == "unreachable"
    assert failure["status_code"] == 502
    assert failure["message"]
    assert failure["hint"]
    assert failure["pairs_failed"] == 1
    assert client.get(url + "/events?since=0").json()["failure"] == failure


def test_the_retry_form_reuses_the_engine_action(client, lab):
    port = _closed_port()
    url = _start(client, kind="sci", port=port, actor="sakshi",
                 asset="ADS-2026-027")
    _wait_for(client, url)
    block = _terminal_block(_text(client.get(url)))
    assert 'value="sci"' in block
    assert f'value="{port}"' in block
    # Re-posting the same form is the only way to retry: no new endpoint exists.
    assert len(re.findall(r'action="/ui/actions/run-assessment"', block)) == 1


# --- a partial demonstration -------------------------------------------------

def test_a_partial_demonstration_is_never_reported_as_complete(client, lab, monkeypatch):
    real = execution._run_bola_pair
    calls = {"n": 0}

    def flaky(job, request, store):
        calls["n"] += 1
        if calls["n"] == 3:
            raise execution.HTTPProblem(502, "TargetLab request refused or failed; "
                                             "no evidence was stored")
        return real(job, request, store)

    monkeypatch.setattr(execution, "_run_bola_pair", flaky)
    url = _start(client, kind="demo", port=lab.port)
    snapshot = _wait_for(client, url)

    assert calls["n"] == 3
    assert snapshot["status"] == "partial"
    assert len(snapshot["results"]) == 2
    assert snapshot["failure"]["reason"] == "partial"
    assert snapshot["failure"]["pairs_failed"] == 1

    page = _text(client.get(url))
    assert "<title>Assessment partially complete" in page
    block = _terminal_block(page)
    assert "2 of 3 runs stored" in block
    assert "Assessment complete." not in block
    assert "harsha" in block  # the pair that failed is named
    # Two pairs really were stored. Each stored run covers both directions of its
    # own pair, so seven of the nine cells carry evidence and exactly the two
    # cells the missing pair would have added stay untested.
    matrix = client.get("/api/lab-matrix").json()
    assert matrix["summary"]["runs_considered"] == 2
    assert matrix["summary"]["tested"] == 7
    assert matrix["summary"]["untested"] == 2
    untested = {(cell["requester"], cell["asset_id"])
                for cell in matrix["cells"] if cell["state"] == "untested"}
    assert untested == {("mallapa", "ADS-2026-027"), ("harsha", "MKT-2026-041")}


def test_a_partial_run_is_announced_to_assistive_technology(client, lab, monkeypatch):
    def broken(job, request, store):
        raise execution.HTTPProblem(502, "TargetLab could not be reached; "
                                         "no evidence was stored")

    monkeypatch.setattr(execution, "_run_bola_pair", broken)
    url = _start(client, kind="bola", port=lab.port, actor="mallapa",
                 asset="BRD-2026-018")
    _wait_for(client, url)
    page = client.get(url).text
    header = re.search(r'<section[^>]*data-terminal[^>]*>', page)
    assert header and 'role="status"' in header.group(0)


# --- the engine itself -------------------------------------------------------

def test_an_unexpected_engine_error_is_recorded_as_internal_failure():
    job = execution.AssessmentJob("bola", 8765, [])
    job.start(lambda j: (_ for _ in ()).throw(RuntimeError("boom")))
    job.join(timeout=10)
    snapshot = job.snapshot()
    assert snapshot["status"] == "failed"
    assert snapshot["failure"]["reason"] == "internal"
    assert snapshot["failure"]["status_code"] is None
    assert "boom" in snapshot["error"]
    assert any(event["kind"] == "error" for event in snapshot["events"])


def test_a_clean_job_reports_no_failure_metadata():
    job = execution.AssessmentJob("bola", 8765, [])
    job.start(lambda j: None)
    job.join(timeout=10)
    snapshot = job.snapshot()
    assert snapshot["status"] == "complete"
    assert snapshot["failure"] is None


# --- a rejection before the engine starts ------------------------------------

def test_a_rejected_configuration_reads_as_a_rejection(client, lab):
    response = client.post("/ui/actions/run-assessment",
                           data={"kind": "bola", "port": "80", "actor": "mallapa",
                                 "asset": "BRD-2026-018"})
    assert response.status_code == 422
    page = _text(response)
    # The backend's own sentence survives; the developer wording does not.
    assert "The TargetLab port must be a whole number between 1024 and 65535." in page
    assert "That configuration was rejected" in page
    assert "Backend returned HTTP" not in page
    assert "instead of a JSON error body" not in page
    # And the judge gets a way straight back to the form.
    assert 'href="/ui/assessment"' in page


def test_a_missing_record_still_says_what_is_missing(client):
    response = client.get("/ui/scans/does-not-exist")
    assert response.status_code == 404
    page = _text(response)
    assert "404" in page
    assert "instead of a JSON error body" not in page
