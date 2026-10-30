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

FORBIDDEN = ("mallapa-lab-password", "sakshi-lab-password", "lab-token-mallapa", "lab-token-sakshi",
             "targetlab-mallapa-private-marker", "targetlab-sakshi-private-marker",
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
    assert "cannot name a host, a path, a credential or an expected" in body
    assert "No read-BOLA lab run stored yet" in body


def test_the_lab_page_offers_the_three_accounts_and_their_assets(client):
    body = _text(client.get("/ui/lab"))
    for account, asset in (("mallapa", "MKT-2026-041"), ("sakshi", "BRD-2026-018"),
                           ("harsha", "ADS-2026-027")):
        assert f'value="{account}"' in body
        assert f'value="{asset}"' in body
    assert "Demo tenant — three accounts, three assets" in body
    assert "9 combinations" in body and "3 legitimate owner request(s)" in body
    assert "6 cross-account attempt(s)" in body
    # The frozen offline fixture is named as a different dataset, not merged into this one.
    assert "frozen offline fixture" in body and "scope.yaml" in body
    for secret in FORBIDDEN:
        assert secret not in body


def test_the_bola_selector_runs_the_pair_the_catalog_names(client, lab):
    location = _run_through_ui(client, "lab-bola-scan", lab.port,
                               actor="harsha", asset="BRD-2026-018")
    run_id = location.rsplit("/", 1)[-1]
    run = _api_run(client, "bola", run_id)
    assert {(check["actor"], check["owner"]) for check in run["checks"]} == {
        ("harsha", "harsha"), ("sakshi", "sakshi"),
        ("harsha", "sakshi"), ("sakshi", "harsha")}
    page = _text(client.get(location))
    assert "Vulnerable versus secure route" in page
    comparison = run["checks"]
    vulnerable = {check["id"]: check for check in comparison}["LAB-BOLA-03"]
    assert vulnerable["actor"] == "harsha" and vulnerable["owner"] == "sakshi"
    assert vulnerable["verdict"] == "CONFIRMED"
    assert "harsha → sakshi" in page and "200" in page and "403" in page


def test_a_legitimate_owner_selection_runs_the_owner_baseline(client, lab):
    location = _run_through_ui(client, "lab-bola-scan", lab.port,
                               actor="harsha", asset="ADS-2026-027")
    run = _api_run(client, "bola", location.rsplit("/", 1)[-1])
    own = [check for check in run["checks"]
           if check["direction"] == "owner_baseline" and check["actor"] == "harsha"]
    assert len(own) == 1
    assert own[0]["verdict"] == "SAFE" and own[0]["status"] == 200


def test_an_interaction_selection_without_two_accounts_is_refused(client, lab):
    response = client.post("/ui/actions/lab-sci-scan",
                           data={"port": lab.port, "actor": "harsha", "asset": "ADS-2026-027"},
                           follow_redirects=False)
    assert response.status_code == 422, response.text
    assert "two different accounts" in response.text
    body = _text(client.get("/ui/lab"))
    assert "No interaction lab run stored yet" in body


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


def _structure_offenders(body: str) -> list[str]:
    """Structural contract for the shell the lab pages render through."""
    problems = []
    if body.count("<h1") != 1:
        problems.append(f"{body.count('<h1')} h1 elements")
    if 'class="skip-link" href="#main"' not in body:
        problems.append("no skip link")
    if 'id="main"' not in body:
        problems.append("no main landmark")
    if 'lang="en"' not in body:
        problems.append("no lang attribute")
    if 'aria-label="Main navigation"' not in body:
        problems.append("nav has no accessible name")
    nav = body.split('id="site-nav"', 1)[1].split("</nav>", 1)[0]
    if nav.count('aria-current="page"') != 1:
        problems.append("navigation does not mark exactly one current page")
    if "<img" in body:
        problems.append("image without a text alternative")
    if "style=" in body.replace('style="width:', ""):
        problems.append("inline style")
    return problems


@pytest.mark.parametrize("action", ["lab-bola-scan", "lab-sci-scan", "lab-sci-reset"])
def test_lab_pages_keep_the_structural_accessibility_contract(client, lab, action):
    location = _run_through_ui(client, action, lab.port)
    pages = ["/ui/lab", location]
    if action != "lab-sci-reset":
        pages.append(f"{location}/report")
    for path in pages:
        body = client.get(path).text
        assert _structure_offenders(body) == [], path


def _matrix_table(body: str) -> str:
    start = body.index('<table class="matrix')
    return body[start:body.index("</table>", start)]


def test_the_matrix_page_is_untested_before_any_run(client):
    body = _text(client.get("/ui/lab/matrix"))
    assert "Asset matrix" in body
    assert "Untested is not SAFE" in body
    table = _matrix_table(body)
    assert table.count("cell-link") == 9
    assert table.count("badge-empty") == 9
    assert "CONFIRMED" not in table and "SAFE<" not in table
    assert "/ui/lab/bola/" not in table


def test_the_matrix_fills_from_real_runs_and_links_each_cell(client, lab):
    for actor, asset in (("mallapa", "MKT-2026-041"), ("sakshi", "BRD-2026-018"),
                         ("harsha", "ADS-2026-027"), ("mallapa", "BRD-2026-018"),
                         ("sakshi", "ADS-2026-027"), ("harsha", "MKT-2026-041")):
        _run_through_ui(client, "lab-bola-scan", lab.port, actor=actor, asset=asset)
    matrix = client.get("/api/lab-matrix").json()
    body = _text(client.get("/ui/lab/matrix"))
    table = _matrix_table(body)
    assert table.count("cell-link") == 9
    assert table.count("badge-empty") == 0
    assert matrix["summary"]["tested"] == 9
    assert matrix["summary"]["confirmed"] == 6 and matrix["summary"]["safe"] == 3
    for item in matrix["cells"]:
        # The cell names its check and the short id of the run that produced it.
        assert item["evidence"]["check_id"] in table
        assert item["evidence"]["run_id"][:8] in table
    detail = _text(client.get("/ui/lab/matrix?cell=sakshi:ADS-2026-027"))
    cross = next(item for item in matrix["cells"]
                 if item["requester"] == "sakshi" and item["asset_id"] == "ADS-2026-027")
    assert cross["evidence"]["run_id"] in detail
    assert cross["evidence"]["evidence_sha256"] in detail


def test_selecting_a_cell_shows_its_run_check_and_evidence(client, lab):
    location = _run_through_ui(client, "lab-bola-scan", lab.port,
                               actor="mallapa", asset="BRD-2026-018")
    run = _api_run(client, "bola", location.rsplit("/", 1)[-1])
    cross = next(check for check in run["checks"] if check["id"] == "LAB-BOLA-03")
    secure = next(check for check in run["checks"] if check["id"] == "LAB-BOLA-05")
    body = _text(client.get("/ui/lab/matrix?cell=mallapa:BRD-2026-018"))
    assert 'aria-current="true"' in body
    assert "is-selected" in body
    assert "mallapa" in body and "BRD-2026-018" in body and "sakshi" in body
    assert "owner-only" in body
    assert "private_record_returned" in body
    assert run["id"] in body and "LAB-BOLA-03" in body
    assert cross["evidence_sha256"] in body
    assert f"/ui/lab/bola/{run['id']}#LAB-BOLA-03" in body
    assert secure["evidence_sha256"][:8] in body or "Secure-route counterpart" in body
    assert "403" in body
    assert cross["reason"] in body


def test_an_untested_cell_stays_untested_and_offers_a_real_run(client, lab):
    _run_through_ui(client, "lab-bola-scan", lab.port, actor="mallapa", asset="BRD-2026-018")
    body = _text(client.get("/ui/lab/matrix?cell=harsha:ADS-2026-027"))
    assert "No stored check answers this combination" in body
    assert "It stays untested — not SAFE" in body
    assert 'name="actor" value="harsha"' in body
    assert 'name="asset" value="ADS-2026-027"' in body
    assert "Run and store evidence" in body
    # The untouched cells are still untested on the page, not silently safe.
    matrix = client.get("/api/lab-matrix").json()
    assert matrix["summary"]["untested"] == 5


def test_the_matrix_page_explains_the_reset_and_what_it_preserves(client):
    body = _text(client.get("/ui/lab/matrix"))
    assert "What the reset clears" in body and "What it preserves" in body
    assert "Every stored run, matrix cell, evidence hash, report and reset proof" in body
    assert 'action="/ui/actions/lab-sci-reset"' in body
    assert "A reset is evidence, not a cleanup" in body


def test_no_lab_secret_reaches_the_matrix_page(client, lab):
    _run_through_ui(client, "lab-bola-scan", lab.port, actor="mallapa", asset="BRD-2026-018")
    for url in ("/ui/lab/matrix", "/ui/lab/matrix?cell=mallapa:BRD-2026-018"):
        body = client.get(url).text
        for secret in FORBIDDEN:
            assert secret not in body, (url, secret)


# --- the 3x3 asset matrix ---------------------------------------------------

ASSETS = {"mallapa": "MKT-2026-041", "sakshi": "BRD-2026-018", "harsha": "ADS-2026-027"}
COVERAGE = (("mallapa", "sakshi"), ("sakshi", "harsha"), ("harsha", "mallapa"))


def _matrix_cells(body: str) -> list[str]:
    """The nine cell anchors of the grid, in document order."""
    return re.findall(r'<a class="cell-link"[^>]*>(.*?)</a>', body, re.S)


def test_the_matrix_page_is_nine_untested_cells_before_any_run(client):
    body = _text(client.get("/ui/lab/matrix"))
    assert "Asset matrix" in body and "Untested is not SAFE" in body
    cells = _matrix_cells(body)
    assert len(cells) == 9
    assert all("untested" in cell for cell in cells)
    assert "CONFIRMED" not in "".join(cells)
    assert "no stored check" in cells[0]


def test_the_matrix_page_fills_every_cell_from_stored_runs(client, lab):
    for pair in COVERAGE:
        _run_through_ui(client, "lab-bola-scan", lab.port, actor=pair[0], asset=ASSETS[pair[1]])
    api = client.get("/api/lab-matrix").json()
    assert api["summary"]["tested"] == 9 and api["summary"]["untested"] == 0
    body = _text(client.get("/ui/lab/matrix"))
    cells = _matrix_cells(body)
    assert len(cells) == 9
    assert all("untested" not in cell for cell in cells)
    for item in api["cells"]:
        # Each cell names the check and the short id of the run it came from.
        assert item["evidence"]["check_id"] in body
        assert item["evidence"]["run_id"][:8] in body


def test_the_cell_detail_shows_the_run_check_and_both_routes(client, lab):
    _run_through_ui(client, "lab-bola-scan", lab.port, actor="mallapa", asset=ASSETS["sakshi"])
    item = next(cell for cell in client.get("/api/lab-matrix").json()["cells"]
                if cell["requester"] == "mallapa" and cell["asset_id"] == ASSETS["sakshi"])
    body = _text(client.get("/ui/lab/matrix?cell=mallapa:BRD-2026-018"))
    assert 'aria-current="true"' in body and "is-selected" in body
    for value in (item["evidence"]["run_id"], item["evidence"]["check_id"],
                  item["evidence"]["evidence_sha256"], "private_record_returned",
                  "owner-only", "403"):
        assert value in body, value
    assert item["evidence"]["endpoint"] in body
    # Identity, asset and the oracle's own repair text, all from the API payload.
    assert item["requester"] in body and item["owner"] in body
    assert item["asset_id"] in body
    assert item["evidence"]["evidence_id"] in body
    assert item["evidence"]["remediation"] and item["evidence"]["remediation"] in body
    if item["evidence"]["lab_instance"]:
        assert item["evidence"]["lab_instance"] in body
    for secret in FORBIDDEN:
        assert secret not in body, secret
    # Both routes are shown with their own status and verdict.
    assert item["secure"]["check_id"] in body
    assert item["secure"]["evidence_sha256"][:8] in body
    assert f'/ui/lab/bola/{item["evidence"]["run_id"]}#{item["evidence"]["check_id"]}' in body


def test_an_untested_cell_is_shown_as_untested_not_safe(client, lab):
    _run_through_ui(client, "lab-bola-scan", lab.port, actor="mallapa", asset=ASSETS["sakshi"])
    api = client.get("/api/lab-matrix").json()
    assert api["summary"]["untested"] == 5
    body = _text(client.get("/ui/lab/matrix?cell=harsha:ADS-2026-027"))
    assert "No stored check answers this combination" in body
    assert "stays untested — not SAFE" in body
    assert "CONFIRMED" not in body.split("No stored check answers this combination")[1].split("</div>")[0]


def test_the_matrix_page_offers_the_full_demonstration_and_explains_the_reset(client):
    body = _text(client.get("/ui/lab/matrix"))
    assert 'action="/ui/actions/lab-demo-run"' in body
    assert "Run full authorization demonstration" in body
    assert "What the reset clears" in body and "What it preserves" in body
    assert "does not reset, delete or rewrite" in body


def test_the_full_demonstration_runs_the_catalog_pairs_and_claims_coverage(client, lab):
    response = client.post("/ui/actions/lab-demo-run", data={"port": lab.port})
    assert response.status_code == 200, response.text
    body = _text(response)
    assert "All nine cells have stored evidence" in body
    assert "3 / 3" in body
    for pair in COVERAGE:
        assert f'{pair[0]} → {pair[1]}' in body
    # Three runs were stored, and every one is linked from the result page.
    runs = client.get("/api/lab-matrix").json()
    assert runs["summary"]["runs_considered"] == 3 and runs["summary"]["untested"] == 0
    for item in runs["cells"]:
        assert item["evidence"]["run_id"][:8] in body


def test_a_refused_demonstration_reports_partial_coverage_honestly(client, lab):
    dead = socket.socket()
    dead.bind(("127.0.0.1", 0))
    port = dead.getsockname()[1]
    dead.close()                                   # nothing is listening there now
    response = client.post("/ui/actions/lab-demo-run", data={"port": port})
    assert response.status_code == 200, response.text
    body = _text(response)
    assert "Coverage is incomplete" in body
    assert "0 / 3" in body
    assert "not stored" in body
    assert "All nine cells have stored evidence" not in body
    assert client.get("/api/lab-matrix").json()["summary"]["untested"] == 9


@pytest.mark.parametrize("bad", ["", "not-a-port", "80", "70000"])
def test_the_demonstration_refuses_an_unusable_port_without_running_anything(client, bad):
    response = client.post("/ui/actions/lab-demo-run", data={"port": bad})
    assert response.status_code == 422, response.text
    assert "1024 and 65535" in _text(response)
    assert client.get("/api/lab-matrix").json()["summary"]["runs_considered"] == 0


def test_the_demonstration_stores_ordinary_runs_of_the_scan_api(client, lab):
    body = _text(client.post("/ui/actions/lab-demo-run", data={"port": lab.port}))
    run_ids = sorted(set(re.findall(r'/ui/lab/bola/([0-9a-f-]{36})', body)))
    assert len(run_ids) == 3
    for run_id in run_ids:
        detail = client.get(f"/api/lab-bola-scans/{run_id}").json()
        # Each is an ordinary stored run: same schema, same scope, same checks.
        assert detail["mode"] == "targetlab_bola"
        assert detail["scope"]["request_budget"] > 0
        assert len(detail["checks"]) == 6
        assert detail["scope"]["port"] == lab.port


def test_an_interrupted_demonstration_keeps_the_runs_it_already_stored(tmp_path, monkeypatch):
    """The lab disappears after two pairs: the stored runs stay, the rest is untested."""
    from targetlab.testing import GatedLabTlsServer

    monkeypatch.setenv("CANARYGATE_TARGETLAB_CA", str(lab_server.TARGETLAB_CERT))
    # 18 requests per run; the gate closes after the two completed runs.
    with GatedLabTlsServer(cut_after=36) as gate:
        with TestClient(create_ui_app(tmp_path / "interrupted.sqlite3")) as ui:
            response = ui.post("/ui/actions/lab-demo-run", data={"port": gate.port})
            assert response.status_code == 200, response.text
            body = _text(response)
            assert "Coverage is incomplete" in body
            assert "2 / 3" in body
            assert "All nine cells have stored evidence" not in body
            assert "TargetLab could not be reached; no evidence was stored" in body
            assert "harsha → mallapa" in body

            matrix = ui.get("/api/lab-matrix").json()
            assert matrix["summary"]["tested"] == 7 and matrix["summary"]["untested"] == 2
            assert matrix["summary"]["runs_considered"] == 2
            # The two untested cells are exactly the ones the missing pair answers.
            untested = {(cell["requester"], cell["asset_id"]) for cell in matrix["cells"]
                        if cell["state"] == "untested"}
            assert untested == {("mallapa", "ADS-2026-027"), ("harsha", "MKT-2026-041")}
            assert all(cell["verdict"] is None for cell in matrix["cells"]
                       if cell["state"] == "untested")
            # The runs that did succeed are ordinary, complete, retrievable runs.
            for cell in matrix["cells"]:
                if cell["state"] != "tested":
                    continue
                stored = ui.get(f"/api/lab-bola-scans/{cell['evidence']['run_id']}").json()
                assert len(stored["checks"]) == 6
                assert stored["constraints"]["requests_sent"] == 18
            assert gate.cut and gate.connections == 36


def test_running_the_demonstration_twice_keeps_history_and_selects_the_newest(client, lab):
    first = _text(client.post("/ui/actions/lab-demo-run", data={"port": lab.port}))
    first_ids = set(re.findall(r'/ui/lab/bola/([0-9a-f-]{36})', first))
    second = _text(client.post("/ui/actions/lab-demo-run", data={"port": lab.port}))
    second_ids = set(re.findall(r'/ui/lab/bola/([0-9a-f-]{36})', second))
    assert len(first_ids) == 3 and len(second_ids) == 3 and not first_ids & second_ids

    matrix = client.get("/api/lab-matrix").json()
    assert matrix["summary"]["tested"] == 9 and matrix["summary"]["untested"] == 0
    assert matrix["summary"]["runs_considered"] == 6
    assert matrix["summary"]["duplicated_cells"] == 9
    assert matrix["summary"]["stale_cells"] == 0
    for cell in matrix["cells"]:
        # Current evidence always comes from the newest batch ...
        assert cell["evidence"]["run_id"] in second_ids
        # ... and the older answer is listed, not silently dropped.
        assert set(cell["superseded_runs"]) & first_ids

    # Selection is deterministic: the same database answers the same way twice.
    again = client.get("/api/lab-matrix").json()
    assert [(cell["evidence"]["evidence_id"], cell["verdict"]) for cell in again["cells"]] == \
           [(cell["evidence"]["evidence_id"], cell["verdict"]) for cell in matrix["cells"]]


def test_a_connection_failure_is_never_reported_as_safe(client):
    dead = socket.socket()
    dead.bind(("127.0.0.1", 0))
    port = dead.getsockname()[1]
    dead.close()
    response = client.post("/ui/actions/lab-demo-run", data={"port": port})
    assert response.status_code == 200, response.text
    body = _text(response)
    assert "Coverage is incomplete" in body and "0 / 3" in body
    assert "not stored" in body
    assert "All nine cells have stored evidence" not in body
    assert "Cells tested" in body and "0 / 9" in body
    assert "Pairs run" in body and "0 / 3" in body
    matrix = client.get("/api/lab-matrix").json()["summary"]
    assert matrix["tested"] == 0 and matrix["safe"] == 0 and matrix["confirmed"] == 0
    assert matrix["untested"] == 9


def test_the_matrix_page_leaks_no_lab_secret(client, lab):
    for pair in COVERAGE:
        _run_through_ui(client, "lab-bola-scan", lab.port, actor=pair[0], asset=ASSETS[pair[1]])
    for url in ("/ui/lab/matrix", "/ui/lab/matrix?cell=mallapa:BRD-2026-018"):
        body = client.get(url).text
        for secret in FORBIDDEN:
            assert secret not in body, (url, secret)


# --- the assessment workspace and the recorded execution view ----------------

def test_the_assessment_workspace_is_built_from_backend_data(client):
    body = _text(client.get("/ui/assessment"))
    catalog = client.get("/api/lab-catalog").json()
    for heading in ("A · API specification", "B · Testing environment",
                    "C · Demo accounts", "D · Test selection"):
        assert heading in body, heading
    assert "Inventory only — no security scan performed" in body
    assert "RUN SECURITY ASSESSMENT" in body
    for account in catalog["accounts"]:
        assert account["account"] in body and account["title"] in body
        assert account["asset_id"] in body and account["asset_label"] in body
    # The forms post to the existing action routes and nowhere else.
    for action in ("/ui/actions/lab-bola-scan", "/ui/actions/lab-sci-scan",
                   "/ui/actions/lab-demo-run"):
        assert f'action="{action}"' in body, action
    # Opening the workspace starts nothing.
    assert client.get("/api/lab-matrix").json()["summary"]["runs_considered"] == 0
    for secret in FORBIDDEN:
        assert secret not in body, secret


def test_the_assessment_form_runs_the_pair_it_names(client, lab):
    response = client.post("/ui/actions/lab-bola-scan",
                           data={"port": lab.port, "actor": "sakshi", "asset": "ADS-2026-027"},
                           follow_redirects=False)
    assert response.status_code == 303
    run = client.get(f"/api/lab-bola-scans/{response.headers['location'].rsplit('/', 1)[-1]}").json()
    cross = {(check["actor"], check["owner"]) for check in run["checks"]
             if check["direction"] == "cross_account"}
    assert cross == {("sakshi", "harsha"), ("harsha", "sakshi")}
    baselines = {(check["actor"], check["owner"]) for check in run["checks"]
                 if check["direction"] == "owner_baseline"}
    assert baselines == {("sakshi", "sakshi"), ("harsha", "harsha")}
    assert run["verdict"] == "CONFIRMED"


def test_the_run_page_shows_a_recorded_timeline_and_the_disclosure_proof(client, lab):
    response = client.post("/ui/actions/lab-bola-scan",
                           data={"port": lab.port, "actor": "mallapa", "asset": "BRD-2026-018"},
                           follow_redirects=False)
    run_id = response.headers["location"].rsplit("/", 1)[-1]
    body = _text(client.get(f"/ui/lab/bola/{run_id}"))
    assert "Execution timeline" in body
    assert "the backend streams no live events" in body
    for stage in ("Authentication", "Ownership baselines", "Cross-account request",
                  "Disclosure verification", "Secure-route comparison"):
        assert stage in body, stage
    assert "Disclosure proof" in body
    assert "mallapa → sakshi's record" in body
    assert "Private data disclosed" in body
    assert "The same request · secure route" in body
    # Every step links to the stored check it came from.
    for check_id in ("LAB-BOLA-03", "LAB-BOLA-05"):
        assert f'target="#{check_id}"' in body or f'href="#{check_id}"' in body
        assert f'id="{check_id}"' in body
    for secret in FORBIDDEN:
        assert secret not in body, secret
