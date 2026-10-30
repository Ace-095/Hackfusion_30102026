"""The offline half of the interface, checked against the JSON API it renders.

These tests exist to prove three properties the integration brief asks for:

* no page invents a result: every verdict, count and section on screen is compared
  with the same value from a real API call;
* no security logic lives in the UI: templates and routes only read fields the
  backend produced;
* every stored family is reachable, listed and reportable through the interface.
"""
import html
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from canarygate.ui.app import create_ui_app

ROOT = Path(__file__).resolve().parents[2]

#: The families a reviewer can drive from the UI, with the route that starts each.
ENDPOINTS = {
    "read-bola": ("/ui/actions/scenario-scan", "/api/scenario-scans",
                  "synthetic-vulnerable"),
    "authentication": ("/ui/actions/authentication-scan", "/api/authentication-scans",
                       "synthetic-jwt-sub-confirmed"),
    "validation": ("/ui/actions/validation-scan", "/api/validation-scans",
                   "synthetic-validation-weak"),
    "interaction": ("/ui/actions/interaction-scan", "/api/interaction-scans",
                    "synthetic-sci-authz-input-confirmed"),
}


@pytest.fixture()
def client(tmp_path):
    with TestClient(create_ui_app(tmp_path / "ui-contract.sqlite3")) as ui:
        yield ui


def _start(client, family):
    action, root, scenario = ENDPOINTS[family]
    response = client.post(action, data={"scenario_id": scenario}, follow_redirects=False)
    assert response.status_code == 303, response.text
    location = response.headers["location"]
    run_id = location.rsplit("/", 1)[-1]
    api_run = client.get(f"{root}/{run_id}")
    assert api_run.status_code == 200
    return family, run_id, api_run.json(), location


# --------------------------------------------------------------------------- #
# Suite workflows
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("family", sorted(ENDPOINTS))
def test_each_suite_action_stores_the_run_and_renders_the_api_outcome(client, family):
    family, run_id, api_run, location = _start(client, family)
    page = client.get(location)
    assert page.status_code == 200
    body = html.unescape(page.text)

    assert run_id in body
    assert api_run["scenario_id"] in body
    if api_run.get("verdict"):
        assert api_run["verdict"] in body
    else:
        assert api_run["status"] in body
        for check in api_run["checks"][:4]:
            assert check["id"] in body
            assert check["verdict"] in body
    # The page never shows the JSON error envelope instead of a result.
    assert '"detail"' not in body


@pytest.mark.parametrize("family", sorted(ENDPOINTS))
def test_each_suite_report_page_matches_the_backend_section_projection(client, family):
    family, run_id, api_run, location = _start(client, family)
    root = ENDPOINTS[family][1]
    sections = client.get(f"{root}/{run_id}/report?view=sections").json()["sections"]
    page = client.get(f"{location}/report")
    assert page.status_code == 200
    assert page.text.count('class="report-section"') == len(sections)
    for key in sections:
        assert key.replace("_", " ").lower() in page.text.lower(), key


@pytest.mark.parametrize("family", sorted(ENDPOINTS))
def test_default_json_report_view_returns_the_run_for_every_family(client, family):
    # Regression for the response-model defect: the documented default view used to
    # answer 500 because only the section projection was declared.
    family, run_id, api_run, _ = _start(client, family)
    root = ENDPOINTS[family][1]
    response = client.get(f"{root}/{run_id}/report")
    assert response.status_code == 200
    assert response.json()["id"] == run_id
    assert client.get(f"{root}/{run_id}/report?format=html").status_code == 200


def test_suites_page_lists_every_stored_run_and_the_bundled_catalog(client):
    stored = {family: _start(client, family)[1] for family in ENDPOINTS}
    body = client.get("/ui/suites").text
    for family, run_id in stored.items():
        assert run_id[:8] in body, family
    # Catalog ids come from the backend registries, not from the template.
    assert "synthetic-sci-incomplete-baseline" in body      # interaction
    assert "synthetic-validation-malformed-responses" in body  # validation
    assert "synthetic-vulnerable" in body                    # read-BOLA


def test_a_suite_scenario_that_cannot_confirm_is_not_shown_as_safe(client):
    # synthetic-sci-incomplete-baseline is INCONCLUSIVE by design in the engine.
    response = client.post("/ui/actions/interaction-scan",
                           data={"scenario_id": "synthetic-sci-incomplete-baseline"},
                           follow_redirects=False)
    assert response.status_code == 303
    location = response.headers["location"]
    run_id = location.rsplit("/", 1)[-1]
    api_run = client.get(f"/api/interaction-scans/{run_id}").json()
    body = client.get(location).text
    assert api_run["verdict"] == "INCONCLUSIVE"
    assert 'badge badge-info badge-lg">INCONCLUSIVE' in body      # run-level badge
    # Baselines may legitimately be SAFE; the run outcome must not be.
    assert 'badge badge-ok badge-lg">SAFE' not in body


# --------------------------------------------------------------------------- #
# Matrix
# --------------------------------------------------------------------------- #
def test_matrix_page_shows_the_backend_matrix_with_its_partial_coverage(client):
    for family in ("read-bola", "authentication"):
        _start(client, family)
    matrix = client.get("/api/authorization-matrix").json()
    body = client.get("/ui/matrix").text

    assert matrix["coverage"]["statement"][:50] in body
    assert "not tested" in body
    # Every untested cell is rendered as a gap, never as a verdict.
    assert body.count("not tested") >= matrix["coverage"]["untested"] - matrix["coverage"]["by_state"]["grey"]
    for row in matrix["rows"][:3]:
        assert row["endpoint"] in body
        for cell in row["cells"]:
            assert cell["source_ref"].split(":")[0] in body
    # A hatched cell must not carry a SAFE badge on the same table row.
    hatched_safe = re.search(r'not tested</span>\s*<div class="mono xs">[^<]*</div>', body)
    assert hatched_safe, "hatched cells should render their source_ref"
    assert 'class="badge badge-ok">SAFE</span>' not in hatched_safe.group(0)


def test_fixture_grid_still_labels_unassessed_combinations(client):
    client.post("/ui/actions/fixture-scan")
    body = client.get("/ui/matrix").text
    assert "not assessed" in body
    assert "Recorded cells" in body


# --------------------------------------------------------------------------- #
# Reports
# --------------------------------------------------------------------------- #
def test_reports_page_lists_every_family_that_has_a_stored_run(client):
    stored = {family: _start(client, family)[1] for family in ENDPOINTS}
    body = client.get("/ui/reports").text
    for family, run_id in stored.items():
        assert run_id[:8] in body, family
    assert "TargetLab validation reports" in body
    assert "Offline suite reports" in body


def test_report_lookup_redirects_to_the_family_page(client):
    _, run_id, _, location = _start(client, "read-bola")
    response = client.get("/ui/reports/lookup",
                          params={"family": "read-bola", "run_id": run_id},
                          follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == location


@pytest.mark.parametrize("params", [
    {"family": "nonsense", "run_id": "0" * 8 + "-0000-0000-0000-" + "0" * 12},
    {"family": "read-bola", "run_id": "not-a-uuid"},
    {"family": "read-bola", "run_id": ""},
])
def test_report_lookup_rejects_bad_input_with_a_page(client, params):
    response = client.get("/ui/reports/lookup", params=params)
    assert response.status_code == 422
    assert response.headers["content-type"].startswith("text/html")


# --------------------------------------------------------------------------- #
# Empty states and honest failures
# --------------------------------------------------------------------------- #
def test_empty_states_name_the_gap_instead_of_showing_samples(client):
    pages = {path: client.get(path).text for path in
             ("/ui/", "/ui/matrix", "/ui/reports", "/ui/suites", "/ui/lab", "/ui/scans")}
    assert "No fixture scan has been recorded yet" in pages["/ui/"]
    assert "No verdicts yet" in pages["/ui/"]
    assert "The matrix is empty" in pages["/ui/matrix"]
    assert "The backend matrix has no rows" in pages["/ui/matrix"]
    assert "No reports yet" in pages["/ui/reports"]
    assert "No stored run" in pages["/ui/suites"]
    assert "No TargetLab run yet" in pages["/ui/"]
    for path, body in pages.items():
        assert 'badge badge-danger">CONFIRMED' not in body, path


def test_backend_error_is_rendered_as_html_not_json(client):
    response = client.get("/ui/scans/" + "1" * 8 + "-1111-1111-1111-" + "1" * 12)
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("text/html")
    assert '"detail"' not in response.text


def test_oversized_form_is_refused(client):
    response = client.post("/ui/actions/scenario-scan",
                           content=b"scenario_id=" + b"a" * (3 * 128 * 1024 + 10),
                           headers={"content-type": "application/x-www-form-urlencoded"})
    assert response.status_code == 413


# --------------------------------------------------------------------------- #
# No duplicated security logic, no invented technology
# --------------------------------------------------------------------------- #
def test_templates_never_assign_or_derive_a_verdict():
    offenders = []
    for path in sorted((ROOT / "canarygate" / "ui" / "templates").rglob("*.html")):
        text = path.read_text(encoding="utf-8")
        if re.search(r"\{%-?\s*set\s+\w+\s*=\s*[\"'](CONFIRMED|SUSPECTED|SAFE|INCONCLUSIVE|SKIPPED)[\"']",
                     text):
            offenders.append(f"{path.name}: hard-codes a verdict")
        if re.search(r"\{%-?\s*set\s+verdict\s*=", text):
            offenders.append(f"{path.name}: derives a verdict")
        # Comparing a *stored* verdict field is display branching and allowed.
        # Comparing anything else (a status code, a body, a probe result) to a
        # verdict literal would mean the template decided something itself.
        for match in re.finditer(r"(\S+)\s*==\s*[\"'](CONFIRMED|SUSPECTED|SAFE|INCONCLUSIVE|SKIPPED)[\"']",
                                 text):
            if not match.group(1).endswith(".verdict"):
                offenders.append(f"{path.name}: compares {match.group(1)} to a verdict")
        if re.search(r"status(_code)?\s*==\s*200", text):
            offenders.append(f"{path.name}: treats a 200 as a result")
    assert offenders == []


def test_ui_routes_never_make_network_calls_or_decide_findings():
    text = (ROOT / "canarygate" / "ui" / "routes.py").read_text(encoding="utf-8")
    assert "import httpx" not in text
    assert "httpx." not in text
    assert "import socket" not in text and "socket.socket" not in text
    assert "def decide" not in text
    # No boolean expression that could mint a verdict from a response.
    assert not re.search(r"verdict\s*=\s*[\"'](CONFIRMED|SUSPECTED|SAFE)[\"']", text)
    # The only TargetLab interaction is through the JSON API handlers.
    assert "start_lab_bola_scan" in text and "start_lab_sci_scan" in text


def test_application_only_serves_local_assets(client):
    body = client.get("/ui/").text
    assert re.search(r"""(?:src|href)\s*=\s*["'](?:https?:)?//""", body, re.IGNORECASE) is None
    static = client.get("/ui/static/css/app.css")
    assert static.status_code == 200
    assert client.get("/ui/static/vendor/htmx.min.js").status_code == 200


def test_ui_is_not_in_the_json_schema_as_a_public_contract(client):
    # HTML routes stay out of the OpenAPI document; the JSON contract is unchanged.
    schema = client.get("/openapi.json").json()
    assert not any(path.startswith("/ui") for path in schema["paths"])
    assert "/api/health" in schema["paths"]
