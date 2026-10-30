"""Integration tests for the server-rendered UI.

These tests verify behaviour, not templates: every page is fetched from the real
application, actions go through the real API handlers and the assertions compare
what the page shows against what the JSON API returns. Nothing here asserts a
verdict invented by the UI.
"""
import re

import pytest
from fastapi.testclient import TestClient

from canarygate.api.app import create_app

PATHS = ["/ui/", "/ui/endpoints", "/ui/setup", "/ui/scans", "/ui/matrix",
         "/ui/reports", "/ui/suites", "/ui/spec"]
EXTERNAL_REFERENCE = re.compile(r"""(?:src|href)\s*=\s*["'](?:https?:)?//""", re.IGNORECASE)


def _client(tmp_path, name="ui.sqlite3"):
    return TestClient(create_app(tmp_path / name))


def test_every_page_renders_before_any_run_without_sample_data(tmp_path):
    with _client(tmp_path) as client:
        for path in PATHS:
            response = client.get(path)
            assert response.status_code == 200, path
            assert response.headers["content-type"].startswith("text/html")
            body = response.text
            # Honesty: the fixture banner is on every page and no verdict exists yet.
            assert "Fixture-only build" in body
            assert "not evidence about any real" in body
            # No verdict badge is rendered anywhere: verdict names may appear only
            # in the empty legend on the dashboard, never as a result.
            assert 'badge badge-danger">CONFIRMED' not in body, path
            assert "No verdict yet" in body or path != "/ui/"
            # Local assets only, and a responsive viewport.
            assert EXTERNAL_REFERENCE.search(body) is None, path
            assert '<meta name="viewport"' in body

        assert "No fixture scan has been recorded yet" in client.get("/ui/").text
        assert "Setup has not been evaluated" in client.get("/ui/setup").text
        assert "The matrix is empty" in client.get("/ui/matrix").text
        assert "No reports yet" in client.get("/ui/reports").text


def test_ui_scan_action_renders_the_same_run_the_api_returns(tmp_path):
    with _client(tmp_path) as client:
        response = client.post("/ui/actions/fixture-scan", follow_redirects=False)
        assert response.status_code == 303
        location = response.headers["location"]
        assert location.startswith("/ui/scans/")
        run_id = location.rsplit("/", 1)[-1]

        api_run = client.get(f"/api/scan/{run_id}").json()
        page = client.get(location)
        assert page.status_code == 200
        body = page.text
        assert api_run["verdict"] == "CONFIRMED"
        assert api_run["verdict"] in body
        assert api_run["reason"] in body
        assert api_run["endpoint"] in body
        assert api_run["verified_owner"] in body
        assert api_run["target_resource"] in body
        # Both evidence parts and the decision checklist are rendered from the API.
        assert "1 · Ownership evidence" in body and "2 · Disclosure evidence" in body
        for key in api_run["bola_checklist"]:
            assert key in body
        assert api_run["evidence"]["ownership"]["sha256"] in body
        # Constraints are the backend's counters, including the zero-violation rows.
        assert str(api_run["constraints"]["requests_sent"]) in body
        assert "Out-of-scope requests executed: 0" in body
        assert "Destructive requests executed: 0" in body

        # The run is stored exactly once and the list/matrix now reflect it.
        findings = client.get("/api/findings").json()["findings"]
        assert [item["id"] for item in findings] == [run_id]
        assert run_id[:8] in client.get("/ui/scans").text
        assert run_id[:8] in client.get("/ui/matrix").text


def test_ui_never_renders_credentials_or_raw_tokens(tmp_path):
    with _client(tmp_path) as client:
        run = client.post("/ui/actions/fixture-scan", follow_redirects=False)
        run_id = run.headers["location"].rsplit("/", 1)[-1]
        pages = [client.get(f"/ui/scans/{run_id}").text,
                 client.get(f"/ui/scans/{run_id}/evidence").text,
                 client.get(f"/api/reports/{run_id}?format=html").text]
        for body in pages:
            assert "offline-token" not in body
            assert "Bearer " not in body
            assert "alice-secret" not in body
            assert "synthetic-alpha-private" not in body
            assert "[REDACTED]" in body  # redaction is visible, not hidden


def test_ui_evidence_page_reports_recorded_coverage(tmp_path):
    with _client(tmp_path) as client:
        run = client.post("/ui/actions/fixture-scan", follow_redirects=False)
        run_id = run.headers["location"].rsplit("/", 1)[-1]
        observations = client.get(f"/api/scan/{run_id}/observations").json()
        body = client.get(f"/ui/scans/{run_id}/evidence").text
        assert observations["coverage"] in body
        for observation in observations["observations"]:
            assert observation["phase"] in body
            assert observation["sha256"] in body
        assert len(observations["observations"]) >= 1


def test_ui_htmx_actions_return_fragments_and_plain_posts_redirect(tmp_path):
    with _client(tmp_path) as client:
        fragment = client.post("/ui/actions/fixture-scan", headers={"HX-Request": "true"},
                               follow_redirects=False)
        assert fragment.status_code == 200
        assert "<html" not in fragment.text
        assert "New fixture run recorded" in fragment.text
        run_id = client.get("/api/findings").json()["findings"][-1]["id"]
        assert f"/ui/scans/{run_id}" in fragment.text

        plain = client.post("/ui/actions/scenario-scan",
                            data={"scenario_id": "synthetic-secure"},
                            follow_redirects=False)
        assert plain.status_code == 303
        assert plain.headers["location"].startswith("/ui/suites/read-bola/")


def test_ui_suite_runs_render_backend_verdicts(tmp_path):
    with _client(tmp_path) as client:
        vulnerable = client.post("/ui/actions/scenario-scan",
                                 data={"scenario_id": "synthetic-vulnerable"},
                                 follow_redirects=False)
        vuln_id = vulnerable.headers["location"].rsplit("/", 1)[-1]
        api_run = client.get(f"/api/scenario-scans/{vuln_id}").json()
        body = client.get(f"/ui/suites/read-bola/{vuln_id}").text
        assert api_run["verdict"] == "CONFIRMED"
        assert api_run["verdict"] in body
        assert api_run["reason"] in body
        assert api_run["scenario_id"] in body
        assert "network_transport_enabled" not in body or "false" in body
        for limitation in api_run["limitations"]:
            assert limitation in body

        secure = client.post("/ui/actions/scenario-scan",
                             data={"scenario_id": "synthetic-secure"},
                             follow_redirects=False)
        secure_id = secure.headers["location"].rsplit("/", 1)[-1]
        secure_run = client.get(f"/api/scenario-scans/{secure_id}").json()
        secure_body = client.get(f"/ui/suites/read-bola/{secure_id}").text
        assert secure_run["verdict"] in secure_body

        authentication = client.post("/ui/actions/authentication-scan",
                                     data={"scenario_id": "synthetic-jwt-sub-confirmed"},
                                     follow_redirects=False)
        auth_id = authentication.headers["location"].rsplit("/", 1)[-1]
        auth_run = client.get(f"/api/authentication-scans/{auth_id}").json()
        auth_body = client.get(f"/ui/suites/authentication/{auth_id}").text
        assert "claims_unverified" in auth_body
        assert str(auth_run["summary"]["executed"]) in auth_body
        for check in auth_run["checks"]:
            assert check["id"] in auth_body


def test_ui_rejects_unknown_suite_and_run_ids_with_html_errors(tmp_path):
    with _client(tmp_path) as client:
        missing = client.get("/ui/scans/00000000-0000-0000-0000-000000000000")
        assert missing.status_code == 404
        assert missing.headers["content-type"].startswith("text/html")
        assert "HTTP 404" in missing.text

        assert client.get("/ui/suites/read-bola/00000000-0000-0000-0000-000000000000").status_code == 404
        assert client.get("/ui/suites/not-a-family/abc").status_code == 404
        assert client.get("/ui/reports/lookup?family=read-bola&run_id=abc").status_code == 422

        unknown_scenario = client.post("/ui/actions/scenario-scan",
                                       data={"scenario_id": "no-such-scenario"},
                                       follow_redirects=False)
        assert unknown_scenario.status_code == 404
        assert "Unknown offline scenario" in unknown_scenario.text


def test_ui_spec_inspection_is_bounded_and_never_scan_sources(tmp_path):
    document = (tmp_path / "spec.yaml")
    document.write_text(
        "openapi: 3.0.3\n"
        "info: {title: Example, version: '1'}\n"
        "paths:\n"
        "  /things:\n"
        "    get:\n"
        "      security: [{bearerAuth: []}]\n"
        "      responses:\n"
        "        '200': {description: ok}\n",
        encoding="utf-8")

    with _client(tmp_path) as client:
        before = client.get("/api/endpoints").json()["endpoints"]
        page = client.post("/ui/actions/spec-inspect",
                           data={"document": document.read_text(encoding="utf-8")})
        assert page.status_code == 200
        assert "mode=inventory_only" in page.text
        assert "/things" in page.text
        # Inspection must not change the fixture inventory or start a scan.
        assert client.get("/api/endpoints").json()["endpoints"] == before
        assert client.get("/api/findings").json()["findings"] == []

        invalid = client.post("/ui/actions/spec-inspect", data={"document": "not: openapi"})
        assert invalid.status_code == 422
        assert "Invalid or unsupported OpenAPI specification." in invalid.text

        assert client.post("/ui/actions/spec-inspect", data={"document": ""}).status_code == 422
        assert client.post("/ui/actions/spec-inspect",
                           data={"document": "a" * (130 * 1024)}).status_code == 413
        assert client.post("/ui/actions/spec-inspect", content=b"{}",
                           headers={"content-type": "application/json"}).status_code == 415


def test_ui_static_assets_are_local_and_served(tmp_path):
    with _client(tmp_path) as client:
        css = client.get("/ui/static/css/app.css")
        js = client.get("/ui/static/js/app.js")
        htmx = client.get("/ui/static/vendor/htmx.min.js")
        for response in (css, js, htmx):
            assert response.status_code == 200
        assert "url(http" not in css.text
        assert "@import" not in css.text
        assert "htmx" in htmx.text.lower()
        assert client.get("/ui/static/vendor/htmx.LICENSE").status_code == 200


def test_ui_pages_use_the_same_backend_handlers_as_the_json_api(tmp_path):
    """The UI must not recompute verdicts: compare counts against the API."""
    with _client(tmp_path) as client:
        for _ in range(2):
            client.post("/ui/actions/fixture-scan")
        findings = client.get("/api/findings").json()["findings"]
        matrix = client.get("/api/matrix").json()["cells"]
        scans_page = client.get("/ui/scans").text
        matrix_page = client.get("/ui/matrix").text
        assert f"{len(findings)} stored run(s)" in scans_page
        for run in findings:
            assert run["endpoint"] in scans_page
            assert run["id"][:8] in scans_page
        assert len(matrix) == len(findings)
        for cell in matrix:
            assert cell["id"][:8] in matrix_page
        # Counts are derived from the same verdicts the API returns.
        confirmed = sum(1 for run in findings if run["verdict"] == "CONFIRMED")
        assert f"<span class=\"stat-value\">{confirmed}</span>" in scans_page


def test_ui_fixture_scan_needs_no_network(tmp_path, monkeypatch):
    """A UI-triggered scan must stay offline, exactly like the API scan."""
    def no_network(*args, **kwargs):
        raise AssertionError("UI flow attempted a network connection")

    with _client(tmp_path) as client:
        with monkeypatch.context() as isolated:
            isolated.setattr("socket.socket.connect", no_network)
            isolated.setattr("socket.getaddrinfo", no_network)
            response = client.post("/ui/actions/fixture-scan", follow_redirects=False)
            assert response.status_code == 303
            run_id = response.headers["location"].rsplit("/", 1)[-1]
            detail = client.get(f"/ui/scans/{run_id}")
            assert detail.status_code == 200
            assert "CONFIRMED" in detail.text


@pytest.mark.parametrize("family", ["read-bola", "authentication"])
def test_ui_suite_lookup_redirects_to_stored_runs(tmp_path, family):
    with _client(tmp_path) as client:
        if family == "read-bola":
            created = client.post("/ui/actions/scenario-scan",
                                  data={"scenario_id": "synthetic-metadata"},
                                  follow_redirects=False)
        else:
            created = client.post("/ui/actions/authentication-scan",
                                  data={"scenario_id": "synthetic-jwt-opaque"},
                                  follow_redirects=False)
        run_id = created.headers["location"].rsplit("/", 1)[-1]
        lookup = client.get(f"/ui/reports/lookup?family={family}&run_id={run_id}",
                            follow_redirects=False)
        assert lookup.status_code == 303
        assert lookup.headers["location"] == f"/ui/suites/{family}/{run_id}"
        assert client.get(lookup.headers["location"]).status_code == 200
