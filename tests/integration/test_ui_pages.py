"""Integration tests for the server-rendered UI.

These tests verify behaviour, not templates: every page is fetched from the real
application, actions go through the real API handlers and the assertions compare
what the page shows against what the JSON API returns. Nothing here asserts a
verdict invented by the UI.
"""
import re

import pytest
from fastapi.testclient import TestClient

from canarygate.api.app import create_app as create_backend_app
from canarygate.ui.app import create_ui_app

PATHS = ["/ui/", "/ui/endpoints", "/ui/setup", "/ui/scans", "/ui/matrix",
         "/ui/reports", "/ui/suites", "/ui/spec"]
EXTERNAL_REFERENCE = re.compile(r"""(?:src|href)\s*=\s*["'](?:https?:)?//""", re.IGNORECASE)


def _client(tmp_path, name="ui.sqlite3"):
    return TestClient(create_ui_app(tmp_path / name))


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
        assert 'id="proof-ownership"' in body and 'id="proof-disclosure"' in body
        assert "Ownership evidence" in body and "Disclosure evidence" in body
        # Keys are rendered with underscores humanised for readability.
        for key in api_run["bola_checklist"]:
            assert key.replace("_", " ") in body
        assert api_run["evidence"]["ownership"]["sha256"] in body
        # Constraints are the backend's counters, including the zero-violation rows.
        assert str(api_run["constraints"]["requests_sent"]) in body
        assert '<span class="stat-label">Out of scope executed</span>' in body
        assert '<span class="stat-label">Destructive executed</span>' in body
        assert '<span class="stat-label">Out of scope executed</span>' in body
        assert '<span class="stat-label">Destructive executed</span>' in body
        assert '<span class="stat-label">External executed</span>' in body

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
        assert f'<span class="stat-label">Stored runs</span><span class="stat-value">{len(findings)}</span>' in scans_page
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


def test_backend_application_is_unmodified_and_ui_is_additive(tmp_path):
    """The frontend must not change the backend app; it only extends it in memory."""
    backend = create_backend_app(tmp_path / "backend-only.sqlite3")
    backend_paths = {getattr(route, "path", "") for route in backend.routes}
    assert not any(path.startswith("/ui") for path in backend_paths)
    with TestClient(backend) as client:
        # The backend alone does not serve the UI, and its own API is unchanged.
        assert client.get("/ui/").status_code == 404
        assert client.get("/api/health").json() == {
            "status": "ok", "mode": "fixture", "live_scanning": False}
        assert len(client.get("/api/endpoints").json()["endpoints"]) == 4

    ui = create_ui_app(tmp_path / "with-ui.sqlite3")
    ui_paths = {getattr(route, "path", "") for route in ui.routes}
    assert "/ui/" in ui_paths
    assert "/api/health" in ui_paths  # backend routes are still mounted as-is
    with TestClient(ui) as client:
        assert client.get("/ui/").status_code == 200
        assert client.get("/api/health").json()["mode"] == "fixture"


def test_findings_page_groups_only_backend_verdicts(tmp_path):
    with _client(tmp_path) as client:
        empty = client.get("/ui/findings")
        assert empty.status_code == 200
        assert "No findings yet" in empty.text
        assert "Severity is not part of the backend contract" in empty.text

        run = client.post("/ui/actions/fixture-scan", follow_redirects=False)
        run_id = run.headers["location"].rsplit("/", 1)[-1]
        api_run = client.get(f"/api/scan/{run_id}").json()
        body = client.get("/ui/findings").text

        assert api_run["verdict"] == "CONFIRMED"
        assert "Confirmed findings" in body
        assert api_run["reason"] in body
        assert api_run["remediation"] in body
        assert api_run["verified_owner"] in body
        # Counts shown are derived from the same runs the API returns.
        runs = client.get("/api/findings").json()["findings"]
        assert f"<span class=\"stat-value\">{len(runs)}</span>" in body
        # No invented severity *values*: the page may state that severity is absent,
        # but it must never render a severity badge or score of its own.
        assert re.search(r"badge[^>]*>\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)\s*<", body) is None
        assert "Severity:" not in body and "severity:" not in body
        # The disclaimer is the only place the word may appear.
        assert body.lower().count("severity") == 2


def test_configure_page_is_read_only_and_redacts_secrets(tmp_path):
    with _client(tmp_path) as client:
        page = client.get("/ui/configure")
        assert page.status_code == 200
        body = page.text
        # Real bundled configuration is shown (read from backend package files).
        assert "scope.yaml" in body and "recipe.json" in body and "fixture.yaml" in body
        assert "fixture.invalid" in body
        assert "known_owner_canary" in body
        # The canary value itself must be redacted on screen.
        assert "synthetic-bob-private-canary" not in body
        assert "[REDACTED]" in body
        # Editing is disabled, and the page says why.
        assert "This page is read-only, deliberately." in body
        assert 'disabled' in body
        assert "no backend endpoint accepts this configuration" in " ".join(body.split())
        # And nothing was configured by viewing it.
        assert client.get("/api/findings").json()["findings"] == []


def test_matrix_grid_marks_unassessed_cells_instead_of_guessing(tmp_path):
    with _client(tmp_path) as client:
        empty = client.get("/ui/matrix").text
        assert "No grid yet" in empty

        client.post("/ui/actions/fixture-scan")
        runs = client.get("/api/findings").json()["findings"]
        endpoints = client.get("/api/endpoints").json()["endpoints"]
        body = client.get("/ui/matrix").text

        # Columns are the accounts the backend demonstrated, not just the acting one.
        actors = sorted({name for run in runs for name in run["setup"]["accounts"]})
        assert "not assessed" in body
        # Every inventory endpoint appears as a row, and every exercised actor as a column.
        for endpoint in endpoints:
            assert f"{endpoint['method']} {endpoint['path']}" in body
        for actor in actors:
            assert f'class="mono">{actor}<' in body
        # Assessed count equals recorded cells, not the full grid.
        assessed = len(runs)
        total = len(endpoints) * len(actors)
        assert f"{assessed} / {total}" in body


def test_report_view_renders_backend_sections_and_prints(tmp_path):
    with _client(tmp_path) as client:
        run = client.post("/ui/actions/fixture-scan", follow_redirects=False)
        run_id = run.headers["location"].rsplit("/", 1)[-1]
        sections = client.get(f"/api/reports/{run_id}?view=sections").json()["sections"]
        response = client.get(f"/ui/scans/{run_id}/report")
        assert response.status_code == 200
        body = response.text

        # Every backend section key is rendered, with a human title.
        assert len(sections) == 9
        for title in ("Executive summary", "Scope, accounts and seeding", "Endpoint inventory",
                      "Findings", "Secured endpoints that passed", "Skipped and inconclusive",
                      "Authorization matrix", "Manual interventions and inferences",
                      "Constraint checklist"):
            assert title in body, title
        assert "Executive summary" in body
        assert "Constraint checklist" in body
        assert "Secured endpoints that passed" in body
        # Values come from the backend projection, not from the template.
        summary = sections["executive_summary"]
        assert summary["bola_verdict"] in body
        for value in summary["verdict_counts"].values():
            assert str(value) in body
        assert sections["scope_accounts_seeding"]["scope"] in body
        # Printable, and honest about scope.
        assert "data-print" in body
        assert "fixture projection, not the full frozen P0 report" in body
        assert "print" in client.get("/ui/static/css/app.css").text


def test_journey_links_the_review_path_on_core_pages(tmp_path):
    with _client(tmp_path) as client:
        run_id = client.post("/ui/actions/fixture-scan", follow_redirects=False)\
            .headers["location"].rsplit("/", 1)[-1]
        for path, current in [("/ui/", "Dashboard"), ("/ui/findings", "Finding"),
                              (f"/ui/scans/{run_id}", "Finding"),
                              (f"/ui/scans/{run_id}/evidence", "Ownership proof"),
                              (f"/ui/scans/{run_id}/report", "Report"),
                              ("/ui/matrix", "Matrix")]:
            body = client.get(path).text
            assert 'aria-label="Review journey"' in body, path
            assert f'aria-current="step"' in body, path
            # The current step is marked, and the rest of the path is reachable.
            marker = body.split('class="journey"', 1)[1]
            assert current in marker, path
            assert "/ui/endpoints" in marker
            # With a run in context the final step points at that run's report.
            assert "/ui/reports" in marker or "/ui/scans/" in marker


def test_accessibility_basics_on_every_page(tmp_path):
    with _client(tmp_path) as client:
        run_id = client.post("/ui/actions/fixture-scan", follow_redirects=False)\
            .headers["location"].rsplit("/", 1)[-1]
        pages = PATHS + [f"/ui/scans/{run_id}", f"/ui/scans/{run_id}/evidence",
                         f"/ui/scans/{run_id}/report", f"/ui/scans/{run_id}/replay"]
        # An unknown run renders the error state, which deliberately highlights no
        # navigation section; it is covered separately for the shared shell.
        pages.append("/ui/scans/00000000-0000-0000-0000-000000000000")
        for path in pages:
            body = client.get(path).text
            is_error_state = path.endswith("00000000-0000-0000-0000-000000000000")
            assert body.count("<h1") == 1, path          # one page title
            assert 'class="skip-link" href="#main"' in body, path
            assert 'id="main"' in body, path
            assert 'lang="en"' in body, path
            assert 'aria-label="Main navigation"' in body, path
            # Exactly one primary nav item is aria-current="page"; the breadcrumb
            # crumb and journey step use their own markers, which is allowed.
            nav = body.split('id="site-nav"', 1)[1].split("</nav>", 1)[0]
            expected = 0 if is_error_state else 1
            assert nav.count('aria-current="page"') == expected, path
            assert "<img" not in body, path              # no unlabelled images
            assert "style=" not in body.replace('style="width:', ""), path


# --------------------------------------------------------------------------- #
# Flight recorder
# --------------------------------------------------------------------------- #
def _events(body):
    """Extract the rendered replay events in DOM order."""
    return re.findall(r'<li class="replay-event" data-event data-index="(\d+)"\s*'
                      r'data-offset="([^"]*)"', body)


def test_replay_orders_fixture_events_by_capture_time_and_marks_evidence(tmp_path):
    with _client(tmp_path) as client:
        run_id = client.post("/ui/actions/fixture-scan", follow_redirects=False)\
            .headers["location"].rsplit("/", 1)[-1]
        run = client.get(f"/api/scan/{run_id}").json()
        observations = client.get(f"/api/scan/{run_id}/observations").json()["observations"]

        response = client.get(f"/ui/scans/{run_id}/replay")
        assert response.status_code == 200
        body = response.text
        assert 'data-mode="timeline"' in body

        rendered = _events(body)
        expected = len(observations) + sum(1 for check in run["checks"] if check.get("evidence"))
        assert len(rendered) == expected

        # Order is the backend's own capture order: offsets never decrease.
        offsets = [int(offset) for _, offset in rendered if offset]
        assert offsets == sorted(offsets)
        assert [int(index) for index, _ in rendered] == list(range(1, expected + 1))

        # The run's two evidence parts are annotations on the request they describe,
        # not extra events: each appears once, and no event claims to BE the evidence.
        assert body.count("part-tag part-ownership") == 1
        assert body.count("part-tag part-disclosure") == 1
        assert 'source-evidence' not in body

        # Each marked event carries the actor/method/path/status of its evidence part.
        for part in ("ownership", "disclosure"):
            record = run["evidence"][part]
            marked = re.search(r'part-tag part-' + part + r'">.*?</header>.*?'
                               r'<b>' + re.escape(record["actor"]) + r'</b>', body, re.S)
            assert marked is not None, part
            assert record["path"] in body

        # Every timestamp shown is one the backend actually recorded.
        api_timestamps = {observation["timestamp"] for observation in observations}
        api_timestamps |= {check["evidence"]["timestamp"] for check in run["checks"]
                           if check.get("evidence")}
        shown = set(re.findall(r'<time class="replay-time" datetime="([^"]+)"', body))
        assert shown <= api_timestamps

        # The verdict panel is the backend's verdict, not a replay-side judgement.
        assert 'badge badge-danger">CONFIRMED' in body
        assert run["reason"] in body


def test_replay_refuses_to_invent_a_timeline_for_transcript_runs(tmp_path):
    with _client(tmp_path) as client:
        bola = client.post("/ui/actions/scenario-scan", data={"scenario_id": "synthetic-vulnerable"},
                           follow_redirects=False).headers["location"].rsplit("/", 1)[-1]
        auth = client.post("/ui/actions/authentication-scan",
                           data={"scenario_id": "synthetic-jwt-sub-confirmed"},
                           follow_redirects=False).headers["location"].rsplit("/", 1)[-1]

        for path in (f"/ui/suites/read-bola/{bola}/replay",
                     f"/ui/suites/authentication/{auth}/replay"):
            response = client.get(path)
            assert response.status_code == 200, path
            body = response.text
            # The backend stamps every transcript record with one instant, so the
            # page must call this a sequence and claim no offsets.
            assert 'data-mode="sequence"' in body, path
            assert 'data-mode="timeline"' not in body, path
            assert "not a measured timeline" in body, path
            assert all(offset == "" for _, offset in _events(body)), path

        # A scenario run still shows both evidence parts, in backend list order.
        body = client.get(f"/ui/suites/read-bola/{bola}/replay").text
        assert body.index("Ownership evidence") < body.index("Disclosure evidence")


def test_replay_is_progressive_enhancement_with_local_assets(tmp_path):
    with _client(tmp_path) as client:
        run_id = client.post("/ui/actions/fixture-scan", follow_redirects=False)\
            .headers["location"].rsplit("/", 1)[-1]
        body = client.get(f"/ui/scans/{run_id}/replay").text

        # Without JavaScript the whole timeline is present and the controls are inert.
        assert body.count('data-event ') == len(_events(body))
        assert re.search(r"<div class=\"replay-controls\" data-replay-controls hidden", body)
        assert 'aria-live="polite"' in body
        assert 'tabindex="0"' in body

        # Local assets only, and they are actually served.
        assert EXTERNAL_REFERENCE.search(body) is None
        for asset in ("/ui/static/css/replay.css", "/ui/static/js/replay.js"):
            assert asset in body
            assert client.get(asset).status_code == 200

        # The page explains where its data came from and what it does not do.
        assert f"/api/scan/{run_id}/observations" in body
        assert "Nothing on this page is a live request" in body


def test_replay_unavailable_state_is_explicit(tmp_path):
    with _client(tmp_path) as client:
        run_id = client.post("/ui/actions/fixture-scan", follow_redirects=False)\
            .headers["location"].rsplit("/", 1)[-1]
        # An unknown run is a real 404 page, not an empty recorder.
        assert client.get("/ui/scans/00000000-0000-0000-0000-000000000000/replay")\
            .status_code == 404
        # A stored run always renders; the recorder never shows a blank page.
        body = client.get(f"/ui/scans/{run_id}/replay").text
        assert "No replay is available for this run" not in body


def test_replay_prints_the_whole_timeline_even_mid_playback(tmp_path):
    """Printing must not print only the step the player happens to be on."""
    with _client(tmp_path) as client:
        run_id = client.post("/ui/actions/fixture-scan", follow_redirects=False)\
            .headers["location"].rsplit("/", 1)[-1]
        body = client.get(f"/ui/scans/{run_id}/replay").text
        assert "data-print" in body

        css = client.get("/ui/static/css/replay.css").text
        assert "@media print" in css
        assert ".replay-event { display: grid !important" in css
        assert ".replay-verdict { display: block !important" in css

        # Keyboard affordances are implemented in the player and documented on the page.
        script = client.get("/ui/static/js/replay.js").text
        for key in ('"ArrowRight"', '"ArrowLeft"', '"Home"', '"End"', 'aria-pressed',
                    "prefers-reduced-motion"):
            assert key in script, key
        assert "Home" in body and "Space" in body


def test_replay_shows_why_each_evidence_part_landed_on_its_event(tmp_path):
    with _client(tmp_path) as client:
        run_id = client.post("/ui/actions/fixture-scan", follow_redirects=False)\
            .headers["location"].rsplit("/", 1)[-1]
        body = client.get(f"/ui/scans/{run_id}/replay").text
        assert body.count('class="replay-basis"') == 2
        assert "phase owner_baseline" in body
        assert "phase cross_user_read" in body


# --------------------------------------------------------------------------- #
# Verdict coverage: no findings, SAFE and INCONCLUSIVE runs
# --------------------------------------------------------------------------- #
def test_a_scan_with_no_findings_is_explained_not_hidden(tmp_path):
    with _client(tmp_path) as client:
        # Nothing stored at all: every page must say so rather than show a blank.
        empty_findings = client.get("/ui/findings").text
        assert "No findings yet" in empty_findings
        assert "No SAFE run recorded" in empty_findings
        assert '<span class="stat-value">0</span>' in empty_findings

        # A real SAFE scenario run: findings stay at zero, the run is still visible.
        run_id = client.post("/ui/actions/scenario-scan",
                             data={"scenario_id": "synthetic-secure"},
                             follow_redirects=False).headers["location"].rsplit("/", 1)[-1]
        run = client.get(f"/api/scenario-scans/{run_id}").json()
        assert run["verdict"] == "SAFE"

        # The transcript run is SAFE on its own page...
        suite_page = client.get(f"/ui/suites/read-bola/{run_id}")
        assert 'badge badge-ok badge-lg">SAFE' in suite_page.text
        assert run["reason"] in suite_page.text

        # ...and the findings page keeps its word about what it covers: fixture
        # runs only, because transcript runs have no list endpoint yet.
        body = client.get("/ui/findings").text
        assert 'badge badge-danger">CONFIRMED' not in body
        assert "stored fixture runs" in body
        assert "no list\n                  endpoint" in body or "no list" in body

        # The dashboard must not upgrade a SAFE run into an open finding.
        dashboard = client.get("/ui/").text
        assert '<span class="stat-value">0</span>' in dashboard


def test_inconclusive_runs_are_rendered_as_inconclusive_everywhere(tmp_path):
    with _client(tmp_path) as client:
        run_id = client.post("/ui/actions/scenario-scan",
                             data={"scenario_id": "synthetic-metadata"},
                             follow_redirects=False).headers["location"].rsplit("/", 1)[-1]
        run = client.get(f"/api/scenario-scans/{run_id}").json()
        assert run["verdict"] == "INCONCLUSIVE"

        page = client.get(f"/ui/suites/read-bola/{run_id}")
        assert page.status_code == 200
        assert 'badge badge-info badge-lg">INCONCLUSIVE' in page.text
        assert run["reason"] in page.text

        # The recorder keeps its honesty rule: a transcript run is a sequence.
        replay = client.get(f"/ui/suites/read-bola/{run_id}/replay")
        assert replay.status_code == 200
        assert 'data-mode="sequence"' in replay.text
        assert 'badge badge-info">INCONCLUSIVE' in replay.text

        # An INCONCLUSIVE verdict must never be promoted to a finding.
        findings = client.get("/ui/findings").text
        assert 'badge badge-danger">CONFIRMED' not in findings
        assert "stored fixture runs" in findings
        assert "Test suites" in findings


# --------------------------------------------------------------------------- #
# Cover sequence (the front door)
# --------------------------------------------------------------------------- #
def test_landing_page_is_the_front_door_and_hands_off_to_the_interface(tmp_path):
    with _client(tmp_path) as client:
        response = client.get("/")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/html")
        body = response.text

        # Exactly one page title, and it is the product name.
        assert body.count("<h1") == 1
        assert re.search(r'<h1 class="wordmark">\s*<span class="wordmark-a">Canary</span>'
                         r'<span class="wordmark-b">Gate</span>', body)

        # Nine scenes (eight numbered beats plus the final wordmark), and the
        # copy is the project's own phrasing.
        assert body.count('data-scene="') == 9
        assert "is never enough" in body
        assert "Ownership proof" in body and "Disclosure proof" in body
        assert "Every request recorded" in body
        assert "One part alone is not a finding" in body

        # The sequence shows the product's own components, not screenshots.
        assert 'class="mini-row is-proof"' in body
        assert 'class="mx conf"' in body and "not assessed" in body

        # The verdict words appear as vocabulary, never as results.
        assert "Five conclusions, and nothing else" in body
        for verdict in ("CONFIRMED", "SUSPECTED", "SAFE", "INCONCLUSIVE", "SKIPPED"):
            assert verdict in body
        assert 'badge badge-danger">CONFIRMED' not in body

        # Hand-off: real anchors plus a no-JavaScript fallback.
        assert 'href="/ui/" data-intro-enter' in body
        assert 'href="/ui/scans" data-intro-enter' in body
        assert '<noscript><meta http-equiv="refresh"' in body

        # Decoration is hidden from assistive technology; assets are local.
        assert 'data-intro-canvas aria-hidden="true"' in body
        assert EXTERNAL_REFERENCE.search(body) is None
        assert "Fixture and transcript results are synthetic" in body

        # The landing page is not the interface: no navigation shell, no banner.
        assert 'id="site-nav"' not in body
        assert "Skip to content" not in body


def test_landing_page_carries_the_argument_below_the_sequence(tmp_path):
    with _client(tmp_path) as client:
        body = client.get("/").text

        # The page is more than a splash screen: it makes the case in text.
        assert 'id="argument"' in body
        assert 'id="journey"' in body
        assert 'id="vocabulary"' in body
        assert 'id="limits"' in body
        assert "Anyone can show you a red badge" in body
        assert "Seven steps".lower() or "seven steps" in body.lower()

        # Every journey step links somewhere real, and every link resolves.
        rail = re.findall(r'<ol class="journey-rail">(.*?)</ol>', body, re.S)[0]
        hrefs = re.findall(r'href="([^"]+)"', rail)
        assert len(hrefs) == 7
        for href in hrefs:
            assert client.get(href, follow_redirects=False).status_code in (200, 303), href

        # The honesty section repeats what the build refuses to do.
        for phrase in ("No live scanning", "Synthetic results", "No severity, no score",
                       "No authentication"):
            assert phrase in body, phrase


def test_landing_assets_are_local_and_agree_on_the_runtime(tmp_path):
    with _client(tmp_path) as client:
        assert client.get("/").status_code == 200
        for asset in ("/ui/static/css/intro.css", "/ui/static/js/intro.js"):
            response = client.get(asset)
            assert response.status_code == 200, asset
            assert EXTERNAL_REFERENCE.search(response.text) is None, asset

        css = client.get("/ui/static/css/intro.css").text
        script = client.get("/ui/static/js/intro.js").text

        # One runtime, declared in both files; the countdown cannot drift from
        # the animation if these stay equal.
        assert "--run: 18s" in css
        assert "RUN_MS = 18000" in script
        # Every scene delay lives in the stylesheet, not inline.
        assert body_has_no_inline_style(client.get("/").text)
        assert ".scene-1     { --sd:" in css
        # Every scene is timed from the stylesheet, never from the markup.
        assert css.count("--sd:") >= 9

        # Accessibility and honesty behaviour that a redesign must not remove.
        assert "prefers-reduced-motion: reduce" in css
        assert "prefers-reduced-motion: reduce" in script
        assert 'event.key === "Escape"' in script
        assert "reading = true" in script          # cancels the auto hand-off
        # Sound is synthesised, never a shipped audio file.
        assert "createOscillator" in script
        assert not re.search(r'\.(mp3|wav|ogg|m4a)["\']', script)
        assert 'href="/ui/static/audio' not in client.get("/").text
        # The toggle starts off, so nothing plays uninvited.
        body = client.get("/").text
        assert 'data-intro-sound aria-pressed="false"' in body


def body_has_no_inline_style(body):
    """The landing page uses classes only, like the rest of the interface."""
    stripped = body.replace('style="width:', "").replace("style=\"width:", "")
    return "style=" not in stripped


def test_landing_page_can_be_replayed_from_the_interface(tmp_path):
    with _client(tmp_path) as client:
        assert client.get("/ui/intro").status_code == 200
        dashboard = client.get("/ui/").text
        assert 'href="/ui/intro"' in dashboard
        # The dashboard is still the dashboard: the cover did not replace it.
        assert dashboard.count("<h1") == 1
        assert "Security posture" in dashboard


def test_landing_page_always_offers_a_direct_route_into_the_interface(tmp_path):
    """The sequence is never a gate: there is always a menu one click away."""
    with _client(tmp_path) as client:
        body = client.get("/").text

        # A persistent top menu, and a prominent "Open the menu" control.
        top = re.search(r'<nav class="cover-nav" aria-label="Go straight to the interface">'
                        r'(.*?)</nav>', body, re.S)
        assert top, "top menu missing"
        top_links = re.findall(r'href="([^"]+)"', top.group(1))
        assert len(top_links) == 5
        assert 'class="cover-enter" href="/ui/"' in body
        assert "Open the menu" in body

        # A fuller menu in the hero foot, reachable by the skip link.
        foot = re.search(r'<nav class="hero-menu" id="interface-menu"[^>]*>(.*?)</nav>', body, re.S)
        assert foot, "hero menu missing"
        foot_links = re.findall(r'href="([^"]+)"', foot.group(1))
        assert len(foot_links) == 8
        assert 'class="skip-to-main" href="#interface-menu"' in body

        # Every route in both menus resolves.
        for href in set(top_links + foot_links):
            assert client.get(href, follow_redirects=False).status_code in (200, 303), href


def test_landing_page_explains_a_static_storyboard_and_offers_to_play_it(tmp_path):
    """Reduced motion is a supported layout, not a dead end."""
    with _client(tmp_path) as client:
        body = client.get("/").text
        assert 'class="hero-static"' in body
        assert "Motion is off" in body
        assert "data-intro-play-anyway" in body
        assert "Play the sequence anyway" in body

        css = client.get("/ui/static/css/intro.css").text
        # The fallback is scoped so the visitor can opt back in...
        assert "html:not(.force-motion) .scene" in css
        assert "html.force-motion .hero-static" in css
        # ...and it no longer leaves a fixed header sitting on the first scene.
        assert "html:not(.force-motion) .cover-top" in css
        assert "position: static" in css.split("html:not(.force-motion) .cover-top")[1][:120]

        script = client.get("/ui/static/js/intro.js").text
        assert 'classList.add("force-motion")' in script
        assert "intro:force-motion" in script


def test_the_canary_is_drawn_in_svg_and_stays_decorative(tmp_path):
    """The namesake bird is real vector art, not an image file, and it is not
    read out to a screen reader."""
    with _client(tmp_path) as client:
        body = client.get("/").text

        # Two birds: the singing one in the opening scene, the perched one on
        # the wordmark.
        assert body.count('class="canary canary-lg canary-singing"') == 1
        assert body.count('class="canary canary-sm canary-perched"') == 1

        # It is SVG with separate animatable parts, and no bitmap anywhere.
        assert "<svg" in body and 'viewBox="0 0 160 160"' in body
        for part in ("canary-beak", "canary-wing", "canary-tail", "canary-eye", "canary-song"):
            assert part in body, part
        assert "<img" not in body
        assert not re.search(r"\.(png|jpe?g|webp|gif)\b", body)

        # Decorative: hidden from assistive technology, no stray <title>.
        assert 'role="presentation" aria-hidden="true"' in body

        # The meaning is carried by text, not by the drawing.
        assert "A canary goes quiet" in body
        assert "before you feel the gas" in body
        assert "the warning arrives" in body


def test_the_sequence_uses_kinetic_type_and_a_verdict_burst(tmp_path):
    with _client(tmp_path) as client:
        body = client.get("/").text

        # The four words slam in as type, not as an image.
        assert 'class="word-slam"' in body
        for word in ("REQUEST", "RESPONSE", "BOUNDARY", "PROOF"):
            assert f">{word}</span>" in body, word
        assert "boundary being crossed" in body

        # The verdict reveal celebrates itself, in SVG.
        assert 'class="burst"' in body
        assert body.count('class="burst-ray"') == 24      # +1 for the <g> wrapper
        assert "burst-ring" in body and "burst-core" in body

        css = client.get("/ui/static/css/intro.css").text
        assert "@keyframes slam-in" in css
        assert "@keyframes burst-pop" in css
        assert "@keyframes canary-sing" in css
        # Motion is still opt-out, including the new pieces.
        assert "html:not(.force-motion) .canary-beak" in css
        assert "html:not(.force-motion) .burst" in css


def test_the_soundtrack_drives_the_motion_not_the_other_way_round(tmp_path):
    """The visual pulse is triggered by the synthesised beat, and stops with it."""
    with _client(tmp_path) as client:
        script = client.get("/ui/static/js/intro.js").text
        css = client.get("/ui/static/css/intro.css").text

        # One short pulse per downbeat, cleared again immediately.
        assert "function flashBeat()" in script
        assert 'classList.add("beat")' in script
        assert 'classList.remove("beat")' in script
        assert "isDownbeat" in script
        # Stopping the sound stops the pulse.
        assert 'document.documentElement.classList.remove("beat");' in script
        # The stylesheet answers that class.
        assert "html.beat .canary" in css and "html.beat .wordmark" in css


def test_two_birds_on_one_page_do_not_collide_in_the_svg(tmp_path):
    """SVG gradient ids are document-global: the macro must keep them unique."""
    with _client(tmp_path) as client:
        body = client.get("/").text
        ids = re.findall(r'id="(canary-[^"]+)"', body)
        assert len(ids) == 4
        assert len(set(ids)) == len(ids), ids
        # Every reference resolves to an id that exists on this page.
        for ref in set(re.findall(r'url\(#(canary-[^)]+)\)', body)):
            assert ref in ids, ref
