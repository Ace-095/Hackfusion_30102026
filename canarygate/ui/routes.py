"""HTML routes for the local CanaryGate UI.

Design rules enforced here:

* The UI owns no state and invents no data. Every value rendered comes from the
  frozen fixture API handlers in :mod:`canarygate.api.app` (called in-process) or
  from the bundled backend modules they use.
* Every action form works without JavaScript (plain POST + redirect). When the
  request carries an ``HX-Request`` header the same endpoint returns an HTML
  fragment instead, so HTMX can swap it in place.
* Missing backend capability is reported as missing. There is no sample data,
  no placeholder verdict and no "demo mode" toggle.
"""
from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from importlib import resources

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from canarygate.scan.auth_models import AuthenticationScanRequest
from canarygate.scan.auth_scenarios import SCENARIO_IDS as AUTHENTICATION_SCENARIO_IDS
from canarygate.scan.auth_scenarios import build_auth_scenario
from canarygate.scan.models import ScenarioScanRequest
from canarygate.scan.scenarios import SCENARIO_IDS as READ_BOLA_SCENARIO_IDS
from canarygate.offline.scan import fixture_recipe
from canarygate.spec.parser import MAX_SPEC_BYTES, parse_inventory
from canarygate.ui.replay import build_replay
from canarygate.ui.templating import templates

router = APIRouter(include_in_schema=False)

#: Forms are parsed without the optional ``python-multipart`` dependency; the
#: bound also protects the local server from oversized bodies. A urlencoded body
#: can grow up to ~3x for non-ASCII text, so allow headroom over the spec limit.
MAX_FORM_BYTES = 3 * MAX_SPEC_BYTES

#: Backend run ids are UUIDs; validate before building a redirect target.
_UUID_PATTERN = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")

#: Navigation is a flat list because the UI is deliberately small.
#: Grouped, flat navigation: (group label, [(key, href, label, icon)]).
NAV_GROUPS = (
    ("Overview", (
        ("dashboard", "/ui/", "Dashboard", "dashboard"),
        ("findings", "/ui/findings", "Findings", "findings"),
    )),
    ("Analysis", (
        ("endpoints", "/ui/endpoints", "API inventory", "inventory"),
        ("matrix", "/ui/matrix", "Authorization matrix", "matrix"),
    )),
    ("Runs and evidence", (
        ("scans", "/ui/scans", "Read-BOLA scans", "scans"),
        ("suites", "/ui/suites", "Test suites", "suites"),
        ("reports", "/ui/reports", "Reports", "reports"),
    )),
    ("Configuration", (
        ("configure", "/ui/configure", "Scan configuration", "config"),
        ("setup", "/ui/setup", "Setup & readiness", "setup"),
        ("spec", "/ui/spec", "Spec inspection", "spec"),
    )),
)

#: Shown on every page. These statements come from the backend's own contract.
BUILD_FACTS = (
    "Offline fixture mode: the API reports mode=\"fixture\", live_scanning=false and "
    "network_transport_enabled=false.",
    "Fixture and transcript results are synthetic recordings. They are not evidence "
    "about any real or organizer-supplied API.",
    "The API contracts are provisional (docs/API.md), not frozen.",
    "This local server has no authentication. Do not expose it to other users or the internet.",
)


def _api():
    """Import the API module lazily to avoid an import cycle.

    ``canarygate.api.app`` imports this module inside ``create_app`` so that the
    UI can be mounted next to the JSON routes without duplicating any logic.
    """
    import canarygate.api.app as api

    return api


def _store(request: Request, kind: str = "fixture"):
    # States come from the backend factory (create_backend_app); the UI reads
    # them exactly like the JSON API does.
    if kind == "scenario":
        return request.app.state.scenario_store
    if kind == "authentication":
        return request.app.state.auth_store
    return request.app.state.store


async def _form_fields(request: Request) -> dict[str, str]:
    """Read a urlencoded form without adding a multipart dependency.

    ``request.form()`` in Starlette requires ``python-multipart`` even for
    urlencoded bodies, and this project pins no such package. Every UI form is
    urlencoded (the spec file picker only fills a textarea), so parsing here is
    both sufficient and dependency-free.
    """
    media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media_type not in {"application/x-www-form-urlencoded", ""}:
        raise HTTPException(status_code=415, detail="Submit this form as urlencoded data")
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_FORM_BYTES:
            raise HTTPException(status_code=413, detail="Submitted form data is too large")
        body.extend(chunk)
    try:
        text = bytes(body).decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=422, detail="Form data must be UTF-8") from None
    parsed = urllib.parse.parse_qs(text, keep_blank_values=True, strict_parsing=False)
    return {key: values[-1] for key, values in parsed.items()}


def _is_htmx(request: Request) -> bool:
    return request.headers.get("hx-request", "").lower() == "true"


def _page(request: Request, template: str, active: str, http_status: int = 200, **context):
    base = {
        "active": active,
        "nav_groups": NAV_GROUPS,
        "build_facts": BUILD_FACTS,
        "provisional": True,
    }
    base.update(context)
    return templates.TemplateResponse(request, template, base, status_code=http_status)


def _error(request: Request, status_code: int, title: str, detail: str):
    # ``status_code`` is also exposed to the template; ``http_status`` sets the
    # response status so an error page is not served as a successful 200.
    return _page(request, "error.html", "error", http_status=status_code,
                 status_code=status_code, title=title, detail=detail)


def _backend_error(request: Request, exc: HTTPException, *, fragment: bool):
    """Render a backend HTTPException as HTML instead of leaking JSON into a page."""
    if fragment:
        return templates.TemplateResponse(
            request, "partials/error.html",
            {"status_code": exc.status_code, "detail": exc.detail}, status_code=exc.status_code)
    return _error(request, exc.status_code, f"Backend returned HTTP {exc.status_code}",
                  str(exc.detail))


def _guard(request: Request, callback, *, fragment: bool = False):
    """Run a backend call and convert expected failures into HTML error pages."""
    try:
        return callback()
    except HTTPException as exc:
        return _backend_error(request, exc, fragment=fragment)
    except (OSError, ValueError, KeyError) as exc:  # storage/decoding failures
        if fragment:
            return templates.TemplateResponse(
                request, "partials/error.html", {"status_code": 500, "detail": str(exc)},
                status_code=500)
        return _error(request, 500, "The local fixture store could not be read", str(exc))


# --------------------------------------------------------------------------- #
# View helpers (pure functions over backend data)
# --------------------------------------------------------------------------- #
def _newest_first(runs: list[dict]) -> list[dict]:
    return list(reversed(runs))


def _verdict_counts(runs: list[dict]) -> dict[str, int]:
    counts = {"CONFIRMED": 0, "SUSPECTED": 0, "SAFE": 0, "INCONCLUSIVE": 0, "SKIPPED": 0}
    for run in runs:
        verdict = run.get("verdict")
        if verdict in counts:
            counts[verdict] += 1
    return counts


def _check_counts(run: dict) -> dict[str, int]:
    counts: dict[str, int] = {}
    for check in run.get("checks", []):
        counts[check.get("verdict", "UNKNOWN")] = counts.get(check.get("verdict", "UNKNOWN"), 0) + 1
    return counts


def _runs(request: Request) -> list[dict]:
    """Fixture runs as returned by the API's /api/findings handler."""
    return _api().findings(store=_store(request))["findings"]


def _setup_gates(setup: dict | None) -> list[dict]:
    """The three readiness gates plus BOLA coverage, as reported by the backend."""
    if setup is None:
        return []
    gates = [
        {"name": "Authentication", "value": setup.get("authentication"),
         "note": "Both supplied accounts must authenticate before any test runs."},
        {"name": "Resources", "value": setup.get("resources"),
         "note": "A private resource per account must be discovered."},
        {"name": "Ownership verification", "value": setup.get("ownership_verification"),
         "note": "Ownership evidence is required before a BOLA verdict is allowed."},
        {"name": "BOLA coverage", "value": setup.get("bola_coverage"),
         "note": "The backend's own statement of how far seeding reached."},
    ]
    return gates


def _suite_catalog() -> dict[str, list[dict]]:
    """Bundled offline scenario ids, read from the backend registries."""
    read_bola = [{"id": scenario_id, "title": None} for scenario_id in READ_BOLA_SCENARIO_IDS]
    authentication = []
    for scenario_id in AUTHENTICATION_SCENARIO_IDS:
        try:
            title = build_auth_scenario(scenario_id).title
        except (KeyError, AttributeError):
            title = None
        authentication.append({"id": scenario_id, "title": title})
    return {"read_bola": read_bola, "authentication": authentication}


def _known_actors(runs: list[dict]) -> list[str]:
    """Actors the backend has actually demonstrated, newest run first."""
    actors: list[str] = []
    for run in reversed(runs):
        for name in (run.get("setup", {}).get("accounts") or {}):
            if name not in actors:
                actors.append(name)
        actor = run.get("actor")
        if actor and actor not in actors:
            actors.append(actor)
    return actors


def _matrix_grid(endpoints: list[dict], runs: list[dict]) -> dict:
    """Endpoint × actor grid built only from backend data.

    Rows come from the backend inventory (plus any endpoint a run recorded), and
    columns from accounts the backend has actually used. A combination with no
    stored run is rendered as ``not assessed`` — it is never assumed safe.
    """
    actors = _known_actors(runs)
    labels: list[str] = []
    for endpoint in endpoints:
        label = f"{endpoint['method']} {endpoint['path']}"
        if label not in labels:
            labels.append(label)
    for run in reversed(runs):
        if run["endpoint"] not in labels:
            labels.append(run["endpoint"])

    latest: dict[tuple[str, str], dict] = {}
    for run in runs:  # oldest → newest, so later runs win
        latest[(run["endpoint"], run["actor"])] = run

    rows = []
    for label in labels:
        cells = []
        for actor in actors:
            run = latest.get((label, actor))
            cells.append({"actor": actor, "run": run})
        rows.append({"endpoint": label, "cells": cells,
                     "assessed": sum(1 for cell in cells if cell["run"] is not None)})
    return {"actors": actors, "rows": rows,
            "assessed": sum(row["assessed"] for row in rows),
            "total": len(rows) * len(actors)}


def _bundled_configuration() -> list[dict]:
    """The bundled files the backend actually loads, shown read-only.

    Reading backend files is allowed; changing them is not. Values that would be
    credentials or canaries are redacted for display.
    """
    package = resources.files("canarygate.offline")
    entries = [
        ("scope.yaml", "Scope file: exact host/port, allowed methods, budget and the "
                       "operation allow-list the guard enforces."),
        ("recipe.json", "Setup recipe: login operation, supplied accounts, resource "
                        "discovery, id/ownership fields and the ownership model."),
        ("fixture.yaml", "OpenAPI document the parser turns into the endpoint inventory "
                         "with expected access and provenance."),
    ]
    shown = []
    for name, purpose in entries:
        text = package.joinpath(name).read_text(encoding="utf-8")
        if name == "recipe.json":
            text = _redact_json_secrets(text)
        shown.append({"name": name, "purpose": purpose, "text": text})
    return shown


def _redact_json_secrets(text: str) -> str:
    """Hide canary/credential-like values in a JSON document for display."""
    try:
        document = json.loads(text)
    except ValueError:
        return text
    return json.dumps(_walk_redact(document), indent=2)


def _walk_redact(value):
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            if any(word in key.lower() for word in ("canary", "secret", "token", "password")):
                cleaned[key] = "[REDACTED]"
            else:
                cleaned[key] = _walk_redact(item)
        return cleaned
    if isinstance(value, list):
        return [_walk_redact(item) for item in value]
    return value


def _check_findings(runs: list[dict]) -> list[dict]:
    """Per-check findings across all stored runs (CONFIRMED/SUSPECTED only)."""
    found = []
    for run in reversed(runs):
        for check in run.get("checks", []):
            if check.get("verdict") in {"CONFIRMED", "SUSPECTED"}:
                found.append({"run": run, "check": check})
    return found


def _check_gaps(runs: list[dict]) -> dict[str, int]:
    gaps = {"SKIPPED": 0, "INCONCLUSIVE": 0, "SAFE": 0}
    for run in runs:
        for check in run.get("checks", []):
            verdict = check.get("verdict")
            if verdict in gaps:
                gaps[verdict] += 1
    return gaps


# --------------------------------------------------------------------------- #
# Pages
# --------------------------------------------------------------------------- #
def _cover(request: Request):
    """Render the twenty-one second cover sequence.

    It is a real page, not a splash gate: the interface is one click away, the
    sequence is CSS so it plays without JavaScript, and the hand-off is done by
    ``intro.js`` (with a ``<noscript>`` refresh as the fallback).
    """
    return templates.TemplateResponse(request, "intro.html", {}, status_code=200)


@router.get("/")
def root(request: Request):
    """The front door: the cover, which then hands the visitor to /ui/."""
    return _cover(request)


@router.get("/ui/intro")
def intro_page(request: Request):
    """Replay the cover at any time (linked from the sidebar)."""
    return _cover(request)


@router.get("/ui/")
def dashboard(request: Request):
    def build():
        api = _api()
        health = api.health()
        inventory = api.endpoints()["endpoints"]
        setup_response = api.setup_status(store=_store(request))
        runs = _newest_first(api.findings(store=_store(request))["findings"])
        return health, inventory, setup_response, runs

    result = _guard(request, build)
    if not isinstance(result, tuple):
        return result
    health, inventory, setup_response, runs = result
    latest = runs[0] if runs else None
    return _page(
        request, "dashboard.html", "dashboard",
        health=health,
        endpoints=inventory,
        setup=setup_response["setup"],
        setup_message=setup_response["message"],
        gates=_setup_gates(setup_response["setup"]),
        latest=latest,
        runs=runs[:5],
        run_count=len(runs),
        counts=_verdict_counts(runs),
        suite_count=len(READ_BOLA_SCENARIO_IDS) + len(AUTHENTICATION_SCENARIO_IDS),
    )


@router.get("/ui/endpoints")
def endpoints_page(request: Request):
    def build():
        api = _api()
        return api.endpoints()["endpoints"], _newest_first(api.findings(store=_store(request))["findings"])

    result = _guard(request, build)
    if not isinstance(result, tuple):
        return result
    endpoints, runs = result
    # Backend runs name a concrete path (e.g. /items/bob-item); map them onto the
    # templated inventory row they belong to. No matching is invented: a run that
    # fits no template is reported separately.
    by_endpoint: dict[str, list[dict]] = {}
    for run in runs:
        by_endpoint.setdefault(run["endpoint"], []).append(run)
    rows = []
    for endpoint in endpoints:
        label = f"{endpoint['method']} {endpoint['path']}"
        rows.append({"endpoint": endpoint, "label": label, "runs": by_endpoint.get(label, [])})
    matched = {row["label"] for row in rows if row["runs"]}
    unmatched = [run for run in runs if run["endpoint"] not in matched]
    access_counts: dict[str, int] = {}
    for row in rows:
        access = row["endpoint"]["expected_access"]
        access_counts[access] = access_counts.get(access, 0) + 1
    return _page(request, "endpoints.html", "endpoints", rows=rows,
                 run_count=len(runs), unmatched=unmatched, access_counts=access_counts)


@router.get("/ui/setup")
def setup_page(request: Request):
    result = _guard(request, lambda: _api().setup_status(store=_store(request)))
    if not isinstance(result, dict):
        return result
    setup = result["setup"]
    return _page(request, "setup.html", "setup", setup=setup,
                 message=result["message"], gates=_setup_gates(setup))


@router.get("/ui/scans")
def scans_page(request: Request):
    result = _guard(request, lambda: _runs(request))
    if not isinstance(result, list):
        return result
    runs = _newest_first(result)
    return _page(request, "scans.html", "scans", runs=runs,
                 counts=_verdict_counts(runs))


@router.get("/ui/scans/{run_id}")
def scan_page(request: Request, run_id: str):
    def build():
        api = _api()
        run = api.scan(run_id=run_id, store=_store(request))
        return run

    result = _guard(request, build)
    if not isinstance(result, dict):
        return result
    return _page(request, "scan_detail.html", "scans", run=result,
                 check_counts=_check_counts(result))


@router.get("/ui/scans/{run_id}/evidence")
def evidence_page(request: Request, run_id: str):
    def build():
        api = _api()
        run = api.scan(run_id=run_id, store=_store(request))
        observations = api.scan_observations(run_id=run_id, store=_store(request))
        return run, observations

    result = _guard(request, build)
    if not isinstance(result, tuple):
        return result
    run, observations = result
    return _page(request, "evidence.html", "scans", run=run, observations=observations)


@router.get("/ui/scans/{run_id}/replay")
def replay_page(request: Request, run_id: str):
    """Replay one fixture run from the evidence the backend recorded for it."""
    def build():
        api = _api()
        run = api.scan(run_id=run_id, store=_store(request))
        observations = api.scan_observations(run_id=run_id, store=_store(request))
        return build_replay("fixture", run, observations)

    result = _guard(request, build)
    if not isinstance(result, dict):
        return result
    return _page(request, "replay.html", "scans", **result)


@router.get("/ui/matrix")
def matrix_page(request: Request):
    def build():
        api = _api()
        return (api.matrix(store=_store(request))["cells"],
                api.endpoints()["endpoints"],
                _newest_first(api.findings(store=_store(request))["findings"]))

    result = _guard(request, build)
    if not isinstance(result, tuple):
        return result
    cells, endpoints, runs = result
    return _page(request, "matrix.html", "matrix", cells=cells,
                 grid=_matrix_grid(endpoints, runs), run_count=len(runs))


@router.get("/ui/findings")
def findings_page(request: Request):
    def build():
        return _newest_first(_runs(request))

    result = _guard(request, build)
    if not isinstance(result, list):
        return result
    runs = result
    grouped: dict[str, list[dict]] = {"CONFIRMED": [], "SUSPECTED": [], "SAFE": [],
                                      "INCONCLUSIVE": [], "SKIPPED": []}
    for run in runs:
        grouped.setdefault(run["verdict"], []).append(run)
    return _page(
        request, "findings.html", "findings",
        runs=runs,
        grouped=grouped,
        check_findings=_check_findings(runs),
        coverage=_check_gaps(runs),
        findings_count=len(grouped["CONFIRMED"]) + len(grouped["SUSPECTED"]),
    )


@router.get("/ui/configure")
def configure_page(request: Request):
    def build():
        return fixture_recipe()

    result = _guard(request, build)
    if not isinstance(result, dict):
        return result
    return _page(request, "configure.html", "configure",
                 files=_bundled_configuration(),
                 recipe_summary=_walk_redact(result),
                 live_config_allowed=False)


@router.get("/ui/reports")
def reports_page(request: Request):
    result = _guard(request, lambda: _runs(request))
    if not isinstance(result, list):
        return result
    return _page(request, "reports.html", "reports", runs=_newest_first(result))


@router.get("/ui/reports/lookup")
def report_lookup(request: Request, family: str = "", run_id: str = ""):
    """Small helper for suites that have no list endpoint in the backend."""
    if family not in {"read-bola", "authentication"}:
        return _error(request, 422, "Unknown test-suite family",
                      "Choose read-bola or authentication.")
    if _UUID_PATTERN.fullmatch(run_id.strip()) is None:
        return _error(request, 422, "That is not a run id",
                      "A run id is a 36-character UUID returned when the suite ran.")
    return RedirectResponse(f"/ui/suites/{family}/{run_id.strip()}", status_code=303)


@router.get("/ui/suites")
def suites_page(request: Request):
    return _page(request, "suites.html", "suites", catalog=_suite_catalog())


@router.get("/ui/suites/{family}/{run_id}")
def suite_run_page(request: Request, family: str, run_id: str):
    if family not in {"read-bola", "authentication"}:
        return _error(request, 404, "Unknown test-suite family",
                      "Use read-bola or authentication.")

    def build():
        api = _api()
        if family == "read-bola":
            return api.scenario_scan(run_id=run_id, store=_store(request, "scenario"))
        return api.authentication_scan(run_id=run_id,
                                       store=_store(request, "authentication"))

    result = _guard(request, build)
    if not isinstance(result, dict):
        return result
    return _page(request, "suite_run.html", "suites", run=result, family=family,
                 proof_family="Read-BOLA scenario" if family == "read-bola"
                 else "Authentication scenario")


@router.get("/ui/suites/{family}/{run_id}/replay")
def suite_replay_page(request: Request, family: str, run_id: str):
    """Replay an offline transcript run, as a sequence rather than a timeline."""
    if family not in {"read-bola", "authentication"}:
        return _error(request, 404, "Unknown test-suite family",
                      "Use read-bola or authentication.")

    def build():
        api = _api()
        if family == "read-bola":
            run = api.scenario_scan(run_id=run_id, store=_store(request, "scenario"))
        else:
            run = api.authentication_scan(run_id=run_id,
                                          store=_store(request, "authentication"))
        return build_replay(family, run)

    result = _guard(request, build)
    if not isinstance(result, dict):
        return result
    return _page(request, "replay.html", "suites", family=family, **result)


@router.get("/ui/spec")
def spec_page(request: Request):
    return _page(request, "spec.html", "spec", result=None)


@router.get("/ui/scans/{run_id}/report")
def report_view(request: Request, run_id: str):
    """Render the backend's own nine-section projection as a printable report."""
    def build():
        api = _api()
        run = api.scan(run_id=run_id, store=_store(request))
        response = api.report(run_id=run_id, view="sections", format="json",
                              store=_store(request))
        # The backend's section view is dispatched as a JSONResponse; decode it
        # without re-implementing any section logic in the UI.
        payload = response if isinstance(response, dict) else json.loads(response.body)
        return run, payload["sections"]

    result = _guard(request, build)
    if not isinstance(result, tuple):
        return result
    run, sections = result
    return _page(request, "report_view.html", "reports", run=run, sections=sections)


# --------------------------------------------------------------------------- #
# Form actions (progressive: HTML redirect without JS, HTMX fragment with JS)
# --------------------------------------------------------------------------- #
@router.post("/ui/actions/fixture-scan")
def fixture_scan_action(request: Request):
    htmx = _is_htmx(request)
    result = _guard(request, lambda: _api().start_scan(store=_store(request)), fragment=htmx)
    if not isinstance(result, dict):
        return result
    if htmx:
        return templates.TemplateResponse(request, "partials/fixture_scan_result.html",
                                          {"run": result})
    return RedirectResponse(f"/ui/scans/{result['id']}", status_code=303)


@router.post("/ui/actions/scenario-scan")
async def scenario_scan_action(request: Request):
    htmx = _is_htmx(request)
    try:
        fields = await _form_fields(request)
    except HTTPException as exc:
        return _backend_error(request, exc, fragment=htmx)
    scenario_id = fields.get("scenario_id", "")
    try:
        payload = ScenarioScanRequest(scenario_id=scenario_id)
    except ValueError:
        return templates.TemplateResponse(
            request, "partials/error.html",
            {"status_code": 422, "detail": "Select a bundled read-BOLA scenario id."},
            status_code=422) if htmx else _error(
            request, 422, "Invalid scenario selection", "Select a bundled read-BOLA scenario id.")

    def run():
        return _api().start_scenario_scan(payload, store=_store(request, "scenario"))

    result = _guard(request, run, fragment=htmx)
    if not isinstance(result, dict):
        return result
    if htmx:
        return templates.TemplateResponse(request, "partials/suite_result.html",
                                          {"run": result, "family": "read-bola"})
    return RedirectResponse(f"/ui/suites/read-bola/{result['id']}", status_code=303)


@router.post("/ui/actions/authentication-scan")
async def authentication_scan_action(request: Request):
    htmx = _is_htmx(request)
    try:
        fields = await _form_fields(request)
    except HTTPException as exc:
        return _backend_error(request, exc, fragment=htmx)
    scenario_id = fields.get("scenario_id", "")
    try:
        payload = AuthenticationScanRequest(scenario_id=scenario_id)
    except ValueError:
        message = "Select a bundled authentication scenario id."
        if htmx:
            return templates.TemplateResponse(
                request, "partials/error.html",
                {"status_code": 422, "detail": message}, status_code=422)
        return _error(request, 422, "Invalid scenario selection", message)

    def run():
        return _api().start_authentication_scan(payload,
                                                store=_store(request, "authentication"))

    result = _guard(request, run, fragment=htmx)
    if not isinstance(result, dict):
        return result
    if htmx:
        return templates.TemplateResponse(request, "partials/suite_result.html",
                                          {"run": result, "family": "authentication"})
    return RedirectResponse(f"/ui/suites/authentication/{result['id']}", status_code=303)


@router.post("/ui/actions/spec-inspect")
async def spec_inspect_action(request: Request):
    htmx = _is_htmx(request)
    try:
        fields = await _form_fields(request)
    except HTTPException as exc:
        return _backend_error(request, exc, fragment=htmx)
    document = fields.get("document")
    if not isinstance(document, str) or not document.strip():
        message = "Paste a YAML or JSON OpenAPI document, or choose a local file."
        if htmx:
            return templates.TemplateResponse(
                request, "partials/error.html", {"status_code": 422, "detail": message},
                status_code=422)
        return _error(request, 422, "No document supplied", message)
    raw = document.encode("utf-8")
    if len(raw) > MAX_SPEC_BYTES:
        message = f"The document exceeds the {MAX_SPEC_BYTES} byte inspection limit."
        if htmx:
            return templates.TemplateResponse(
                request, "partials/error.html", {"status_code": 413, "detail": message},
                status_code=413)
        return _error(request, 413, "Specification too large", message)

    def inspect():
        # Same bounded parser the JSON API uses; nothing is persisted or scanned.
        endpoints = parse_inventory(document)
        return {
            "mode": "inventory_only",
            "live_scanning": False,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "endpoint_count": len(endpoints),
            "endpoints": endpoints,
            "message": ("Inspection only; the document is not saved, not used by "
                        "fixture scans and does not select a target."),
        }

    try:
        result = inspect()
    except ValueError:
        # Mirrors the JSON API: a malformed or unsupported document is a 422, not
        # a server error. The parser's message is not echoed (it may quote input).
        message = "Invalid or unsupported OpenAPI specification."
        if htmx:
            return templates.TemplateResponse(
                request, "partials/error.html", {"status_code": 422, "detail": message},
                status_code=422)
        return _error(request, 422, "Invalid specification", message)
    if htmx:
        return templates.TemplateResponse(request, "partials/spec_result.html",
                                          {"result": result})
    return _page(request, "spec.html", "spec", result=result)
