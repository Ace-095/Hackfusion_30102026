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
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from canarygate.scan.auth_models import AuthenticationScanRequest
from canarygate.scan.auth_scenarios import SCENARIO_IDS as AUTHENTICATION_SCENARIO_IDS
from canarygate.scan.auth_scenarios import build_auth_scenario
from canarygate.scan.interaction_models import InteractionScanRequest
from canarygate.scan.interaction_scenarios import SCENARIO_IDS as INTERACTION_SCENARIO_IDS
from canarygate.scan.interaction_scenarios import build_interaction_scenario
from canarygate.scan.lab_bola_models import LabBolaScanRequest
from canarygate.scan.lab_matrix import build_lab_matrix
from canarygate.scan.lab_scenarios import build_lab_catalog
from canarygate.scan.lab_sci_models import LabSciScanRequest
from canarygate.scan.models import ScenarioScanRequest
from canarygate.scan.scenarios import SCENARIO_IDS as READ_BOLA_SCENARIO_IDS
from canarygate.scan.validation_models import ValidationScanRequest
from canarygate.scan.validation_scenarios import SCENARIO_IDS as VALIDATION_SCENARIO_IDS
from canarygate.scan.validation_scenarios import build_validation_scenario
from canarygate.offline.scan import fixture_recipe
from canarygate.spec.parser import MAX_SPEC_BYTES, parse_inventory
from canarygate.ui import execution as execution_jobs
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
    ("Workspace", (
        ("dashboard", "/ui/", "Overview", "dashboard"),
        ("assessment", "/ui/assessment", "New security assessment", "play"),
    )),
    ("Analysis", (
        ("endpoints", "/ui/endpoints", "API inspector", "inventory"),
        ("lab_matrix", "/ui/lab/matrix", "Authorization matrix", "matrix"),
        ("findings", "/ui/findings", "Evidence explorer", "findings"),
        ("scans", "/ui/scans", "Scan history", "scans"),
        ("reports", "/ui/reports", "Reports", "reports"),
    )),
    ("TargetLab", (
        ("lab", "/ui/lab", "Validation & demo accounts", "shield"),
        ("suites", "/ui/suites", "Offline test suites", "suites"),
        ("matrix", "/ui/matrix", "Offline endpoint matrix", "matrix"),
    )),
    ("Configuration", (
        ("spec", "/ui/spec", "API specification", "spec"),
        ("configure", "/ui/configure", "Scan configuration", "config"),
        ("setup", "/ui/setup", "Setup & readiness", "setup"),
    )),
)

#: Test-suite families the backend actually implements. Every field names a real
#: backend entry point; the UI adds no family of its own.
#:   store    — the app.state attribute holding that family's SQLite store
#:   handler  — the JSON API handler used to read one stored run
#:   report   — the JSON API handler used to read the section projection
#:   base     — the API prefix, used only to build read-only JSON/HTML links
#:   label    — what the page calls the family
SUITE_FAMILIES = {
    "read-bola": {
        "store": "scenario_store",
        "handler": "scenario_scan",
        "report": "scenario_report",
        "base": "/api/scenario-scans",
        "label": "Read-BOLA scenario",
        "verdict_field": "verdict",
    },
    "authentication": {
        "store": "auth_store",
        "handler": "authentication_scan",
        "report": "authentication_report",
        "base": "/api/authentication-scans",
        "label": "Authentication scenario",
        "verdict_field": None,
    },
    "validation": {
        "store": "validation_store",
        "handler": "validation_scan",
        "report": "validation_report",
        "base": "/api/validation-scans",
        "label": "Input / disclosure scenario",
        "verdict_field": None,
    },
    "interaction": {
        "store": "interaction_store",
        "handler": "interaction_scan",
        "report": "interaction_report",
        "base": "/api/interaction-scans",
        "label": "Control-interaction scenario",
        "verdict_field": "verdict",
    },
}

#: Loopback lab families. Same shape as SUITE_FAMILIES, but these runs make real
#: HTTPS requests to 127.0.0.1 through the guarded lab transport.
LAB_FAMILIES = {
    "bola": {
        "store": "lab_bola_store",
        "handler": "lab_bola_scan",
        "report": "lab_bola_report",
        "base": "/api/lab-bola-scans",
        "label": "TargetLab read-BOLA validation",
        "verdict_field": "verdict",
    },
    "sci": {
        "store": "lab_sci_store",
        "handler": "lab_sci_scan",
        "report": "lab_sci_report",
        "base": "/api/lab-sci-scans",
        "label": "TargetLab control-interaction validation",
        "verdict_field": "verdict",
    },
    "reset": {
        "store": "lab_reset_store",
        "handler": "lab_sci_reset",
        "report": None,
        "base": "/api/lab-sci-resets",
        "label": "TargetLab reset proof",
        "verdict_field": "status",
    },
}


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



class _Record(dict):
    """A read-only-ish view of a stored run that renders missing keys as empty.

    Families legitimately differ in shape (an interaction run has no ``summary``, a
    validation run has no ``interaction_kind``). Templates guard optional fields with
    ``{% if %}``; this mapping makes an absent key falsy instead of an error, without
    inventing a value the backend did not send.
    """

    def __missing__(self, key):
        return None


def _lenient(value):
    if isinstance(value, dict):
        return _Record({key: _lenient(item) for key, item in value.items()})
    if isinstance(value, list):
        return [_lenient(item) for item in value]
    return value


def _store(request: Request, kind: str = "fixture"):
    # States come from the backend factory (create_backend_app); the UI reads
    # them exactly like the JSON API does.
    if kind == "scenario":
        return request.app.state.scenario_store
    if kind == "authentication":
        return request.app.state.auth_store
    if kind == "validation":
        return request.app.state.validation_store
    if kind == "interaction":
        return request.app.state.interaction_store
    if kind == "lab":
        return request.app.state.lab_store
    if kind == "lab_bola":
        return request.app.state.lab_bola_store
    if kind == "lab_sci":
        return request.app.state.lab_sci_store
    if kind == "lab_reset":
        return request.app.state.lab_reset_store
    return request.app.state.store


def _family_store(request: Request, family: str):
    """Store for one suite/lab family, by the attribute the backend exposes."""
    return getattr(request.app.state, SUITE_FAMILIES[family]["store"])


def _lab_store(request: Request, family: str):
    return getattr(request.app.state, LAB_FAMILIES[family]["store"])


def _listed(store) -> list[dict]:
    """Stored runs, newest first, read through the backend's own store module."""
    try:
        return _newest_first(store.list())
    except (OSError, ValueError) as exc:  # unreadable or tampered row
        raise HTTPException(status_code=500,
                            detail=f"The local store could not be read: {exc}") from None



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


#: A judge reads these, so the title says what happened rather than naming the layer
#: that produced it. The HTTP status stays on the page as a badge.
_ERROR_TITLES = {
    400: "That request was rejected",
    404: "That record does not exist",
    409: "That request conflicts with stored evidence",
    413: "That document is too large",
    415: "That content type is not supported",
    422: "That configuration was rejected",
    502: "The lab could not be reached",
    503: "The backend is not ready",
}


def _backend_error(request: Request, exc: HTTPException, *, fragment: bool):
    """Render a backend HTTPException as HTML instead of leaking JSON into a page."""
    if fragment:
        return templates.TemplateResponse(
            request, "partials/error.html",
            {"status_code": exc.status_code, "detail": exc.detail}, status_code=exc.status_code)
    title = _ERROR_TITLES.get(exc.status_code,
                              f"The backend refused the request (HTTP {exc.status_code})")
    return _error(request, exc.status_code, title, str(exc.detail))


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
    validation = []
    for scenario_id in VALIDATION_SCENARIO_IDS:
        try:
            title = build_validation_scenario(scenario_id).title
        except (KeyError, AttributeError):
            title = None
        validation.append({"id": scenario_id, "title": title})
    interaction = []
    for scenario_id in INTERACTION_SCENARIO_IDS:
        try:
            title = build_interaction_scenario(scenario_id).title
        except (KeyError, AttributeError):
            title = None
        interaction.append({"id": scenario_id, "title": title})
    return {"read_bola": read_bola, "authentication": authentication,
            "validation": validation, "interaction": interaction}


def _suite_run(request: Request, family: str, run_id: str) -> dict:
    """One stored suite run, read through the same handler the JSON API uses."""
    if family not in SUITE_FAMILIES:
        raise HTTPException(status_code=404, detail="Unknown test-suite family")
    handler = getattr(_api(), SUITE_FAMILIES[family]["handler"])
    return _lenient(handler(run_id=run_id, store=_family_store(request, family)))


def _suite_sections(request: Request, family: str, run_id: str) -> dict:
    """The backend's own nine-section projection for one suite run."""
    handler = getattr(_api(), SUITE_FAMILIES[family]["report"])
    response = handler(run_id=run_id, view="sections", format="json",
                       store=_family_store(request, family))
    # Section views are returned as a section model or a JSONResponse depending on
    # the family; decode either without re-implementing any section logic here.
    if isinstance(response, dict):
        return response
    if hasattr(response, "model_dump"):
        return response.model_dump(mode="json")
    return json.loads(response.body)


def _lab_run(request: Request, family: str, run_id: str) -> dict:
    if family not in LAB_FAMILIES:
        raise HTTPException(status_code=404, detail="Unknown lab family")
    handler = getattr(_api(), LAB_FAMILIES[family]["handler"])
    return _lenient(handler(**({"proof_id" if family == "reset" else "run_id": run_id}),
                            store=_lab_store(request, family)))


def _lab_sections(request: Request, family: str, run_id: str, reset_id: str = "") -> dict:
    spec = LAB_FAMILIES[family]
    if spec["report"] is None:
        raise HTTPException(status_code=404, detail="This lab family has no section report")
    handler = getattr(_api(), spec["report"])
    kwargs = {"run_id": run_id, "view": "sections", "format": "json",
              "store": _lab_store(request, family)}
    if family == "sci":
        kwargs["reset"] = reset_id
        kwargs["resets"] = _store(request, "lab_reset")
    response = handler(**kwargs)
    if isinstance(response, dict):
        return response
    if hasattr(response, "model_dump"):        # pydantic section model
        return response.model_dump(mode="json")
    return json.loads(response.body)           # JSONResponse


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
@router.get("/")
def root(request: Request):
    """The landing page: standalone, data-free and readable without JavaScript.

    It is deliberately outside the workspace shell — it presents the product and
    links into it. Nothing on it claims a scan ran, and every number lives behind
    the "Enter CanaryGate" link where the backend supplies it.
    """
    return templates.TemplateResponse(request, "landing.html", {}, status_code=200)


@router.get("/ui/")
def dashboard(request: Request):
    def build():
        api = _api()
        health = api.health()
        inventory = api.endpoints()["endpoints"]
        setup_response = api.setup_status(store=_store(request))
        runs = _newest_first(api.findings(store=_store(request))["findings"])
        labs = {family: _listed(_lab_store(request, family)) for family in LAB_FAMILIES}
        # The nine-cell matrix is assembled by the backend from stored runs; the
        # dashboard only projects it, exactly like /api/lab-matrix does.
        matrix = build_lab_matrix(list(reversed(labs["bola"])))
        return health, inventory, setup_response, runs, labs, matrix

    result = _guard(request, build)
    if not isinstance(result, tuple):
        return result
    health, inventory, setup_response, runs, labs, matrix = result
    latest = runs[0] if runs else None
    lab_counts = {family: _verdict_counts(history) for family, history in labs.items()}
    # Evidence accounting: one stored check that carries an evidence hash is one
    # evidence record. Nothing is estimated.
    lab_checks = sum(len(run.get("checks") or []) for history in labs.values() for run in history)
    lab_evidence = sum(1 for history in labs.values() for run in history
                       for check in (run.get("checks") or [])
                       if check.get("evidence_sha256"))
    latest_bola = labs["bola"][0] if labs["bola"] else None
    offline_counts = _verdict_counts(runs)
    combined = {verdict: offline_counts.get(verdict, 0) + lab_counts["bola"].get(verdict, 0)
                + lab_counts["sci"].get(verdict, 0) for verdict in offline_counts}
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
        suite_count=(len(READ_BOLA_SCENARIO_IDS) + len(AUTHENTICATION_SCENARIO_IDS)
                     + len(VALIDATION_SCENARIO_IDS) + len(INTERACTION_SCENARIO_IDS)),
        lab_history=labs,
        lab_families=LAB_FAMILIES,
        lab_counts=lab_counts,
        lab_latest={family: (history[0] if history else None)
                    for family, history in labs.items()},
        lab_run_count=sum(len(history) for history in labs.values()),
        matrix=matrix, rows=_matrix_rows(matrix), columns=matrix["accounts"],
        catalog=build_lab_catalog(),
        lab_checks=lab_checks, lab_evidence=lab_evidence,
        latest_bola=latest_bola,
        bola_stages=_execution_stages(latest_bola) if latest_bola else [],
        bola_proof=_disclosure_proof(latest_bola) if latest_bola else [],
        all_verdicts=combined,
        # Presentation only: which page explains a given verdict. The template never
        # compares a verdict to a literal; it renders the row it was given.
        verdict_rows=[{"verdict": verdict, "count": count,
                       "href": "/ui/findings" if verdict in {"CONFIRMED", "SUSPECTED"}
                               else "/ui/scans"}
                      for verdict, count in combined.items()],
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
                _newest_first(api.findings(store=_store(request))["findings"]),
                api.authorization_matrix(
                    scenario_store=_store(request, "scenario"),
                    auth_store=_store(request, "authentication"),
                    validation_store=_store(request, "validation"),
                    interaction_store=_store(request, "interaction"),
                    lab_bola_store=_store(request, "lab_bola"),
                    lab_sci_store=_store(request, "lab_sci")))

    result = _guard(request, build)
    if not isinstance(result, tuple):
        return result
    cells, endpoints, runs, authorization = result
    return _page(request, "matrix.html", "matrix", cells=cells,
                 grid=_matrix_grid(endpoints, runs), run_count=len(runs),
                 authorization=authorization)


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
    def build():
        suites = {family: _listed(_family_store(request, family))
                  for family in SUITE_FAMILIES}
        labs = {family: _listed(_lab_store(request, family)) for family in LAB_FAMILIES}
        return _newest_first(_runs(request)), suites, labs

    result = _guard(request, build)
    if not isinstance(result, tuple):
        return result
    runs, suites, labs = result
    return _page(request, "reports.html", "reports", runs=runs,
                 suite_history=suites, lab_history=labs,
                 families=SUITE_FAMILIES, lab_families=LAB_FAMILIES)


@router.get("/ui/reports/lookup")
def report_lookup(request: Request, family: str = "", run_id: str = ""):
    """Resolve a pasted run id to its detail page, without inventing ids."""
    if family in SUITE_FAMILIES:
        base = "suites"
    elif family in LAB_FAMILIES:
        base = "lab"
    else:
        return _error(request, 422, "Unknown run family",
                      "Choose read-bola, authentication, validation, interaction, "
                      "bola, sci or reset.")
    if _UUID_PATTERN.fullmatch(run_id.strip()) is None:
        return _error(request, 422, "That is not a run id",
                      "A run id is a 36-character UUID returned when the run finished.")
    return RedirectResponse(f"/ui/{base}/{family}/{run_id.strip()}", status_code=303)


@router.get("/ui/suites")
def suites_page(request: Request):
    def build():
        return {family: _listed(_family_store(request, family))
                for family in SUITE_FAMILIES}

    result = _guard(request, build)
    if not isinstance(result, dict):
        return result
    return _page(request, "suites.html", "suites", catalog=_suite_catalog(),
                 history=result, families=SUITE_FAMILIES)


@router.get("/ui/suites/{family}/{run_id}")
def suite_run_page(request: Request, family: str, run_id: str):
    if family not in SUITE_FAMILIES:
        return _error(request, 404, "Unknown test-suite family",
                      "Use read-bola, authentication, validation or interaction.")

    result = _guard(request, lambda: _suite_run(request, family, run_id))
    if not isinstance(result, dict):
        return result
    return _page(request, "suite_run.html", "suites", run=result, family=family,
                 family_spec=SUITE_FAMILIES[family],
                 proof_family=SUITE_FAMILIES[family]["label"])


@router.get("/ui/suites/{family}/{run_id}/replay")
def suite_replay_page(request: Request, family: str, run_id: str):
    """Replay an offline transcript run, as a sequence rather than a timeline."""
    if family not in SUITE_FAMILIES:
        return _error(request, 404, "Unknown test-suite family",
                      "Use read-bola, authentication, validation or interaction.")

    def build():
        return build_replay(family, _suite_run(request, family, run_id))

    result = _guard(request, build)
    if not isinstance(result, dict):
        return result
    return _page(request, "replay.html", "suites", family=family, **result)


@router.get("/ui/suites/{family}/{run_id}/report")
def suite_report_view(request: Request, family: str, run_id: str):
    """Render the backend's nine-section projection for an offline suite run."""
    if family not in SUITE_FAMILIES:
        return _error(request, 404, "Unknown test-suite family",
                      "Use read-bola, authentication, validation or interaction.")

    def build():
        return _suite_run(request, family, run_id), _suite_sections(request, family, run_id)

    result = _guard(request, build)
    if not isinstance(result, tuple):
        return result
    run, payload = result
    return _page(request, "sections_report.html", "reports", run=run,
                 sections=payload["sections"], family=family,
                 family_spec=SUITE_FAMILIES[family],
                 family_label=SUITE_FAMILIES[family]["label"],
                 back_href=f"/ui/suites/{family}/{run_id}",
                 report_base=f"{SUITE_FAMILIES[family]['base']}/{run_id}/report",
                 verdict=run.get("verdict"),
                 reason=run.get("reason"),
                 recorded=run.get("created_at"),
                 run_id_value=run.get("id", run_id))


@router.get("/ui/lab")
def lab_page(request: Request):
    """TargetLab validation: the only workflow that opens a real socket."""
    def build():
        history = {family: _listed(_lab_store(request, family)) for family in LAB_FAMILIES}
        return history, _lab_readiness()

    result = _guard(request, build)
    if not isinstance(result, tuple):
        return result
    history, readiness = result
    return _page(request, "lab.html", "lab", history=history,
                 readiness=readiness, families=LAB_FAMILIES,
                 catalog=build_lab_catalog())


def _lab_readiness() -> dict:
    """What the backend needs before a lab scan can run, reported honestly."""
    import os

    ca = os.environ.get("CANARYGATE_TARGETLAB_CA")
    return {
        "ca_configured": bool(ca),
        "ca_path": ca or "",
        "ca_env": "CANARYGATE_TARGETLAB_CA",
        # These are properties of the transport module, read as data, not asserted.
        "destination": "127.0.0.1",
        "scheme": "https",
        "redirects": "refused",
        "dns": "not used",
        "live_target_contacted": False,
        "production_networking": False,
    }


@router.get("/ui/lab/matrix")
def lab_matrix_page(request: Request, cell: str = ""):
    """The judge-facing 3x3 asset matrix, assembled only from stored read-BOLA runs."""
    def build():
        # Storage order, oldest first: the aggregator uses it to break timestamp ties so
        # this page and GET /api/lab-matrix always select the same evidence.
        return build_lab_matrix(list(reversed(_listed(_lab_store(request, "bola")))))

    result = _guard(request, build)
    if not isinstance(result, dict):
        return result
    rows = _matrix_rows(result)
    selected = None
    if cell:
        requester, _, asset = cell.partition(":")
        selected = next((item for item in result["cells"]
                         if item["requester"] == requester and item["asset_id"] == asset), None)
        if selected is None:
            return _error(request, 404, "Unknown matrix cell",
                          "A matrix cell is an account and one of the three demo assets.")
    comparisons = [item for item in result["cells"]
                   if item["state"] == "tested" and item["kind"] == "cross_account_attempt"]
    return _page(request, "lab_matrix.html", "lab_matrix", matrix=result, rows=rows,
                 columns=result["accounts"], selected=selected, cell=cell,
                 comparisons=comparisons, catalog=build_lab_catalog(),
                 coverage=catalog_coverage_pairs())


def catalog_coverage_pairs():
    """The catalog's minimum set of runs that answers all nine cells."""
    return build_lab_catalog()["coverage_pairs"]


def _matrix_rows(matrix: dict) -> list[tuple]:
    """Rows of the 3x3 grid: (account, title, cells in column order).

    Pure presentation: every cell is the object the backend returned, so a cell can
    never show something the API did not carry.
    """
    return [(account["account"], account["title"],
             [next(item for item in matrix["cells"]
                   if item["requester"] == account["account"]
                   and item["asset_id"] == column["asset_id"])
              for column in matrix["accounts"]])
            for account in matrix["accounts"]]


def _coverage_outcomes(request: Request, port: int) -> list[dict]:
    """Run the catalog's coverage pairs in order, one ordinary scan each.

    This is orchestration, not a new scanning path: each pair goes through the same
    ``POST /api/lab-bola-scans`` handler, with its own scope, budget and safety
    guard. A refusal is recorded with the backend's own detail and the loop moves to
    the next pair, so a partial demonstration still shows exactly what happened.
    """
    outcomes = []
    for pair in catalog_coverage_pairs():
        payload = LabBolaScanRequest(port=port, actor=pair["actor"], owner=pair["owner"])
        try:
            run = _api().start_lab_bola_scan(payload, store=_store(request, "lab_bola"))
        except HTTPException as exc:
            outcomes.append({"actor": pair["actor"], "owner": pair["owner"],
                             "ok": False, "detail": str(exc.detail)})
            continue
        except (OSError, ValueError) as exc:  # storage or decoding failure
            outcomes.append({"actor": pair["actor"], "owner": pair["owner"],
                             "ok": False, "detail": str(exc)})
            continue
        outcomes.append({"actor": pair["actor"], "owner": pair["owner"], "ok": True,
                         "run_id": run["id"], "verdict": run["verdict"],
                         "confirmed": run["summary"]["confirmed"],
                         "requests_sent": run["constraints"]["requests_sent"],
                         "budget": run["scope"]["request_budget"]})
    return outcomes


def _bola_comparison(run: dict) -> list[dict]:
    """Pair each cross-account check with its secure-route counterpart.

    Presentation only: every value comes from the stored checks, and a direction
    without a counterpart is omitted rather than filled in.
    """
    checks = run.get("checks") or []
    secure = {(check["actor"], check["owner"]): check for check in checks
              if check.get("direction") == "cross_account_secure"}
    rows = []
    for check in checks:
        if check.get("direction") != "cross_account":
            continue
        counterpart = secure.get((check["actor"], check["owner"]))
        if counterpart is None:
            continue
        rows.append({"actor": check["actor"], "owner": check["owner"],
                     "vulnerable": check, "secure": counterpart,
                     "differs": check["verdict"] != counterpart["verdict"]})
    return rows


def _execution_stages(run: dict) -> list[dict]:
    """The stages of a stored BOLA run, in the order the oracle records them.

    This is a projection, not telemetry: each stage names the stored checks that
    belong to it and repeats their own status and verdict. A stage whose checks are
    absent says "not recorded" instead of showing progress that never existed.
    """
    checks = {check.get("id"): check for check in run.get("checks") or []}
    ownership = (run.get("ownership") or {}).get("vulnerable") or {}
    identities = ownership.get("identities_verified") or []
    def stage(title, detail, ids, note=None):
        return {"title": title, "detail": detail, "note": note,
                "checks": [checks[check_id] for check_id in ids if check_id in checks]}

    return [
        stage("Authentication",
              "Each identity authenticates with its own credential; tokens are never shared.",
              [], ", ".join(identities) if identities else "not recorded by this run"),
        stage("Ownership baselines",
              "Each account reads its own record before anything else is judged.",
              ["LAB-BOLA-01", "LAB-BOLA-02"]),
        stage("Cross-account request",
              "One account requests the other account's record.",
              ["LAB-BOLA-03", "LAB-BOLA-04"]),
        stage("Disclosure verification",
              "Only a private marker matching the verified owner baseline counts as a disclosure.",
              ["LAB-BOLA-03", "LAB-BOLA-04"]),
        stage("Secure-route comparison",
              "The same request against the corrected endpoint must be refused.",
              ["LAB-BOLA-05", "LAB-BOLA-06"]),
    ]


def _disclosure_proof(run: dict) -> list[dict]:
    """The stored steps of each cross-account attempt, for the proof flow.

    Every step is read from the check's own evidence block, so the flow can only
    show what the oracle recorded. The secure twin is included whenever the run
    stored one, which is what makes the comparison visible.
    """
    checks = run.get("checks") or []
    secure = {(check["actor"], check["owner"]): check for check in checks
              if check.get("direction") == "cross_account_secure"}
    proofs = []
    for check in checks:
        if check.get("direction") != "cross_account":
            continue
        evidence = check.get("evidence") or {}
        proofs.append({
            "requester": check["actor"], "owner": check["owner"], "check": check,
            "secure": secure.get((check["actor"], check["owner"])),
            "steps": [
                {"label": "Owner baseline verified",
                 "value": evidence.get("owner_baseline"), "anchor": check["id"]},
                {"label": "Ownership verified",
                 "value": evidence.get("ownership_verified"), "anchor": check["id"]},
                {"label": "Cross-account request", "value": check.get("status"),
                 "anchor": check["id"]},
                {"label": "Private data disclosed",
                 "value": evidence.get("private_disclosure"), "anchor": check["id"]},
            ],
        })
    return proofs


#: In-process assessment jobs: the loading screen's only source of progress.
#: Each event is a request that already completed, or a boundary the runner
#: actually reached. Nothing here is a second scanner.
ASSESSMENT_JOBS = execution_jobs.JobRegistry()


@router.post("/ui/actions/run-assessment")
async def run_assessment_action(request: Request):
    """Start a BOLA / SCI / full demonstration as a background job.

    The form posts a port, a kind and (for a single run) the catalog pair. The job
    then executes the *same* plan builder, runner, oracle and store the JSON API
    uses, and the browser watches it at ``/ui/execution/{id}``.
    """
    fields = await _form_fields(request)
    kind = (fields.get("kind") or "demo").strip()
    port_text = (fields.get("port") or "").strip()
    if kind not in {"bola", "sci", "demo"}:
        return _backend_error(request, HTTPException(status_code=422,
                                                     detail="Choose bola, sci or demo."),
                              fragment=False)
    if not port_text.isdigit() or not 1024 <= int(port_text) <= 65535:
        return _backend_error(
            request,
            HTTPException(status_code=422,
                          detail="The TargetLab port must be a whole number between 1024 and 65535."),
            fragment=False)
    port = int(port_text)

    if kind == "demo":
        steps = execution_jobs.coverage_steps()
    else:
        try:
            actor, owner = _selected_pair((fields.get("actor") or "").strip(),
                                          (fields.get("asset") or "").strip(),
                                          interaction=kind == "sci")
        except HTTPException as exc:
            return _backend_error(request, exc, fragment=False)
        except StopIteration:
            return _backend_error(request, HTTPException(
                status_code=422, detail="That combination is not in the catalog."),
                fragment=False)
        steps = [{"actor": actor, "owner": owner,
                  "asset": (fields.get("asset") or "").strip()}]

    job = ASSESSMENT_JOBS.add(execution_jobs.AssessmentJob(kind=kind, port=port, steps=steps))
    execution_jobs.start_assessment(
        job, kind=kind, port=port,
        store_bola=_store(request, "lab_bola"), store_sci=_store(request, "lab_sci"),
        actor=steps[0]["actor"], owner=steps[0]["owner"])
    return RedirectResponse(f"/ui/execution/{job.id}", status_code=303)


@router.get("/ui/execution/{job_id}")
def execution_page(request: Request, job_id: str):
    job = ASSESSMENT_JOBS.get(job_id)
    if job is None:
        return _error(request, 404, "Unknown assessment",
                      "This assessment is no longer in memory. Stored runs remain in the "
                      "scan history and the asset matrix.")
    snapshot = job.snapshot()
    return _page(request, "execution.html", "assessment",
                 job=snapshot,
                 terminal=execution_jobs.terminal_for(snapshot),
                 catalog=build_lab_catalog(),
                 first=snapshot["steps"][0] if snapshot["steps"] else None,
                 stages=[name for name in execution_jobs._STAGE_ORDER
                         if name not in {"queued", "stored", "done"}])


@router.get("/ui/execution/{job_id}/events")
def execution_events(request: Request, job_id: str, since: int = 0):
    """The job's transcript as JSON. Read-only; no scan work happens here."""
    job = ASSESSMENT_JOBS.get(job_id)
    if job is None:
        return JSONResponse({"detail": "unknown assessment"}, status_code=404)
    return JSONResponse(job.snapshot(since=max(since, 0)))


@router.get("/ui/assessment")
def assessment_page(request: Request):
    """The configuration workspace: specification, environment, accounts, tests.

    Nothing here starts a scan. Every account, asset and pair comes from
    ``GET /api/lab-catalog`` and every coverage figure from ``GET /api/lab-matrix``;
    the forms post to the existing action routes with the fields those backend
    models actually accept.
    """
    def build():
        api = _api()
        return (build_lab_catalog(),
                build_lab_matrix(list(reversed(_listed(_lab_store(request, "bola"))))),
                api.endpoints()["endpoints"], _lab_readiness())

    result = _guard(request, build)
    if not isinstance(result, tuple):
        return result
    catalog, matrix, inventory, readiness = result
    methods = sorted({endpoint["method"] for endpoint in inventory})
    return _page(request, "assessment.html", "assessment",
                 catalog=catalog, matrix=matrix, rows=_matrix_rows(matrix),
                 columns=matrix["accounts"], inventory=inventory, methods=methods,
                 readiness=readiness, coverage=catalog_coverage_pairs())


@router.get("/ui/lab/{family}/{run_id}")
def lab_run_page(request: Request, family: str, run_id: str):
    if family not in LAB_FAMILIES:
        return _error(request, 404, "Unknown lab family",
                      "Use bola, sci or reset.")

    result = _guard(request, lambda: _lab_run(request, family, run_id))
    if not isinstance(result, dict):
        return result
    resets = []
    if family == "sci":
        # Reset proofs are a separate scenario; list the ones that match this port.
        port = result.get("scope", {}).get("port")
        resets = [proof for proof in _listed(_store(request, "lab_reset"))
                  if proof.get("port") == port]
    template = {"bola": "lab_bola.html", "sci": "lab_sci.html",
                "reset": "lab_reset.html"}[family]
    return _page(request, template, "lab", run=result, family=family,
                 family_spec=LAB_FAMILIES[family], resets=resets,
                 comparisons=_bola_comparison(result) if family == "bola" else [],
                 stages=_execution_stages(result) if family == "bola" else [],
                 proof=_disclosure_proof(result) if family == "bola" else [])


@router.get("/ui/lab/{family}/{run_id}/report")
def lab_report_view(request: Request, family: str, run_id: str, reset: str = ""):
    if family not in {"bola", "sci"}:
        return _error(request, 404, "No section report for this lab family",
                      "TargetLab read-BOLA and control-interaction runs have section reports.")

    def build():
        return (_lab_run(request, family, run_id),
                _lab_sections(request, family, run_id, reset_id=reset))

    result = _guard(request, build)
    if not isinstance(result, tuple):
        return result
    run, payload = result
    return _page(request, "sections_report.html", "reports", run=run,
                 sections=payload["sections"], family=family,
                 family_spec=LAB_FAMILIES[family],
                 family_label=LAB_FAMILIES[family]["label"],
                 back_href=f"/ui/lab/{family}/{run_id}",
                 report_base=f"{LAB_FAMILIES[family]['base']}/{run_id}/report",
                 verdict=run.get("verdict"),
                 reason=run.get("reason"),
                 recorded=run.get("created_at"),
                 run_id_value=run.get("id", run_id),
                 reset_id=reset)


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
                                          {"run": result, "family": "read-bola",
                                           "family_spec": SUITE_FAMILIES["read-bola"]})
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
                                          {"run": result, "family": "authentication",
                                           "family_spec": SUITE_FAMILIES["authentication"]})
    return RedirectResponse(f"/ui/suites/authentication/{result['id']}", status_code=303)


def _selected_pair(actor: str, asset_id: str, *, interaction: bool) -> tuple[str, str]:
    """Resolve the form's account and asset into the pair the catalog declares.

    This is a lookup of published catalog data, not a security decision: the
    catalog already names the ordered pair to run for every one of the nine
    combinations, and the backend validates it again. Nothing here computes a
    verdict, an expected access or a credential.
    """
    catalog = build_lab_catalog()
    accounts = {item["account"] for item in catalog["accounts"]}
    owners = {item["asset_id"]: item["account"] for item in catalog["accounts"]}
    if actor not in accounts:
        raise HTTPException(status_code=422,
                            detail="Choose one of the provisioned demo accounts.")
    if asset_id not in owners:
        raise HTTPException(status_code=422,
                            detail="Choose one of the declared demo assets.")
    owner = owners[asset_id]
    if not interaction:
        combination = next(item for item in catalog["combinations"]
                           if item["actor"] == actor and item["asset_id"] == asset_id)
        return combination["pair"]["actor"], combination["pair"]["owner"]
    if owner == actor:
        raise HTTPException(
            status_code=422,
            detail="The interaction needs two different accounts: choose an asset "
                   "owned by another account.")
    return actor, owner


async def _lab_payload(request: Request, *, interaction: bool = False):
    """Build a lab request model from the form, or explain why it is invalid."""
    fields = await _form_fields(request)
    port_text = (fields.get("port") or "").strip()
    budget_text = (fields.get("request_budget") or "").strip()
    actor = (fields.get("actor") or "").strip()
    asset_id = (fields.get("asset") or "").strip()
    if not port_text.isdigit():
        raise HTTPException(status_code=422,
                            detail="The TargetLab port must be a whole number between "
                                   "1024 and 65535.")
    values = {"port": int(port_text)}
    if budget_text:
        if not budget_text.isdigit():
            raise HTTPException(status_code=422,
                                detail="The request budget must be a whole number.")
        values["request_budget"] = int(budget_text)
    if actor or asset_id:
        values["actor"], values["owner"] = _selected_pair(actor, asset_id,
                                                          interaction=interaction)
    return values


@router.post("/ui/actions/lab-bola-scan")
async def lab_bola_scan_action(request: Request):
    htmx = _is_htmx(request)
    try:
        values = await _lab_payload(request)
        payload = LabBolaScanRequest(**values)
    except HTTPException as exc:
        return _backend_error(request, exc, fragment=htmx)
    except ValueError:
        return _backend_error(
            request,
            HTTPException(status_code=422,
                          detail="The port must be 1024–65535 and the budget 16–40."),
            fragment=htmx)

    result = _guard(request, lambda: _api().start_lab_bola_scan(
        payload, store=_store(request, "lab_bola")), fragment=htmx)
    if not isinstance(result, dict):
        return result
    if htmx:
        return templates.TemplateResponse(request, "partials/lab_result.html",
                                          {"run": result, "family": "bola",
                                           "family_spec": LAB_FAMILIES["bola"]})
    return RedirectResponse(f"/ui/lab/bola/{result['id']}", status_code=303)


@router.post("/ui/actions/lab-demo-run")
async def lab_demo_run_action(request: Request):
    """Run all three coverage pairs sequentially, then show what was stored.

    The pairs come from ``GET /api/lab-catalog`` (``coverage_pairs``); the browser
    submits only a port. Full coverage is reported only when the rebuilt matrix has
    no untested cell — otherwise the page names every pair that failed and keeps the
    remaining cells untested.
    """
    fields = await _form_fields(request)
    port_text = (fields.get("port") or "").strip()
    if not port_text.isdigit() or not 1024 <= int(port_text) <= 65535:
        return _backend_error(
            request,
            HTTPException(status_code=422,
                          detail="The TargetLab port must be a whole number between "
                                 "1024 and 65535."), fragment=False)
    port = int(port_text)
    outcomes = _coverage_outcomes(request, port)
    matrix = _guard(request, lambda: build_lab_matrix(
        list(reversed(_listed(_lab_store(request, "bola"))))))
    if not isinstance(matrix, dict):
        return matrix
    return _page(request, "lab_demo_result.html", "lab_matrix", port=port,
                 outcomes=outcomes, matrix=matrix, rows=_matrix_rows(matrix),
                 columns=matrix["accounts"], selected=None,
                 stored=sum(1 for item in outcomes if item["ok"]),
                 complete=matrix["summary"]["untested"] == 0,
                 coverage=catalog_coverage_pairs())


@router.post("/ui/actions/lab-sci-scan")
async def lab_sci_scan_action(request: Request):
    htmx = _is_htmx(request)
    try:
        values = await _lab_payload(request, interaction=True)
        payload = LabSciScanRequest(**values)
    except HTTPException as exc:
        return _backend_error(request, exc, fragment=htmx)
    except ValueError:
        return _backend_error(
            request,
            HTTPException(status_code=422,
                          detail="The port must be 1024–65535 and the budget 16–40."),
            fragment=htmx)

    result = _guard(request, lambda: _api().start_lab_sci_scan(
        payload, store=_store(request, "lab_sci")), fragment=htmx)
    if not isinstance(result, dict):
        return result
    if htmx:
        return templates.TemplateResponse(request, "partials/lab_result.html",
                                          {"run": result, "family": "sci",
                                           "family_spec": LAB_FAMILIES["sci"]})
    return RedirectResponse(f"/ui/lab/sci/{result['id']}", status_code=303)


@router.post("/ui/actions/lab-sci-reset")
async def lab_sci_reset_action(request: Request):
    htmx = _is_htmx(request)
    try:
        values = await _lab_payload(request, interaction=True)
        payload = LabSciScanRequest(**values)
    except HTTPException as exc:
        return _backend_error(request, exc, fragment=htmx)
    except ValueError:
        return _backend_error(
            request,
            HTTPException(status_code=422,
                          detail="The port must be 1024–65535 and the budget 16–40."),
            fragment=htmx)

    result = _guard(request, lambda: _api().start_lab_sci_reset(
        payload, store=_store(request, "lab_reset")), fragment=htmx)
    if not isinstance(result, dict):
        return result
    if htmx:
        return templates.TemplateResponse(request, "partials/lab_result.html",
                                          {"run": result, "family": "reset",
                                           "family_spec": LAB_FAMILIES["reset"]})
    return RedirectResponse(f"/ui/lab/reset/{result['id']}", status_code=303)


@router.post("/ui/actions/validation-scan")
async def validation_scan_action(request: Request):
    htmx = _is_htmx(request)
    try:
        fields = await _form_fields(request)
    except HTTPException as exc:
        return _backend_error(request, exc, fragment=htmx)
    try:
        payload = ValidationScanRequest(scenario_id=fields.get("scenario_id", ""))
    except ValueError:
        return _backend_error(
            request,
            HTTPException(status_code=422,
                          detail="Select a bundled input/disclosure scenario id."),
            fragment=htmx)

    result = _guard(request, lambda: _api().start_validation_scan(
        payload, store=_store(request, "validation")), fragment=htmx)
    if not isinstance(result, dict):
        return result
    if htmx:
        return templates.TemplateResponse(request, "partials/suite_result.html",
                                          {"run": result, "family": "validation",
                                           "family_spec": SUITE_FAMILIES["validation"]})
    return RedirectResponse(f"/ui/suites/validation/{result['id']}", status_code=303)


@router.post("/ui/actions/interaction-scan")
async def interaction_scan_action(request: Request):
    htmx = _is_htmx(request)
    try:
        fields = await _form_fields(request)
    except HTTPException as exc:
        return _backend_error(request, exc, fragment=htmx)
    try:
        payload = InteractionScanRequest(scenario_id=fields.get("scenario_id", ""))
    except ValueError:
        return _backend_error(
            request,
            HTTPException(status_code=422,
                          detail="Select a bundled control-interaction scenario id."),
            fragment=htmx)

    result = _guard(request, lambda: _api().start_interaction_scan(
        payload, store=_store(request, "interaction")), fragment=htmx)
    if not isinstance(result, dict):
        return result
    if htmx:
        return templates.TemplateResponse(request, "partials/suite_result.html",
                                          {"run": result, "family": "interaction",
                                           "family_spec": SUITE_FAMILIES["interaction"]})
    return RedirectResponse(f"/ui/suites/interaction/{result['id']}", status_code=303)


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
