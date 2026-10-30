"""Local-only API with fixture-only SQLite persistence; no live targets."""
from contextlib import asynccontextmanager
import hashlib
from pathlib import Path
import sqlite3

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.concurrency import run_in_threadpool

from canarygate.database.scenario_store import ScenarioStore
from canarygate.database.store import FixtureStore, default_database_path
from canarygate.evidence.redaction import EvidenceIntegrityError
from canarygate.offline.scan import inventory, run_fixture
from canarygate.report.fixture import build_fixture_sections, render_fixture_report
from canarygate.report.scenario import build_scenario_sections, render_scenario_report
from canarygate.scan.models import (ScenarioRun, ScenarioScanRequest, ScenarioSectionReport)
from canarygate.scan.scenarios import build_scenario, execute_offline_scenario
from canarygate.spec.parser import MAX_SPEC_BYTES, parse_inventory
from .schemas import (Health, Inventory, SetupResponse, FixtureRun, FindingsResponse, MatrixResponse,
                      ObservationSet, FixtureReportBundle, FixtureSectionReport, SpecInspection)

router = APIRouter()


def get_store(request: Request) -> FixtureStore:
    return request.app.state.store


def get_scenario_store(request: Request) -> ScenarioStore:
    return request.app.state.scenario_store


def _database_call(method, *args):
    try:
        return method(*args)
    except EvidenceIntegrityError:
        raise HTTPException(status_code=500, detail="Stored fixture data failed integrity verification") from None
    except (sqlite3.Error, OSError, ValueError):
        raise HTTPException(status_code=500, detail="Fixture storage unavailable or invalid") from None


def _scenario_call(method, *args):
    try:
        return method(*args)
    except EvidenceIntegrityError:
        raise HTTPException(status_code=500, detail="Stored scenario data failed integrity verification") from None
    except (sqlite3.Error, OSError, ValueError):
        raise HTTPException(status_code=500, detail="Scenario storage unavailable or invalid") from None


@router.get("/api/health", response_model=Health)
def health():
    return {"status": "ok", "mode": "fixture", "live_scanning": False}


@router.post("/api/spec/upload", response_model=SpecInspection)
async def spec_upload(request: Request):
    """Inspect a raw UTF-8 OpenAPI document; never select a target or start a scan."""
    media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media_type not in {"application/yaml", "application/x-yaml", "text/yaml", "text/plain",
                          "application/json", "application/octet-stream"}:
        raise HTTPException(status_code=415, detail="Send a raw YAML or JSON document")
    if request.headers.get("content-encoding", "identity").lower() != "identity":
        raise HTTPException(status_code=415, detail="Compressed documents are not supported")
    content_length = request.headers.get("content-length")
    if content_length is not None:
        if not content_length.isascii() or not content_length.isdigit():
            raise HTTPException(status_code=400, detail="Invalid content length")
        if len(content_length) > 10 or int(content_length) > MAX_SPEC_BYTES:
            raise HTTPException(status_code=413, detail="Specification too large")
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_SPEC_BYTES:
            raise HTTPException(status_code=413, detail="Specification too large")
        body.extend(chunk)
    try:
        text = bytes(body).decode("utf-8-sig")
        endpoints = await run_in_threadpool(parse_inventory, text)
    except (UnicodeDecodeError, ValueError):
        raise HTTPException(status_code=422, detail="Invalid or unsupported OpenAPI specification") from None
    return {"mode": "inventory_only", "live_scanning": False,
            "sha256": hashlib.sha256(body).hexdigest(), "endpoint_count": len(endpoints),
            "endpoints": endpoints,
            "message": "Inspection only; uploaded specifications are not saved or used by fixture scans."}


@router.get("/api/endpoints", response_model=Inventory)
def endpoints():
    return {"mode": "fixture", "endpoints": inventory()}


@router.get("/api/setup/status", response_model=SetupResponse)
def setup_status(store: FixtureStore = Depends(get_store)):
    latest = _database_call(store.latest)
    return {"mode": "fixture", "setup": latest["setup"] if latest else None,
            "message": "Run the fixture scan to evaluate setup." if latest is None else "Latest fixture scan setup."}


@router.post("/api/scan", status_code=201, response_model=FixtureRun)
def start_scan(store: FixtureStore = Depends(get_store)):
    # Run and its minimized observations are stored in one SQLite transaction.
    observations = []
    run = run_fixture(observation_sink=observations)
    return _database_call(store.save, run, observations)


def _find(store: FixtureStore, run_id: str):
    run = _database_call(store.get, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Fixture scan not found")
    return run


@router.get("/api/scan/{run_id}", response_model=FixtureRun)
def scan(run_id: str, store: FixtureStore = Depends(get_store)):
    return _find(store, run_id)


@router.get("/api/scan/{run_id}/observations", response_model=ObservationSet)
def scan_observations(run_id: str, store: FixtureStore = Depends(get_store)):
    _find(store, run_id)
    return _observation_set(store, run_id)


def _observation_set(store: FixtureStore, run_id: str):
    observations = _database_call(store.get_observations, run_id)
    return {"mode": "fixture", "run_id": run_id,
            "coverage": "NOT_RECORDED" if observations is None else "RECORDED",
            "observations": [] if observations is None else observations}


@router.get("/api/findings", response_model=FindingsResponse)
def findings(store: FixtureStore = Depends(get_store)):
    return {"mode": "fixture", "findings": _database_call(store.list)}


@router.get("/api/matrix", response_model=MatrixResponse)
def matrix(store: FixtureStore = Depends(get_store)):
    runs = _database_call(store.list)
    cells = [{key: run[key] for key in ("id", "endpoint", "actor", "target_resource", "expected_access", "expected_source", "verdict")} for run in runs]
    return {"mode": "fixture", "cells": cells}


@router.post("/api/scenario-scans", status_code=201, response_model=ScenarioRun)
def start_scenario_scan(payload: ScenarioScanRequest, store: ScenarioStore = Depends(get_scenario_store)):
    """Run one bundled synthetic offline scenario through the generic workflow."""
    try:
        plan = build_scenario(payload.scenario_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Unknown offline scenario") from None
    run = execute_offline_scenario(plan)
    return _scenario_call(store.save, run)


def _find_scenario(store, run_id):
    run = _scenario_call(store.get, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Scenario scan not found")
    return run


@router.get("/api/scenario-scans/{run_id}", response_model=ScenarioRun)
def scenario_scan(run_id: str, store: ScenarioStore = Depends(get_scenario_store)):
    return _find_scenario(store, run_id)


@router.get("/api/scenario-scans/{run_id}/report", response_model=ScenarioSectionReport,
            responses={200: {"content": {"text/html": {"schema": {"type": "string"}}}}})
def scenario_report(run_id: str, format: str = "json", view: str = "run",
                    store: ScenarioStore = Depends(get_scenario_store)):
    run = _find_scenario(store, run_id)
    if view not in {"run", "sections"}:
        raise HTTPException(status_code=400, detail="View must be run or sections")
    if format not in {"json", "html"}:
        raise HTTPException(status_code=400, detail="Format must be json or html")
    if format == "html":
        return HTMLResponse(render_scenario_report(run))
    if view == "sections":
        return ScenarioSectionReport(mode="offline_scenario", id=run_id, run_id=run_id,
                                     sections=build_scenario_sections(run))
    return run


@router.get("/api/reports/{run_id}", response_model=FixtureRun | FixtureReportBundle | FixtureSectionReport,
            responses={200: {"content": {"text/html": {"schema": {"type": "string"}}}}})
def report(run_id: str, format: str = "json", include_observations: bool = False, view: str = "run",
           store: FixtureStore = Depends(get_store)):
    run = _find(store, run_id)
    if view not in {"run", "sections"}:
        raise HTTPException(status_code=400, detail="View must be run or sections")
    if view == "sections" and include_observations:
        raise HTTPException(status_code=400, detail="Section view does not include observation sets; fetch observations separately")
    if view == "sections" and format == "json":
        report = FixtureSectionReport(mode="fixture", run_id=run_id, sections=build_fixture_sections(run))
        return JSONResponse(content=report.model_dump(mode="json"))
    if format == "json" and not include_observations:
        return run  # Existing JSON contract is unchanged.
    if format not in {"json", "html"}:
        raise HTTPException(status_code=400, detail="Format must be json or html")
    observation_set = _observation_set(store, run_id)
    if format == "json":
        bundle = FixtureReportBundle(run=run, observation_set=ObservationSet(**observation_set))
        return JSONResponse(content=bundle.model_dump(mode="json"))
    return HTMLResponse(render_fixture_report(run, observation_set))


def create_app(database_path: str | Path | None = None) -> FastAPI:
    path = database_path if database_path is not None else default_database_path()
    store = FixtureStore(path)
    scenario_store = ScenarioStore(path)

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        store.initialize()
        scenario_store.initialize()
        yield

    # Default Swagger/ReDoc CDN assets are disabled to avoid external requests.
    application = FastAPI(title="CanaryGate offline fixture API", version="0.1.0",
                          docs_url=None, redoc_url=None, lifespan=lifespan)
    application.state.store = store
    application.state.scenario_store = scenario_store
    application.include_router(router)
    return application


app = create_app()
