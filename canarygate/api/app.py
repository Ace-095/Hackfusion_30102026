"""Local-only API with fixture-only SQLite persistence; no live targets."""
from contextlib import asynccontextmanager
from pathlib import Path
import sqlite3

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from canarygate.database.store import FixtureStore, default_database_path
from canarygate.evidence.redaction import EvidenceIntegrityError
from canarygate.offline.scan import inventory, run_fixture
from canarygate.report.fixture import render_fixture_report
from .schemas import (Health, Inventory, SetupResponse, FixtureRun, FindingsResponse, MatrixResponse,
                      ObservationSet, FixtureReportBundle)

router = APIRouter()


def get_store(request: Request) -> FixtureStore:
    return request.app.state.store


def _database_call(method, *args):
    try:
        return method(*args)
    except EvidenceIntegrityError:
        raise HTTPException(status_code=500, detail="Stored fixture data failed integrity verification") from None
    except (sqlite3.Error, OSError, ValueError):
        raise HTTPException(status_code=500, detail="Fixture storage unavailable or invalid") from None


@router.get("/api/health", response_model=Health)
def health():
    return {"status": "ok", "mode": "fixture", "live_scanning": False}


@router.post("/api/spec/upload", status_code=501)
def spec_upload():
    return {"detail": "Spec upload is not implemented; only the bundled fixture is available."}


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


@router.get("/api/reports/{run_id}", response_model=FixtureRun | FixtureReportBundle,
            responses={200: {"content": {"text/html": {"schema": {"type": "string"}}}}})
def report(run_id: str, format: str = "json", include_observations: bool = False,
           store: FixtureStore = Depends(get_store)):
    run = _find(store, run_id)
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
    store = FixtureStore(database_path if database_path is not None else default_database_path())

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        store.initialize()
        yield

    # Default Swagger/ReDoc CDN assets are disabled to avoid external requests.
    application = FastAPI(title="CanaryGate offline fixture API", version="0.1.0",
                          docs_url=None, redoc_url=None, lifespan=lifespan)
    application.state.store = store
    application.include_router(router)
    return application


app = create_app()
