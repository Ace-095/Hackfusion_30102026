"""Local-only API with fixture-only SQLite persistence; no live targets."""
from contextlib import asynccontextmanager
import hashlib
import os
from pathlib import Path
import sqlite3

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.concurrency import run_in_threadpool

from canarygate.database.auth_store import AuthenticationStore
from canarygate.database.scenario_store import ScenarioStore
from canarygate.database.interaction_store import InteractionStore
from canarygate.database.lab_bola_store import LabBolaStore
from canarygate.database.lab_reset_store import LabResetStore
from canarygate.database.lab_sci_store import LabSciStore
from canarygate.database.lab_store import LabStore
from canarygate.database.validation_store import ValidationStore
from canarygate.database.store import FixtureStore, default_database_path
from canarygate.evidence.redaction import EvidenceIntegrityError
from canarygate.offline.scan import inventory, run_fixture
from canarygate.report.fixture import build_fixture_sections, render_fixture_report
from canarygate.report.authentication import (build_authentication_sections,
                                              render_authentication_report)
from canarygate.report.matrix import AuthorizationMatrix, build_authorization_matrix
from canarygate.report.p0 import build_p0_report, render_p0_report
from canarygate.report.scenario import build_scenario_sections, render_scenario_report
from canarygate.report.interaction import build_interaction_sections, render_interaction_report
from canarygate.report.lab import build_lab_sections, render_lab_report
from canarygate.report.lab_bola import build_lab_bola_sections, render_lab_bola_report
from canarygate.report.lab_sci import build_lab_sci_sections, render_lab_sci_report
from canarygate.report.validation import build_validation_sections, render_validation_report
from canarygate.scan.auth_generic import run_authentication_scan
from canarygate.scan.auth_models import (AuthenticationRun, AuthenticationScanRequest,
                                         AuthenticationSectionReport)
from canarygate.scan.auth_scenarios import build_auth_scenario, runner_for
from canarygate.scan.models import (ScenarioRun, ScenarioScanRequest, ScenarioSectionReport)
from canarygate.scan.scenarios import build_scenario, execute_offline_scenario
from canarygate.scan.interaction_generic import run_offline_interaction
from canarygate.scan.interaction_models import (InteractionRun, InteractionScanRequest,
                                                InteractionSectionReport)
from canarygate.scan.interaction_scenarios import (build_interaction_scenario,
                                                   runner_for as interaction_runner_for)
from canarygate.network.targetlab import TargetLabRefused, TargetLabRunner
from canarygate.scan.lab_bola import run_lab_bola_scan
from canarygate.scan.lab_bola_models import LabBolaRun, LabBolaScanRequest, LabBolaSectionReport
from canarygate.scan.lab_bola_scenarios import build_bola_plan
from canarygate.scan.lab_generic import run_lab_evidence
from canarygate.scan.lab_sci import run_lab_sci_reset, run_lab_sci_scan
from canarygate.scan.lab_sci_models import (LabResetProof, LabSciScanRequest, LabSciSectionReport)
from canarygate.scan.lab_sci_scenarios import build_sci_plan
from canarygate.scan.lab_models import LabRun, LabScanRequest, LabSectionReport
from canarygate.scan.lab_scenarios import build_lab_plan
from canarygate.scan.validation_generic import run_offline_validation
from canarygate.scan.validation_models import (ValidationRun, ValidationScanRequest,
                                               ValidationSectionReport)
from canarygate.scan.validation_scenarios import build_validation_scenario, runner_for as validation_runner_for
from canarygate.spec.parser import MAX_SPEC_BYTES, parse_inventory
from .schemas import (Health, Inventory, SetupResponse, FixtureRun, FindingsResponse, MatrixResponse,
                      ObservationSet, FixtureReportBundle, FixtureSectionReport, SpecInspection)

router = APIRouter()


def get_store(request: Request) -> FixtureStore:
    return request.app.state.store


def get_scenario_store(request: Request) -> ScenarioStore:
    return request.app.state.scenario_store


def get_auth_store(request: Request) -> AuthenticationStore:
    return request.app.state.auth_store


def get_validation_store(request: Request) -> ValidationStore:
    return request.app.state.validation_store


def get_interaction_store(request: Request) -> InteractionStore:
    return request.app.state.interaction_store


def get_lab_store(request: Request) -> LabStore:
    return request.app.state.lab_store


def get_lab_bola_store(request: Request) -> LabBolaStore:
    return request.app.state.lab_bola_store


def get_lab_sci_store(request: Request) -> LabSciStore:
    return request.app.state.lab_sci_store


def get_lab_reset_store(request: Request) -> LabResetStore:
    return request.app.state.lab_reset_store


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


def _interaction_call(method, *args):
    try:
        return method(*args)
    except EvidenceIntegrityError:
        raise HTTPException(status_code=500, detail="Stored interaction data failed integrity verification") from None
    except (sqlite3.Error, OSError, ValueError):
        raise HTTPException(status_code=500, detail="Interaction storage unavailable or invalid") from None


def _validation_call(method, *args):
    try:
        return method(*args)
    except EvidenceIntegrityError:
        raise HTTPException(status_code=500, detail="Stored validation data failed integrity verification") from None
    except (sqlite3.Error, OSError, ValueError):
        raise HTTPException(status_code=500, detail="Validation storage unavailable or invalid") from None


def _auth_call(method, *args):
    try:
        return method(*args)
    except EvidenceIntegrityError:
        raise HTTPException(status_code=500, detail="Stored authentication data failed integrity verification") from None
    except (sqlite3.Error, OSError, ValueError):
        raise HTTPException(status_code=500, detail="Authentication storage unavailable or invalid") from None


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
    if view not in {"run", "sections", "p0"}:
        raise HTTPException(status_code=400, detail="View must be run, sections or p0")
    if format not in {"json", "html"}:
        raise HTTPException(status_code=400, detail="Format must be json or html")
    if view == "p0":
        if format == "html":
            return HTMLResponse(render_p0_report("scenario", run))
        return JSONResponse(content=build_p0_report("scenario", run).model_dump(mode="json"))
    if format == "html":
        return HTMLResponse(render_scenario_report(run))
    if view == "sections":
        return ScenarioSectionReport(mode="offline_scenario", id=run_id, run_id=run_id,
                                     sections=build_scenario_sections(run))
    return run


@router.post("/api/authentication-scans", status_code=201, response_model=AuthenticationRun)
def start_authentication_scan(payload: AuthenticationScanRequest,
                              store: AuthenticationStore = Depends(get_auth_store)):
    """Run one bundled synthetic offline authentication scenario; no live target."""
    try:
        plan = build_auth_scenario(payload.scenario_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Unknown offline authentication scenario") from None
    runner = runner_for(plan)
    try:
        run = run_authentication_scan(runner, plan)
    finally:
        runner.close()
    return _auth_call(store.save, run)


def _find_auth_run(store, run_id):
    run = _auth_call(store.get, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Authentication scan not found")
    return run


@router.get("/api/authentication-scans/{run_id}", response_model=AuthenticationRun)
def authentication_scan(run_id: str, store: AuthenticationStore = Depends(get_auth_store)):
    return _find_auth_run(store, run_id)


@router.get("/api/authentication-scans/{run_id}/report", response_model=AuthenticationSectionReport,
            responses={200: {"content": {"text/html": {"schema": {"type": "string"}}}}})
def authentication_report(run_id: str, format: str = "json", view: str = "run",
                          store: AuthenticationStore = Depends(get_auth_store)):
    run = _find_auth_run(store, run_id)
    if view not in {"run", "sections", "p0"}:
        raise HTTPException(status_code=400, detail="View must be run, sections or p0")
    if format not in {"json", "html"}:
        raise HTTPException(status_code=400, detail="Format must be json or html")
    if view == "p0":
        if format == "html":
            return HTMLResponse(render_p0_report("authentication", run))
        return JSONResponse(content=build_p0_report("authentication", run).model_dump(mode="json"))
    if format == "html":
        return HTMLResponse(render_authentication_report(run))
    if view == "sections":
        return AuthenticationSectionReport(mode="offline_authentication", id=run_id, run_id=run_id,
                                           sections=build_authentication_sections(run))
    return run


@router.post("/api/validation-scans", status_code=201, response_model=ValidationRun)
def start_validation_scan(payload: ValidationScanRequest,
                          store: ValidationStore = Depends(get_validation_store)):
    """Run one bundled synthetic offline validation scenario; no live target."""
    try:
        plan = build_validation_scenario(payload.scenario_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Unknown offline validation scenario") from None
    runner = validation_runner_for(plan)
    try:
        run = run_offline_validation(plan, runner)
    finally:
        runner.close()
    return _validation_call(store.save, run)


def _find_validation_run(store, run_id):
    run = _validation_call(store.get, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Validation scan not found")
    return run


@router.get("/api/validation-scans/{run_id}", response_model=ValidationRun)
def validation_scan(run_id: str, store: ValidationStore = Depends(get_validation_store)):
    return _find_validation_run(store, run_id)


@router.get("/api/validation-scans/{run_id}/report", response_model=ValidationSectionReport,
            responses={200: {"content": {"text/html": {"schema": {"type": "string"}}}}})
def validation_report(run_id: str, format: str = "json", view: str = "run",
                      store: ValidationStore = Depends(get_validation_store)):
    run = _find_validation_run(store, run_id)
    if view not in {"run", "sections", "p0"}:
        raise HTTPException(status_code=400, detail="View must be run, sections or p0")
    if format not in {"json", "html"}:
        raise HTTPException(status_code=400, detail="Format must be json or html")
    if view == "p0":
        if format == "html":
            return HTMLResponse(render_p0_report("validation", run))
        return JSONResponse(content=build_p0_report("validation", run).model_dump(mode="json"))
    if format == "html":
        return HTMLResponse(render_validation_report(run))
    if view == "sections":
        return ValidationSectionReport(mode="offline_validation", id=run_id, run_id=run_id,
                                       sections=build_validation_sections(run))
    return run




@router.post("/api/interaction-scans", status_code=201, response_model=InteractionRun)
def start_interaction_scan(payload: InteractionScanRequest,
                           store: InteractionStore = Depends(get_interaction_store)):
    """Run one bundled synthetic SCI interaction scenario; no live target."""
    try:
        plan = build_interaction_scenario(payload.scenario_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Unknown offline SCI scenario") from None
    runner = interaction_runner_for(plan)
    try:
        run = run_offline_interaction(plan, runner)
    finally:
        runner.close()
    return _interaction_call(store.save, run)


def _find_interaction_run(store, run_id):
    run = _interaction_call(store.get, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Interaction scan not found")
    return run


@router.get("/api/interaction-scans/{run_id}", response_model=InteractionRun)
def interaction_scan(run_id: str, store: InteractionStore = Depends(get_interaction_store)):
    return _find_interaction_run(store, run_id)


@router.get("/api/interaction-scans/{run_id}/report", response_model=InteractionSectionReport,
            responses={200: {"content": {"text/html": {"schema": {"type": "string"}}}}})
def interaction_report(run_id: str, format: str = "json", view: str = "run",
                       store: InteractionStore = Depends(get_interaction_store)):
    run = _find_interaction_run(store, run_id)
    if view not in {"run", "sections", "p0"}:
        raise HTTPException(status_code=400, detail="View must be run, sections or p0")
    if format not in {"json", "html"}:
        raise HTTPException(status_code=400, detail="Format must be json or html")
    if view == "p0":
        if format == "html":
            return HTMLResponse(render_p0_report("interaction", run))
        return JSONResponse(content=build_p0_report("interaction", run).model_dump(mode="json"))
    if format == "html":
        return HTMLResponse(render_interaction_report(run))
    if view == "sections":
        return InteractionSectionReport(mode="offline_interaction", id=run_id, run_id=run_id,
                                        sections=build_interaction_sections(run))
    return run


def _lab_call(method, *args):
    try:
        return method(*args)
    except EvidenceIntegrityError:
        raise HTTPException(status_code=500, detail="Stored TargetLab data failed integrity verification") from None


@router.post("/api/lab-scans", status_code=201, response_model=LabRun)
def start_lab_scan(payload: LabScanRequest, store: LabStore = Depends(get_lab_store)):
    """Run the fixed evidence workflow against a loopback TargetLab over HTTPS.

    Requires CANARYGATE_TARGETLAB_CA to point at the test-only certificate. The
    destination is pinned to 127.0.0.1; nothing else can be configured.
    """
    ca_file = os.environ.get("CANARYGATE_TARGETLAB_CA")
    if not ca_file:
        raise HTTPException(status_code=400,
                            detail="TargetLab CA is not configured; set CANARYGATE_TARGETLAB_CA")
    try:
        plan = build_lab_plan(payload.port, budget=payload.request_budget)
        runner = TargetLabRunner(plan.scope, plan.credentials, ca_file=ca_file)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid TargetLab scan configuration") from None
    try:
        run = run_lab_evidence(plan, runner)
    except (TargetLabRefused, OSError):
        raise HTTPException(status_code=502,
                            detail="TargetLab request refused or failed; no evidence was stored") from None
    finally:
        runner.close()
    return _lab_call(store.save, run)


def _find_lab_run(store, run_id):
    run = _lab_call(store.get, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="TargetLab scan not found")
    return run


@router.get("/api/lab-scans/{run_id}", response_model=LabRun)
def lab_scan(run_id: str, store: LabStore = Depends(get_lab_store)):
    return _find_lab_run(store, run_id)


@router.get("/api/lab-scans/{run_id}/report", response_model=LabSectionReport,
            responses={200: {"content": {"text/html": {"schema": {"type": "string"}}}}})
def lab_report(run_id: str, format: str = "json", view: str = "run",
               store: LabStore = Depends(get_lab_store)):
    run = _find_lab_run(store, run_id)
    if view not in {"run", "sections"}:
        raise HTTPException(status_code=400, detail="View must be run or sections")
    if format not in {"json", "html"}:
        raise HTTPException(status_code=400, detail="Format must be json or html")
    if format == "html":
        return HTMLResponse(render_lab_report(run))
    if view == "sections":
        return LabSectionReport(mode="targetlab_https", id=run_id, run_id=run_id,
                                sections=build_lab_sections(run))
    return run


def _lab_bola_call(method, *args):
    try:
        return method(*args)
    except EvidenceIntegrityError:
        raise HTTPException(status_code=500,
                            detail="Stored TargetLab BOLA data failed integrity verification") from None


@router.post("/api/lab-bola-scans", status_code=201, response_model=LabBolaRun)
def start_lab_bola_scan(payload: LabBolaScanRequest,
                        store: LabBolaStore = Depends(get_lab_bola_store)):
    """Run the fixed read-BOLA validation against a loopback TargetLab over HTTPS."""
    ca_file = os.environ.get("CANARYGATE_TARGETLAB_CA")
    if not ca_file:
        raise HTTPException(status_code=400,
                            detail="TargetLab CA is not configured; set CANARYGATE_TARGETLAB_CA")
    try:
        plan = build_bola_plan(payload.port, budget=payload.request_budget)
        runner = TargetLabRunner(plan.scope, plan.credentials, ca_file=ca_file)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid TargetLab BOLA configuration") from None
    try:
        run = run_lab_bola_scan(plan, runner)
    except (TargetLabRefused, OSError):
        raise HTTPException(status_code=502,
                            detail="TargetLab request refused or failed; no evidence was stored") from None
    finally:
        runner.close()
    if all(check.status is None for check in run.checks):
        # Nothing was ever observed: the lab was unreachable or refused TLS. That
        # is a transport failure, not evidence, so no run is stored.
        raise HTTPException(status_code=502,
                            detail="TargetLab could not be reached; no evidence was stored")
    return _lab_bola_call(store.save, run)


def _find_lab_bola_run(store, run_id):
    run = _lab_bola_call(store.get, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="TargetLab BOLA scan not found")
    return run


@router.get("/api/lab-bola-scans/{run_id}", response_model=LabBolaRun)
def lab_bola_scan(run_id: str, store: LabBolaStore = Depends(get_lab_bola_store)):
    return _find_lab_bola_run(store, run_id)


@router.get("/api/lab-bola-scans/{run_id}/report", response_model=LabBolaSectionReport,
            responses={200: {"content": {"text/html": {"schema": {"type": "string"}}}}})
def lab_bola_report(run_id: str, format: str = "json", view: str = "run",
                    store: LabBolaStore = Depends(get_lab_bola_store)):
    run = _find_lab_bola_run(store, run_id)
    if view not in {"run", "sections", "p0"}:
        raise HTTPException(status_code=400, detail="View must be run, sections or p0")
    if format not in {"json", "html"}:
        raise HTTPException(status_code=400, detail="Format must be json or html")
    if view == "p0":
        if format == "html":
            return HTMLResponse(render_p0_report("lab_bola", run))
        return JSONResponse(content=build_p0_report("lab_bola", run).model_dump(mode="json"))
    if format == "html":
        return HTMLResponse(render_lab_bola_report(run))
    if view == "sections":
        return LabBolaSectionReport(mode="targetlab_bola", id=run_id, run_id=run_id,
                                    sections=build_lab_bola_sections(run))
    return run


def _open_targetlab_runner(port, *, budget, ca_file):
    """Build the fixed plan and one guarded runner; 400 on invalid configuration."""
    from canarygate.network.targetlab import TargetLabRunner

    try:
        plan = build_sci_plan(port, budget=budget)
        return plan, TargetLabRunner(plan.scope, plan.credentials, ca_file=ca_file)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid TargetLab SCI configuration") from None


@router.post("/api/lab-sci-scans", status_code=201, response_model=InteractionRun)
def start_lab_sci_scan(payload: LabSciScanRequest,
                       store: LabSciStore = Depends(get_lab_sci_store)):
    """Run the fixed control-interaction validation against a loopback TargetLab."""
    ca_file = os.environ.get("CANARYGATE_TARGETLAB_CA")
    if not ca_file:
        raise HTTPException(status_code=400,
                            detail="TargetLab CA is not configured; set CANARYGATE_TARGETLAB_CA")
    plan, runner = _open_targetlab_runner(payload.port, budget=payload.request_budget,
                                          ca_file=ca_file)
    try:
        run = run_lab_sci_scan(plan, runner)
    except (TargetLabRefused, OSError):
        raise HTTPException(status_code=502,
                            detail="TargetLab request refused or failed; no evidence was stored") from None
    finally:
        runner.close()
    if run.requests_sent == 0:
        raise HTTPException(status_code=502,
                            detail="TargetLab could not be reached; no evidence was stored")
    return _lab_bola_call(store.save, run)


@router.get("/api/lab-sci-scans/{run_id}", response_model=InteractionRun)
def lab_sci_scan(run_id: str, store: LabSciStore = Depends(get_lab_sci_store)):
    run = _lab_bola_call(store.get, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="TargetLab SCI run not found")
    return run


@router.get("/api/lab-sci-scans/{run_id}/report", response_model=LabSciSectionReport,
            responses={200: {"content": {"text/html": {"schema": {"type": "string"}}}}})
def lab_sci_report(run_id: str, format: str = "json", view: str = "run", reset: str = "",
                   store: LabSciStore = Depends(get_lab_sci_store),
                   resets: LabResetStore = Depends(get_lab_reset_store)):
    run = _lab_bola_call(store.get, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="TargetLab SCI run not found")
    if view not in {"run", "sections", "p0"}:
        raise HTTPException(status_code=400, detail="View must be run, sections or p0")
    if format not in {"json", "html"}:
        raise HTTPException(status_code=400, detail="Format must be json or html")
    proof = None
    if reset:
        proof = _lab_bola_call(resets.get, reset)
        if proof is None:
            raise HTTPException(status_code=404, detail="TargetLab reset proof not found")
        if proof["port"] != run["scope"]["port"]:
            raise HTTPException(status_code=400,
                                detail="The reset proof belongs to another TargetLab port")
    if view == "p0":
        if format == "html":
            return HTMLResponse(render_p0_report("lab_sci", run))
        return JSONResponse(content=build_p0_report("lab_sci", run).model_dump(mode="json"))
    if format == "html":
        return HTMLResponse(render_lab_sci_report(run, reset_proof=proof))
    if view == "sections":
        return LabSciSectionReport(mode="targetlab_sci", id=run_id, run_id=run_id,
                                   sections=build_lab_sci_sections(run, reset_proof=proof))
    return run


@router.post("/api/lab-sci-resets", status_code=201, response_model=LabResetProof)
def start_lab_sci_reset(payload: LabSciScanRequest,
                        store: LabResetStore = Depends(get_lab_reset_store)):
    """Prove the lab condition is set by a rejected login and cleared by a success."""
    ca_file = os.environ.get("CANARYGATE_TARGETLAB_CA")
    if not ca_file:
        raise HTTPException(status_code=400,
                            detail="TargetLab CA is not configured; set CANARYGATE_TARGETLAB_CA")
    runners = []
    try:
        plan, first = _open_targetlab_runner(payload.port, budget=payload.request_budget,
                                             ca_file=ca_file)
        runners.append(first)
        from canarygate.network.targetlab import TargetLabRunner
        second = TargetLabRunner(plan.scope, plan.credentials, ca_file=ca_file)
        runners.append(second)
        proof = run_lab_sci_reset(plan, first, second)
    except (TargetLabRefused, OSError):
        raise HTTPException(status_code=502,
                            detail="TargetLab request refused or failed; nothing was stored") from None
    finally:
        for runner in runners:
            runner.close()
    if proof.requests["total"] == 0:
        raise HTTPException(status_code=502,
                            detail="TargetLab could not be reached; nothing was stored")
    return _lab_bola_call(store.save, proof)


@router.get("/api/lab-sci-resets/{proof_id}", response_model=LabResetProof)
def lab_sci_reset(proof_id: str, store: LabResetStore = Depends(get_lab_reset_store)):
    proof = _lab_bola_call(store.get, proof_id)
    if proof is None:
        raise HTTPException(status_code=404, detail="TargetLab reset proof not found")
    return proof


@router.get("/api/authorization-matrix", response_model=AuthorizationMatrix)
def authorization_matrix(scenario_store: ScenarioStore = Depends(get_scenario_store),
                         auth_store: AuthenticationStore = Depends(get_auth_store),
                         validation_store: ValidationStore = Depends(get_validation_store),
                         interaction_store: InteractionStore = Depends(get_interaction_store),
                         lab_bola_store: LabBolaStore = Depends(get_lab_bola_store),
                         lab_sci_store: LabSciStore = Depends(get_lab_sci_store)):
    """Partial authorization coverage over stored offline runs; gaps stay visible."""
    try:
        scenarios = _scenario_call(scenario_store.list)
        authentications = _auth_call(auth_store.list)
        validations = _validation_call(validation_store.list)
        interactions = _interaction_call(interaction_store.list)
        lab_runs = _lab_bola_call(lab_bola_store.list)
        lab_sci_runs = _lab_bola_call(lab_sci_store.list)
    except HTTPException:
        raise
    try:
        return build_authorization_matrix(scenarios, authentications, validations, interactions,
                                          lab_runs, lab_sci_runs)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=500, detail="Authorization matrix could not be built") from None


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
    auth_store = AuthenticationStore(path)
    validation_store = ValidationStore(path)
    interaction_store = InteractionStore(path)
    lab_store = LabStore(path)
    lab_bola_store = LabBolaStore(path)
    lab_sci_store = LabSciStore(path)
    lab_reset_store = LabResetStore(path)

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        store.initialize()
        scenario_store.initialize()
        auth_store.initialize()
        validation_store.initialize()
        interaction_store.initialize()
        lab_store.initialize()
        lab_bola_store.initialize()
        lab_sci_store.initialize()
        lab_reset_store.initialize()
        yield

    # Default Swagger/ReDoc CDN assets are disabled to avoid external requests.
    application = FastAPI(title="CanaryGate offline fixture API", version="0.1.0",
                          docs_url=None, redoc_url=None, lifespan=lifespan)
    application.state.store = store
    application.state.scenario_store = scenario_store
    application.state.auth_store = auth_store
    application.state.validation_store = validation_store
    application.state.interaction_store = interaction_store
    application.state.lab_store = lab_store
    application.state.lab_bola_store = lab_bola_store
    application.state.lab_sci_store = lab_sci_store
    application.state.lab_reset_store = lab_reset_store
    application.include_router(router)
    return application


app = create_app()
