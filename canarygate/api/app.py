"""Local-only API with fixture-only SQLite persistence; no live targets."""
from contextlib import asynccontextmanager
from html import escape
import json
from pathlib import Path
import sqlite3

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse

from canarygate.database.store import FixtureStore, default_database_path
from canarygate.evidence.redaction import EvidenceIntegrityError
from canarygate.offline.scan import inventory, run_fixture
from .schemas import (Health, Inventory, SetupResponse, FixtureRun, FindingsResponse, MatrixResponse)

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
    # The returned value is the redacted, integrity-checked version that was stored.
    return _database_call(store.save, run_fixture())


def _find(store: FixtureStore, run_id: str):
    run = _database_call(store.get, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Fixture scan not found")
    return run


@router.get("/api/scan/{run_id}", response_model=FixtureRun)
def scan(run_id: str, store: FixtureStore = Depends(get_store)):
    return _find(store, run_id)


@router.get("/api/findings", response_model=FindingsResponse)
def findings(store: FixtureStore = Depends(get_store)):
    return {"mode": "fixture", "findings": _database_call(store.list)}


@router.get("/api/matrix", response_model=MatrixResponse)
def matrix(store: FixtureStore = Depends(get_store)):
    runs = _database_call(store.list)
    cells = [{key: run[key] for key in ("id", "endpoint", "actor", "target_resource", "expected_access", "expected_source", "verdict")} for run in runs]
    return {"mode": "fixture", "cells": cells}


@router.get("/api/reports/{run_id}", response_model=FixtureRun, responses={200: {"content": {"text/html": {"schema": {"type": "string"}}}}})
def report(run_id: str, format: str = "json", store: FixtureStore = Depends(get_store)):
    run = _find(store, run_id)
    if format == "json":
        return run
    if format != "html":
        raise HTTPException(status_code=400, detail="Format must be json or html")
    # All untrusted values are escaped, including fixture data and JSON summaries.
    def field(label, value):
        return f"<p><strong>{escape(str(label))}:</strong> {escape(str(value))}</p>"

    def block(value):
        return "<pre>" + escape(json.dumps(value, indent=2, ensure_ascii=True)) + "</pre>"

    html = "<!doctype html><html><head><meta charset='utf-8'><title>Fixture report</title>"
    html += "<style>body{font:16px system-ui;max-width:960px;margin:2rem auto;padding:0 1rem;color:#18212d}pre{background:#f3f5f7;padding:1rem;white-space:pre-wrap}h1,h2{color:#18334f} .warning{background:#fff3c4;padding:1rem}</style></head><body>"
    html += "<h1>CanaryGate fixture report — not live testing</h1>"
    html += "<p class='warning'>Offline synthetic results only. This is a partial backend checkpoint, not a production scan.</p>"
    html += "<h2>Executive summary</h2>"
    for label, value in (("Scan ID", run["id"]), ("Timestamp", run["created_at"]),
                         ("Category", "Read-BOLA"), ("Verdict", run["verdict"]),
                         ("Reason", run["reason"]), ("Actor / role", f"{run['actor']} / {run['account_role']}"),
                         ("Target resource", run["target_resource"] or "Not established"),
                         ("Verified owner", run["verified_owner"] or "Not established"),
                         ("Expected access / source", f"{run['expected_access']} / {run['expected_source']}"),
                         ("Remediation", run["remediation"] or "No finding-specific remediation")):
        html += field(label, value)
    html += "<h2>Endpoint inventory (OpenAPI authentication requirements only)</h2>" + block(run["inventory"])
    html += "<h2>Three setup gates and BOLA coverage</h2>" + block(run["setup"])
    html += "<h2>Separate ownership and disclosure evidence</h2>"
    for kind, evidence in run["evidence"].items():
        html += "<h3>" + escape(kind.title()) + "</h3>" + block(evidence)
    html += "<p>Evidence bodies and credentials are minimized/redacted. Hashes cover the displayed redacted summaries, not raw traffic or signatures.</p>"
    for category in ("Authentication", "Input validation", "Disclosure"):
        html += "<h2>" + escape(category) + " checks</h2>" + block(
            [check for check in run["checks"] if check["category"] == category])
    html += "<h2>Secured endpoints that passed</h2>"
    secured = []
    if run["verdict"] == "SAFE":
        secured.append(run["endpoint"] + " — cross-user denial observed")
    secured.extend(check["id"] + " — " + check["reason"] for check in run["checks"]
                   if check["verdict"] == "SAFE" and check["category"] != "Disclosure")
    html += block(secured if secured else ["None observed in this fixture run"])
    html += "<h2>Not yet executed</h2><p>JWT tampering, remaining validation and disclosure checks, BFLA and live-target scans are not implemented in this checkpoint; none are reported as SAFE. Individual skipped checks are listed above.</p>"
    html += "<h2>Fixture constraint checklist</h2>" + block(run["constraints"]) + field("Scope file SHA-256", run["scope_hash"]) + field("Specification SHA-256", run["spec_hash"])
    return HTMLResponse(html + "</body></html>")


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
