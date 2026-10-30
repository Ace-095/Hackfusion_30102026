"""Local-only, in-memory API. It does not accept or scan live targets."""
from html import escape
import json
from threading import Lock

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from canarygate.offline.scan import inventory, run_fixture
from .schemas import (Health, Inventory, SetupResponse, FixtureRun, FindingsResponse, MatrixResponse)

# FastAPI's default Swagger/ReDoc pages load CDN assets; disable them so the
# backend never instructs a browser to contact external systems.
app = FastAPI(title="CanaryGate offline fixture API", version="0.1.0", docs_url=None, redoc_url=None)
_runs: dict[str, dict] = {}
_lock = Lock()


@app.get("/api/health", response_model=Health)
def health():
    return {"status": "ok", "mode": "fixture", "live_scanning": False}


@app.post("/api/spec/upload", status_code=501)
def spec_upload():
    return {"detail": "Spec upload is not implemented; only the bundled fixture is available."}


@app.get("/api/endpoints", response_model=Inventory)
def endpoints():
    return {"mode": "fixture", "endpoints": inventory()}


@app.get("/api/setup/status", response_model=SetupResponse)
def setup_status():
    with _lock:
        latest = next(reversed(_runs.values()), None) if _runs else None
        return {"mode": "fixture", "setup": latest["setup"] if latest else None,
                "message": "Run the fixture scan to evaluate setup." if latest is None else "Latest fixture scan setup."}


@app.post("/api/scan", status_code=201, response_model=FixtureRun)
def start_scan():
    result = run_fixture()
    with _lock:
        _runs[result["id"]] = result
    return result


def _find(run_id: str):
    with _lock:
        run = _runs.get(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Fixture scan not found")
    return run


@app.get("/api/scan/{run_id}", response_model=FixtureRun)
def scan(run_id: str):
    return _find(run_id)


@app.get("/api/findings", response_model=FindingsResponse)
def findings():
    with _lock:
        return {"mode": "fixture", "findings": list(_runs.values())}


@app.get("/api/matrix", response_model=MatrixResponse)
def matrix():
    with _lock:
        cells = [{key: run[key] for key in ("id", "endpoint", "actor", "target_resource", "expected_access", "expected_source", "verdict")} for run in _runs.values()]
    return {"mode": "fixture", "cells": cells}


@app.get("/api/reports/{run_id}", response_model=FixtureRun, responses={200: {"content": {"text/html": {"schema": {"type": "string"}}}}})
def report(run_id: str, format: str = "json"):
    run = _find(run_id)
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
    html += "<h2>Endpoint inventory (OpenAPI authentication requirements only)</h2>" + block(inventory())
    html += "<h2>Three setup gates and BOLA coverage</h2>" + block(run["setup"])
    html += "<h2>Separate ownership and disclosure evidence</h2>"
    for kind, evidence in run["evidence"].items():
        html += "<h3>" + escape(kind.title()) + "</h3>" + block(evidence)
    html += "<p>Evidence bodies and credentials are minimized/redacted. Hashes cover the displayed redacted summaries, not raw traffic or signatures.</p>"
    html += "<h2>Secured endpoints that passed</h2>"
    html += field("Observed", run["endpoint"] + " — cross-user denial observed" if run["verdict"] == "SAFE" else "None in this fixture run")
    html += "<h2>Not yet executed</h2><p>Authentication weakness checks, input validation, disclosure checks, BFLA and live-target scans are not implemented in this checkpoint; none are reported as SAFE.</p>"
    html += "<h2>Fixture constraint checklist</h2>" + block(run["constraints"]) + field("Scope file SHA-256", run["scope_hash"])
    return HTMLResponse(html + "</body></html>")
