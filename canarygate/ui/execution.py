"""Background assessment jobs that report genuine progress.

Why this module exists
----------------------
Every lab scan is synchronous: the JSON API runs it and returns the stored run.
A judge-facing loading screen therefore has nothing truthful to draw unless the
work is moved off the request thread *and* the transport tells us when a real
request has happened.

This module does exactly that, and nothing more:

* it runs the **same** engine the API runs — ``build_bola_plan`` / ``build_sci_plan``,
  ``TargetLabRunner``, ``run_lab_bola_scan`` / ``run_lab_sci_scan`` and the same
  stores — in a worker thread;
* it attaches the transport's read-only ``observer``, which is called *after* each
  exchange with the actor, method, path, status and measured duration;
* it appends the run to the same store, so the result page and ``/api/lab-matrix``
  read exactly the run a synchronous call would have produced.

Nothing here decides a verdict, opens a socket of its own, retries a request or
invents an event. Every event in the feed corresponds to a request that already
completed, or to a boundary the runner actually reached (plan built, run stored).
"""
from __future__ import annotations

import os
import threading
import time
import uuid
from datetime import datetime, timezone

from canarygate.network.targetlab import TargetLabRefused, TargetLabRunner
from canarygate.scan.lab_bola import run_lab_bola_scan
from canarygate.scan.lab_bola_models import LabBolaScanRequest
from canarygate.scan.lab_bola_scenarios import build_bola_plan
from canarygate.scan.lab_sci import run_lab_sci_scan
from canarygate.scan.lab_sci_models import LabSciScanRequest
from canarygate.scan.lab_scenarios import build_lab_catalog
from canarygate.scan.lab_sci_scenarios import build_sci_plan

#: How many finished jobs stay in memory before the oldest is dropped. A job is
#: only a progress transcript; the evidence lives in SQLite.
MAX_JOBS = 24

#: Path → stage label. A stage is a *group of real requests*, so the loading
#: screen can say which phase is happening without inventing progress.
_STAGE_BY_PATH = {
    "/login": "authentication",
    "/profile": "identity",
    "/records": "ownership",
    "/records/{id}": "authorization",
    "/records/{id}/secure": "secure comparison",
    "/records/{id}/guarded": "interaction",
}


def stage_for(path) -> str:
    """Map a concrete TargetLab path onto the stage it belongs to."""
    if not isinstance(path, str):
        return "request"
    if path in _STAGE_BY_PATH:
        return _STAGE_BY_PATH[path]
    if path.startswith("/records/"):
        suffix = path[len("/records/"):]
        if "/" in suffix:
            _, _, tail = suffix.partition("/")
            return _STAGE_BY_PATH.get(f"/records/{{id}}/{tail}", "authorization")
        return "authorization"
    return _STAGE_BY_PATH.get(path, "request")

_STAGE_ORDER = ("queued", "authentication", "identity", "ownership",
                "authorization", "secure comparison", "interaction", "stored")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class AssessmentJob:
    """One assessment running (or finished) in a worker thread."""

    def __init__(self, kind: str, port: int, steps: list[dict]):
        self.id = uuid.uuid4().hex
        self.kind = kind
        self.port = port
        self.steps = steps                     # the pairs/plan about to run
        self.status = "running"                # running | complete | failed
        self.error: str | None = None
        self.results: list[dict] = []          # {actor, owner, run_id, verdict}
        self.started_at = _now()
        self.finished_at: str | None = None
        self.total_requests = 0
        self._events: list[dict] = []
        self._lock = threading.Lock()
        self._t0 = time.monotonic()
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------- events
    def emit(self, kind: str, label: str, **fields) -> None:
        """Append one event. ``kind`` is ``stage``, ``request``, ``result`` or ``error``."""
        with self._lock:
            self._events.append({
                "seq": len(self._events),
                "at": _now(),
                "t_ms": int((time.monotonic() - self._t0) * 1000),
                "kind": kind,
                "label": label,
                **fields,
            })

    def observe(self, event: dict) -> None:
        """Transport callback: one request completed, so one event is real.

        The counter is incremented here, not copied from the runner, because a
        demonstration runs several runners one after another and the loading
        screen must report the whole assessment, not the last plan.
        """
        path = event.get("path")
        with self._lock:
            self.total_requests += 1
        self.emit("request", f'{event["method"]} {path}',
                  actor=event.get("actor"), method=event.get("method"), path=path,
                  status=event.get("status"), elapsed_ms=event.get("elapsed_ms"),
                  stage=stage_for(path))

    def snapshot(self, since: int = 0) -> dict:
        with self._lock:
            events = [dict(item) for item in self._events if item["seq"] >= since]
            return {
                "id": self.id,
                "kind": self.kind,
                "port": self.port,
                "status": self.status,
                "error": self.error,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "requests_sent": self.total_requests,
                "steps": self.steps,
                "results": list(self.results),
                "events": events,
                "next": (events[-1]["seq"] + 1) if events else since,
            }

    # ------------------------------------------------------------- running
    def start(self, target) -> None:
        def run():
            try:
                target(self)
            except Exception as exc:           # never let a thread die silently
                self.error = str(exc) or exc.__class__.__name__
                self.status = "failed"
                self.emit("error", "Assessment failed", detail=self.error)
            finally:
                self.finished_at = _now()
                if self.status == "running":
                    self.status = "failed" if self.error else "complete"
                self.emit("stage", "Assessment finished", stage="done",
                          status=self.status)

        self._thread = threading.Thread(target=run, name=f"assessment-{self.id[:8]}",
                                        daemon=True)
        self._thread.start()

    def join(self, timeout: float = 120.0) -> None:
        if self._thread is not None:
            self._thread.join(timeout=timeout)


class JobRegistry:
    """Small, bounded, in-memory registry of assessment jobs."""

    def __init__(self, limit: int = MAX_JOBS):
        self._jobs: dict[str, AssessmentJob] = {}
        self._order: list[str] = []
        self._lock = threading.Lock()
        self._limit = limit

    def add(self, job: AssessmentJob) -> AssessmentJob:
        with self._lock:
            self._jobs[job.id] = job
            self._order.append(job.id)
            while len(self._order) > self._limit:
                self._jobs.pop(self._order.pop(0), None)
        return job

    def get(self, job_id: str) -> AssessmentJob | None:
        with self._lock:
            return self._jobs.get(job_id)


# --------------------------------------------------------------------- runner
def _observer_for(job: AssessmentJob):
    return job.observe


def _ca_file() -> str | None:
    value = (os.environ.get("CANARYGATE_TARGETLAB_CA") or "").strip()
    return value or None


def _run_bola_pair(job: AssessmentJob, request: LabBolaScanRequest, store) -> dict:
    ca_file = _ca_file()
    if not ca_file:
        raise HTTPProblem(400, "TargetLab CA is not configured; set CANARYGATE_TARGETLAB_CA")
    try:
        plan = build_bola_plan(request.port, budget=request.request_budget,
                               actor=request.actor, owner=request.owner)
        runner = TargetLabRunner(plan.scope, plan.credentials, ca_file=ca_file,
                                 observer=_observer_for(job))
    except ValueError:
        raise HTTPProblem(400, "Invalid TargetLab BOLA configuration") from None
    try:
        run = run_lab_bola_scan(plan, runner)
    except (TargetLabRefused, OSError):
        raise HTTPProblem(502, "TargetLab request refused or failed; no evidence was stored") from None
    finally:
        runner.close()
    if all(check.status is None for check in run.checks):
        raise HTTPProblem(502, "TargetLab could not be reached; no evidence was stored")
    stored = store.save(run)
    return {"actor": plan.accounts[0], "owner": plan.accounts[1],
            "run_id": stored["id"], "verdict": stored["verdict"],
            "confirmed": stored["summary"]["confirmed"],
            "requests_sent": stored["constraints"]["requests_sent"]}


def _run_sci_pair(job: AssessmentJob, request: LabSciScanRequest, store) -> dict:
    ca_file = _ca_file()
    if not ca_file:
        raise HTTPProblem(400, "TargetLab CA is not configured; set CANARYGATE_TARGETLAB_CA")
    try:
        plan = build_sci_plan(request.port, budget=request.request_budget,
                              actor=request.actor, owner=request.owner)
        runner = TargetLabRunner(plan.scope, plan.credentials, ca_file=ca_file,
                                 observer=_observer_for(job))
    except ValueError:
        raise HTTPProblem(400, "Invalid TargetLab SCI configuration") from None
    try:
        run = run_lab_sci_scan(plan, runner)
    except (TargetLabRefused, OSError):
        raise HTTPProblem(502, "TargetLab request refused or failed; no evidence was stored") from None
    finally:
        runner.close()
    if run.requests_sent == 0:
        raise HTTPProblem(502, "TargetLab could not be reached; no evidence was stored")
    stored = store.save(run)
    return {"actor": plan.accounts[0], "owner": plan.accounts[1],
            "run_id": stored["id"], "verdict": stored["verdict"],
            "confirmed": stored.get("summary", {}).get("confirmed", 0),
            "requests_sent": run.requests_sent}


class HTTPProblem(Exception):
    """A failure that maps onto the backend's own status code and sentence."""

    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def start_assessment(job: AssessmentJob, *, kind: str, port: int,
                     store_bola, store_sci, actor: str | None = None,
                     owner: str | None = None) -> AssessmentJob:
    """Start the requested assessment. Returns the job immediately."""

    def work(job: AssessmentJob) -> None:
        job.emit("stage", "Assessment started", stage="queued", port=port)
        pairs = job.steps
        failures = 0
        for index, pair in enumerate(pairs, start=1):
            job.emit("stage", f"Pair {index} of {len(pairs)}: {pair['actor']} → {pair['owner']}",
                     stage="pair", pair=index, actor=pair["actor"], owner=pair["owner"])
            try:
                if kind == "sci":
                    result = _run_sci_pair(job, LabSciScanRequest(port=port,
                                                                  actor=pair["actor"],
                                                                  owner=pair["owner"]), store_sci)
                else:
                    result = _run_bola_pair(job, LabBolaScanRequest(port=port,
                                                                    actor=pair["actor"],
                                                                    owner=pair["owner"]), store_bola)
            except HTTPProblem as exc:
                failures += 1
                job.emit("error", f"Pair {index} refused", stage="failed",
                         detail=exc.detail, status_code=exc.status_code,
                         actor=pair["actor"], owner=pair["owner"])
                continue
            job.results.append(result)
            job.emit("result", f"{pair['actor']} → {pair['owner']} stored",
                     stage="stored", **result)
        if failures and not job.results:
            job.error = "No pair completed; nothing was stored."
            job.status = "failed"
        else:
            job.status = "complete"

    job.start(work)
    return job


def coverage_steps() -> list[dict]:
    """The catalog's ordered coverage pairs, as the loader will run them."""
    return [{"actor": pair["actor"], "owner": pair["owner"]}
            for pair in build_lab_catalog()["coverage_pairs"]]
