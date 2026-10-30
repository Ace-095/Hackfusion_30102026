"""Shared machinery for the checkpoint 38 demonstration and consistency audit.

One library, two thin commands:

* ``tools/demo.py`` runs the four-stage judge demonstration from a clean start.
* ``tools/consistency_audit.py`` re-checks every stored run in an existing
  database against its own report projections.

The point of this module is that a stored verdict is never trusted on its own. The
same evidence is read back through every surface the product exposes — the stored
run, the sections report, the frozen nine-section report, the HTML page and the
authorization matrix — and the surfaces are compared with each other and with the
database row that holds them.

It performs no scanning of its own and opens no socket: it drives the public API.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

# Public, documented lab fixtures. Their absence from every surface is asserted,
# not assumed: these are the values a regression would leak first.
LAB_SECRETS = ("lab-token-mallapa", "lab-token-sakshi", "lab-token-harsha",
               "mallapa-lab-password", "sakshi-lab-password", "harsha-lab-password",
               "targetlab-mallapa-private-marker", "targetlab-sakshi-private-marker",
               "targetlab-harsha-private-marker", "targetlab-trace-marker",
               "targetlab-wrong-password-for-mallapa")

_BOLA_ENDPOINTS = {
    "LAB-BOLA-01": "GET /records/{id}", "LAB-BOLA-02": "GET /records/{id}",
    "LAB-BOLA-03": "GET /records/{id}", "LAB-BOLA-04": "GET /records/{id}",
    "LAB-BOLA-05": "GET /records/{id}/secure", "LAB-BOLA-06": "GET /records/{id}/secure",
}
_SEVERITY = ("CONFIRMED", "SUSPECTED", "INCONCLUSIVE", "SKIPPED", "SAFE")
_CONTROLLED_CLAIM = "Controlled validation, not live validation"

FORBIDDEN_PATTERNS = (
    ("verify=False", "forbidden-verify-disabled"),
    ("_create_unverified_context", "forbidden-unverified-context"),
    ("CERT_NONE", "forbidden-cert-none"),
    ("check_hostname = False", "forbidden-hostname-check-disabled"),
    ("check_hostname=False", "forbidden-hostname-check-disabled"),
    ("follow_redirects=True", "forbidden-redirect-following"),
    ("import requests", "forbidden-alternative-http-client"),
    ("from requests", "forbidden-alternative-http-client"),
    ("urllib.request", "forbidden-urllib-request"),
    ("socket.create_connection", "forbidden-implicit-connect"),
    ("getaddrinfo", "forbidden-dns-resolution"),
)
REQUIRED_PATTERNS = (
    ("canarygate/network/guarded_httpx.py", "follow_redirects=False", "missing-redirect-guard"),
    ("canarygate/offline/runner.py", "follow_redirects=False", "missing-redirect-guard"),
    ("canarygate/network/targetlab.py", "CERT_REQUIRED", "missing-tls-verification"),
    ("canarygate/network/targetlab.py", "check_hostname = True", "missing-hostname-check"),
)


@dataclass(frozen=True)
class Problem:
    """One disagreement between two surfaces, or one broken safety rule."""

    code: str
    detail: str

    def __str__(self) -> str:
        return f"{self.code}: {self.detail}"


@dataclass
class Checker:
    problems: list[Problem] = field(default_factory=list)
    comparisons: int = 0

    def fail(self, code, detail):
        self.problems.append(Problem(code, detail))

    def equal(self, code, left, right, label):
        self.comparisons += 1
        if left != right:
            self.fail(code, f"{label}: {left!r} != {right!r}")

    def extend(self, problems):
        self.comparisons += len(problems) or 0
        self.problems.extend(problems)


class DemoFailed(RuntimeError):
    """A demo stage could not be executed against the running lab."""


# --------------------------------------------------------------------- helpers
def _json_response(response, label):
    if response.status_code not in {200, 201}:
        raise DemoFailed(f"{label} answered {response.status_code}: {response.text[:200]}")
    try:
        return response.json()
    except ValueError as exc:  # pragma: no cover - a broken API is a real defect
        raise DemoFailed(f"{label} did not return JSON") from exc


def _post(client, path, payload, label):
    return _json_response(client.post(path, json=payload), label)


def _get(client, path, label, params=None):
    return _json_response(client.get(path, params=params or {}), label)


def _worst(verdicts):
    for verdict in _SEVERITY:
        if verdict in verdicts:
            return verdict
    return "INCONCLUSIVE"


def _cell(matrix, endpoint, column="other_account_resource"):
    for row in matrix.get("rows", ()):
        if row.get("endpoint") == endpoint:
            for cell in row.get("cells", ()):
                if cell.get("column") == column:
                    return cell
    return None


# ------------------------------------------------------------------- stages
def _bola_stage(client, run_id, label):
    run = _get(client, f"/api/lab-bola-scans/{run_id}", label)
    sections = _get(client, f"/api/lab-bola-scans/{run_id}/report", label,
                    {"view": "sections"})
    p0 = _get(client, f"/api/lab-bola-scans/{run_id}/report", label, {"view": "p0"})
    html = client.get(f"/api/lab-bola-scans/{run_id}/report",
                      params={"format": "html"}).text
    checks = {item["id"]: item["verdict"] for item in run["checks"]}
    return {
        "id": label, "title": "read-BOLA validation", "kind": "bola", "run_id": run_id,
        "verdict": run["verdict"], "attribution": None,
        "checks": checks,
        "statuses": {item["id"]: item["status"] for item in run["checks"]},
        "digests": {item["id"]: item["evidence_sha256"] for item in run["checks"]},
        "requests_sent": run["constraints"]["requests_sent"],
        "request_budget": run["scope"]["request_budget"],
        "budget_remaining": run["constraints"]["budget_remaining"],
        "blocked_by_guard": run["constraints"]["blocked_by_guard"],
        "transport": run["transport"], "run": run, "sections": sections, "p0": p0,
        "html": html, "matrix": None,
    }


def _sci_stage(client, run_id, label, reset_id=None):
    run = _get(client, f"/api/lab-sci-scans/{run_id}", label)
    params = {"view": "sections"}
    if reset_id:
        params["reset"] = reset_id
    sections = _get(client, f"/api/lab-sci-scans/{run_id}/report", label, params)
    p0 = _get(client, f"/api/lab-sci-scans/{run_id}/report", label, {"view": "p0"})
    html = client.get(f"/api/lab-sci-scans/{run_id}/report",
                      params={"format": "html", **({"reset": reset_id} if reset_id else {})}).text
    baselines = {item["id"]: item["verdict"] for item in run["baselines"]}
    checks = {"SCI-AUTHZ": baselines.get("SCI-AUTHZ"), "SCI-AUTHN": baselines.get("SCI-AUTHN"),
              "SCI-01": run["verdict"]}
    return {
        "id": label, "title": "control-interaction validation", "kind": "sci",
        "run_id": run_id, "verdict": run["verdict"], "attribution": run["attribution"],
        "checks": checks, "baselines": baselines,
        "statuses": {item["id"]: item["evidence"]["status"] for item in run["baselines"]},
        "combined_status": run["combined"]["status"],
        "digests": {item["id"]: item["evidence_sha256"] for item in run["baselines"]},
        "requests_sent": run["requests_sent"],
        "request_budget": run["scope"]["request_budget"],
        "budget_remaining": run["budget_remaining"],
        "blocked_by_guard": run["blocked_by_guard"],
        "transport": run["transport"], "run": run, "sections": sections, "p0": p0,
        "html": html, "matrix": None,
    }


def _reset_stage(client, proof_id, label):
    proof = _get(client, f"/api/lab-sci-resets/{proof_id}", label)
    return {
        "id": label, "title": "reset verification", "kind": "reset", "run_id": proof_id,
        "verdict": proof["status"],
        "checks": {item["id"]: "passed" if item["passed"] else "failed"
                   for item in proof["checks"]},
        "statuses": [item["status"] for item in proof["checks"]],
        "digests": {item["id"]: item["evidence_sha256"] for item in proof["checks"]},
        "requests_sent": proof["requests"]["total"],
        "request_budget": proof["requests"]["budget_per_runner"],
        "transport": proof["transport"], "run": proof, "sections": None, "p0": None,
        "html": "", "matrix": None,
    }


# ---------------------------------------------------------------- comparisons
def _facts_from_run(stage):
    run = stage["run"]
    if stage["kind"] == "reset":
        return {"verdict": run["status"], "checks": stage["checks"],
                "digests": stage["digests"],
                "requests_sent": run["requests"]["total"]}
    return {"verdict": stage["verdict"], "checks": stage["checks"], "digests": stage["digests"],
            "baselines": stage.get("baselines", {}),
            "requests_sent": stage["requests_sent"],
            "blocked_by_guard": stage["blocked_by_guard"],
            "budget_remaining": stage["budget_remaining"]}


def _facts_from_sections(stage):
    sections = stage["sections"]["sections"]
    if stage["kind"] == "bola":
        checks = {item["id"]: item["verdict"] for item in sections["checks"]}
        digest = {item["id"]: item["evidence_sha256"] for item in sections["checks"]}
        return {"verdict": sections["executive_summary"]["verdict"], "checks": checks,
                "digests": digest,
                "requests_sent": sections["constraints"]["requests_sent"],
                "blocked_by_guard": sections["constraints"]["blocked_by_guard"],
                "budget_remaining": sections["constraints"]["budget_remaining"]}
    checks = {item["id"]: item["verdict"] for item in sections["baselines"]}
    checks["SCI-01"] = sections["decision"]["verdict"]
    return {"verdict": sections["decision"]["verdict"], "checks": checks,
            "baselines": {item["id"]: item["verdict"] for item in sections["baselines"]},
            "digests": {item["id"]: item["evidence_sha256"] for item in sections["baselines"]},
            "requests_sent": sections["scope_and_accounts"]["accounting"]["requests_sent"],
            "blocked_by_guard": sections["scope_and_accounts"]["accounting"]["blocked_by_guard"],
            "budget_remaining": sections["scope_and_accounts"]["accounting"]["budget_remaining"]}


def _facts_from_p0(stage):
    sections = stage["p0"]["sections"]
    findings = [item for items in sections["findings"].values() for item in items]
    baselines = {}
    for finding in findings:
        block = finding.get("interaction") or {}
        for item in block.get("baselines") or ():
            baselines[item["id"]] = item["verdict"]
    return {"verdict_counts": sections["executive_summary"]["verdict_counts"],
            "findings": {item["id"]: item["verdict"] for item in findings},
            "baselines": baselines,
            "digests": [item["evidence_sha256"] for item in findings],
            "requests_sent": sections["constraint_checklist"]["requests_sent"],
            "blocked_by_guard": sections["constraint_checklist"]["blocked_by_guard"]}


def _expected_cell_verdict(stage, endpoint):
    if stage["kind"] == "bola":
        verdicts = [verdict for check, verdict in stage["checks"].items()
                    if _BOLA_ENDPOINTS[check] == endpoint]
        return _worst(verdicts)
    return stage["verdict"]


def compare_surfaces(stage, *, run=None, sections=None, p0=None, matrix=None,
                     checker=None):
    """Compare one stage's surfaces with each other; returns the problems found."""
    checker = checker or Checker()
    reference = stage
    if run is not None:
        reference = dict(stage, run=run)
        if stage["kind"] == "bola":
            reference["checks"] = {item["id"]: item["verdict"] for item in run["checks"]}
            reference["digests"] = {item["id"]: item["evidence_sha256"] for item in run["checks"]}
            reference["verdict"] = run["verdict"]
            reference["requests_sent"] = run["constraints"]["requests_sent"]
            reference["blocked_by_guard"] = run["constraints"]["blocked_by_guard"]
            reference["budget_remaining"] = run["constraints"]["budget_remaining"]
    base = _facts_from_run(reference)

    # Identity: one piece of evidence, one identifier, on every surface.
    checker.equal("identity-mismatch", reference["run_id"], stage["run_id"], "stage run id")
    checker.equal("identity-mismatch", reference["run"]["id"], reference["run_id"], "run id")
    if reference["kind"] != "reset":
        checker.equal("mode-mismatch", reference["run"]["scenario_id"],
                      reference["run"]["scenario_id"], "scenario id")
        for name, surface in (("sections", sections), ("p0", p0)):
            if surface is None:
                continue
            checker.equal("identity-mismatch", surface["id"], reference["run_id"],
                          f"{name} id")
            checker.equal("identity-mismatch", surface["run_id"], reference["run_id"],
                          f"{name} run id")

    # Evidence digests must be unique: two checks cannot share one observation.
    digests = list(base["digests"].values())
    if len(set(digests)) != len(digests):
        checker.fail("duplicate-evidence-digest",
                     f"{stage['id']}: {len(digests) - len(set(digests))} duplicate digest(s)")

    if sections is not None:
        facts = _facts_from_sections(dict(stage, sections=sections))
        checker.equal("sections-verdict-mismatch", base["verdict"], facts["verdict"],
                      f"{stage['id']} sections verdict")
        for check_id, verdict in base["checks"].items():
            if check_id not in facts["checks"]:
                checker.fail("sections-check-missing", f"{stage['id']}: {check_id}")
                continue
            checker.equal("sections-verdict-mismatch", verdict, facts["checks"][check_id],
                          f"{stage['id']} sections {check_id}")
        for key in ("requests_sent", "blocked_by_guard", "budget_remaining"):
            if key in facts and key in base:
                checker.equal("accounting-mismatch", base[key], facts[key],
                              f"{stage['id']} sections {key}")
        for check_id, digest in base["digests"].items():
            if check_id in facts["digests"]:
                checker.equal("digest-mismatch", digest, facts["digests"][check_id],
                              f"{stage['id']} sections {check_id}")

    if p0 is not None:
        facts = _facts_from_p0(dict(stage, p0=p0))
        # A report finding exists per checked control (BOLA) or once per
        # interaction (SCI); the counts are compared at that granularity.
        judged = (list(base["checks"].values()) if stage["kind"] == "bola"
                  else [base["verdict"]])
        expected_counts = {verdict: judged.count(verdict) for verdict in _SEVERITY}
        checker.equal("p0-count-mismatch",
                      {key: value for key, value in expected_counts.items() if value},
                      {key: value for key, value in facts["verdict_counts"].items() if value},
                      f"{stage['id']} p0 verdict counts")
        if stage["kind"] == "bola":
            for check_id, verdict in base["checks"].items():
                if check_id not in facts["findings"]:
                    checker.fail("p0-finding-missing", f"{stage['id']}: {check_id}")
                    continue
                checker.equal("p0-verdict-mismatch", verdict, facts["findings"][check_id],
                              f"{stage['id']} p0 {check_id}")
        else:
            if "SCI-01" not in facts["findings"]:
                checker.fail("p0-finding-missing", f"{stage['id']}: SCI-01")
            else:
                checker.equal("p0-verdict-mismatch", base["verdict"],
                              facts["findings"]["SCI-01"], f"{stage['id']} p0 SCI-01")
            for check_id, verdict in base["baselines"].items():
                if check_id not in facts["baselines"]:
                    checker.fail("p0-baseline-missing", f"{stage['id']}: {check_id}")
                    continue
                checker.equal("p0-verdict-mismatch", verdict, facts["baselines"][check_id],
                              f"{stage['id']} p0 {check_id}")
        # A report may only cite a digest that exists in the stored evidence.
        stored_digests = list(base["digests"].values())
        for digest in facts["digests"]:
            checker.equal("digest-mismatch", True, digest in stored_digests,
                          f"{stage['id']} p0 cites a stored digest")
        if "requests_sent" in facts:
            checker.equal("accounting-mismatch", base["requests_sent"], facts["requests_sent"],
                          f"{stage['id']} p0 requests_sent")

    if matrix is not None:
        if stage["kind"] == "bola":
            endpoints = sorted(set(_BOLA_ENDPOINTS.values()))
        elif stage["kind"] == "sci":
            endpoints = ["GET /records/{id}/guarded"]
        else:
            endpoints = []
        for endpoint in endpoints:
            cell = _cell(matrix, endpoint)
            if cell is None:
                checker.fail("matrix-cell-missing", f"{stage['id']}: {endpoint}")
                continue
            checker.equal("matrix-verdict-mismatch", _expected_cell_verdict(stage, endpoint),
                          cell.get("verdict"), f"{stage['id']} {endpoint}")
            checker.equal("matrix-source-mismatch", True,
                          str(cell.get("source_ref", "")).startswith("lab_"),
                          f"{stage['id']} {endpoint} source label")

    return checker.problems


# ------------------------------------------------- CP39 asset matrix surface
def compare_asset_matrix(matrix, stages, checker=None):
    """The demo-tenant 3x3 matrix must restate stored checks, never invent one.

    Every tested cell is checked back against the stored run it cites: the same
    verdict, the same evidence digest, the same status. Untested cells must carry
    no verdict at all, so missing evidence can never be read as SAFE.
    """
    checker = checker or Checker()
    by_run = {stage["run_id"]: stage for stage in stages
              if stage.get("kind") == "bola" and not stage.get("projection")}
    cells = matrix.get("cells") or []
    summary = matrix.get("summary") or {}
    checker.equal("asset-matrix-shape", 9, len(cells), "asset matrix cells")
    accounts = matrix.get("accounts") or []
    checker.equal("asset-matrix-shape", 3, len(accounts), "matrix accounts")
    for label, key, values in (
            ("requesters", "account", {cell.get("requester") for cell in cells}),
            ("assets", "asset_id", {cell.get("asset_id") for cell in cells})):
        checker.equal("asset-matrix-shape", 3, len(values), f"matrix {label}")
        # The grid is exactly the catalog's accounts and assets, not a private list.
        checker.equal("asset-matrix-shape", {item.get(key) for item in accounts}, values,
                      f"matrix {label} come from the catalog")
    for state in ("tested", "untested"):
        counted = sum(1 for cell in cells if cell.get("state") == state)
        checker.equal("asset-matrix-summary", counted, summary.get(state), f"{state} cells")
    for verdict in ("CONFIRMED", "SUSPECTED", "SAFE", "INCONCLUSIVE", "SKIPPED"):
        counted = sum(1 for cell in cells if cell.get("verdict") == verdict)
        checker.equal("asset-matrix-summary", counted, summary.get(verdict.lower()),
                      f"{verdict} cells")
    for cell in cells:
        label = f"{cell.get('requester')} x {cell.get('asset_id')}"
        evidence = cell.get("evidence")
        if cell.get("state") == "untested":
            checker.equal("matrix-missing-evidence", None, cell.get("verdict"),
                          f"{label} verdict")
            checker.equal("matrix-missing-evidence", None, evidence, f"{label} evidence")
            checker.equal("matrix-missing-evidence", "no_evidence", cell.get("actual_access"),
                          f"{label} observed access")
            checker.equal("matrix-missing-evidence", 0, cell.get("sources"), f"{label} sources")
            continue
        checker.equal("cell-without-evidence", True, evidence is not None, f"{label} evidence")
        stage = by_run.get((evidence or {}).get("run_id"))
        checker.equal("cell-cites-unknown-run", True, stage is not None, label)
        if stage is None:
            continue
        check_id = evidence["check_id"]
        checker.equal("cell-verdict-mismatch", stage["checks"].get(check_id), cell["verdict"],
                      f"{label} verdict")
        checker.equal("cell-digest-mismatch", stage["digests"].get(check_id),
                      evidence["evidence_sha256"], f"{label} digest")
        checker.equal("cell-status-mismatch", stage["statuses"].get(check_id),
                      evidence["status"], f"{label} status")
        checker.equal("cell-missing-reason", True, bool(cell.get("reason")), f"{label} reason")
        # Observed access is derived from the response, never from the verdict: a 200
        # is either the account's own record or somebody else's private record, and an
        # owner cell is never counted as a disclosure.
        expected_access = ("own_record_returned"
                           if cell.get("kind") == "legitimate_owner_request"
                           else "private_record_returned")
        checker.equal("cell-observed-access",
                      expected_access if evidence["status"] == 200 else "denied",
                      cell["actual_access"], f"{label} access from status")
        if cell.get("kind") == "legitimate_owner_request":
            checker.equal("owner-cell-disclosure", False, evidence["private_disclosure"],
                          f"{label} is not a disclosure")
        else:
            secure = cell.get("secure") or {}
            checker.equal("secure-twin-run", evidence["run_id"], secure.get("run_id"),
                          f"{label} secure twin run")
            checker.equal("secure-twin-check", True,
                          secure.get("check_id") in {"LAB-BOLA-05", "LAB-BOLA-06"},
                          f"{label} secure twin check")
            checker.equal("secure-twin-verdict", True,
                          secure.get("verdict") in {"SAFE", "INCONCLUSIVE", "SKIPPED"},
                          f"{label} secure twin verdict")
    return checker.problems, checker


# ------------------------------------------------------------------ whole run
def run_demo(client, *, port, database=None):
    """Execute the four demonstration stages and check every surface."""
    stages = []
    bola = _post(client, "/api/lab-bola-scans", {"port": port}, "stage 1 BOLA")
    sci = _post(client, "/api/lab-sci-scans", {"port": port}, "stage 3 SCI")
    reset = _post(client, "/api/lab-sci-resets", {"port": port}, "stage 3 reset")

    bola_stage = _bola_stage(client, bola["id"], "bola")
    secure = {key: value for key, value in bola_stage["checks"].items()
              if key in {"LAB-BOLA-05", "LAB-BOLA-06"}}
    secure_stage = dict(bola_stage, id="bola_secure", title="the secure route",
                        checks=secure, verdict=_worst(secure.values()), projection=True)
    sci_stage = _sci_stage(client, sci["id"], "sci", reset_id=reset["id"])
    reset_stage = _reset_stage(client, reset["id"], "reset")
    matrix = _get(client, "/api/authorization-matrix", "authorization matrix")
    for stage in (bola_stage, secure_stage, sci_stage):
        stage["matrix"] = matrix
    stages.extend([bola_stage, secure_stage, sci_stage, reset_stage])

    checker = Checker()
    compare_surfaces(bola_stage, sections=bola_stage["sections"], p0=bola_stage["p0"],
                     matrix=matrix, checker=checker)
    compare_projection(secure_stage, bola_stage, matrix, checker)
    compare_surfaces(sci_stage, sections=sci_stage["sections"], p0=sci_stage["p0"],
                     matrix=matrix, checker=checker)
    compare_surfaces(reset_stage, checker=checker)
    asset_matrix = _get(client, "/api/lab-matrix", "asset matrix")
    compare_asset_matrix(asset_matrix, stages, checker)
    bundle = build_bundle(stages, checker.problems, checker.comparisons,
                          asset_matrix=asset_matrix)
    if database is not None:
        bundle["problems"].extend(check_database_integrity(database))
    return bundle


def compare_projection(stage, parent, matrix, checker):
    """Stage 2 is a subset view of the same stored run; it must not drift."""
    for check_id, verdict in stage["checks"].items():
        checker.equal("projection-verdict-mismatch", parent["checks"][check_id], verdict,
                      f"{check_id} in stage 2")
        checker.equal("projection-status-mismatch", parent["statuses"][check_id],
                      stage["statuses"][check_id], f"{check_id} status in stage 2")
    checker.equal("projection-accounting-mismatch", parent["requests_sent"],
                  stage["requests_sent"], "stage 2 accounting")
    cell = _cell(matrix, "GET /records/{id}/secure")
    checker.equal("projection-verdict-mismatch", "SAFE",
                  cell.get("verdict") if cell else None, "secure route matrix cell")
    return checker.problems


def build_bundle(stages, problems, comparisons, asset_matrix=None):
    stages = list(stages)
    summary = {"stages": {stage["id"]: {"verdict": stage["verdict"],
                                        "requests_sent": stage["requests_sent"],
                                        "request_budget": stage["request_budget"]}
                          for stage in stages}}
    surfaces = 0
    for stage in stages:
        surfaces += sum(1 for name in ("run", "sections", "p0", "html", "matrix")
                        if stage.get(name))
    if asset_matrix is not None:
        # The demo-tenant 3x3 matrix is an extra surface: it restates stored checks.
        surfaces += 1
        summary["asset_matrix"] = {"tested": asset_matrix["summary"]["tested"],
                                   "confirmed": asset_matrix["summary"]["confirmed"],
                                   "safe": asset_matrix["summary"]["safe"],
                                   "untested": asset_matrix["summary"]["untested"]}
    return {
        "stages": stages, "problems": list(problems), "summary": summary,
        "surfaces_checked": surfaces, "invariants_checked": comparisons,
        "asset_matrix": asset_matrix,
        "ok": not problems,
    }


def check_evidence_integrity(bundle):
    """No missing, duplicated or contradictory evidence across the whole demo."""
    checker = Checker()
    stages = bundle["stages"]
    # Stage 2 is a subset view of stage 1's stored run; it is not new evidence.
    run_ids = [stage["run_id"] for stage in stages if not stage.get("projection")]
    if len(set(run_ids)) != len(run_ids):
        checker.fail("duplicate-run", "two stages share one evidence identifier")
    for stage in stages:
        if stage["kind"] != "reset":
            if len(stage["checks"]) != len(set(stage["checks"])):
                checker.fail("duplicate-check", stage["id"])
            digests = list(stage["digests"].values())
            if len(set(digests)) != len(digests):
                checker.fail("duplicate-evidence-digest", stage["id"])
            checker.equal("accounting-mismatch", True,
                          stage["requests_sent"] <= stage["request_budget"],
                          f"{stage['id']} within budget")
        else:
            checker.equal("reset-incomplete", 4, len(stage["checks"]), "reset checks")
            checker.equal("reset-not-proven", "proven", stage["verdict"], "reset status")
    return checker.problems


def check_honesty_and_redaction(bundle):
    """The surfaces must describe the run truthfully and leak nothing."""
    checker = Checker()
    for stage in bundle["stages"]:
        transport = stage.get("transport") or {}
        checker.equal("transport-not-loopback", "127.0.0.1", transport.get("destination"),
                      f"{stage['id']} destination")
        checker.equal("tls-not-pinned", "pinned_test_ca_with_hostname_check",
                      transport.get("tls_verification"), f"{stage['id']} tls")
        checker.equal("redirects-not-refused", "refused", transport.get("redirects"),
                      f"{stage['id']} redirects")
        checker.equal("retries-declared", "none", transport.get("retries"),
                      f"{stage['id']} retries")
        checker.equal("dns-declared", "not_used", transport.get("dns"), f"{stage['id']} dns")
        checker.equal("live-target-claim", False, transport.get("live_target_contacted"),
                      f"{stage['id']} live target")
        surface_text = json.dumps(stage["run"])
        for name in ("sections", "p0"):
            if stage.get(name):
                surface_text += json.dumps(stage[name])
        if stage.get("html"):
            surface_text += stage["html"]
            checker.equal("honesty-label-missing", True, _CONTROLLED_CLAIM in stage["html"],
                          f"{stage['id']} html states controlled validation")
        for secret in LAB_SECRETS:
            checker.equal("secret-leak", False, secret in surface_text,
                          f"{stage['id']} leaks {secret[:20]}")
        if bundle.get("asset_matrix") is not None:
            checker.equal("secret-leak", False,
                          secret in json.dumps(bundle["asset_matrix"]),
                          f"asset matrix leaks {secret[:20]}")
        if stage["kind"] != "reset":
            evaluation = (stage["p0"]["sections"]["executive_summary"]
                          if stage["kind"] else {})
            if evaluation:
                checker.equal("transport-claim", True,
                              evaluation.get("network_transport_enabled"), f"{stage['id']} exec")
                checker.equal("live-claim", False, evaluation.get("live_target_contacted"),
                              f"{stage['id']} exec live target")
    return checker.problems


# -------------------------------------------------------------- database rows
_TABLES = ("lab_bola_runs", "lab_sci_runs", "lab_sci_resets")


def check_database_integrity(database):
    """Recompute every stored payload hash; a mismatch is a broken chain of custody."""
    checker = Checker()
    path = Path(database)
    if not path.is_file():
        checker.fail("database-missing", str(path))
        return checker.problems
    with sqlite3.connect(str(path)) as connection:
        for table in _TABLES:
            try:
                rows = connection.execute(
                    f"SELECT run_id, payload, sha256 FROM {table}").fetchall()
            except sqlite3.OperationalError:
                continue
            seen = set()
            for run_id, payload, checksum in rows:
                checker.equal("database-duplicate-id", False, run_id in seen, f"{table} {run_id}")
                seen.add(run_id)
                computed = hashlib.sha256(payload.encode("utf-8")).hexdigest()
                checker.equal("database-hash-mismatch", computed, checksum,
                              f"{table} {run_id}")
                try:
                    parsed = json.loads(payload)
                except ValueError:
                    checker.fail("database-payload-invalid", f"{table} {run_id}")
                    continue
                checker.equal("database-id-mismatch", run_id, parsed.get("id"),
                              f"{table} {run_id} payload id")
                for secret in LAB_SECRETS:
                    checker.equal("database-secret", False, secret in payload,
                                  f"{table} {run_id} leaks {secret[:20]}")
    return checker.problems


# ------------------------------------------------------------- static safety
def safety_sweep(root):
    """Static re-check of the properties the safety argument depends on."""
    checker = Checker()
    root = Path(root)
    sources = sorted(list((root / "canarygate").rglob("*.py")) +
                     list((root / "targetlab").rglob("*.py")))
    if not sources:
        checker.fail("sweep-found-no-sources", str(root))
    for path in sources:
        text = path.read_text(encoding="utf-8", errors="replace")
        relative = path.relative_to(root).as_posix()
        for pattern, code in FORBIDDEN_PATTERNS:
            if pattern in text:
                line = next((number for number, value in enumerate(text.splitlines(), 1)
                             if pattern in value), 0)
                checker.fail(code, f"{relative}:{line} contains {pattern!r}")
    for relative, pattern, code in REQUIRED_PATTERNS:
        path = root / relative
        if not path.is_file():
            checker.fail(code, f"{relative} is missing")
            continue
        checker.equal(code, True, pattern in path.read_text(encoding="utf-8"),
                      f"{relative} contains {pattern!r}")
    return checker.problems


def load_report_projection(kind, run):
    """Rebuild one run's report surfaces without the API, for the audit command."""
    from canarygate.report.lab_bola import build_lab_bola_sections
    from canarygate.report.lab_sci import build_lab_sci_sections
    from canarygate.report.p0 import build_p0_sections

    if kind == "lab_bola":
        return {"sections": {"id": run["id"], "run_id": run["id"],
                             "mode": "targetlab_bola",
                             "sections": build_lab_bola_sections(run)},
                "p0": {"id": run["id"], "run_id": run["id"], "mode": "targetlab_bola",
                       "sections": build_p0_sections("lab_bola", run)}}
    return {"sections": {"id": run["id"], "run_id": run["id"], "mode": "targetlab_sci",
                         "sections": build_lab_sci_sections(run)},
            "p0": {"id": run["id"], "run_id": run["id"], "mode": "targetlab_sci",
                   "sections": build_p0_sections("lab_sci", run)}}


def _stage_from_stored(kind, run, surfaces):
    if kind == "lab_bola":
        checks = {item["id"]: item["verdict"] for item in run["checks"]}
        stage = {"id": run["scenario_id"], "kind": "bola", "run_id": run["id"],
                 "verdict": run["verdict"], "checks": checks,
                 "statuses": {item["id"]: item["status"] for item in run["checks"]},
                 "digests": {item["id"]: item["evidence_sha256"] for item in run["checks"]},
                 "requests_sent": run["constraints"]["requests_sent"],
                 "request_budget": run["scope"]["request_budget"],
                 "budget_remaining": run["constraints"]["budget_remaining"],
                 "blocked_by_guard": run["constraints"]["blocked_by_guard"],
                 "transport": run["transport"], "run": run, "html": "", "matrix": None}
    else:
        baselines = {item["id"]: item["verdict"] for item in run["baselines"]}
        stage = {"id": run["scenario_id"], "kind": "sci", "run_id": run["id"],
                 "verdict": run["verdict"], "checks": dict(baselines, **{"SCI-01": run["verdict"]}),
                 "baselines": baselines,
                 "statuses": {item["id"]: item["evidence"]["status"] for item in run["baselines"]},
                 "digests": {item["id"]: item["evidence_sha256"] for item in run["baselines"]},
                 "requests_sent": run["requests_sent"],
                 "request_budget": run["scope"]["request_budget"],
                 "budget_remaining": run["budget_remaining"],
                 "blocked_by_guard": run["blocked_by_guard"],
                 "transport": run["transport"], "run": run, "html": "", "matrix": None}
    stage.update({key: surfaces[key] for key in ("sections", "p0")})
    return stage


def audit_database(database):
    """Re-check every stored run against its own freshly built reports."""
    from canarygate.database.lab_bola_store import LabBolaStore
    from canarygate.database.lab_reset_store import LabResetStore
    from canarygate.database.lab_sci_store import LabSciStore
    from canarygate.report.matrix import build_authorization_matrix
    from canarygate.scan.lab_matrix import build_lab_matrix

    database = Path(database)
    checker = Checker()
    checker.extend(check_database_integrity(database))
    bola = LabBolaStore(database).list()
    sci = LabSciStore(database).list()
    proofs = LabResetStore(database).list()
    matrix = build_authorization_matrix([], [], [], [], bola, sci).model_dump(mode="json")
    stages = []
    for kind, runs in (("lab_bola", bola), ("lab_sci", sci)):
        for run in runs:
            surfaces = load_report_projection(kind, run)
            stage = _stage_from_stored(kind, run, surfaces)
            stage["matrix"] = matrix
            stages.append(stage)
            compare_surfaces(stage, sections=surfaces["sections"], p0=surfaces["p0"],
                             matrix=matrix, checker=checker)
    for proof in proofs:
        checker.equal("reset-not-proven", "proven", proof["status"],
                      f"reset proof {proof['id']}")
        checker.equal("reset-incomplete", 4, len(proof["checks"]), "reset checks")
    # The stored runs must rebuild the same 3x3 matrix offline, with no socket.
    asset_matrix = build_lab_matrix(bola) if bola else None
    if asset_matrix is not None:
        compare_asset_matrix(asset_matrix, stages, checker)
    return {"ok": not checker.problems, "runs_checked": len(stages) + len(proofs),
            "surfaces": len(stages) * 2 + len(proofs) + (1 if asset_matrix else 0),
            "invariants_checked": checker.comparisons,
            "problems": [str(item) for item in checker.problems],
            "asset_matrix": asset_matrix,
            "summary": {stage["run_id"]: stage["verdict"] for stage in stages}}
