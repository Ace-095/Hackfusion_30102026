"""Aggregate stored TargetLab read-BOLA runs into the judge-facing 3x3 matrix.

Nothing here decides a verdict, opens a socket or reads the lab's ground truth.
Each cell is a projection of one stored check:

* a legitimate cell (requester == owner) comes from an ``owner_baseline`` check;
* a cross-account cell comes from a ``cross_account`` check;
* the secure-route counterpart comes from the ``cross_account_secure`` check of
  the same run, and only when that check exists.

When several stored runs answer the same cell, the newest one is used and the
others are listed as superseded. A cell with no stored check stays ``untested``
with no verdict — never SAFE.
"""
from __future__ import annotations

from datetime import datetime, timezone

from canarygate.scan.lab_matrix_models import (LabMatrix, LabMatrixAccount, LabMatrixCell,
                                               LabMatrixEvidence, LabMatrixSecure,
                                               LabMatrixSummary, actual_access_for)
from canarygate.scan.lab_scenarios import (ACCOUNT_ROLES, ACCOUNT_TITLES, ASSET_IDS,
                                           ASSET_LABELS, ASSET_TYPES, KNOWN_ACCOUNTS,
                                           asset_owner_map)

MATRIX_NOTES = (
    "Every tested cell names the stored run, check and evidence hash it came from; "
    "nothing on this matrix is inferred, simulated or typed in by hand.",
    "An untested cell has no verdict at all. It is not SAFE, SKIPPED or INCONCLUSIVE, "
    "because no check produced it.",
    "When several stored runs answer one cell, the newest run is displayed and the older "
    "ones are listed as superseded; the counts stay visible so duplication is never hidden.",
    "A cell marked stale comes from a run against a different loopback lab instance than "
    "the most recent run; the evidence is still linked and still labelled.",
    "Owner (diagonal) cells come from the owner-baseline check. A BOLA run records no "
    "secure-route owner read, so the secure counterpart is absent instead of assumed.",
    "The matrix is derived only from stored evidence. It makes no request and cannot "
    "change a stored run.",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _bounded_checklist(checklist):
    """Only the four booleans the matrix renders survive into a cell."""
    return {"private_disclosure": bool(checklist.get("private_disclosure")),
            "verified_denial": bool(checklist.get("verified_denial")),
            "ownership_verified": bool(checklist.get("ownership_verified")),
            "owner_baseline": bool(checklist.get("owner_baseline"))}


def _evidence(run, check):
    flags = _bounded_checklist(check.get("checklist") or {})
    evidence = check.get("evidence") or {}
    return LabMatrixEvidence(
        run_id=run["id"], check_id=check["id"], direction=check["direction"],
        verdict=check["verdict"], status=check.get("status"),
        endpoint=check["endpoint"], evidence_sha256=check["evidence_sha256"],
        created_at=run["created_at"], port=run["scope"]["port"],
        requests_sent=run["constraints"]["requests_sent"],
        checklist_true=sum(1 for value in flags.values() if value),
        checklist_total=4,
        **flags)


def _candidates(runs):
    """(requester, asset_id) -> ordered list of (sort_key, run, check) candidates."""
    found: dict[tuple[str, str], list[tuple]] = {}
    for index, run in enumerate(runs):
        if run.get("mode") != "targetlab_bola":
            continue
        scope = run.get("scope") or {}
        if not isinstance(scope.get("port"), int):
            continue
        for check in run.get("checks") or []:
            direction = check.get("direction")
            actor, owner = check.get("actor"), check.get("owner")
            if direction == "owner_baseline" and actor in ASSET_IDS:
                cell = (actor, ASSET_IDS[actor])
            elif direction == "cross_account" and owner in ASSET_IDS:
                cell = (actor, ASSET_IDS[owner])
            else:
                continue
            # Storage order (oldest first) breaks ties: two runs can share a timestamp,
            # and the newer insert is the newer evidence.
            key = (run["created_at"], index, run["id"])
            found.setdefault(cell, []).append((key, run, check))
    for items in found.values():
        items.sort(key=lambda item: item[0])
    return found


def _secure_counterpart(run, check):
    if check["direction"] != "cross_account":
        return None
    for other in run.get("checks") or []:
        if (other.get("direction") == "cross_account_secure"
                and other.get("actor") == check["actor"]
                and other.get("owner") == check["owner"]):
            return LabMatrixSecure(
                run_id=run["id"], check_id=other["id"], verdict=other["verdict"],
                status=other.get("status"), evidence_sha256=other["evidence_sha256"],
                verified_denial=bool((other.get("checklist") or {}).get("verified_denial")))
    return None


def _current_port(runs):
    """The port of the most recent stored run, using storage order to break ties."""
    newest = None
    for index, run in enumerate(runs):
        if isinstance(run.get("scope"), dict) and isinstance(run["scope"].get("port"), int):
            key = (run["created_at"], index)
            if newest is None or key > newest[0]:
                newest = (key, run)
    return None if newest is None else newest[1]["scope"]["port"]


def build_lab_matrix(runs, *, generated_at: str | None = None) -> dict:
    """Project stored runs into the nine-cell matrix (validated on the way out).

    ``runs`` must be in storage order (oldest first); ties on the second-precision
    timestamp are broken by that order, so every caller selects the same evidence.
    """
    runs = [run for run in (runs or []) if isinstance(run, dict)]
    current_port = _current_port(runs)
    found = _candidates(runs)
    owners = asset_owner_map()
    cells = []
    for requester in KNOWN_ACCOUNTS:
        for asset in ASSET_IDS.values():
            owner = owners[asset]
            kind = ("legitimate_owner_request" if requester == owner
                    else "cross_account_attempt")
            candidates = found.get((requester, asset), [])
            if not candidates:
                cells.append(LabMatrixCell(
                    requester=requester, asset_id=asset, owner=owner, kind=kind,
                    state="untested", expected_access="owner-only",
                    actual_access="no_evidence", stale=False, sources=0))
                continue
            _, run, check = candidates[-1]
            evidence = _evidence(run, check)
            cells.append(LabMatrixCell(
                requester=requester, asset_id=asset, owner=owner, kind=kind,
                state="tested", expected_access="owner-only",
                actual_access=actual_access_for(check["verdict"],
                                                _bounded_checklist(check.get("checklist") or {}),
                                                check["direction"]),
                verdict=check["verdict"], reason=check["reason"], evidence=evidence,
                secure=_secure_counterpart(run, check),
                stale=current_port is not None and evidence.port != current_port,
                sources=len(candidates),
                superseded_runs=sorted({item[1]["id"] for item in candidates[:-1]})[:32]))
    tested = [cell for cell in cells if cell.state == "tested"]
    summary = LabMatrixSummary(
        tested=len(tested), untested=len(cells) - len(tested),
        confirmed=sum(cell.verdict == "CONFIRMED" for cell in tested),
        suspected=sum(cell.verdict == "SUSPECTED" for cell in tested),
        safe=sum(cell.verdict == "SAFE" for cell in tested),
        inconclusive=sum(cell.verdict == "INCONCLUSIVE" for cell in tested),
        skipped=sum(cell.verdict == "SKIPPED" for cell in tested),
        runs_considered=len(runs),
        ports=sorted({run["scope"]["port"] for run in runs
                      if isinstance(run.get("scope"), dict)
                      and isinstance(run["scope"].get("port"), int)}),
        stale_cells=sum(cell.stale for cell in cells),
        duplicated_cells=sum(cell.sources > 1 for cell in cells))
    accounts = [LabMatrixAccount(account=account, title=ACCOUNT_TITLES[account],
                                 role=ACCOUNT_ROLES[account], asset_id=ASSET_IDS[account],
                                 asset_type=ASSET_TYPES[ASSET_IDS[account]],
                                 asset_label=ASSET_LABELS[ASSET_IDS[account]])
                for account in KNOWN_ACCOUNTS]
    return LabMatrix(
        mode="targetlab_matrix", dataset="demo_tenant",
        derived_from="stored_lab_bola_runs", generated_at=generated_at or _now(),
        accounts=accounts, cells=cells, summary=summary, notes=list(MATRIX_NOTES)
    ).model_dump(mode="json")
