"""Assemble the TargetLab three-by-three asset matrix from stored runs only.

Nothing here scans anything. The input is the list of already-stored read-BOLA
runs; the output is a projection of their checks onto the nine account x asset
combinations. That is a deliberate design choice: a judge-facing matrix must not
be able to disagree with the evidence it links to, so the matrix carries the
stored verdict, run id, check id and evidence digest rather than deriving a
verdict of its own.

Selection rules, all deterministic:

* a legitimate cell (requester owns the asset) is answered by the ``owner_baseline``
  check of a run that authenticated that account;
* a cross-account cell is answered by the ``cross_account`` check whose actor is
  the requester and whose owner owns the asset;
* when several stored runs answer the same cell, the newest one is used and the
  older run ids are listed as superseded (``sources`` counts all of them);
* the secure-route counterpart is taken from the *same* run. If that run recorded
  no secure check, the cell says so instead of implying a pass;
* a cell whose evidence came from a different loopback port than the most recent
  run is flagged ``stale`` — the lab was restarted in between.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from canarygate.scan.lab_matrix_models import (LabMatrix, LabMatrixAccount, LabMatrixCell,
                                               LabMatrixEvidence, LabMatrixSecure,
                                               LabMatrixSummary, actual_access_for)
from canarygate.scan.lab_scenarios import (ACCOUNT_ROLES, ACCOUNT_TITLES, ASSET_IDS,
                                           ASSET_LABELS, ASSET_TYPES, KNOWN_ACCOUNTS,
                                           asset_owner_map)

_INSTANCE = re.compile(r"^[0-9a-f]{16}$")

NOTES = (
    "Every tested cell is a projection of one stored LAB-BOLA check: the run id, "
    "check id, evidence SHA-256 and verdict are copied, never recomputed.",
    "A cell with no stored check is 'untested'. It has no verdict at all — it is not "
    "SAFE, SKIPPED or INCONCLUSIVE, because absence of evidence is not a result.",
    "The matrix reads no ground truth and opens no socket. It is assembled from the "
    "stored runs the lab workflow already produced.",
    "A cell is 'stale' when its stored evidence came from a different loopback port "
    "than the most recent run; the lab was restarted, but the evidence is unchanged.",
    "Duplicate evidence is counted (sources) and the superseded run ids are listed; "
    "the newest stored run is the one displayed.",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _scope_of(run: dict) -> dict:
    scope = run.get("scope")
    return scope if isinstance(scope, dict) else {}


def _lab_instance(run: dict) -> str | None:
    """The lab process identity the run recorded, when it recorded a valid one."""
    value = _scope_of(run).get("lab_instance")
    return value if isinstance(value, str) and _INSTANCE.fullmatch(value) else None


def _port_of(run: dict, check: dict) -> int:
    """The loopback port the check was recorded against; required, never invented."""
    port = _scope_of(run).get("port")
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("a stored run must carry the port its evidence came from")
    return port


def _flag(checklist: dict, evidence: dict, name: str) -> bool:
    """A stored boolean, read from the checklist and falling back to its summary."""
    return bool(checklist.get(name, evidence.get(name)))


def _evidence(run: dict, check: dict) -> LabMatrixEvidence:
    checklist = check.get("checklist") or {}
    summary = check.get("evidence") or {}
    truths = int(summary.get("checklist_true")
                 or sum(1 for value in checklist.values() if value is True))
    total = int(summary.get("checklist_total") or len(checklist) or truths)
    return LabMatrixEvidence(
        evidence_id=f"{run['id']}#{check['id']}",
        run_id=run["id"], check_id=check["id"], direction=check["direction"],
        verdict=check["verdict"], status=check.get("status"),
        endpoint=check["endpoint"], evidence_sha256=check["evidence_sha256"],
        created_at=run["created_at"], port=_port_of(run, check),
        lab_instance=_lab_instance(run),
        requests_sent=int((run.get("constraints") or {}).get("requests_sent") or 0),
        checklist_true=truths, checklist_total=total,
        private_disclosure=_flag(checklist, summary, "private_disclosure"),
        verified_denial=_flag(checklist, summary, "verified_denial"),
        owner_baseline=_flag(checklist, summary, "owner_baseline"),
        remediation=check.get("remediation"),
    )


def _secure_counterpart(run: dict, check: dict) -> LabMatrixSecure | None:
    """The secure-route check for the same actor and owner, in the same run."""
    if check.get("direction") != "cross_account":
        return None
    for other in run.get("checks") or []:
        if (other.get("direction") == "cross_account_secure"
                and other.get("actor") == check.get("actor")
                and other.get("owner") == check.get("owner")):
            checklist = other.get("checklist") or {}
            summary = other.get("evidence") or {}
            return LabMatrixSecure(
                run_id=run["id"], check_id=other["id"], status=other.get("status"),
                verdict=other["verdict"], evidence_sha256=other["evidence_sha256"],
                verified_denial=_flag(checklist, summary, "verified_denial"))
    return None


def _candidates(runs: list[dict]) -> dict[tuple[str, str], list[tuple]]:
    """(requester, asset) -> [(sort key, run, check)] for every answering check."""
    found: dict[tuple[str, str], list[tuple]] = {}
    for run in runs:
        created = str(run.get("created_at") or "")
        for check in run.get("checks") or []:
            direction = check.get("direction")
            actor, owner = check.get("actor"), check.get("owner")
            if direction == "owner_baseline" and actor in ASSET_IDS:
                key = (actor, ASSET_IDS[actor])
            elif direction == "cross_account" and owner in ASSET_IDS:
                key = (actor, ASSET_IDS[owner])
            else:
                continue
            found.setdefault(key, []).append(((created, str(run.get("id") or "")), run, check))
    for items in found.values():
        items.sort(key=lambda item: item[0])
    return found


def _newest_run(runs: list[dict]) -> dict | None:
    if not runs:
        return None
    return max(runs, key=lambda run: (str(run.get("created_at") or ""),
                                      str(run.get("id") or "")))


def _is_stale(evidence: LabMatrixEvidence, newest: dict | None) -> bool:
    """Is this evidence older than the lab process the newest run talked to?

    A port alone cannot answer that: two lab processes reuse ephemeral ports. When
    both runs published an ``X-Lab-Instance`` id the identity decides; otherwise the
    port is the only signal available and is used, and that fallback is documented.
    """
    if newest is None:
        return False
    newest_instance = _lab_instance(newest)
    if evidence.lab_instance is not None and newest_instance is not None:
        return evidence.lab_instance != newest_instance
    port = _scope_of(newest).get("port")
    return isinstance(port, int) and evidence.port != port


def build_lab_matrix(runs, *, generated_at: str | None = None) -> dict:
    """Project stored read-BOLA runs onto the nine demo-tenant cells."""
    runs = [run for run in (runs or [])
            if isinstance(run, dict) and run.get("mode") == "targetlab_bola"]
    owners = asset_owner_map()
    newest = _newest_run(runs)
    found = _candidates(runs)

    cells: list[LabMatrixCell] = []
    for requester in KNOWN_ACCOUNTS:
        for owner in KNOWN_ACCOUNTS:
            asset_id = ASSET_IDS[owner]
            kind = ("legitimate_owner_request" if requester == owner
                    else "cross_account_attempt")
            items = found.get((requester, asset_id)) or []
            if not items:
                cells.append(LabMatrixCell(
                    requester=requester, asset_id=asset_id, owner=owners[asset_id],
                    kind=kind, state="untested", expected_access="owner-only",
                    actual_access="no_evidence"))
                continue
            _, run, check = items[-1]
            checklist = check.get("checklist") or {}
            evidence = _evidence(run, check)
            superseded: list[str] = []
            for _, older_run, _check in items[:-1]:
                run_id = str(older_run.get("id"))
                if run_id not in superseded:
                    superseded.append(run_id)
            cells.append(LabMatrixCell(
                requester=requester, asset_id=asset_id, owner=owner, kind=kind,
                state="tested", expected_access="owner-only",
                actual_access=actual_access_for(check["direction"], check["verdict"],
                                                checklist, check.get("status")),
                verdict=check["verdict"], reason=check.get("reason") or "",
                evidence=evidence, secure=_secure_counterpart(run, check),
                stale=_is_stale(evidence, newest),
                sources=len(items), superseded_runs=superseded))

    tested = [cell for cell in cells if cell.state == "tested"]

    def count(verdict: str) -> int:
        return sum(1 for cell in tested if cell.verdict == verdict)

    summary = LabMatrixSummary(
        tested=len(tested), untested=len(cells) - len(tested),
        confirmed=count("CONFIRMED"), suspected=count("SUSPECTED"), safe=count("SAFE"),
        inconclusive=count("INCONCLUSIVE"), skipped=count("SKIPPED"),
        runs_considered=len(runs),
        ports=sorted({port for port in (_scope_of(run).get("port") for run in runs)
                      if isinstance(port, int)}),
        lab_instances=len({instance for instance in map(_lab_instance, runs)
                           if instance is not None}),
        stale_cells=sum(1 for cell in cells if cell.stale),
        duplicated_cells=sum(1 for cell in cells if cell.sources > 1))

    accounts = [LabMatrixAccount(account=account, title=ACCOUNT_TITLES[account],
                                 role=ACCOUNT_ROLES[account], asset_id=ASSET_IDS[account],
                                 asset_type=ASSET_TYPES[ASSET_IDS[account]],
                                 asset_label=ASSET_LABELS[ASSET_IDS[account]])
                for account in KNOWN_ACCOUNTS]
    return LabMatrix(
        mode="targetlab_matrix", dataset="demo_tenant",
        derived_from="stored_lab_bola_runs",
        evaluated_after_verdicts=True, used_as_decision_input=False,
        generated_at=generated_at or _now(),
        accounts=accounts, cells=cells, summary=summary, notes=list(NOTES),
    ).model_dump(mode="json")
