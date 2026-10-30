"""Owner-baseline and disclosure proof, assembled from stored TargetLab runs.

Both functions are pure projections: they read run payloads that are already in the
database and the published lab catalog, and they group the stored checks so a
reviewer can follow one claim from the identity that made it to the evidence hash
that records it. Nothing here can create a check, a verdict, a status or a hash.

Two details matter and are easy to get wrong:

* **A denial is not a disclosure.** The secure-route checks carry
  ``private_disclosure: false`` because the read was refused. That is the *desired*
  answer. Nothing in this module treats a false flag on a denial as a missing step,
  which is why the pages built on it never show "disclosure: no" for a run whose
  verdict is CONFIRMED.
* **A missing check is missing.** When no stored run contains an owner read for an
  account, the account is reported as not verified. It is never inferred from the
  catalog, from a neighbouring run, or from the fact that the account exists.
"""
from __future__ import annotations

from canarygate.scan.lab_scenarios import build_lab_catalog

#: Flags that carry meaning for each direction, in the order a reviewer reads them.
_FLAGS = {
    "owner_baseline": ("owner_baseline", "ownership_verified", "private_resource"),
    "cross_account": ("attacker_request", "owner_baseline", "ownership_verified",
                      "private_baseline", "private_disclosure", "response_checked"),
    "cross_account_secure": ("attacker_request", "response_checked", "verified_denial",
                             "private_disclosure"),
}

#: What a `false` means per direction. A false on a refusal is the good outcome.
_FALSE_MEANS = {
    "owner_baseline": "the owner read did not return the caller's own record",
    "cross_account": "the oracle did not record this step",
    "cross_account_secure": "the endpoint did not deny the read",
}


def _flags(check: dict) -> list[dict]:
    checklist = check.get("checklist") or {}
    return [{"key": key, "label": key.replace("_", " "), "value": bool(checklist.get(key))}
            for key in _FLAGS.get(check.get("direction"), ())
            if key in checklist]


def _brief(check: dict) -> dict:
    return {
        "id": check.get("id", ""),
        "direction": check.get("direction", ""),
        "actor": check.get("actor", ""),
        "owner": check.get("owner", ""),
        "endpoint": check.get("endpoint", ""),
        "status": check.get("status"),
        "verdict": check.get("verdict", ""),
        "reason": check.get("reason", ""),
        "evidence_sha256": check.get("evidence_sha256", ""),
        "flags": _flags(check),
        "false_means": _FALSE_MEANS.get(check.get("direction"), ""),
        "disclosed": bool((check.get("checklist") or {}).get("private_disclosure")),
        "denied": bool((check.get("checklist") or {}).get("verified_denial")),
    }


def _catalog():
    catalog = build_lab_catalog()
    return catalog, {item["account"]: item for item in catalog["accounts"]}


def ownership_proof(runs: list[dict]) -> dict:
    """One row per catalog account: who verified ownership, and with which read.

    ``runs`` are stored run payloads, newest first. The newest owner read wins, so a
    later run can supersede an earlier one but an older run never hides a newer
    failure: if the newest run for an account recorded no successful owner read, the
    account is reported with that run's evidence, not with an older success.
    """
    catalog, accounts = _catalog()
    rows = []
    for name, account in accounts.items():
        verify = None
        for run in runs:
            baseline = next((check for check in run.get("checks", [])
                             if check.get("direction") == "owner_baseline"
                             and check.get("actor") == name
                             and check.get("owner") in (None, name)), None)
            if baseline is not None:
                verify = (run, baseline)
                break
        run, baseline = verify if verify else (None, None)
        rows.append({
            "account": name,
            "title": account.get("title", ""),
            "asset_id": account.get("asset_id", ""),
            "asset_label": account.get("asset_label", ""),
            "verified": bool(baseline and baseline.get("verdict") == "SAFE"
                             and baseline.get("status") == 200),
            "check": _brief(baseline) if baseline else None,
            "run_id": (run or {}).get("id", ""),
            "recorded_at": (run or {}).get("created_at", ""),
            "run_verdict": (run or {}).get("verdict", ""),
        })
    verified = sum(1 for row in rows if row["verified"])
    return {
        "rows": rows,
        "accounts_total": len(rows),
        "accounts_verified": verified,
        "baselines_stored": sum(1 for run in runs for check in run.get("checks", [])
                                if check.get("direction") == "owner_baseline"),
        "runs_considered": len(runs),
        "catalog_order": list(catalog.get("accounts", []) and accounts),
    }


def disclosure_proof(runs: list[dict]) -> dict:
    """One chain per stored cross-account request, newest run first.

    Each chain is the four things a read-BOLA finding needs, each one a stored
    check of the same run: the owner's own read, the requester's own read, the
    cross-account request, and the same request against the secure route.
    """
    _catalog_doc, accounts = _catalog()
    chains = []
    for run in runs:
        checks = run.get("checks", [])
        baselines = {}
        for check in checks:
            if check.get("direction") == "owner_baseline":
                baselines.setdefault(check.get("actor"), check)
        secure_checks = {(check.get("actor"), check.get("owner")): check
                         for check in checks
                         if check.get("direction") == "cross_account_secure"}
        for check in checks:
            if check.get("direction") != "cross_account":
                continue
            owner = check.get("owner")
            secure = secure_checks.get((check.get("actor"), owner))
            chain = {
                "run_id": run.get("id", ""),
                "recorded_at": run.get("created_at", ""),
                "run_verdict": run.get("verdict", ""),
                "requester": check.get("actor", ""),
                "owner": owner,
                "asset_id": accounts.get(owner, {}).get("asset_id", ""),
                "asset_label": accounts.get(owner, {}).get("asset_label", ""),
                "requester_baseline": _brief(baselines[check["actor"]])
                if check.get("actor") in baselines else None,
                "owner_baseline": _brief(baselines[owner]) if owner in baselines else None,
                "request": _brief(check),
                "secure": _brief(secure) if secure else None,
                "confirmed": check.get("verdict") == "CONFIRMED",
                "remediation": check.get("remediation"),
            }
            chains.append(chain)
    confirmed = sum(1 for chain in chains if chain["confirmed"])
    denied = sum(1 for chain in chains if chain["secure"] and chain["secure"]["denied"])
    return {
        "chains": chains,
        "chains_total": len(chains),
        "confirmed": confirmed,
        "denied": denied,
        "runs_considered": len(runs),
        "secure_checks": sum(1 for run in runs for check in run.get("checks", [])
                             if check.get("direction") == "cross_account_secure"),
    }


def proof_anchors(runs: list[dict]) -> dict:
    """Where the two proofs live, for the review journey.

    Returns ``None`` when no lab run is stored, so a page keeps the fixture journey
    it has always had rather than pointing at an empty lab surface.
    """
    if not runs:
        return None
    newest = runs[0]
    return {
        "runs": "/ui/lab",
        "matrix": "/ui/lab/matrix",
        "ownership": "/ui/lab/proof/ownership",
        "disclosure": "/ui/lab/proof/disclosure",
        "run": f"/ui/lab/bola/{newest.get('id', '')}",
        "report": f"/ui/lab/bola/{newest.get('id', '')}/report",
    }


#: How the run page groups its stored evidence, and what a false means per group.
#: A false flag on a *denial* is the desired answer, which is why the groups are
#: kept apart instead of being ANDed into one misleading summary.
_EVIDENCE_GROUPS = (
    ("owner_baseline", "Owner baselines",
     "Each account read its own record. These are the reads that prove ownership."),
    ("cross_account", "Cross-account requests",
     "One account asked for the other account's record on the vulnerable route."),
    ("cross_account_secure", "Secure-route denials",
     "The same request against the corrected route. A false private_disclosure here "
     "is the expected answer: nothing was disclosed because the read was refused."),
)


def evidence_groups(run: dict) -> list[dict]:
    """The run's stored checks, grouped by direction, with their own flags.

    Nothing is aggregated across directions: an owner baseline, a cross-account
    request and a secure-route denial answer different questions, and ANDing their
    flags together produces claims that contradict the verdict the run already has.
    """
    checks = run.get("checks") or []
    groups = []
    for direction, label, note in _EVIDENCE_GROUPS:
        members = [check for check in checks if check.get("direction") == direction]
        groups.append({
            "direction": direction,
            "label": label,
            "note": note,
            "present": bool(members),
            "checks": [{
                "id": check.get("id", ""),
                "actor": check.get("actor", ""),
                "owner": check.get("owner", ""),
                "status": check.get("status"),
                "verdict": check.get("verdict", ""),
                "evidence_sha256": check.get("evidence_sha256", ""),
                "flags": _flags(check),
            } for check in members],
        })
    return groups
