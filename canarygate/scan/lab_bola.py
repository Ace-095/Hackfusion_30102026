"""Read-BOLA validation against a running TargetLab over loopback HTTPS.

This module contains **no oracle of its own**. Ownership is collected by the one
shared registry (`collect_guarded_ownership`) and every verdict comes from the
one shared read-BOLA oracle (`evaluate_read_bola`). What it adds is the lab
workflow: two endpoints, both directions, and a ground-truth comparison that is
computed *after* the verdicts so it can never influence them.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from canarygate.evidence.redaction import digest
from canarygate.oracles.read_bola import evaluate_read_bola
from canarygate.scan.lab_bola_models import (GroundTruthComparison, GroundTruthRow,
                                             LabBolaCheck, LabBolaConstraints, LabBolaRun,
                                             LabBolaSummary, LabBolaTransport)
from canarygate.scan.lab_bola_scenarios import CHECK_IDS, EXPECTED_VERDICTS
from canarygate.scan.lab_scenarios import ADMIN_PATH, EXPECTED_POLICY
from canarygate.seed.registry import collect_guarded_ownership

REMEDIATION = ("Enforce object-level authorization on every record handler: derive the permitted "
               "owner from the authenticated identity and deny cross-owner reads before the "
               "record is loaded.")
LIMITATIONS = (
    "Controlled validation against the loopback TargetLab only: real HTTPS requests were made to "
    "127.0.0.1 with a pinned test certificate. This is not live-organizer validation and cannot "
    "measure real-world detection quality, because the lab is written by the same team.",
    "The decision is produced by the existing read-BOLA oracle and ownership registry; this "
    "workflow adds no second detection engine.",
    "The lab ground truth at /lab/ground-truth is never requested. It is compared with the "
    "finished verdicts afterwards, so it cannot influence them.",
    "Evidence is bounded to status codes, checklist flags and digests; response bodies, tokens "
    "and passwords are never stored or reported.",
    "Redirects are refused, no request is retried, no external DNS is used and no destructive "
    "method can be issued.",
)
DEFERRED = (
    "Interaction (SCI) validation against the lab is deferred to checkpoint 37: this run proves "
    "the individual controls and the BOLA mapping only."
)


def _now():
    """Microsecond precision: two runs in the same second must still order."""
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _bounded(decision, status):
    """Only booleans and counts survive into stored evidence."""
    return {
        "status": status,
        "checklist_true": sum(1 for value in decision.checklist.values() if value),
        "checklist_total": len(decision.checklist),
        "verified_denial": bool(decision.checklist.get("verified_denial")),
        "private_disclosure": bool(decision.checklist.get("private_disclosure")),
        "ownership_verified": bool(decision.checklist.get("ownership_verified")),
        "owner_baseline": bool(decision.checklist.get("owner_baseline")),
    }


def _check(check_id, title, direction, endpoint, actor, owner, status, decision, *, direction_ok=True):
    evidence = _bounded(decision, status)
    return LabBolaCheck(
        id=check_id, title=title, direction=direction, endpoint=endpoint, actor=actor,
        owner=owner, status=status, verdict=decision.verdict,
        reason=decision.verdict_reason, checklist=decision.checklist, evidence=evidence,
        evidence_sha256=digest({"id": check_id, "verdict": decision.verdict,
                                "checklist": decision.checklist, "evidence": evidence}),
        remediation=REMEDIATION if decision.verdict == "CONFIRMED" else None)


def _blocked(check_id, title, direction, endpoint, actor, owner):
    from canarygate.models.result import Result

    decision = Result(verdict="SKIPPED",
                      verdict_reason="The safety guard blocked this request",
                      checklist={}, remediation_key="")
    evidence = {"blocked_by_guard": True, "request_sent": False}
    return LabBolaCheck(
        id=check_id, title=title, direction=direction, endpoint=endpoint, actor=actor,
        owner=owner, status=None, verdict="SKIPPED", reason=decision.verdict_reason,
        checklist={}, evidence=evidence,
        evidence_sha256=digest({"id": check_id, "blocked": True, "evidence": evidence}))


def _owner_baseline_check(check_id, actor, ownership, resource, endpoint):
    """SAFE for the owner reading their own record, only when the registry verified it."""
    verified = (ownership.ownership_status == "SUCCESS"
                and actor in ownership.ids and actor in ownership.baselines)
    checklist = {"ownership_verified": True, "owner_baseline": verified,
                 "distinct_accounts": True, "private_resource": True}
    if not verified:
        evidence = {"owner_baseline": False}
        from canarygate.models.result import Result

        decision = Result(verdict="INCONCLUSIVE",
                          verdict_reason="The owner baseline was not verified", checklist={},
                          remediation_key="")
        status = None
    else:
        status = ownership.baselines[actor][0].status_code
        evidence = {"owner_baseline": True, "status": status,
                    "owner_matches_actor": True, "private_marker_present": True}
        from canarygate.models.result import Result

        decision = Result(verdict="SAFE",
                          verdict_reason="The owner baseline returned the caller's own record",
                          checklist=checklist, remediation_key="")
    return LabBolaCheck(
        id=check_id, title=f"{actor} reads their own record", direction="owner_baseline",
        endpoint=endpoint, actor=actor, owner=actor, status=status,
        verdict=decision.verdict, reason=decision.verdict_reason, checklist=decision.checklist,
        evidence=evidence,
        evidence_sha256=digest({"id": check_id, "verdict": decision.verdict,
                                "checklist": decision.checklist, "evidence": evidence}))


def _ownership_status(ownership):
    return "SKIPPED" if ownership is None else ownership.ownership_status


def _ownership_summary(ownership):
    if ownership is None:
        return {"status": "SKIPPED", "resource_status": "SKIPPED",
                "reason": "Ownership was not collected", "identities_verified": [],
                "owners": {}, "baselines_verified": {}, "cross_list_isolated": False,
                "resource_ids_withheld": True}
    return {
        "status": ownership.ownership_status,
        "resource_status": ownership.resource_status,
        "reason": ownership.reason,
        "identities_verified": list(ownership.identity_accounts),
        "owners": {actor: True for actor in ownership.ids},
        "baselines_verified": {actor: True for actor in ownership.baselines},
        "cross_list_isolated": ownership.ownership_status == "SUCCESS",
        "resource_ids_withheld": True,
    }


def _evaluate(endpoint_resource, ownership, actor, owner, response):
    return evaluate_read_bola(
        ownership=ownership, resource_type="record", resource=endpoint_resource,
        actor=actor, owner=owner, response=response, expected_access="owner-only",
        expected_source="targetlab declared record policy")


def _read(runner, actor, path):
    try:
        return runner.get(actor, path), None
    except ValueError:
        return None, "blocked"


def run_lab_bola_scan(plan, runner, *, store=None):
    """Execute the six declared checks and return a validated run."""
    accounts = plan.accounts
    first, second = accounts
    checks = []
    notes = {}
    authenticated = {}
    for actor in accounts:
        try:
            authenticated[actor] = runner.login(actor) is True
        except ValueError:
            authenticated[actor] = False

    vulnerable = plan.resource
    secure = plan.secure_resource

    if not all(authenticated.values()):
        # Without two real authenticated identities no ownership or policy claim is
        # possible, so every declared check is SKIPPED rather than guessed.
        failed = sorted(actor for actor, ok in authenticated.items() if not ok)
        for check_id, direction, actor, owner, path in _check_layout(accounts, vulnerable, secure):
            checks.append(_skipped(check_id, direction, actor, owner, f"GET {path}",
                                   "Account authentication was not established for: "
                                   + ", ".join(failed)))
        failed_run = _finish_run(plan, runner, checks)
        return store.save(failed_run) if store is not None else failed_run

    # One ownership collection per endpoint, both through the shared registry.
    ownership = collect_guarded_ownership(
        runner, resource_type="record", resource=vulnerable, accounts=accounts,
        profile_path=plan.profile_path, identity_field=plan.identity_field)
    notes["vulnerable"] = ownership.reason
    ownership_secure = collect_guarded_ownership(
        runner, resource_type="record", resource=secure, accounts=accounts,
        profile_path=plan.profile_path, identity_field=plan.identity_field)
    notes["secure"] = ownership_secure.reason

    # 1-2: owner baselines on the vulnerable route (already verified by the registry).
    checks.append(_owner_baseline_check("LAB-BOLA-01", first, ownership, vulnerable,
                                        f"GET {vulnerable.detail.path}"))
    checks.append(_owner_baseline_check("LAB-BOLA-02", second, ownership, vulnerable,
                                        f"GET {vulnerable.detail.path}"))

    # 3-4: cross-account reads of the vulnerable route, both directions.
    for check_id, actor, owner in (("LAB-BOLA-03", first, second),
                                   ("LAB-BOLA-04", second, first)):
        title = f"{actor} reads {owner}'s private record"
        if ownership.ownership_status != "SUCCESS" or owner not in ownership.ids:
            from canarygate.models.result import Result

            decision = evaluate_read_bola(
                ownership=ownership, resource_type="record", resource=vulnerable,
                actor=actor, owner=owner, response=None, expected_access="owner-only",
                expected_source="targetlab declared record policy")
            assert decision.verdict == "INCONCLUSIVE"
            checks.append(_check(check_id, title, "cross_account",
                                 f"GET {vulnerable.detail.path}", actor, owner, None, decision))
            continue
        path = vulnerable.detail.path.replace("{id}", ownership.ids[owner])
        response, blocked = _read(runner, actor, path)
        if blocked:
            checks.append(_blocked(check_id, title, "cross_account",
                                   f"GET {vulnerable.detail.path}", actor, owner))
            continue
        decision = _evaluate(vulnerable, ownership, actor, owner, response)
        checks.append(_check(check_id, title, "cross_account",
                             f"GET {vulnerable.detail.path}", actor, owner,
                             response.status_code, decision))

    # 5-6: the same cross-account reads against the secure route.
    for check_id, actor, owner in (("LAB-BOLA-05", first, second),
                                   ("LAB-BOLA-06", second, first)):
        title = f"{actor} is denied on {owner}'s secure record"
        if ownership_secure.ownership_status != "SUCCESS" or owner not in ownership_secure.ids:
            from canarygate.models.result import Result

            decision = evaluate_read_bola(
                ownership=ownership_secure, resource_type="record", resource=secure,
                actor=actor, owner=owner, response=None, expected_access="owner-only",
                expected_source="targetlab declared record policy")
            checks.append(_check(check_id, title, "cross_account_secure",
                                 f"GET {secure.detail.path}", actor, owner, None, decision))
            continue
        path = secure.detail.path.replace("{id}", ownership_secure.ids[owner])
        response, blocked = _read(runner, actor, path)
        if blocked:
            checks.append(_blocked(check_id, title, "cross_account_secure",
                                   f"GET {secure.detail.path}", actor, owner))
            continue
        decision = _evaluate(secure, ownership_secure, actor, owner, response)
        checks.append(_check(check_id, title, "cross_account_secure",
                             f"GET {secure.detail.path}", actor, owner,
                             response.status_code, decision))

    run = _finish_run(plan, runner, checks, ownership=ownership,
                      ownership_secure=ownership_secure)
    return store.save(run) if store is not None else run


def _check_layout(accounts, vulnerable, secure):
    first, second = accounts
    return (("LAB-BOLA-01", "owner_baseline", first, first, vulnerable.detail.path),
            ("LAB-BOLA-02", "owner_baseline", second, second, vulnerable.detail.path),
            ("LAB-BOLA-03", "cross_account", first, second, vulnerable.detail.path),
            ("LAB-BOLA-04", "cross_account", second, first, vulnerable.detail.path),
            ("LAB-BOLA-05", "cross_account_secure", first, second, secure.detail.path),
            ("LAB-BOLA-06", "cross_account_secure", second, first, secure.detail.path))


def _skipped(check_id, direction, actor, owner, endpoint, reason):
    evidence = {"skipped": True, "reason_code": "authentication_not_established"}
    return LabBolaCheck(
        id=check_id, title=f"{actor} to {owner}" if actor != owner else f"{actor} own record",
        direction=direction, endpoint=endpoint, actor=actor, owner=owner, status=None,
        verdict="SKIPPED", reason=reason[:1024], checklist={}, evidence=evidence,
        evidence_sha256=digest({"id": check_id, "skipped": reason}))


def _finish_run(plan, runner, checks, *, ownership=None, ownership_secure=None):
    """Assemble the validated run from whatever the checks actually established."""
    checks.sort(key=lambda item: item.id)
    timestamp = _now()
    vulnerable, secure = plan.resource, plan.secure_resource
    summary = LabBolaSummary(
        total=6,
        confirmed=sum(item.verdict == "CONFIRMED" for item in checks),
        safe=sum(item.verdict == "SAFE" for item in checks),
        suspected=sum(item.verdict == "SUSPECTED" for item in checks),
        inconclusive=sum(item.verdict == "INCONCLUSIVE" for item in checks),
        skipped=sum(item.verdict == "SKIPPED" for item in checks),
    )
    overall = ("CONFIRMED" if summary.confirmed else
               "INCONCLUSIVE" if summary.inconclusive else
               "SUSPECTED" if summary.suspected else
               "SKIPPED" if summary.skipped else "SAFE")
    reason = _overall_reason(overall, summary)

    stats = runner.stats()
    scope = runner.scope
    inventory = _inventory(scope)
    checks_payload = [item.model_dump(mode="json") for item in checks]
    lab_instance = runner.lab_instance
    run = LabBolaRun(
        id=str(uuid.uuid4()), created_at=timestamp, mode="targetlab_bola",
        status="completed" if ownership is not None and ownership.ownership_status == "SUCCESS" else "failed",
        scenario_id=plan.scenario_id, title=plan.title, verdict=overall, reason=reason,
        scope={"origin": scope.origin, "mode": scope.mode, "hostname": scope.hostname,
               "port": scope.port, "scheme": scope.scheme,
               "written_authorization_reference": scope.written_authorization_reference,
               "request_budget": scope.request_budget,
               "scope_sha256": digest(scope.model_dump(mode="json")),
               "accounts": [{"account": item.account, "role": item.role} for item in scope.accounts],
               "operations": [{"method": item.method, "path": item.path,
                               "classification": item.classification} for item in scope.operations],
               "expected_policy": {path: {"expected_access": access, "source": source}
                                   for path, (access, source) in EXPECTED_POLICY.items()},
               # Which lab process answered, when the lab published an identity.
               # Operational metadata only: it says nothing about the lab's flaws.
               **({"lab_instance": lab_instance} if lab_instance else {})},
        transport=LabBolaTransport(mode="local_lab", scheme="https", destination="127.0.0.1",
                                   port=scope.port,
                                   tls_verification="pinned_test_ca_with_hostname_check",
                                   redirects="refused", retries="none", dns="not_used",
                                   network_transport_enabled=True, live_target_contacted=False,
                                   production_networking=False),
        recipe={"resource_type": "record",
                "discovery": f"{vulnerable.discovery.method} {vulnerable.discovery.path}",
                "detail": f"{vulnerable.detail.method} {vulnerable.detail.path}",
                "secure_detail": f"{secure.detail.method} {secure.detail.path}",
                "id_field": vulnerable.id_field,
                "ownership_field": vulnerable.ownership_field,
                "ownership_model": vulnerable.ownership_model,
                "private_field": vulnerable.private_field},
        policy={"expected_access": plan.policy.expected_access,
                "expected_source": plan.policy.expected_source},
        ownership={"vulnerable": _ownership_summary(ownership),
                   "secure": _ownership_summary(ownership_secure)},
        checks=checks,
        summary=summary,
        ground_truth=_compare_to_ground_truth(checks),
        constraints=LabBolaConstraints(requests_sent=stats["requests_sent"],
                                       blocked_by_guard=stats["blocked_by_guard"],
                                       budget_remaining=stats["budget_remaining"],
                                       halted=stats["halted"], redirects_observed=0,
                                       destructive_requests_executed=0),
        inventory=inventory,
        evidence={"ownership": {"actor": plan.accounts[0], "role": _role(scope, plan.accounts[0]),
                                "status": _ownership_status(ownership),
                                "checklist": {"ownership_verified": _ownership_status(ownership) == "SUCCESS",
                                              "both_owner_baselines": _ownership_status(ownership) == "SUCCESS",
                                              "cross_list_isolation": _ownership_status(ownership) == "SUCCESS"}},
                  "disclosure": {"actor": plan.accounts[0],
                                 "checklist": {key: _all_true(checks, key) for key in
                                               ("owner_baseline", "attacker_request",
                                                "response_checked", "private_disclosure",
                                                "verified_denial")}}},
        checklist=_run_checklist(checks),
        remediation=REMEDIATION if overall == "CONFIRMED" else None,
        transcript_sha256=digest(checks_payload),
        limitations=list(LIMITATIONS) + [DEFERRED],
    )
    return run


def _role(scope, account):
    for item in scope.accounts:
        if item.account == account:
            return item.role
    return "unknown"


def _all_true(checks, key):
    relevant = [item for item in checks if key in item.checklist]
    return bool(relevant) and all(item.checklist[key] for item in relevant)


def _run_checklist(checks):
    """The run-level checklist proves a CONFIRMED result is fully evidenced."""
    by_id = {item.id: item for item in checks}
    confirmed = [item for item in checks if item.verdict == "CONFIRMED"]
    if not confirmed:
        return {key: False for key in ("private_resource", "distinct_accounts",
                                       "ownership_verified", "owner_baseline",
                                       "private_disclosure", "policy_denies_access")}
    return {
        "private_resource": True,
        "distinct_accounts": True,
        "ownership_verified": all(item.checklist.get("ownership_verified") for item in confirmed),
        "owner_baseline": all(item.checklist.get("owner_baseline") for item in confirmed),
        "private_disclosure": all(item.checklist.get("private_disclosure") for item in confirmed),
        "policy_denies_access": all(item.checklist.get("policy_denies_access") for item in confirmed),
    }


def _overall_reason(overall, summary):
    if overall == "CONFIRMED":
        return (f"{summary.confirmed} of 6 checks confirmed cross-account private disclosure on the "
                "vulnerable route, while the secure route denied the same reads")
    if overall == "SAFE":
        return "every declared check returned a verified result and no private disclosure occurred"
    if overall == "INCONCLUSIVE":
        return (f"{summary.inconclusive} of 6 checks could not be decided from the observed "
                "evidence; an incomplete case is never reported as confirmed or safe")
    if overall == "SUSPECTED":
        return "part of the evidence suggests a disclosure that could not be fully verified"
    return "the run did not execute enough of the declared checks to reach a conclusion"


def _inventory(scope):
    from canarygate.api.schemas import InventoryEndpoint

    items = []
    for operation in scope.operations:
        access, source = EXPECTED_POLICY.get(operation.path, ("authenticated", "TargetLab scope"))
        public = operation.classification == "AUTHENTICATION"
        items.append(InventoryEndpoint(
            method=operation.method, path=operation.path, parameters=[],
            security=[] if public else [{"bearerAuth": []}],
            expected_access="public authentication operation" if public else access,
            expected_source="TargetLab authentication contract" if public else source,
        ).model_dump(mode="json"))
    return items


def _compare_to_ground_truth(checks):
    """Score the finished verdicts against the declared table. Runs last, always."""
    rows = []
    for check in checks:
        expected = EXPECTED_VERDICTS[check.id]
        rows.append(GroundTruthRow(check_id=check.id, expected=expected,
                                   observed=check.verdict,
                                   matched=expected == check.verdict))
    matched = sum(row.matched for row in rows)
    return GroundTruthComparison(
        source="declared_targetlab_ground_truth", evaluated_after_verdicts=True,
        used_as_decision_input=False, rows=rows, matched=matched,
        mismatched=len(rows) - matched,
        statement=("Ground truth is a declared table scored against the finished verdicts. The "
                   "scanner never reads /lab/ground-truth and never consults this table before "
                   "deciding."))
