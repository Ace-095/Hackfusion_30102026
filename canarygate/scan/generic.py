"""Transport-agnostic offline scan orchestrator for read-BOLA evidence.

The same function consumes guarded HTTPX observations or the recorded offline
transport, then writes nothing itself: persistence and reporting are separate.
Production networking remains disabled; callers supply an already guarded,
strictly typed runner.
"""
from datetime import datetime, timezone
from uuid import uuid4

from canarygate.evidence.redaction import digest
from canarygate.models.result import Result
from canarygate.network.boundary import GuardedReadRunner
from canarygate.oracles.read_bola import empty_checklist, evaluate_read_bola
from canarygate.scan.plan import OfflineScenarioPlan
from canarygate.seed.registry import collect_guarded_ownership

LIMITATIONS = (
    "Offline recorded transport only: no live target, socket, DNS lookup or organizer approval was used.",
    "Authentication, input-validation and information-disclosure checks are outside this scenario scan.",
    "Evidence is minimized to fixed metadata and checklist flags; raw bodies and credentials are not stored.",
    "Provenance checks are in-process integrity checks, not cryptographic signatures.",
    "Production guarded HTTPX execution remains disabled pending separate safety review and written approval.",
)
_SETUP_SKIPPED = {"authentication": "SYNTHETIC_PREPROVISIONED", "ownership_verification": "SKIPPED",
                  "bola_coverage": "SKIPPED", "reason": "Setup incomplete"}


def _evidence(phase, actor, role, path_template, status_code, flags, timestamp):
    summary = {"phase": phase, "timestamp": timestamp, "actor": actor, "role": role,
               "method": "GET", "path_template": path_template, "status_code": status_code,
               "checklist": {key: bool(value) for key, value in flags.items()},
               "redacted": True}
    summary["sha256"] = digest({key: value for key, value in summary.items()
                                if key not in {"sha256", "redacted"}})
    return summary


def _constraints(runner):
    stats = runner.stats() if isinstance(runner, GuardedReadRunner) else {}
    return {
        "requests_sent": stats.get("requests_sent", 0),
        "blocked_by_guard": stats.get("blocked_by_guard", 0),
        "redirects_observed": stats.get("redirects_observed", 0),
        "redirects_followed": 0,
        "out_of_scope_requests_executed": 0,
        "destructive_requests_executed": 0,
        "external_requests_executed": 0,
        "budget_remaining": stats.get("budget_remaining", 0),
        "network_transport_enabled": False,
        "halted_reason": "halted" if stats.get("halted") else None,
    }


def _base_run(plan, timestamp, transport):
    scope = plan.scope
    scope_payload = scope.model_dump(mode="json")
    return {
        "id": str(uuid4()), "created_at": timestamp, "mode": "offline_scenario",
        "status": "completed", "scenario_id": plan.scenario_id,
        "transport": transport,
        "network_transport_enabled": False,
        "scope": {
            "origin": scope.origin, "hostname": scope.hostname, "port": scope.port,
            "written_authorization_reference": scope.written_authorization_reference,
            "scope_sha256": digest(scope_payload), "request_budget": scope.request_budget,
            "accounts": [{"account": item.account, "role": item.role} for item in scope.accounts],
        },
        "recipe": {
            "resource_type": plan.resource_type,
            "discovery": f"{plan.resource.discovery.method} {plan.resource.discovery.path}",
            "detail": f"{plan.resource.detail.method} {plan.resource.detail.path}",
            "id_field": plan.resource.id_field,
            "ownership_field": plan.resource.ownership_field,
            "ownership_model": plan.resource.ownership_model,
            "private_field": plan.resource.private_field,
        },
        "policy": {"expected_access": plan.policy.expected_access,
                   "expected_source": plan.policy.expected_source},
        "setup": dict(_SETUP_SKIPPED),
        "evidence": {"ownership": None, "disclosure": None},
        "checklist": empty_checklist(),
        "verdict": "SKIPPED",
        "reason": "Scenario scan did not establish a security conclusion",
        "remediation": None,
        "constraints": _constraints(None),
        "inventory": [entry.model_dump(mode="json") for entry in plan.inventory],
        "transcript_sha256": plan.transcript.sha256(),
        "limitations": list(LIMITATIONS),
    }


def _finish(run, runner, verdict, reason, *, status="completed", setup=None):
    run["verdict"] = verdict
    run["reason"] = reason
    run["status"] = status
    if setup:
        run["setup"].update(setup)
    run["constraints"] = _constraints(runner)
    return run


def run_generic_scan(runner, plan):
    """Run one guarded read-BOLA scenario; raises ValueError on invalid inputs."""
    if not isinstance(runner, GuardedReadRunner) or not isinstance(plan, OfflineScenarioPlan):
        raise ValueError("a guarded read runner and validated offline plan are required")
    runner_scope = getattr(runner, "scope", None)
    if runner_scope is None or runner_scope.origin != plan.scope.origin:
        raise ValueError("runner scope does not match the plan")
    timestamp = datetime.now(timezone.utc).isoformat()
    run = _base_run(plan, timestamp, runner.transport_label)
    actor, owner = plan.accounts
    roles = plan.account_roles()
    try:
        if not runner.has_distinct_credentials(actor, owner):
            return _finish(run, runner, "SKIPPED",
                           "Two distinct scoped credentials are required",
                           setup={"reason": "Authentication prerequisites were not met"})
        ownership = collect_guarded_ownership(
            runner, resource_type=plan.resource_type, resource=plan.resource,
            accounts=(actor, owner), profile_path=plan.profile_path,
            identity_field=plan.identity_field)
        run["setup"]["ownership_verification"] = ownership.ownership_status
        oracle_args = dict(ownership=ownership, resource_type=plan.resource_type,
                           resource=plan.resource, actor=actor, owner=owner,
                           expected_access=plan.policy.expected_access,
                           expected_source=plan.policy.expected_source)
        readiness = evaluate_read_bola(**oracle_args, response=None)
        run["checklist"] = readiness.checklist
        if ownership.ownership_status != "SUCCESS":
            return _finish(run, runner, "SKIPPED", ownership.reason,
                           setup={"reason": ownership.reason})
        if not readiness.checklist["private_baseline"]:
            return _finish(run, runner, "SKIPPED", readiness.verdict_reason,
                           setup={"bola_coverage": "FAILED", "reason": readiness.verdict_reason})
        owner_response = ownership.baselines[owner][0]
        run["evidence"]["ownership"] = _evidence(
            "ownership", owner, roles[owner], plan.resource.detail.path,
            owner_response.status_code,
            {"ownership_verified": True, "both_owner_baselines": True, "cross_list_isolation": True},
            timestamp)
        run["setup"]["ownership_verification"] = "SUCCESS"
        path = plan.resource.detail.path.replace("{id}", ownership.ids[owner])
        try:
            response = runner.get(actor, path)
        except ValueError:
            return _finish(run, runner, "SKIPPED",
                           "The safety guard blocked the required cross-account read",
                           setup={"bola_coverage": "BLOCKED",
                                  "reason": "The safety guard blocked the required cross-account read"})
        decision = evaluate_read_bola(**oracle_args, response=response)
        run["checklist"] = decision.checklist
        run["evidence"]["disclosure"] = _evidence(
            "disclosure", actor, roles[actor], plan.resource.detail.path, response.status_code,
            {"owner_baseline": decision.checklist["owner_baseline"],
             "attacker_request": decision.checklist["attacker_request"],
             "response_checked": decision.checklist["response_checked"],
             "private_disclosure": decision.checklist["private_disclosure"],
             "verified_denial": decision.checklist["verified_denial"]},
            timestamp)
        run["setup"]["bola_coverage"] = "SUCCESS"
        if decision.verdict == "CONFIRMED":
            run["remediation"] = (
                "Enforce object-level authorization for every read: derive the permitted owner "
                "from the authenticated identity and deny cross-owner access to the requested "
                f"{plan.resource_type} resource.")
        return _finish(run, runner, decision.verdict, decision.verdict_reason,
                       setup={"reason": None})
    except (ValueError, KeyError, TypeError, AttributeError, IndexError):
        return _finish(run, runner, "INCONCLUSIVE",
                       "Generic offline scan failed closed; no security conclusion",
                       status="failed", setup={"reason": "Scenario execution failed closed"})
