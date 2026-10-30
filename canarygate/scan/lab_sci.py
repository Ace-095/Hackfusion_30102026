"""Real control-interaction (SCI) validation against a running TargetLab.

This module adds orchestration only. The interaction verdict comes from the one
SCI decision engine (`canarygate.oracles.interaction.decide`), the credential
rejection rule from the one authentication oracle, and ownership from the one
registry. What is new here is the *sequence*: authenticate, prove ownership and
owner baselines, record a denial, submit a rejected login, read again, and check
that the second read carries the other owner's private marker.

None of that is decided by a route name or a scenario label. Every leg is a real
HTTPS response verified by the transport that produced it.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from canarygate.evidence.redaction import digest
from canarygate.oracles.authn_probes import credential_rejection_decision, observe_identity
from canarygate.network.targetlab import TargetLabRefused
from canarygate.oracles.interaction import SCI_REMEDIATIONS, Baseline, Combined, decide
from canarygate.scan.interaction_models import InteractionRun, SciBaseline, SciCombined
from canarygate.scan.lab_sci_models import LabResetProof, ResetCheck
from canarygate.seed.extraction import MISSING, extract
from canarygate.seed.registry import collect_guarded_ownership

LIMITATIONS = (
    "Controlled validation against the loopback TargetLab only: real HTTPS requests were made to "
    "127.0.0.1 with a pinned test certificate. This is not live-organizer validation.",
    "The lab is written by the same team as the scanner, so this does not measure real-world "
    "detection quality or general-purpose SCI coverage.",
    "The verdict comes from the existing SCI decision engine; this module adds orchestration and "
    "evidence adapters, not a second detector.",
    "The lab's /lab/ground-truth route is never requested. The declared table is compared with "
    "the finished run at report time, so it cannot influence the verdict.",
    "Evidence is bounded to status codes, checklist flags and digests; response bodies, tokens, "
    "passwords and private markers are never stored or reported.",
    "The reset proof is a separate scenario with its own runs; it is not part of this verdict.",
)
_RESET_LIMITATIONS = (
    "The reset proof is a separate controlled scenario, not a security verdict.",
    "It needs two guarded runs because a single run may authenticate an account only once by "
    "design; the second run performs the successful login that clears the lab condition.",
    "The lab clears the condition on a successful login, never on a read, so the proof records "
    "the clearing login explicitly.",
)
_MARKER_PLACEHOLDERS = frozenset({"[redacted]", "<redacted>", "redacted", "[masked]", "<masked>",
                                  "masked", "null", "none"})


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _body(response):
    """Strict JSON: duplicate keys and non-standard constants are rejected."""
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def reject_constant(value):
        raise ValueError("invalid JSON constant")

    try:
        return json.loads(response.content, object_pairs_hook=unique,
                          parse_constant=reject_constant)
    except (ValueError, UnicodeError, RecursionError, AttributeError):
        return None


def guarded_denial_verdict(status, body, denial_body):
    """The authorization control passes only with the exact checked denial."""
    if type(status) is int and status == 403 and isinstance(body, dict) and body == denial_body:
        return ("SAFE",
                "The authorization control denied the cross-account read with the checked "
                "denial body", True)
    if type(status) is int and 200 <= status < 300:
        return ("CONFIRMED",
                "The authorization control returned another account's record on its own; the "
                "interaction could not be blamed for it", True)
    return ("INCONCLUSIVE",
            "The denial baseline established neither a checked denial nor an undened read", False)


def rejection_verdict(status, body, rejection_body, actor, owner):
    """The authentication control passes only with the exact declared rejection."""
    effect = observe_identity(body, field="identity", actor=actor, target=owner)
    verdict, reason = credential_rejection_decision(
        status, body, expected_denial_body=rejection_body, identity_effect=effect)
    return verdict, reason, verdict != "INCONCLUSIVE"


def _marker(value, owner_baseline):
    return (isinstance(value, str) and bool(value.strip()) and len(value) <= 4096
            and "*" not in value and value.strip().casefold() not in _MARKER_PLACEHOLDERS
            and isinstance(owner_baseline, str) and value == owner_baseline)


def disclosure_impact(body, *, owner_baseline, owner_id, owner, private_field):
    """Decide what the combined response actually disclosed.

    ``private_data`` needs the owner's own baseline marker *and* a body that still
    identifies itself as the owner's record. A matched marker with incomplete
    identity is ambiguous, never confirmed.
    """
    if not isinstance(body, dict):
        return "none", "The combined response was not an unambiguous JSON object"
    value = extract(body, private_field)
    if value is MISSING or not _marker(value, owner_baseline):
        return ("none",
                "The combined response did not carry the private marker recorded on the owner's "
                "own baseline")
    observed_id = extract(body, "id")
    observed_owner = extract(body, "owner")
    if observed_id == owner_id and observed_owner == owner:
        return ("private_data",
                "The combined response carried the owner's private marker with the owner's "
                "record identity")
    return ("ambiguous",
            "The private marker was observed but the record identity in the response was "
            "incomplete")


def _project_scope(scope):
    return {
        "origin": scope.origin, "mode": scope.mode, "hostname": scope.hostname,
        "port": scope.port, "scheme": scope.scheme,
        "written_authorization_reference": scope.written_authorization_reference,
        "scope_sha256": digest(scope.model_dump(mode="json")),
        "request_budget": scope.request_budget,
        "accounts": [{"account": item.account, "role": item.role} for item in scope.accounts],
        "operations": [{"method": item.method, "path": item.path,
                        "classification": item.classification} for item in scope.operations],
    }


def _inventory(plan):
    from canarygate.api.schemas import InventoryEndpoint

    items = []
    for operation in plan.scope.operations:
        public = operation.classification == "AUTHENTICATION"
        detail = operation.path in {"/records/{id}/guarded", "/records/ra", "/records/rb"}
        if public:
            access, source = "public authentication operation", "TargetLab authentication contract"
        elif detail:
            access, source = "owner-only", "TargetLab record policy"
        else:
            access, source = "authenticated", "TargetLab scope"
        items.append(InventoryEndpoint(
            method=operation.method, path=operation.path, parameters=[],
            security=[] if public else [{"bearerAuth": []}],
            expected_access=access, expected_source=source).model_dump(mode="json"))
    return items


def _transport(scope):
    return {"mode": scope.mode, "scheme": scope.scheme, "destination": scope.hostname,
            "port": scope.port, "tls_verification": "pinned_test_ca_with_hostname_check",
            "redirects": "refused", "retries": "none", "dns": "not_used",
            "network_transport_enabled": True, "live_target_contacted": False,
            "production_networking": False}


def _ownership_view(ownership):
    if ownership is None:
        return {"status": "SKIPPED", "reason": "Ownership was not collected",
                "identities_verified": [], "owners": {}, "baselines_verified": {},
                "cross_list_isolated": False, "resource_ids_withheld": True}
    return {"status": ownership.ownership_status, "reason": ownership.reason,
            "identities_verified": list(ownership.identity_accounts),
            "owners": {account: True for account in ownership.ids},
            "baselines_verified": {account: True for account in ownership.baselines},
            "cross_list_isolated": ownership.ownership_status == "SUCCESS",
            "resource_ids_withheld": True}


def _baseline(check_id, control, *, endpoint, action, probe, verdict, reason, observable, evidence):
    return SciBaseline(id=check_id, control=control, endpoint=endpoint, action=action,
                       probe=probe, verdict=verdict, reason=reason[:1024],
                       observable=observable, evidence=evidence,
                       evidence_sha256=digest({"id": check_id, "evidence": evidence}))


def _skipped_baseline(check_id, control, *, endpoint, action, probe, reason):
    evidence = {"executed": False, "status": None, "sequence": None}
    return _baseline(check_id, control, endpoint=endpoint, action=action, probe=probe,
                     verdict="INCONCLUSIVE", reason=reason, observable=False, evidence=evidence)


def _seal(plan, runner, *, baselines, combined, decision, ownership, disclosure, status):
    stats = runner.stats()
    scope = runner.scope
    legs = [item.evidence for item in baselines] + [combined.model_dump(mode="json")]
    return InteractionRun(
        id=str(uuid.uuid4()), created_at=_now(), mode="targetlab_sci", status=status,
        scenario_id=plan.scenario_id, title=plan.title, interaction_kind=plan.kind,
        controls=list(plan.controls), policy_source=plan.policy_source,
        scope=_project_scope(scope), accounts=list(plan.accounts),
        baselines=list(baselines), combined=combined,
        verdict=decision.verdict, reason=decision.reason, attribution=decision.attribution,
        remediation_key=decision.remediation_key,
        remediation=(SCI_REMEDIATIONS[decision.remediation_key]
                     if decision.remediation_key else None),
        checklist=decision.checklist,
        transcript_sha256=digest(legs),
        requests_sent=stats["requests_sent"], blocked_by_guard=stats["blocked_by_guard"],
        budget_remaining=stats["budget_remaining"],
        network_transport_enabled=True, integration_origin="loopback_lab",
        transport=_transport(scope), ownership=_ownership_view(ownership), disclosure=disclosure,
        inventory=_inventory(plan), limitations=list(LIMITATIONS))


def _closed_run(plan, runner, reason):
    """No evidence at all: every leg fails closed and nothing is claimed."""
    baselines = (
        _skipped_baseline("SCI-AUTHZ", "Authorization",
                          endpoint=f"GET {plan.resource.detail.path}", action="get", probe=None,
                          reason=reason),
        _skipped_baseline("SCI-AUTHN", "Authentication",
                          endpoint=f"POST {plan.login_path}", action="submit", probe=plan.probe,
                          reason=reason))
    combined = SciCombined(endpoint=f"GET {plan.resource.detail.path}", action="get_after",
                           probe=plan.probe, executed=False, permitted=True, verified=False,
                           status=None, impact="none", observed="the interaction was not executed")
    decision = _decide(plan, baselines, combined)
    disclosure = {"owner_baseline_collected": False, "marker_matches_owner_baseline": False,
                  "marker_withheld": True}
    return _seal(plan, runner, baselines=baselines, combined=combined, decision=decision,
                 ownership=None, disclosure=disclosure, status="failed")


def _decide(plan, baselines, combined):
    return decide(kind=plan.kind,
                  baselines=[Baseline(id=item.id, control=item.control, verdict=item.verdict,
                                      observable=item.observable) for item in baselines],
                  combined=Combined(executed=combined.executed, permitted=combined.permitted,
                                    verified=combined.verified, status=combined.status,
                                    impact=combined.impact, observed=combined.observed))


def run_lab_sci_scan(plan, runner, *, store=None):
    """Execute the declared interaction once and return the validated run."""
    actor, owner = plan.accounts
    endpoint = f"GET {plan.resource.detail.path}"

    for account in plan.accounts:
        try:
            authenticated = runner.login(account)
        except TargetLabRefused:
            # A refused or failed connection is not evidence about the account: it is
            # a transport failure and must reach the caller, not be stored as a run.
            raise
        except ValueError:
            authenticated = False
        if not authenticated:
            return _finish(_closed_run(plan, runner, "Account authentication was not established"),
                           store)

    ownership = collect_guarded_ownership(
        runner, resource_type="record", resource=plan.resource, accounts=plan.accounts,
        profile_path=plan.profile_path, identity_field="identity")
    if ownership.ownership_status != "SUCCESS":
        return _finish(_closed_run(plan, runner,
                                   "Verified private ownership and owner baselines were not "
                                   "established"), store)

    owner_response = ownership.baselines[owner][0]
    owner_body = _body(owner_response)
    owner_marker = extract(owner_body, plan.resource.private_field) if isinstance(owner_body, dict) else MISSING
    owner_id = ownership.ids[owner]

    # Leg 1: the authorization control on its own. Same actor, same target, same path
    # as the combined read; only the preceding rejected login differs.
    own_read_path = plan.resource.detail.path.replace("{id}", owner_id)
    sequence = {"authorization": 1}
    try:
        denial = runner.get(actor, own_read_path)
        denial_verified = runner.verifies_recorded_read(denial, actor, own_read_path)
    except TargetLabRefused:
        raise
    except ValueError:
        denial, denial_verified = None, False
    if denial is None or not denial_verified:
        return _finish(_closed_run(plan, runner,
                                   "The denial baseline could not be executed or verified"),
                       store)
    denial_verdict, denial_reason, denial_observable = guarded_denial_verdict(
        denial.status_code, _body(denial), plan.denial_body)
    authorization = _baseline(
        "SCI-AUTHZ", "Authorization", endpoint=endpoint, action="get", probe=None,
        verdict=denial_verdict, reason=denial_reason, observable=denial_observable,
        evidence={"status": denial.status_code, "verified": True, "sequence": sequence["authorization"],
                  "actor": actor, "target_owner": owner, "checked_denial": denial_verdict == "SAFE"})

    # Leg 2: the authentication control on its own, through the declared probe.
    sequence["authentication"] = 2
    try:
        probe_response = runner.submit(actor, plan.login_path, plan.probe,
                                       plan.probe_body(actor))
        probe_verified = runner.verifies_response(probe_response, actor, plan.login_path)
    except TargetLabRefused:
        raise
    except ValueError:
        probe_response, probe_verified = None, False
    if probe_response is None or not probe_verified:
        baselines = (authorization,
                     _skipped_baseline("SCI-AUTHN", "Authentication",
                                       endpoint=f"POST {plan.login_path}", action="submit",
                                       probe=plan.probe,
                                       reason="The rejected-login probe could not be executed"))
        combined = SciCombined(endpoint=endpoint, action="get_after", probe=plan.probe,
                               executed=False, permitted=True, verified=False, status=None,
                               impact="none",
                               observed="the combined read was not attempted because the probe "
                                        "was not executed")
        decision = _decide(plan, baselines, combined)
        return _finish(_seal(plan, runner, baselines=baselines, combined=combined,
                             decision=decision, ownership=ownership,
                             disclosure={"owner_baseline_collected": True,
                                         "marker_matches_owner_baseline": False,
                                         "marker_withheld": True},
                             status="completed"), store)
    probe_verdict, probe_reason, probe_observable = rejection_verdict(
        probe_response.status_code, _body(probe_response), plan.rejection_body, actor, owner)
    authentication = _baseline(
        "SCI-AUTHN", "Authentication", endpoint=f"POST {plan.login_path}", action="submit",
        probe=plan.probe, verdict=probe_verdict, reason=probe_reason,
        observable=probe_observable,
        evidence={"status": probe_response.status_code, "verified": True,
                  "sequence": sequence["authentication"], "actor": actor, "probe": plan.probe,
                  "checked_rejection": probe_verdict == "SAFE"})

    # Leg 3: the same read again, after the rejected login.
    sequence["combined"] = 3
    try:
        combined_response = runner.get(actor, own_read_path)
        combined_verified = runner.verifies_recorded_read(combined_response, actor, own_read_path)
    except TargetLabRefused:
        raise
    except ValueError as error:
        combined = SciCombined(endpoint=endpoint, action="get_after", probe=plan.probe,
                               executed=False, permitted="budget" not in str(error).lower(),
                               verified=False, status=None, impact="none",
                               observed="the combined read was not executed")
        decision = _decide(plan, (authorization, authentication), combined)
        return _finish(_seal(plan, runner, baselines=(authorization, authentication),
                             combined=combined, decision=decision, ownership=ownership,
                             disclosure={"owner_baseline_collected": True,
                                         "marker_matches_owner_baseline": False,
                                         "marker_withheld": True},
                             status="completed"), store)
    impact, impact_reason = disclosure_impact(
        _body(combined_response), owner_baseline=owner_marker, owner_id=owner_id, owner=owner,
        private_field=plan.resource.private_field)
    if not combined_verified:
        impact = "none"
        impact_reason = "The combined response could not be verified in this run"
    combined = SciCombined(
        endpoint=endpoint, action="get_after", probe=plan.probe, executed=True, permitted=True,
        verified=bool(combined_verified), status=combined_response.status_code, impact=impact,
        observed=(f"status {combined_response.status_code}; "
                  + ("the owner's private marker was returned after a rejected login"
                     if impact == "private_data"
                     else impact_reason))[:512])

    baselines = (authorization, authentication)
    decision = _decide(plan, baselines, combined)
    disclosure = {"actor": actor, "owner": owner,
                  "owner_baseline_collected": True,
                  "owner_baseline_verified": True,
                  "marker_matches_owner_baseline": impact == "private_data",
                  "marker_withheld": True,
                  "private_field": plan.resource.private_field,
                  "identifiers_withheld": True}
    return _finish(_seal(plan, runner, baselines=baselines, combined=combined, decision=decision,
                         ownership=ownership, disclosure=disclosure, status="completed"), store)


def _finish(run, store):
    return store.save(run) if store is not None else run


def run_lab_sci_reset(plan, runner_a, runner_b):
    """Prove the lab condition is set by a rejected login and cleared by a success.

    Two guarded runs are required: a single run may authenticate an account only
    once, and the reset *is* a second successful login.
    """
    from canarygate.scan.lab_scenarios import ASSET_IDS

    actor, owner = plan.accounts
    # The declared asset of the owner, resolved from the same constant the scenarios
    # use. The owner baseline below still has to return that id; if it does not, the
    # marker match fails and the proof is not "proven" rather than being guessed.
    path = plan.resource.detail.path.replace("{id}", ASSET_IDS[owner])
    checks = []

    def record(check_id, title, endpoint, expected, response, verified, observed, pass_rule):
        status = response.status_code if response is not None else None
        passed = bool(verified and status == expected and pass_rule)
        evidence = {"status": status, "expected": expected, "verified": bool(verified)}
        checks.append(ResetCheck(
            id=check_id, title=title, endpoint=endpoint, actor=actor, expected_status=expected,
            status=status, observed=observed[:512], passed=passed,
            evidence_sha256=digest({"id": check_id, "evidence": evidence})))

    owner_marker, owner_id = MISSING, None
    if True:  # one sequential block; any failure simply leaves the checks short
        runner_a.login(actor)
        runner_a.login(owner)
        owner_baseline = runner_a.get(owner, path)
        owner_body = _body(owner_baseline)
        if runner_a.verifies_recorded_read(owner_baseline, owner, path) and owner_baseline.status_code == 200 \
                and isinstance(owner_body, dict):
            owner_marker = extract(owner_body, plan.resource.private_field)
            owner_id = extract(owner_body, "id")
            if owner_id != ASSET_IDS[owner]:
                owner_marker, owner_id = MISSING, None

        before = runner_a.get(actor, path)
        record("RESET-01", "the guarded read is denied before any rejected login",
               f"GET {plan.resource.detail.path}", 403, before,
               runner_a.verifies_recorded_read(before, actor, path),
               "the condition was clear: the guarded read was denied",
               _body(before) == plan.denial_body)

        probe = runner_a.submit(actor, plan.login_path, plan.probe, plan.probe_body(actor))
        record("RESET-02", "a rejected login is refused and sets the condition",
               f"POST {plan.login_path}", 401, probe,
               runner_a.verifies_response(probe, actor, plan.login_path),
               "the rejected login was refused with the declared body",
               _body(probe) == plan.rejection_body)

        after = runner_a.get(actor, path)
        leaked = _body(after)
        marker_matches = (isinstance(leaked, dict)
                          and _marker(extract(leaked, plan.resource.private_field), owner_marker)
                          and extract(leaked, "owner") == owner)
        record("RESET-03", "the same guarded read succeeds after the rejected login",
               f"GET {plan.resource.detail.path}", 200, after,
               runner_a.verifies_recorded_read(after, actor, path),
               "the condition was set: the guarded read returned the owner's record",
               marker_matches)

        # The clearing login lives in its own run, so it is a second one-shot attempt.
        runner_b.login(actor)

        cleared = runner_a.get(actor, path)
        record("RESET-04", "a successful login clears the condition again",
               f"GET {plan.resource.detail.path}", 403, cleared,
               runner_a.verifies_recorded_read(cleared, actor, path),
               "the condition was cleared: the guarded read was denied again",
               _body(cleared) == plan.denial_body)

    proven = len(checks) == 4 and all(check.passed for check in checks)
    stats_a, stats_b = runner_a.stats(), runner_b.stats()
    scope = runner_a.scope
    return LabResetProof(
        id=str(uuid.uuid4()), created_at=_now(), mode="targetlab_sci_reset",
        scenario_id=f"{plan.scenario_id}-reset", status="proven" if proven else "not_proven",
        reason=("A successful login cleared the lab condition: the same guarded read that leaked "
                "the owner's record after a rejected login was denied again afterwards"
                if proven else
                "The reset sequence did not reproduce the lab condition and its clearing"),
        port=scope.port, checks=checks,
        isolation={"runners": 2, "state": "fresh_run_clears_the_condition",
                   "why": ("One run may authenticate an account only once by design, so the "
                           "clearing login runs in its own guarded run. The lab clears the "
                           "condition on a successful login, never on a read.")},
        disclosure={"owner": owner, "actor": actor, "owner_baseline_collected": owner_id is not None,
                    "marker_matches_owner_baseline": proven,
                    "marker_withheld": True},
        transport=_transport(scope),
        requests={"runner_a": stats_a["requests_sent"], "runner_b": stats_b["requests_sent"],
                  "total": stats_a["requests_sent"] + stats_b["requests_sent"],
                  "budget_per_runner": scope.request_budget,
                  "remaining": {"runner_a": stats_a["budget_remaining"],
                                "runner_b": stats_b["budget_remaining"]}},
        limitations=list(_RESET_LIMITATIONS))
