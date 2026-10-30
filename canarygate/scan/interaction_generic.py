"""SCI orchestrator: run individual control baselines, then one combined exchange.

Both phases use the same guarded runner and the same validated scope. A combined
result is only CONFIRMED when both baselines were observable and passing, the
response verified in this run, and the declared policy was violated with a
demonstrated impact. Anything else is reported as an individual finding, an
incomplete baseline, an unverified response or a harmless variation.
"""
import hashlib
from datetime import datetime, timezone
from uuid import uuid4

from canarygate.evidence.redaction import canonical_json, redact
from canarygate.oracles.authn_probes import credential_rejection_decision
from canarygate.oracles.disclosure import disclosure_signals, signal_verdict
from canarygate.oracles.interaction import SCI_REMEDIATIONS, Baseline, Combined, decide
from canarygate.oracles.validation import (extra_property_decision, malformed_json_decision,
                                           special_characters_decision)
from canarygate.scan.interaction_models import InteractionRun, SciBaseline, SciCombined
from canarygate.scan.interaction_plan import SCI_POLICY_SOURCE

LIMITATIONS = (
    "Offline synthetic transcript only: no live target, socket, DNS lookup or redirect was used",
    "The combined exchange is a recorded synthetic response released after a declared input probe",
    "An individual control failure is reported as its own finding, never as a confirmed interaction",
    "A response variation without a demonstrated security impact is never CONFIRMED",
    "SKIPPED and INCONCLUSIVE results are not clean results",
)
_INPUT_DECISIONS = {
    "extra_property": None,
    "malformed_json": malformed_json_decision,
    "special_characters": special_characters_decision,
}


def _json_body(response):
    try:
        return response.json()
    except ValueError:
        return None


def _digest(value):
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


class InteractionOrchestrator:
    def __init__(self, plan, runner):
        self._plan = plan
        self._runner = runner
        self._actor = plan.accounts[0]
        self._observed = {}

    # ------------------------------------------------------------ execution
    def _execute(self, action, *, combined=False):
        """Run one declared action; return (response, verified, error)."""
        try:
            if action.action == "get":
                response = self._runner.get(self._actor, action.path)
                verified = self._runner.verifies_recorded_read(response, self._actor, action.path)
            elif action.action == "submit":
                response = self._runner.submit(self._actor, action.probe)
                verified = self._runner.verifies_recorded_submission(response, self._actor, action.probe)
            elif action.action == "auth_probe":
                response = self._runner.probe(self._actor, action.path, action.probe)
                verified = self._runner.verifies_recorded_probe(response, self._actor, "GET",
                                                                action.path, action.probe)
            elif action.action == "get_after":
                response = self._runner.get_after(self._actor, action.path, action.probe)
                verified = self._runner.verifies_combined_read(response, self._actor,
                                                               action.path, action.probe)
            else:  # pragma: no cover - the plan validator rejects this
                raise ValueError("unknown SCI action")
        except ValueError as exc:
            return None, False, str(exc)
        return response, bool(verified), None

    # ------------------------------------------------------------- baselines
    def _authorization_baseline(self, response):
        status = response.status_code
        if status in {401, 403}:
            return "SAFE", "The control denied the cross-account request with a stated denial", True
        if 200 <= status < 300:
            body = _json_body(response)
            marker = body.get(self._plan.private_marker_field) if isinstance(body, dict) else None
            if isinstance(marker, str) and marker.strip():
                return ("CONFIRMED",
                        "The control returned another account's private data on its own", True)
            return ("SUSPECTED",
                    "The control allowed the request but no private marker was observed", True)
        return ("INCONCLUSIVE",
                "The baseline did not establish whether the control denies cross-account access",
                False)

    def _input_baseline(self, action, response):
        if action.probe == "extra_property":
            verdict, reason = extra_property_decision(
                response.status_code, _json_body(response),
                field=self._plan.extra_property_field or "is_admin", effect_observed=False)
        else:
            verdict, reason = _INPUT_DECISIONS[action.probe](response.status_code,
                                                             _json_body(response))
        return verdict, reason, verdict != "INCONCLUSIVE"

    def _authentication_baseline(self, response):
        verdict, reason = credential_rejection_decision(
            response.status_code, _json_body(response),
            expected_denial_body=self._plan.denial_body, identity_effect="none")
        return verdict, reason, verdict != "INCONCLUSIVE"

    def _disclosure_baseline(self, response):
        verdict, reason = signal_verdict(disclosure_signals(response),
                                         self._plan.disclosure_signal or "stack_trace")
        return verdict, reason, True

    def _baseline(self, action):
        response, verified, error = self._execute(action)
        endpoint = f"{'POST' if action.action == 'submit' else 'GET'} {action.path}"
        if response is None:
            verdict, reason, observable = ("INCONCLUSIVE",
                                           f"The baseline could not be executed: {error}", False)
        elif not verified:
            verdict, reason, observable = ("INCONCLUSIVE",
                                           "The recorded baseline could not be verified in this run",
                                           False)
        elif action.control == "Authorization":
            verdict, reason, observable = self._authorization_baseline(response)
        elif action.control == "Input validation":
            verdict, reason, observable = self._input_baseline(action, response)
        elif action.control == "Authentication":
            verdict, reason, observable = self._authentication_baseline(response)
        else:
            verdict, reason, observable = self._disclosure_baseline(response)
        evidence = {"status": response.status_code if response is not None else None,
                    "action": action.action, "probe": action.probe,
                    "verified": bool(verified)}
        return SciBaseline(id=action.id, control=action.control, endpoint=endpoint,
                           action=action.action, probe=action.probe, verdict=verdict,
                           reason=reason, observable=observable, evidence=evidence,
                           evidence_sha256=_digest(evidence))

    # -------------------------------------------------------------- combined
    def _permitted_error(self, error):
        lowered = (error or "").lower()
        return "not permitted by preflight" in lowered or "budget exhausted" in lowered \
            or "not in the authorized scope" in lowered or "halted" in lowered

    def _impact(self, response):
        contract = self._plan.combined.impact
        if "signal" in contract:
            signals = disclosure_signals(response)
            return "internal_detail" if contract["signal"] in signals else "none"
        body = _json_body(response)
        value = body.get(contract["field"]) if isinstance(body, dict) else None
        matched = (value == contract["equals"] if "equals" in contract
                   else value not in (None, "", [], {}))
        if matched:
            return ("privileged_data" if self._plan.kind == "AUTHZ+INPUT_VALIDATION"
                    else "private_data")
        return "none"

    def _combined(self):
        action = self._plan.combined
        endpoint = f"{'POST' if action.action == 'submit' else 'GET'} {action.path}"
        precondition = None
        if action.action == "get_after":
            # The combined read exists only after the declared probe was accepted.
            from types import SimpleNamespace
            precondition = SimpleNamespace(action="submit", path=self._plan.login_path,
                                           probe=action.probe)
            probe_response, probe_verified, probe_error = self._execute(precondition)
            if probe_response is None or not probe_verified:
                permitted = not self._permitted_error(probe_error)
                observed = (f"the declared probe was blocked before the combined read: {probe_error}"
                            if probe_error else "the declared probe response was not verifiable")
                return SciCombined(endpoint=endpoint, action=action.action, probe=action.probe,
                                   executed=False, permitted=permitted, verified=False, status=None,
                                   impact="none", observed=observed[:512])
        response, verified, error = self._execute(action, combined=True)
        if response is None:
            permitted = not self._permitted_error(error)
            observed = (f"blocked before release: {error}" if permitted
                        else f"blocked by the shared run guard: {error}")
            return SciCombined(endpoint=endpoint, action=action.action, probe=action.probe,
                               executed=False, permitted=permitted, verified=False, status=None,
                               impact="none", observed=observed[:512])
        impact = self._impact(response) if verified else "none"
        observed = (f"status {response.status_code}; "
                    + ("the declared impact was observed" if impact != "none"
                       else "no declared impact was observed"))
        if not verified:
            observed = "the combined response could not be verified in this run"
        return SciCombined(endpoint=endpoint, action=action.action, probe=action.probe,
                           executed=True, permitted=True, verified=bool(verified),
                           status=response.status_code, impact=impact, observed=observed)

    # ------------------------------------------------------------------- run
    def run(self):
        baselines = tuple(self._baseline(action) for action in self._plan.baselines)
        combined = self._combined()
        decision = decide(kind=self._plan.kind,
                          baselines=[Baseline(id=item.id, control=item.control,
                                              verdict=item.verdict, observable=item.observable)
                                     for item in baselines],
                          combined=Combined(executed=combined.executed,
                                            permitted=combined.permitted,
                                            verified=combined.verified,
                                            status=combined.status,
                                            impact=combined.impact,
                                            observed=combined.observed))
        stats = self._runner.guard.stats()
        scope = self._plan.scope
        origin = f"{scope.scheme}://{scope.hostname}:{scope.port}"
        scope_dump = scope.model_dump(mode="json")
        scope_projection = {
            "origin": origin, "hostname": scope.hostname, "port": scope.port,
            "written_authorization_reference": scope.written_authorization_reference,
            "scope_sha256": hashlib.sha256(canonical_json(scope_dump).encode("utf-8")).hexdigest(),
            "request_budget": scope.request_budget,
            "accounts": [{"account": item.account, "role": item.role} for item in scope.accounts],
        }
        run = InteractionRun(
            id=str(uuid4()),
            created_at=datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            mode="offline_interaction", status="completed",
            scenario_id=self._plan.scenario_id, title=self._plan.title,
            interaction_kind=self._plan.kind, controls=list(self._plan.controls()),
            policy_source=SCI_POLICY_SOURCE, scope=scope_projection,
            accounts=list(self._plan.accounts), baselines=list(baselines), combined=combined,
            verdict=decision.verdict, reason=decision.reason,
            attribution=decision.attribution,
            remediation_key=decision.remediation_key,
            remediation=(SCI_REMEDIATIONS[decision.remediation_key]
                         if decision.remediation_key else None),
            checklist=decision.checklist,
            transcript_sha256=self._runner.transcript_sha256,
            requests_sent=stats["requests_sent"], blocked_by_guard=stats["blocked_by_guard"],
            budget_remaining=stats["budget_remaining"], network_transport_enabled=False,
            inventory=list(self._plan.inventory), limitations=list(LIMITATIONS))
        return InteractionRun.model_validate(redact(run.model_dump(mode="json")))


def run_offline_interaction(plan, runner, *, store=None):
    run = InteractionOrchestrator(plan, runner).run()
    if store is not None:
        store.save(run)
    return run
