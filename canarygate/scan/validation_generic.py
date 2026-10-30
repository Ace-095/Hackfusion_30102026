"""Generic orchestrator for safe input-validation and disclosure checks.

One guarded runner performs every submission and read. Each observed response
must verify against the same run guard before it may inform a verdict, and any
malformed or unverifiable response makes the affected check INCONCLUSIVE.
"""
from datetime import datetime, timezone
from uuid import uuid4

from canarygate.evidence.redaction import redact
from canarygate.oracles.disclosure import (disclosure_signals, excess_fields_decision,
                                           inspect_extra_fields, inspect_sensitive_payload,
                                           sensitive_field_decision, signal_verdict)
from canarygate.oracles.validation import (enumeration_decision, extra_property_decision,
                                           malformed_json_decision, special_characters_decision)
from canarygate.scan.validation_models import (CHECK_CATEGORIES, CHECK_ORDER, REMEDIATIONS,
                                               ValidationCheck, ValidationRun,
                                               ValidationSummary)
from canarygate.scan.validation_plan import VALIDATION_POLICY_SOURCE

_CONTROL_STATUSES = frozenset(range(200, 300)) | {401, 403}
LIMITATIONS = (
    "Offline synthetic transcript only: no live target, socket, DNS lookup or redirect was used",
    "Judgements rest on recorded status codes, bounded error bodies and the declared spec contract",
    "INPUT-05 reports acceptance only; no persistence or state effect is verified in this MVP",
    "INPUT-07 observes error handling only; acceptance is not evidence of injection",
    "SKIPPED and INCONCLUSIVE results are not clean results",
)


def _json_body(response):
    try:
        return response.json()
    except ValueError:
        return None


def _check(check_id, verdict, reason, *, probes=(), evidence=None):
    return ValidationCheck(id=check_id, category=CHECK_CATEGORIES[check_id], verdict=verdict,
                           reason=reason, request_probes=list(probes), evidence=evidence,
                           remediation=REMEDIATIONS[check_id] if verdict == "CONFIRMED" else None)


class ValidationOrchestrator:
    def __init__(self, plan, runner):
        self._plan = plan
        self._runner = runner
        self._responses = {}
        self._results = {}

    def _submit_once(self, actor, probe):
        """Submit one declared probe at most once, reusing its verified response."""
        if probe in self._responses:
            return self._responses[probe]
        response = self._runner.submit(actor, probe)
        if not self._runner.verifies_recorded_submission(response, actor, probe):
            return None
        self._responses[probe] = response
        return response

    def _control_usable(self):
        response = self._submit_once(self._plan.accounts[0], "control")
        return response is not None and response.status_code in _CONTROL_STATUSES

    def _unverified(self, check_id, probe, reason):
        return _check(check_id, "INCONCLUSIVE", reason, probes=(probe,),
                      evidence={"probe": probe, "path": self._plan.login_path})

    def _validation_result(self, check_id, probe, decide):
        response = self._submit_once(self._plan.accounts[0], probe)
        if response is None:
            return self._unverified(check_id, probe,
                                    "The recorded response could not be verified in this run")
        verdict, reason = decide(response.status_code, _json_body(response))
        if verdict == "SAFE" and not self._control_usable():
            verdict, reason = ("INCONCLUSIVE",
                              "No verified control response established that the operation accepts valid input")
        return _check(check_id, verdict, reason, probes=(probe,),
                      evidence={"probe": probe, "path": self._plan.login_path,
                                "status": response.status_code})

    def extra_property(self):
        return self._validation_result(
            "INPUT-05", "extra_property",
            lambda status, body: extra_property_decision(status, body,
                                                         field=self._plan.extra_property_field,
                                                         effect_observed=False))

    def malformed_json(self):
        return self._validation_result("INPUT-06", "malformed_json", malformed_json_decision)

    def special_characters(self):
        return self._validation_result("INPUT-07", "special_characters", special_characters_decision)

    def _disclosure_read(self, check_id, path, signal):
        actor = self._plan.accounts[0]
        response = self._read(actor, path)
        verdict, reason = signal_verdict(disclosure_signals(response), signal)
        return _check(check_id, verdict, reason,
                      evidence={"path": path, "status": response.status_code})

    def stack_trace(self):
        return self._disclosure_read("DISC-01", self._plan.stack_trace_path, "stack_trace")

    def internal_detail(self):
        return self._disclosure_read("DISC-02", self._plan.internal_detail_path,
                                     "internal_error_detail")

    def _read(self, actor, path):
        response = self._runner.get(actor, path)
        if not self._runner.verifies_recorded_read(response, actor, path):
            raise ValueError("the recorded read could not be verified in this run")
        return response

    def sensitive_fields(self):
        actor = self._plan.accounts[0]
        response = self._read(actor, self._plan.sensitive_path)
        signals, complete = inspect_sensitive_payload(response)
        verdict, reason = sensitive_field_decision(signals, complete)
        return _check("DISC-03", verdict, reason,
                      evidence={"path": self._plan.sensitive_path,
                                "status": response.status_code,
                                "signals": sorted(signals)})

    def excess_fields(self):
        actor = self._plan.accounts[0]
        response = self._read(actor, self._plan.sensitive_path)
        if self._plan.response_schemas is None:
            # Not performed: without a declared schema the comparison cannot run.
            return _check("DISC-04", "SKIPPED",
                          "No declared response schema contract is available; comparison not performed")
        excess, usable = inspect_extra_fields(response, self._plan.response_schemas)
        verdict, reason = excess_fields_decision(excess, usable)
        return _check("DISC-04", verdict, reason,
                      evidence={"path": self._plan.sensitive_path,
                                "status": response.status_code,
                                "excess_fields": bool(excess)})

    def server_headers(self):
        actor = self._plan.accounts[0]
        response = self._read(actor, self._plan.sensitive_path)
        signals = disclosure_signals(response)
        verdict, reason = signal_verdict(signals, "version_header")
        if verdict != "CONFIRMED":
            debug_verdict, debug_reason = signal_verdict(signals, "debug_header")
            if debug_verdict == "CONFIRMED":
                verdict, reason = debug_verdict, debug_reason
        return _check("DISC-05", verdict, reason,
                      evidence={"path": self._plan.sensitive_path,
                                "status": response.status_code})

    def enumeration(self):
        actor = self._plan.accounts[0]
        known = self._read(actor, self._plan.known_denied_path)
        unknown = self._read(actor, self._plan.unknown_denied_path)
        verdict, reason = enumeration_decision(known.status_code, _json_body(known),
                                               unknown.status_code, _json_body(unknown))
        return _check("DISC-06", verdict, reason,
                      evidence={"known_status": known.status_code,
                                "unknown_status": unknown.status_code})

    def _run_step(self, step):
        try:
            return step()
        except ValueError:
            return None

    def run(self):
        steps = (self.extra_property, self.malformed_json, self.special_characters,
                 self.stack_trace, self.internal_detail, self.sensitive_fields,
                 self.excess_fields, self.server_headers, self.enumeration)
        for step in steps:
            result = self._run_step(step)
            if result is not None:
                self._results[result.id] = result
        checks = [self._results.get(check_id) or _check(
            check_id, "INCONCLUSIVE",
            "The check could not be completed with verifiable evidence in this run")
            for check_id in CHECK_ORDER]
        counted = {name: 0 for name in ("CONFIRMED", "INCONCLUSIVE", "SAFE", "SKIPPED", "SUSPECTED")}
        for item in checks:
            counted[item.verdict] += 1
        stats = self._runner.guard.stats()
        run = ValidationRun(
            id=str(uuid4()),
            created_at=datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            mode="offline_validation", status="completed",
            scenario_id=self._plan.scenario_id, title=self._plan.title,
            transport=self._runner.transport_label, network_transport_enabled=False,
            policy_source=VALIDATION_POLICY_SOURCE, scope=self._plan.scope,
            accounts=list(self._plan.accounts), checks=checks,
            summary=ValidationSummary(total=9, executed=9 - counted["SKIPPED"],
                                      confirmed=counted["CONFIRMED"], suspected=counted["SUSPECTED"],
                                      safe=counted["SAFE"], inconclusive=counted["INCONCLUSIVE"],
                                      skipped=counted["SKIPPED"]),
            transcript_sha256=self._runner.transcript_sha256,
            requests_sent=stats["requests_sent"], blocked_by_guard=stats["blocked_by_guard"],
            budget_remaining=stats["budget_remaining"],
            limitations=list(LIMITATIONS))
        return ValidationRun.model_validate(redact(run.model_dump(mode="json")))


def run_offline_validation(plan, runner, *, store=None):
    run = ValidationOrchestrator(plan, runner).run()
    if store is not None:
        store.save(run)
    return run
