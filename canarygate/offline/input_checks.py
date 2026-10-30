"""Fixture-only read-only validation and disclosure probes.

The four literal requests are independently approved in the fixture scope.
They are not a generic user-input fuzzing facility or a live-target scanner.
"""
from canarygate.guard.safety_guard import GuardRejected
from canarygate.offline.runner import FixtureResponseTooLarge
from canarygate.oracles.disclosure import disclosure_signals
from canarygate.oracles.validation import input_verdict

INPUT_CASES = (
    ("INPUT-01", "/search", "missing_required_limit"),
    ("INPUT-02", "/search?limit=notanumber", "wrong_type"),
    ("INPUT-04", "/search?limit=999", "out_of_range"),
)
DISC_CASES = (("DISC-01", "stack_trace"), ("DISC-02", "internal_error_detail"),
              ("DISC-05", "version_header"))


def _skipped(check_id, category, reason):
    return {"id": check_id, "category": category, "verdict": "SKIPPED", "reason": reason,
            "evidence": None, "remediation": None}


def pending_input_checks(reason="Fixture validation prerequisites were not met"):
    checks = [_skipped(check_id, "Input validation", reason) for check_id, _, _ in INPUT_CASES]
    checks += [_skipped(check_id, "Disclosure", reason) for check_id, _ in DISC_CASES]
    for check_id, category, why in (
        ("INPUT-03", "Input validation", "Enum check not implemented"),
        ("INPUT-05", "Input validation", "Extra property check not implemented"),
        ("INPUT-06", "Input validation", "Malformed JSON check not implemented"),
        ("INPUT-07", "Input validation", "Special characters check not implemented"),
        ("DISC-03", "Disclosure", "Sensitive-field check not implemented"),
        ("DISC-04", "Disclosure", "Response-schema comparison not implemented"),
        ("DISC-06", "Disclosure", "Resource-enumeration comparison not implemented"),
    ):
        checks.append(_skipped(check_id, category, why))
    return checks


def _spec_supports_cases(endpoints):
    for endpoint in endpoints:
        if endpoint["method"] != "GET" or endpoint["path"] != "/search" or endpoint["expected_access"] != "authenticated":
            continue
        for parameter in endpoint["parameters"]:
            schema = parameter.get("schema")
            if (parameter.get("name") == "limit" and parameter.get("in") == "query"
                    and parameter.get("required") is True and isinstance(schema, dict)
                    and schema.get("type") == "integer" and schema.get("minimum") == 1
                    and schema.get("maximum") == 10):
                return True
    return False


def run_input_checks(runner, *, actor, role, token, endpoints, summary):
    checks = pending_input_checks()
    if not _spec_supports_cases(endpoints):
        return checks
    observed = []  # (response, synthetic case label, signature names)
    incomplete = False

    def execute(path, label):
        nonlocal incomplete
        try:
            response = runner.request(actor, "GET", runner.scope.origin + path, token=token)
        except FixtureResponseTooLarge:
            incomplete = True
            return None, "executed_oversized"
        except GuardRejected:
            incomplete = True
            return None, "blocked"
        signals = disclosure_signals(response)
        observed.append((response, label, signals))
        if 300 <= response.status_code < 400 or response.status_code in (401, 403, 423, 429):
            incomplete = True
        return response, None

    control, control_error = execute("/search?limit=1", "valid_control")
    control_ok = False
    if control is not None and control.status_code == 200:
        try:
            control_body = control.json()
            control_ok = isinstance(control_body, dict) and isinstance(control_body.get("results"), list)
        except ValueError:
            pass
    if not control_ok:
        incomplete = True
        why = "Valid control was not established; invalid-input probes not executed"
        if control_error == "executed_oversized":
            why = "Valid control executed but exceeded the fixture response size limit"
        for index in range(len(INPUT_CASES)):
            checks[index]["reason"] = why
    else:
        for index, (check_id, path, label) in enumerate(INPUT_CASES):
            response, error = execute(path, label)
            if error == "blocked":
                checks[index]["reason"] = "Probe blocked by fixture scope, safety halt or budget; not executed"
                continue
            if error == "executed_oversized":
                checks[index].update(verdict="INCONCLUSIVE", reason="Probe executed but response exceeded fixture size limit")
                continue
            try:
                response_body = response.json()
            except ValueError:
                response_body = None
            verdict, reason = input_verdict(response.status_code, response_body)
            checks[index].update(verdict=verdict, reason=reason,
                                 evidence=summary(actor, role, response, False, input_case=label,
                                                  valid_control_observed=True),
                                 remediation="Validate input against the declared schema on the server." if verdict == "SUSPECTED" else None)

    for offset, (check_id, signature) in enumerate(DISC_CASES, start=len(INPUT_CASES)):
        matched = next(((response, label) for response, label, signals in observed if signature in signals), None)
        if matched:
            response, label = matched
            checks[offset].update(verdict="CONFIRMED", reason=f"Disclosure signature observed in fixture response: {signature}",
                                  evidence=summary(actor, role, response, False, input_case=label,
                                                   disclosure_signature=signature),
                                  remediation="Return generic errors and suppress framework or version details.")
        elif len(observed) == 4 and not incomplete:
            response, label, _ = observed[-1]
            checks[offset].update(verdict="SAFE", reason=f"No {signature} signature observed in the four fixture responses",
                                  evidence=summary(actor, role, response, False, input_case=label,
                                                   inspected_fixture_responses=4, disclosure_signature=signature))
        elif observed:
            checks[offset].update(verdict="INCONCLUSIVE", reason="Fixture response coverage was incomplete; signature absence cannot establish safety")
        else:
            checks[offset]["reason"] = "No fixture response was inspected"
    return checks
