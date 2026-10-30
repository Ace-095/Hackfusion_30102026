"""Fixture-only read-only validation and disclosure probes.

The five literal requests are independently approved in the fixture scope.
They are not a generic user-input fuzzing facility or a live-target scanner.
"""
import yaml

from canarygate.guard.safety_guard import GuardRejected
from canarygate.offline.runner import FixtureResponseTooLarge
from canarygate.oracles.disclosure import disclosure_signals, inspect_sensitive_json, inspect_extra_fields
from canarygate.oracles.validation import input_verdict

INPUT_CASES = (
    ("INPUT-01", "/search", "missing_required_limit"),
    ("INPUT-02", "/search?limit=notanumber", "wrong_type"),
    ("INPUT-04", "/search?limit=999", "out_of_range"),
    ("INPUT-03", "/search?limit=9", "invalid_enum_limit"),
)
DISC_CASES = (("DISC-01", "stack_trace"), ("DISC-02", "internal_error_detail"),
              ("DISC-05", "version_header"))


def _skipped(check_id, category, reason):
    return {"id": check_id, "category": category, "verdict": "SKIPPED", "reason": reason,
            "evidence": None, "remediation": None}


def pending_input_checks(reason="Fixture validation prerequisites were not met"):
    checks = [_skipped(check_id, "Input validation", reason) for check_id, _, _ in INPUT_CASES]
    checks += [_skipped(check_id, "Disclosure", reason) for check_id, _ in DISC_CASES]
    checks += [_skipped(check_id, "Disclosure", reason) for check_id in ("DISC-03", "DISC-04")]
    for check_id, category, why in (
        ("INPUT-05", "Input validation", "Extra property check not implemented"),
        ("INPUT-06", "Input validation", "Malformed JSON check not implemented"),
        ("INPUT-07", "Input validation", "Special characters check not implemented"),
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
                    and schema.get("type") == "integer" and type(schema.get("minimum")) is int
                    and type(schema.get("maximum")) is int and schema.get("minimum") == 1
                    and schema.get("maximum") == 10):
                return True
    return False


def _spec_supports_enum(endpoints):
    # The literal control (1) must be allowed and the probe (9) must be within
    # the declared numeric range but outside the explicitly declared enum.
    for endpoint in endpoints:
        if endpoint["method"] != "GET" or endpoint["path"] != "/search" or endpoint["expected_access"] != "authenticated":
            continue
        for parameter in endpoint["parameters"]:
            schema = parameter.get("schema")
            if parameter.get("name") != "limit" or parameter.get("in") != "query" or not isinstance(schema, dict):
                continue
            choices = schema.get("enum")
            if (schema.get("type") == "integer" and type(schema.get("minimum")) is int
                    and type(schema.get("maximum")) is int and schema.get("minimum") == 1 and schema.get("maximum") == 10
                    and isinstance(choices, list) and choices and all(type(value) is int for value in choices)
                    and 1 in choices and 9 not in choices):
                return True
    return False


def _fixture_response_schemas(spec_text):
    # This is the bundled, already-parsed fixture snapshot, never an uploaded spec.
    # Only explicit application/json response schemas are considered by the oracle.
    if not spec_text:
        return {}
    try:
        doc = yaml.safe_load(spec_text)
        responses = doc["paths"]["/search"]["get"]["responses"]
        if not isinstance(responses, dict):
            return {}
        result = {}
        for status, response in responses.items():
            if isinstance(response, dict):
                content = response.get("content", {})
                media = content.get("application/json", {}) if isinstance(content, dict) else {}
                schema = media.get("schema") if isinstance(media, dict) else None
                if isinstance(schema, dict):
                    result[str(status)] = schema
        return result
    except (yaml.YAMLError, TypeError, KeyError, ValueError):
        return {}


def run_input_checks(runner, *, actor, role, token, endpoints, summary, spec_text=None):
    checks = pending_input_checks()
    if not _spec_supports_cases(endpoints):
        return checks
    enum_applicable = _spec_supports_enum(endpoints)
    expected_responses = 1 + len(INPUT_CASES) - (0 if enum_applicable else 1)
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
        except (ValueError, UnicodeError, RecursionError):
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
            if check_id == "INPUT-03" and not enum_applicable:
                checks[index]["reason"] = "A compatible fixture enum was not declared; probe not executed"
                continue
            response, error = execute(path, label)
            if error == "blocked":
                checks[index]["reason"] = "Probe blocked by fixture scope, safety halt or budget; not executed"
                continue
            if error == "executed_oversized":
                checks[index].update(verdict="INCONCLUSIVE", reason="Probe executed but response exceeded fixture size limit")
                continue
            try:
                response_body = response.json()
            except (ValueError, UnicodeError, RecursionError):
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
        elif len(observed) == expected_responses and not incomplete:
            response, label, _ = observed[-1]
            checks[offset].update(verdict="SAFE", reason=f"No {signature} signature observed in {expected_responses} fixture responses",
                                  evidence=summary(actor, role, response, False, input_case=label,
                                                   inspected_fixture_responses=expected_responses, disclosure_signature=signature))
        elif observed:
            checks[offset].update(verdict="INCONCLUSIVE", reason="Fixture response coverage was incomplete; signature absence cannot establish safety")
        else:
            checks[offset]["reason"] = "No fixture response was inspected"
    # Inspect the same scoped fixture responses; no additional requests are sent.
    schemas = _fixture_response_schemas(spec_text)
    for check_id, signature, inspector, finding, remediation in (
        ("DISC-03", "sensitive_field", lambda response: inspect_sensitive_json(response),
         "CONFIRMED", "Do not return passwords, tokens, secrets or password hashes in responses."),
        ("DISC-04", "unexpected_top_level_field", lambda response: inspect_extra_fields(response, schemas),
         "SUSPECTED", "Review undocumented response fields and restrict response DTOs to the declared schema."),
    ):
        check = next(item for item in checks if item["id"] == check_id)
        inspected = [(response, label, *inspector(response)) for response, label, _ in observed]
        matched = next(((response, label) for response, label, found, _ in inspected if found), None)
        if matched:
            response, label = matched
            check.update(verdict=finding, reason=f"Fixture response contains {signature}; details are redacted",
                         evidence=summary(actor, role, response, False, input_case=label,
                                          disclosure_signature=signature), remediation=remediation)
        elif len(inspected) == expected_responses and not incomplete and all(complete for _, _, _, complete in inspected):
            response, label, _, _ = inspected[-1]
            check.update(verdict="SAFE", reason=f"No {signature} observed in {expected_responses} bounded fixture responses",
                         evidence=summary(actor, role, response, False, input_case=label,
                                          inspected_fixture_responses=expected_responses, disclosure_signature=signature))
        elif inspected:
            check.update(verdict="INCONCLUSIVE", reason="Fixture response inspection or coverage was incomplete")
        else:
            check["reason"] = "No fixture response was inspected"
    return checks
