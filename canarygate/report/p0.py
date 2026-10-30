"""Frozen nine-section P0 report (spec section 12) for stored offline runs.

The report explains what was tested, what was not, why each verdict was reached
and which safety constraints were enforced. It is a projection over minimized
stored evidence: request and response bodies are never retained, so those fields
state that explicitly instead of inventing content.
"""
import hashlib
import json

from pydantic import BaseModel, ConfigDict, model_validator

from canarygate.evidence.redaction import canonical_json
from canarygate.report.matrix import (as_run_dict, build_matrix, cells_from_runs, split_endpoint)
from canarygate.report.scenario import environment

P0_SECTION_KEYS = ("executive_summary", "scope_and_rules", "endpoint_inventory", "findings",
                   "secured_endpoints", "skipped_and_inconclusive", "authorization_matrix",
                   "manual_interventions_and_inferences", "constraint_checklist")
CATEGORIES = ("Authentication", "Authorization", "Input validation", "Disclosure")
# The validation workflow stores "Information disclosure"; the frozen report groups
# findings into four categories and calls the fourth "Disclosure".
CATEGORY_ALIASES = {"Information disclosure": "Disclosure"}
VERDICTS = ("CONFIRMED", "SUSPECTED", "SAFE", "INCONCLUSIVE", "SKIPPED")
MODES = {"scenario": "offline_scenario", "authentication": "offline_authentication",
         "validation": "offline_validation"}

REMEDIATION_CATALOG = {
    "bola": "Enforce object-level ownership checks server-side on every handler.",
    "bfla": "Add a central role check for privileged functions.",
    "missing_authentication": "Require and verify a valid credential for every protected operation.",
    "token_validation": ("Verify token signatures with an approved algorithm and reject modified "
                         "or unsigned tokens."),
    "input_validation": "Validate requests against a strict schema with strict typing and bounded sizes.",
    "verbose_errors": "Return generic error responses and log the detail server-side only.",
    "excessive_data_exposure": "Filter responses through explicit DTOs and remove sensitive fields.",
    "headers": "Remove server version and debug headers from production responses.",
}

_RULES = ("Recorded synthetic responses only. The run is offline: no live target, socket, DNS "
          "lookup, redirect or credential transmission occurs, and this is not organizer "
          "authorization or a production assessment.")
_AUTH_EXPECTATION = {
    "AUTHN-01": "a request without a credential is rejected",
    "AUTHN-02": "a malformed credential is rejected",
    "AUTHN-03": "a credential in the wrong scheme is rejected",
    "AUTHN-04a": "a token with a modified `sub` claim is rejected or has no identity effect",
    "AUTHN-04b": "a token with a modified `role` claim is rejected or grants no capability",
    "AUTHN-05": "an unsigned `alg: none` token is rejected",
    "AUTHN-06": "the observed post-logout behaviour is reported, never confirmed",
    "AUTHN-08": "a missing or invalid API key is rejected",
}
_INPUT_EXPECTATION = {
    "INPUT-05": "an unexpected JSON property is rejected",
    "INPUT-06": "a malformed JSON body is rejected with a bounded error",
    "INPUT-07": "special characters are rejected or handled as an ordinary error",
}
_DISCLOSURE_EXPECTATION = {
    "DISC-01": "no stack trace or framework error text is returned",
    "DISC-02": "no internal paths, SQL fragments or library versions are returned",
    "DISC-03": "no sensitive field name or value pattern is returned",
    "DISC-04": "no field outside the declared response schema is returned",
    "DISC-05": "no server, framework or debug header is returned",
    "DISC-06": "existing and nonexistent resources return indistinguishable errors",
}


class P0ReportSections(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    executive_summary: dict
    scope_and_rules: dict
    endpoint_inventory: list[dict]
    findings: dict
    secured_endpoints: list[dict]
    skipped_and_inconclusive: list[dict]
    authorization_matrix: dict
    manual_interventions_and_inferences: dict
    constraint_checklist: dict

    @model_validator(mode="after")
    def frozen_sections(self):
        if tuple(self.model_dump()) != P0_SECTION_KEYS:
            raise ValueError("the frozen nine sections are required in order")
        if set(self.findings) != set(CATEGORIES):
            raise ValueError("findings must be grouped into the four frozen categories")
        return self


class P0Report(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    mode: str
    id: str
    run_id: str
    run_kind: str
    sections: P0ReportSections


def severity_for(category, check_id, verdict):
    """Fixed mapping from the frozen report section; no CVSS engine."""
    if verdict != "CONFIRMED":
        return None
    if category == "Authorization":
        return "High"
    if category == "Authentication":
        return "High" if check_id in {"AUTHN-01", "AUTHN-02", "AUTHN-03", "AUTHN-08"} else "Medium"
    if category == "Disclosure":
        return "Medium"
    if category == "Input validation":
        return "Low"
    return None


def remediation_key_for(category, check_id):
    if category == "Authorization":
        return "bola"
    if category == "Authentication":
        return ("missing_authentication" if check_id in {"AUTHN-01", "AUTHN-02", "AUTHN-03", "AUTHN-08"}
                else "token_validation")
    if category == "Input validation":
        return "input_validation"
    if category == "Disclosure":
        if check_id in {"DISC-01", "DISC-02", "DISC-06"}:
            return "verbose_errors"
        if check_id in {"DISC-03", "DISC-04"}:
            return "excessive_data_exposure"
        return "headers"
    raise ValueError("unknown finding category")


def curl_for(method, path, actor=None):
    """Credential placeholders only; a real token is never rendered."""
    command = f'curl -sS -X {method} "$BASE{path}"'
    if actor is None:
        return command
    placeholder = "$TOKEN_A" if actor == "account-a" else "$TOKEN_B"
    return command + f' -H "Authorization: Bearer {placeholder}"'


def _digest(value):
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _role_for(run, account):
    for item in run["scope"].get("accounts", ()):
        if item.get("account") == account:
            return item.get("role", "NOT_RECORDED")
    return "NOT_RECORDED"


def _finding(check_id, category, *, timestamp, endpoint, verdict, reason, account, role,
             expected, observed, source, checklist, curl, evidence_sha256,
             target_resource="NOT_APPLICABLE", verified_owner="NOT_APPLICABLE"):
    key = remediation_key_for(category, check_id)
    method, _, path = endpoint.partition(" ")
    if not path:
        method, path = "NOT_RECORDED", "NOT_RECORDED"
    return {
        "id": check_id, "category": category, "timestamp": timestamp, "endpoint": endpoint,
        "severity": severity_for(category, check_id, verdict), "verdict": verdict,
        "reason": reason, "account": account, "role": role,
        "target_resource": target_resource, "verified_owner": verified_owner,
        "request": {"method": method, "path": path,
                    "credentials": "placeholder only" if account != "anonymous" else "none",
                    "body": "not retained (bounded recorded fixture)"},
        "response": {"status": None, "body": "not retained; only bounded facts are stored"},
        "expected": expected, "observed": observed, "expectation_source": source,
        "evidence_checklist": checklist,
        "curl": curl,
        "remediation": REMEDIATION_CATALOG[key] if verdict == "CONFIRMED" else None,
        "remediation_key": key if verdict == "CONFIRMED" else None,
        "evidence_sha256": evidence_sha256,
    }


def _scenario_findings(run):
    evidence = run["evidence"]["disclosure"] or run["evidence"]["ownership"]
    actor = evidence["actor"] if evidence else "account-a"
    observed = {"CONFIRMED": "a cross-account resource body was returned and disclosed",
                "SAFE": "the cross-account request was denied with the checked denial",
                "SUSPECTED": "the response was ambiguous between ownership and disclosure evidence",
                "INCONCLUSIVE": "the recorded responses did not establish ownership or disclosure",
                "SKIPPED": "the check could not be executed"}[run["verdict"]]
    method, path = split_endpoint(run["recipe"]["detail"])
    return [_finding(
        "READ-BOLA", "Authorization", timestamp=evidence["timestamp"] if evidence else run["created_at"],
        endpoint=f"{method} {path}", verdict=run["verdict"], reason=run["reason"],
        account=actor, role=evidence["role"] if evidence else "NOT_RECORDED",
        expected=run["policy"]["expected_access"], observed=observed,
        source=run["policy"]["expected_source"], checklist=run["checklist"],
        curl=curl_for(method, path, actor=actor),
        evidence_sha256=evidence["sha256"] if evidence else "NOT_RECORDED",
        target_resource="NOT_RECORDED (identifier minimised)",
        verified_owner="NOT_RECORDED (fixture ownership is a bundled assumption)")]


def _authentication_findings(run):
    findings = []
    for check in run["checks"]:
        evidence = check.get("evidence")
        endpoint = (f'{evidence["method"]} {evidence["path_template"]}' if evidence
                    else "NOT_RECORDED")
        observed = ("no response was recorded" if not evidence else
                    f'status {evidence["status_code"]}, identity effect '
                    f'{evidence["identity_effect"]}'
                    + (f', capability {evidence["capability"]}' if evidence.get("capability") else ""))
        findings.append(_finding(
            check["id"], "Authentication",
            timestamp=evidence["timestamp"] if evidence else run["created_at"],
            endpoint=endpoint, verdict=check["verdict"], reason=check["reason"],
            account=evidence["actor"] if evidence else "NOT_RECORDED",
            role=evidence["role"] if evidence else "NOT_RECORDED",
            expected=_AUTH_EXPECTATION[check["id"]], observed=observed,
            source="frozen section 8 authentication expectation",
            checklist=evidence["checklist"] if evidence else {},
            curl=(curl_for(evidence["method"], evidence["path_template"], actor=evidence["actor"])
                  if evidence else "no request was performed"),
            evidence_sha256=evidence["sha256"] if evidence else "NOT_RECORDED"))
    return findings


def _validation_findings(run):
    findings = []
    actor = run["accounts"][0]
    for check in run["checks"]:
        evidence = check.get("evidence") or {}
        if "probe" in evidence:
            method, path = "POST", evidence.get("path", "NOT_RECORDED")
            expectation = _INPUT_EXPECTATION[check["id"]]
            curl = (f'curl -sS -X POST "$BASE{path}" -H "content-type: application/json" '
                    f'-d \'<declared {evidence["probe"]} probe body, not retained>\'')
        elif "path" in evidence:
            method, path = "GET", evidence["path"]
            expectation = _DISCLOSURE_EXPECTATION[check["id"]]
            curl = curl_for(method, path, actor=actor)
        else:
            method, path = "GET", "NOT_RECORDED"
            expectation = (_INPUT_EXPECTATION.get(check["id"])
                           or _DISCLOSURE_EXPECTATION.get(check["id"]))
            curl = "no request was performed"
        observed_bits = [f"{key} {value}" for key, value in evidence.items()
                         if key in {"status", "signals", "excess_fields", "known_status",
                                    "unknown_status"}]
        findings.append(_finding(
            check["id"], CATEGORY_ALIASES.get(check["category"], check["category"]),
            timestamp=run["created_at"],
            endpoint=f"{method} {path}", verdict=check["verdict"], reason=check["reason"],
            account=actor if evidence else "NOT_RECORDED",
            role=_role_for(run, actor) if evidence else "NOT_RECORDED",
            expected=expectation,
            observed=", ".join(observed_bits) if observed_bits else "no bounded evidence recorded",
            source="frozen section 9 expectation",
            checklist={}, curl=curl,
            evidence_sha256=_digest(evidence) if evidence else "NOT_RECORDED"))
    return findings


def _findings(kind, run):
    if kind == "scenario":
        return _scenario_findings(run)
    if kind == "authentication":
        return _authentication_findings(run)
    if kind == "validation":
        return _validation_findings(run)
    raise ValueError("unknown run kind")


def _grouped(findings):
    return {category: [item for item in findings if item["category"] == category]
            for category in CATEGORIES}


def _scope_sha(run):
    scope = run["scope"]
    return scope.get("scope_sha256") or _digest(scope)


def _secured(findings):
    secured = []
    for item in findings:
        if item["verdict"] != "SAFE":
            continue
        checklist = item.get("evidence_checklist") or {}
        if item["category"] == "Authentication" and item["id"] in {"AUTHN-01", "AUTHN-02", "AUTHN-03"}:
            if checklist.get("denial_body_checked") is not True:
                continue
        secured.append({"id": item["id"], "category": item["category"],
                        "endpoint": item["endpoint"], "verdict": item["verdict"],
                        "reason": item["reason"], "evidence_checklist": checklist,
                        "expectation_source": item["expectation_source"]})
    return secured


def _inventory(run):
    stored = run.get("inventory") or []
    if stored:
        return [dict(item) for item in stored]
    # Authentication and validation runs store the validated scope, not a plan
    # inventory; the scope operations are the authoritative endpoint list.
    items = []
    for operation in run["scope"].get("operations", ()):
        public = operation.get("classification") == "AUTHENTICATION"
        items.append({"method": operation["method"], "path": operation["path"],
                      "parameters": [],
                      "security": [] if public else [{"bearerAuth": []}],
                      "expected_access": ("public authentication operation" if public
                                          else "authenticated"),
                      "expected_source": "validated scope operation"})
    return items


def _constraints(kind, run):
    constraints = run.get("constraints") or {}
    sent = constraints.get("requests_sent", run.get("requests_sent"))
    blocked = constraints.get("blocked_by_guard", run.get("blocked_by_guard"))
    remaining = constraints.get("budget_remaining", run.get("budget_remaining"))
    authentication_operations = []
    for operation in run["scope"].get("operations", ()):
        if operation.get("classification") == "AUTHENTICATION":
            authentication_operations.append(f'{operation["method"]} {operation["path"]} (recorded only)')
    items = [
        {"item": "Exact host and port allow-listed", "value": "yes", "source": "validated scope origin"},
        {"item": "Out-of-scope requests blocked before connection",
         "value": blocked, "source": "shared run guard counter"},
        {"item": "Out-of-scope requests executed", "value": 0, "source": "shared run guard"},
        {"item": "Redirects followed", "value": 0, "source": "no redirect handling exists"},
        {"item": "Destructive requests executed, including cleanup",
         "value": 0, "source": "preflight rejects every non-read-only operation"},
        {"item": "External requests / third-party calls", "value": 0,
         "source": "offline transport only"},
        {"item": "State-changing requests executed",
         "value": authentication_operations or [],
         "source": "declared authentication operations, recorded only"},
        {"item": "Resources created under explicit authorization", "value": "none",
         "source": "no creation operation was declared"},
        {"item": "Tokens and credentials redacted", "value": "yes",
         "source": "store rejects unredacted payloads"},
        {"item": "UI assets loaded locally; remote $ref disabled", "value": "yes",
         "source": "no external assets or reference fetching"},
        {"item": "Scope file hash", "value": _scope_sha(run), "source": "validated scope"},
        {"item": "Validation mode and target",
         "value": f"offline recorded responses ({kind})", "source": "this run"},
    ]
    return {
        "network_transport_enabled": False,
        "live_target_contacted": False,
        "requests_sent": sent,
        "blocked_by_guard": blocked,
        "budget_remaining": remaining,
        "items": items,
    }


def _manual(kind, run):
    scope = run["scope"]
    interventions = []
    inferences = [
        {"item": "expected_access", "kind": "declared_expectation",
         "source": ("offline scenario policy" if kind == "scenario"
                    else "offline scenario scope"),
         "value": (run["policy"]["expected_access"] if kind == "scenario"
                   else "declared by the bundled scenario scope")},
        {"item": "identity_mapping", "kind": "assumption",
         "source": "validated scope accounts",
         "value": "the first scope account acts; later accounts are the peers under test"},
        {"item": "denial_contract", "kind": "assumption",
         "source": "offline synthetic policy",
         "value": "a 401/403 whose body equals the declared denial counts as a checked denial"},
        {"item": "target_resource_identity", "kind": "limitation",
         "source": "evidence minimisation policy",
         "value": "resource identifiers are not retained, so they are reported as NOT_RECORDED"},
    ]
    if kind == "scenario":
        interventions.append({
            "item": "setup_status", "status": run["setup"]["ownership_verification"],
            "bola_coverage": run["setup"]["bola_coverage"],
            "reason": run["setup"].get("reason"),
            "source": "bundled scenario definition"})
    if run.get("blocked_by_guard"):
        interventions.append({"item": "guard_blocked_requests",
                              "value": run["blocked_by_guard"],
                              "source": "shared run guard"})
    return {
        "status": "RECORDED",
        "manual_intervention_required": False,
        "interventions": interventions,
        "inferences": inferences,
        "statement": ("No manual intervention was required. The run used bundled offline "
                      "scenarios only: no seeding, no login against a live target and no manual "
                      "state change was performed."),
    }


def build_p0_sections(kind, run):
    if kind not in MODES:
        raise ValueError("unknown run kind")
    run = as_run_dict(run)
    findings = _findings(kind, run)
    grouped = _grouped(findings)
    counts = {name: sum(item["verdict"] == name for item in findings) for name in VERDICTS}
    by_category = {category: {name: sum(item["verdict"] == name for item in grouped[category])
                              for name in VERDICTS} for category in CATEGORIES}
    severity_counts = {"High": 0, "Medium": 0, "Low": 0}
    for item in findings:
        if item["severity"]:
            severity_counts[item["severity"]] += 1
    if kind == "scenario":
        cells, _ = cells_from_runs([run], [], [])
    elif kind == "authentication":
        cells, _ = cells_from_runs([], [run], [])
    else:
        cells = []
    matrix = build_matrix(cells)
    sections = {
        "executive_summary": {
            "run_kind": kind, "mode": MODES[kind], "scenario_id": run["scenario_id"],
            "status": run["status"], "verdict_counts": counts,
            "category_counts": by_category, "severity_counts": severity_counts,
            "finding_count": len(findings), "live_target_contacted": False,
            "network_transport_enabled": False,
            "statement": ("Counts include SKIPPED and INCONCLUSIVE results; neither is a clean "
                          "result. No live target was contacted."),
        },
        "scope_and_rules": {
            "origin": scope_origin(run), "hostname": run["scope"]["hostname"],
            "port": run["scope"]["port"], "scope_sha256": _scope_sha(run),
            "written_authorization_reference": run["scope"]["written_authorization_reference"],
            "accounts": run["scope"]["accounts"], "request_budget": run["scope"]["request_budget"],
            "seeding_rung": "NOT_APPLICABLE_OFFLINE_RECORDED_RESPONSES",
            "rules_of_engagement": _RULES,
            "authorization_note": ("The scope file is synthetic; this is not organizer "
                                   "authorization."),
        },
        "endpoint_inventory": _inventory(run),
        "findings": grouped,
        "secured_endpoints": _secured(findings),
        "skipped_and_inconclusive": [
            {"id": item["id"], "category": item["category"], "verdict": item["verdict"],
             "endpoint": item["endpoint"], "reason": item["reason"]}
            for item in findings if item["verdict"] in {"SKIPPED", "INCONCLUSIVE"}],
        "authorization_matrix": matrix.model_dump(mode="json"),
        "manual_interventions_and_inferences": _manual(kind, run),
        "constraint_checklist": _constraints(kind, run),
    }
    return P0ReportSections.model_validate(sections).model_dump(mode="json")


def scope_origin(run):
    scope = run["scope"]
    if "origin" in scope:
        return scope["origin"]
    return f'{scope["scheme"]}://{scope["hostname"]}:{scope["port"]}'


def build_p0_report(kind, run):
    run = as_run_dict(run)
    return P0Report(mode=MODES[kind], id=run["id"], run_id=run["id"], run_kind=kind,
                    sections=build_p0_sections(kind, run))


def render_p0_report(kind, run):
    report = build_p0_report(kind, run)
    base = {"scenario": "scenario-scans", "authentication": "authentication-scans",
            "validation": "validation-scans"}[kind]
    return environment.get_template("p0.html").render(
        report=report, sections=report.sections, json_block=lambda value: json.dumps(
            value, indent=2, ensure_ascii=True, sort_keys=True),
        report_url=f'http://127.0.0.1:8000/api/{base}/{run["id"]}/report?view=p0')
