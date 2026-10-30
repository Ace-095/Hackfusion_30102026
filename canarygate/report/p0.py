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
from canarygate.oracles.interaction import SCI_REMEDIATIONS
from canarygate.report.matrix import (as_run_dict, build_matrix, cells_from_interactions,
                                      cells_from_lab_bola, cells_from_runs, split_endpoint)
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
         "validation": "offline_validation", "interaction": "offline_interaction",
         "lab_bola": "targetlab_bola", "lab_sci": "targetlab_sci"}
LAB_KINDS = frozenset({"lab_bola", "lab_sci"})

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
    # SCI finding types; the frozen eight above remain unchanged.
    "sci_authorization": SCI_REMEDIATIONS["sci_authorization"],
    "sci_authentication": SCI_REMEDIATIONS["sci_authentication"],
    "sci_disclosure": SCI_REMEDIATIONS["sci_disclosure"],
}

_RULES = ("Recorded synthetic responses only. The run is offline: no live target, socket, DNS "
          "lookup, redirect or credential transmission occurs, and this is not organizer "
          "authorization or a production assessment.")
_LAB_RULES = ("Real HTTPS requests to the loopback TargetLab only: the destination is the literal "
              "address 127.0.0.1, TLS is verified against a test-only CA with hostname checking, "
              "redirects are refused, nothing is retried, no external DNS is used and production "
              "networking stays disabled. This is controlled validation of our own lab, not "
              "organizer authorization and not a production assessment.")
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
             target_resource="NOT_APPLICABLE", verified_owner="NOT_APPLICABLE",
             finding_kind="single_control", interaction=None,
             remediation_key=None, remediation=None):
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
        "remediation": (remediation or REMEDIATION_CATALOG[key]) if verdict == "CONFIRMED" else None,
        "remediation_key": (remediation_key or key) if verdict == "CONFIRMED" else None,
        "evidence_sha256": evidence_sha256,
        "finding_kind": finding_kind,
        "interaction": interaction,
    }


OWNER_NOT_VERIFIED = "NOT_VERIFIED (ownership evidence incomplete)"


def redacted_target_resource(run):
    """Resource type plus the fact that the identifier is withheld, never a fake id."""
    return f"{run['recipe']['resource_type']} (owner's private record; identifier minimised)"


def redacted_verified_owner(run, actor):
    """Name the verified owner without exposing identifiers.

    Ownership is only claimed when the stored checklist proves both that ownership
    was verified and that the owner baseline succeeded. With exactly two authorized
    accounts the owner is the one that did not make the cross-account request;
    otherwise the label stays generic rather than guessing.
    """
    checklist = run["checklist"]
    if not (checklist.get("ownership_verified") and checklist.get("owner_baseline")):
        return OWNER_NOT_VERIFIED
    accounts = [item["account"] for item in run["scope"]["accounts"]]
    if len(accounts) == 2 and actor in accounts:
        owner = accounts[0] if accounts[1] == actor else accounts[1]
        return f"{owner} (ownership verified; owner baseline recorded)"
    return "an account distinct from the requester (ownership verified; owner baseline recorded)"


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
        target_resource=redacted_target_resource(run),
        verified_owner=redacted_verified_owner(run, actor))]


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


def _interaction_category(kind):
    return "Disclosure" if kind == "INPUT_VALIDATION+INFORMATION_DISCLOSURE" else "Authorization"


def _interaction_block(run):
    combined = run["combined"]
    return {
        "kind": run["interaction_kind"],
        "controls": list(run["controls"]),
        "attribution": run["attribution"],
        "baselines": [{"id": item["id"], "control": item["control"],
                       "endpoint": item["endpoint"], "verdict": item["verdict"],
                       "observable": item["observable"], "reason": item["reason"],
                       "evidence_sha256": item["evidence_sha256"]}
                      for item in run["baselines"]],
        "combined": {"endpoint": combined["endpoint"], "action": combined["action"],
                     "probe": combined["probe"], "executed": combined["executed"],
                     "permitted": combined["permitted"], "verified": combined["verified"],
                     "status": combined["status"], "impact": combined["impact"],
                     "observed": combined["observed"]},
        "why_not_individual": (
            "every individual baseline passed and was observable"
            if run["attribution"] == "interaction_induced"
            else "no interaction-induced failure could be attributed"),
    }


def _interaction_findings(run):
    combined = run["combined"]
    role = _role_for(run, run["accounts"][0])
    interaction = _interaction_block(run)
    method, _, path = combined["endpoint"].partition(" ")
    return [_finding(
        "SCI-01", _interaction_category(run["interaction_kind"]),
        timestamp=run["created_at"], endpoint=combined["endpoint"],
        verdict=run["verdict"], reason=run["reason"], account=run["accounts"][0], role=role,
        expected="the declared policy for the combined endpoint",
        observed=combined["observed"], source="offline SCI scenario scope",
        checklist=run["checklist"],
        curl=curl_for(method or "GET", path or "NOT_RECORDED", actor=run["accounts"][0]),
        evidence_sha256=run["baselines"][0]["evidence_sha256"],
        target_resource=f"the {path or 'combined'} exchange (identifier minimised)",
        verified_owner="NOT_APPLICABLE — the interaction is about control composition",
        finding_kind="interaction", interaction=interaction,
        remediation_key=run["remediation_key"], remediation=run["remediation"])]


LAB_CHECK_EXPECTATION = {
    "LAB-BOLA-01": "the owner reading their own record is served",
    "LAB-BOLA-02": "the owner reading their own record is served",
    "LAB-BOLA-03": "a cross-owner private read is denied",
    "LAB-BOLA-04": "a cross-owner private read is denied",
    "LAB-BOLA-05": "a cross-owner read on the secure route is denied",
    "LAB-BOLA-06": "a cross-owner read on the secure route is denied",
}


def _lab_bola_findings(run):
    """Real loopback observations projected into the frozen finding shape."""
    role = _role_for(run, run["scope"]["accounts"][0]["account"]) if run["scope"].get("accounts") else "unknown"
    findings = []
    for check in run["checks"]:
        observed = {
            "CONFIRMED": "the response carried the other owner's private marker",
            "SAFE": ("the owner baseline matched the caller's own record"
                     if check["direction"] == "owner_baseline"
                     else "the endpoint denied the cross-account read with the checked denial body"),
            "SUSPECTED": "a private marker was observed without complete response identity",
            "INCONCLUSIVE": "the observed evidence was insufficient for a verdict",
            "SKIPPED": "the request was not executed",
        }[check["verdict"]]
        findings.append(_finding(
            check["id"], "Authorization", timestamp=run["created_at"],
            endpoint=check["endpoint"], verdict=check["verdict"], reason=check["reason"],
            account=check["actor"], role=role,
            expected=LAB_CHECK_EXPECTATION[check["id"]],
            observed=observed, source=run["policy"]["expected_source"],
            checklist=check["checklist"],
            curl=curl_for(*split_endpoint(check["endpoint"]), actor=check["actor"]),
            evidence_sha256=check["evidence_sha256"],
            target_resource=("the caller's own record (identifier minimised)"
                             if check["direction"] == "owner_baseline"
                             else "the owner's private record (identifier minimised)"),
            verified_owner=(f'{check["owner"]} (ownership verified; owner baseline recorded)'
                            if check["direction"] == "owner_baseline"
                            or check["checklist"].get("ownership_verified")
                            else OWNER_NOT_VERIFIED),
            remediation=check["remediation"],
            remediation_key="bola" if check["verdict"] == "CONFIRMED" else None))
    return findings


def _lab_sci_findings(run):
    """A real loopback interaction projected into the frozen finding shape."""
    combined = run["combined"]
    account = run["accounts"][0]
    disclosure = run.get("disclosure") or {}
    proven_owner = bool(disclosure.get("marker_matches_owner_baseline")
                        and (run.get("ownership") or {}).get("status") == "SUCCESS")
    expected = ("the authorization control denies a cross-owner read and the login endpoint "
                "refuses the rejected credential, so the read stays denied afterwards")
    observed = combined["observed"]
    return [_finding(
        "SCI-01", "Authorization", timestamp=run["created_at"], endpoint=combined["endpoint"],
        verdict=run["verdict"], reason=run["reason"], account=account,
        role=_role_for(run, account), expected=expected, observed=observed,
        source=run["policy_source"], checklist=run["checklist"],
        curl=curl_for(*split_endpoint(combined["endpoint"]), actor=account),
        evidence_sha256=run["baselines"][0]["evidence_sha256"],
        target_resource="the owner's private record (identifier minimised)",
        verified_owner=(f'{disclosure.get("owner")} (ownership verified; owner baseline recorded)'
                        if proven_owner else OWNER_NOT_VERIFIED),
        finding_kind="interaction", interaction=_interaction_block(run),
        remediation_key=run["remediation_key"], remediation=run["remediation"])]


def _findings(kind, run):
    if kind == "scenario":
        return _scenario_findings(run)
    if kind == "authentication":
        return _authentication_findings(run)
    if kind == "validation":
        return _validation_findings(run)
    if kind == "interaction":
        return _interaction_findings(run)
    if kind == "lab_bola":
        return _lab_bola_findings(run)
    if kind == "lab_sci":
        return _lab_sci_findings(run)
    raise ValueError("unknown run kind")


def _grouped(findings):
    return {category: [item for item in findings if item["category"] == category]
            for category in CATEGORIES}


def _scope_sha(run):
    scope = run["scope"]
    return scope.get("scope_sha256") or _digest(scope)


def _secured(findings):
    secured = []
    # A confirmed finding outranks a sibling SAFE check on the same endpoint: the
    # report must never call an endpoint secured while listing a CONFIRMED result
    # for it in the same run.
    confirmed_endpoints = {item["endpoint"] for item in findings if item["verdict"] == "CONFIRMED"}
    for item in findings:
        if item["verdict"] != "SAFE":
            continue
        if item["endpoint"] in confirmed_endpoints:
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


def _transport_flags(kind, run):
    """Honest transport facts: the lab run really did open loopback sockets."""
    if kind in LAB_KINDS:
        return {"network_transport_enabled": True, "live_target_contacted": False,
                "loopback_lab_contacted": True}
    return {"network_transport_enabled": False, "live_target_contacted": False,
            "loopback_lab_contacted": False}


def _constraints(kind, run):
    constraints = run.get("constraints") or {}
    sent = constraints.get("requests_sent", run.get("requests_sent"))
    blocked = constraints.get("blocked_by_guard", run.get("blocked_by_guard"))
    remaining = constraints.get("budget_remaining", run.get("budget_remaining"))
    authentication_operations = []
    for operation in run["scope"].get("operations", ()):
        if operation.get("classification") == "AUTHENTICATION":
            authentication_operations.append(f'{operation["method"]} {operation["path"]} (recorded only)')
    lab = kind in LAB_KINDS
    transport = run.get("transport") or {}
    items = [
        {"item": "Exact host and port allow-listed",
         "value": ("127.0.0.1 only; literal address, no hostname" if lab else "yes"),
         "source": "validated scope origin"},
        {"item": "TLS certificate verification",
         "value": ("test CA pinned; hostname checked; verification never disabled" if lab
                   else "not applicable (no socket is opened)"),
         "source": "no unverified-TLS code path exists"},
        {"item": "Out-of-scope requests blocked before connection",
         "value": blocked, "source": "shared run guard counter"},
        {"item": "Out-of-scope requests executed", "value": 0, "source": "shared run guard"},
        {"item": "Redirects followed", "value": 0, "source": "no redirect handling exists"},
        {"item": "Destructive requests executed, including cleanup",
         "value": 0, "source": "preflight rejects every non-read-only operation"},
        {"item": "External requests / third-party calls", "value": 0,
         "source": ("loopback only; no DNS lookup and no hostname" if lab
                    else "offline transport only")},
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
         "value": (f"loopback TargetLab over verified TLS (127.0.0.1:{transport.get('port')})"
                   if lab else f"offline recorded responses ({kind})"),
         "source": "this run"},
    ]
    return {
        **_transport_flags(kind, run),
        "requests_sent": sent,
        "blocked_by_guard": blocked,
        "budget_remaining": remaining,
        "items": items,
    }


def _manual(kind, run):
    if kind == "lab_bola":
        return _lab_manual(run)
    if kind == "lab_sci":
        return _lab_sci_manual(run)
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
         "value": "resource identifiers are not retained; the report names the resource type "
                  "and verified owner but withholds the id"},
    ]
    if kind == "interaction":
        inferences.append({
            "item": "interaction_attribution", "kind": "inference",
            "source": "SCI decision engine",
            "value": (f'{run["attribution"]}: both individual baselines were observably passing'
                      if run["attribution"] == "interaction_induced"
                      else f'{run["attribution"]}: no interaction-induced failure attributed')})
        interventions.append({
            "item": "sci_baselines", "status": "EXECUTED",
            "value": [f'{item["id"]}={item["verdict"]}' for item in run["baselines"]],
            "source": "individual control baselines"})
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


def _lab_manual(run):
    """No invented narrative: what was assumed, and what was evaluated afterwards."""
    ground_truth = run.get("ground_truth") or {}
    interventions = [{
        "item": "ground_truth_comparison", "status": "AFTER_THE_SCAN",
        "value": f'{ground_truth.get("matched")}/6 declared outcomes matched the finished verdicts',
        "source": "declared TargetLab ground truth, scored after the decision"}]
    if run.get("constraints", {}).get("blocked_by_guard"):
        interventions.append({"item": "guard_blocked_requests",
                              "value": run["constraints"]["blocked_by_guard"],
                              "source": "shared run guard"})
    inferences = [
        {"item": "expected_access", "kind": "declared_expectation",
         "source": run["policy"]["expected_source"],
         "value": run["policy"]["expected_access"]},
        {"item": "identity_mapping", "kind": "assumption",
         "source": "validated scope accounts",
         "value": "each account authenticated with its own lab credential; identities were "
                  "confirmed by the profile operation before any ownership claim"},
        {"item": "denial_contract", "kind": "assumption",
         "source": "TargetLab record policy",
         "value": "a 403 whose JSON body equals the declared denial counts as a checked denial; "
                  "status alone is never enough"},
        {"item": "ground_truth_independence", "kind": "inference",
         "source": "workflow design",
         "value": "the scanner never requests /lab/ground-truth and does not consult the declared "
                  "table before deciding; the comparison is computed last and stored separately"},
        {"item": "target_resource_identity", "kind": "limitation",
         "source": "evidence minimisation policy",
         "value": "resource identifiers are withheld; the report names the resource type and "
                  "verified owner only"},
    ]
    return {
        "status": "RECORDED", "manual_intervention_required": False,
        "interventions": interventions, "inferences": inferences,
        "statement": ("No manual intervention was required. Requests were executed against the "
                      "loopback TargetLab over verified TLS. No organizer, internet or "
                      "third-party target was contacted and no state was changed apart from the "
                      "declared authentication operations."),
    }


def _lab_sci_manual(run):
    """What was assumed, what ran afterwards, and where the reset proof lives."""
    interventions = [{
        "item": "sci_baselines", "status": "EXECUTED",
        "value": [f'{item["id"]}={item["verdict"]}' for item in run["baselines"]],
        "source": "individual control baselines on the same runner"},
        {"item": "sequence",
         "value": " -> ".join(["authorization denial", "rejected login", "combined read"]),
         "source": "declared interaction order; every leg verified by its own response"},
        {"item": "ground_truth_comparison", "status": "AFTER_THE_SCAN",
         "value": "the declared outcome is scored when the report is built, not before",
         "source": "declared TargetLab ground truth"},
        {"item": "reset_verification", "status": "SEPARATE_SCENARIO",
         "value": ("recorded apart from this verdict through POST /api/lab-sci-resets; it needs "
                   "its own runs because a run may authenticate an account only once"),
         "source": "reset proof"}]
    if run.get("blocked_by_guard"):
        interventions.append({"item": "guard_blocked_requests",
                              "value": run["blocked_by_guard"],
                              "source": "shared run guard"})
    inferences = [
        {"item": "expected_access", "kind": "declared_expectation",
         "source": run["policy_source"],
         "value": "a cross-owner read on the guarded route is denied, before and after a "
                  "rejected login"},
        {"item": "identity_mapping", "kind": "assumption",
         "source": "validated scope accounts",
         "value": "each account authenticated with its own credential and was confirmed by the "
                  "profile operation before any ownership claim"},
        {"item": "denial_contract", "kind": "assumption",
         "source": "TargetLab record policy",
         "value": "a 403 whose JSON body equals the declared denial counts as a checked denial; "
                  "status alone is never enough"},
        {"item": "rejection_contract", "kind": "assumption",
         "source": "TargetLab login contract",
         "value": "a 401 whose JSON body equals the declared rejection counts as a checked "
                  "rejection; an accepted wrong credential would be an individual failure"},
        {"item": "disclosure_baseline", "kind": "inference",
         "source": "ownership registry",
         "value": "the leaked marker is compared with the marker the owner returned on their own "
                  "baseline, so a stale or unrelated value cannot confirm the finding"},
        {"item": "ground_truth_independence", "kind": "inference",
         "source": "workflow design",
         "value": "the scanner never requests /lab/ground-truth and the comparison is computed "
                  "at report time against a stored run that is sealed first"},
    ]
    return {
        "status": "RECORDED", "manual_intervention_required": False,
        "interventions": interventions, "inferences": inferences,
        "statement": ("No manual intervention was required. Requests were executed sequentially "
                      "against the loopback TargetLab over verified TLS. No organizer, internet or "
                      "third-party target was contacted, no state was changed apart from the "
                      "declared authentication operations, and nothing was retried."),
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
    elif kind == "interaction":
        cells = cells_from_interactions([run])
    elif kind == "lab_bola":
        cells = cells_from_lab_bola([run])
    elif kind == "lab_sci":
        cells = cells_from_interactions([run], prefix="lab_sci")
    else:
        cells = []
    matrix = build_matrix(cells, extra_endpoints=_inventory(run))
    sections = {
        "executive_summary": {
            "run_kind": kind, "mode": MODES[kind], "scenario_id": run["scenario_id"],
            "status": run["status"], "verdict_counts": counts,
            "category_counts": by_category, "severity_counts": severity_counts,
            "finding_count": len(findings), **_transport_flags(kind, run),
            "statement": ("Counts include SKIPPED and INCONCLUSIVE results; neither is a clean "
                          "result. No live target was contacted."
                          + (" Requests were sent to the loopback TargetLab only." 
                             if kind == "lab_bola" else "")),
        },
        "scope_and_rules": {
            "origin": scope_origin(run), "hostname": run["scope"]["hostname"],
            "port": run["scope"]["port"], "scope_sha256": _scope_sha(run),
            "written_authorization_reference": run["scope"]["written_authorization_reference"],
            "accounts": run["scope"]["accounts"], "request_budget": run["scope"]["request_budget"],
            "seeding_rung": ("NOT_APPLICABLE_LOOPBACK_LAB" if kind == "lab_bola"
                             else "NOT_APPLICABLE_OFFLINE_RECORDED_RESPONSES"),
            "rules_of_engagement": (_LAB_RULES if kind == "lab_bola" else _RULES),
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
            "validation": "validation-scans", "interaction": "interaction-scans",
            "lab_bola": "lab-bola-scans", "lab_sci": "lab-sci-scans"}[kind]
    return environment.get_template("p0.html").render(
        report=report, sections=report.sections, json_block=lambda value: json.dumps(
            value, indent=2, ensure_ascii=True, sort_keys=True),
        report_url=f'http://127.0.0.1:8000/api/{base}/{run["id"]}/report?view=p0')
