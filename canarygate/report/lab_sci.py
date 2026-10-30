"""Render TargetLab interaction reports; JSON sections and HTML share one run."""
import json

from canarygate.report.scenario import environment
from canarygate.scan.lab_sci_ground_truth import evaluate_sci

STATEMENT = ("An SCI finding is CONFIRMED only when both individual controls were executed and "
             "passing, the combined exchange was verified in this run, and it demonstrated an "
             "impact neither control explains alone. Here the authorization control denied the "
             "cross-account read and the login endpoint refused the rejected credential, yet the "
             "same read immediately afterwards returned the other owner's private record.")


def _json(value):
    return json.dumps(value, indent=2, ensure_ascii=True, sort_keys=True)


def build_lab_sci_sections(run, *, reset_proof=None):
    """Project one stored, integrity-checked interaction run into report sections."""
    scope = run["scope"]
    transport = run.get("transport") or {}
    sections = {
        "executive_summary": {
            "scenario_id": run["scenario_id"], "title": run["title"], "mode": run["mode"],
            "status": run["status"], "interaction_kind": run["interaction_kind"],
            "controls": run["controls"], "verdict": run["verdict"],
            "attribution": run["attribution"],
            "policy_source": run["policy_source"],
            "network_transport_enabled": run.get("network_transport_enabled", False),
            "live_target_contacted": transport.get("live_target_contacted", False),
            "destination": transport.get("destination", "not recorded"),
            "statement": STATEMENT,
        },
        "scope_and_accounts": {
            "origin": scope["origin"], "mode": scope.get("mode"), "hostname": scope["hostname"],
            "port": scope["port"], "scope_sha256": scope.get("scope_sha256"),
            "written_authorization_reference": scope["written_authorization_reference"],
            "accounts": scope["accounts"], "request_budget": scope["request_budget"],
            "accounting": {"requests_sent": run["requests_sent"],
                           "blocked_by_guard": run["blocked_by_guard"],
                           "budget_remaining": run["budget_remaining"]},
            "tls_verification": transport.get("tls_verification"),
            "redirects": transport.get("redirects"), "retries": transport.get("retries"),
            "dns": transport.get("dns"),
            "note": ("Loopback TargetLab with a pinned test CA. Controlled validation of our own "
                     "lab, not organizer authorization and not a live assessment."),
        },
        "baselines": run["baselines"],
        "combined": run["combined"],
        "decision": {
            "verdict": run["verdict"], "reason": run["reason"],
            "attribution": run["attribution"], "checklist": run["checklist"],
            "remediation_key": run["remediation_key"], "remediation": run["remediation"],
            "statement": STATEMENT,
        },
        "disclosure": run.get("disclosure") or {},
        "ownership": run.get("ownership") or {},
        "evaluation": evaluate_sci(run),
        "limitations": run["limitations"],
    }
    if reset_proof is not None:
        sections["reset_verification"] = reset_proof
    return sections


def render_lab_sci_report(run, *, reset_proof=None):
    return environment.get_template("lab_sci.html").render(
        run=run, sections=build_lab_sci_sections(run, reset_proof=reset_proof),
        json_block=_json,
        reproduce=(f'curl -sS -X POST "http://127.0.0.1:8000/api/lab-sci-scans" '
                   f'-H "content-type: application/json" -d \'{{"port": {run["scope"]["port"]}}}\''
                   f'   # requires a running TargetLab and CANARYGATE_TARGETLAB_CA'),
        report_url=f'http://127.0.0.1:8000/api/lab-sci-scans/{run["id"]}/report?view=sections',
        p0_url=f'http://127.0.0.1:8000/api/lab-sci-scans/{run["id"]}/report?view=p0',
        reset_url="http://127.0.0.1:8000/api/lab-sci-resets")
