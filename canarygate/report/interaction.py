"""Render offline SCI reports; JSON sections and HTML share one stored run."""
import hashlib
import json

from canarygate.evidence.redaction import canonical_json
from canarygate.report.scenario import environment

STATEMENT = ("An SCI finding is CONFIRMED only when both individual controls were observable and "
             "passing, the combined response verified in this run, and the declared policy was "
             "violated with a demonstrated impact. An individual control failure, an incomplete "
             "baseline or a harmless variation is never reported as an interaction.")


def _json(value):
    return json.dumps(value, indent=2, ensure_ascii=True, sort_keys=True)


def build_interaction_sections(run):
    """Project one stored, integrity-checked interaction run into report sections."""
    scope = run["scope"]
    return {
        "executive_summary": {
            "scenario_id": run["scenario_id"], "title": run["title"], "mode": run["mode"],
            "status": run["status"], "interaction_kind": run["interaction_kind"],
            "controls": run["controls"], "verdict": run["verdict"],
            "attribution": run["attribution"], "network_transport_enabled": False,
            "live_target_contacted": False,
        },
        "scope_and_accounts": {
            "origin": scope["origin"], "hostname": scope["hostname"], "port": scope["port"],
            "scope_sha256": scope.get("scope_sha256")
            or hashlib.sha256(canonical_json(scope).encode("utf-8")).hexdigest(),
            "written_authorization_reference": scope["written_authorization_reference"],
            "accounts": scope["accounts"], "request_budget": scope["request_budget"],
            "accounting": {"requests_sent": run["requests_sent"],
                           "blocked_by_guard": run["blocked_by_guard"],
                           "budget_remaining": run["budget_remaining"]},
            "note": "Synthetic offline scenario label; this is not organizer authorization.",
        },
        "baselines": run["baselines"],
        "combined": run["combined"],
        "decision": {
            "verdict": run["verdict"], "reason": run["reason"],
            "attribution": run["attribution"], "checklist": run["checklist"],
            "remediation_key": run["remediation_key"], "remediation": run["remediation"],
            "statement": STATEMENT,
        },
        "limitations": run["limitations"],
    }


def render_interaction_report(run):
    scenario = run["scenario_id"]
    return environment.get_template("interaction.html").render(
        run=run, sections=build_interaction_sections(run), json_block=_json,
        reproduce=(f'curl -sS -X POST "http://127.0.0.1:8000/api/interaction-scans" '
                   f'-H "content-type: application/json" -d \'{{"scenario_id": "{scenario}"}}\''),
        report_url=f'http://127.0.0.1:8000/api/interaction-scans/{run["id"]}/report?view=sections')
