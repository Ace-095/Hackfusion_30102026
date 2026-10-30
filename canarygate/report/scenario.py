"""Render offline scenario reports; JSON sections and HTML derive from one run."""
import json

from jinja2 import Environment, PackageLoader, select_autoescape

environment = Environment(loader=PackageLoader("canarygate.report", "templates"),
                          autoescape=select_autoescape(["html", "xml"]))


def _json(value):
    return json.dumps(value, indent=2, ensure_ascii=True, sort_keys=True)


def build_scenario_sections(run):
    """Project one stored, integrity-checked scenario run into report sections.

    This is a scenario-specific report projection, not the complete frozen
    nine-section P0 report contract.
    """
    secured = run["verdict"] == "SAFE"
    return {
        "executive_summary": {
            "scenario_id": run["scenario_id"], "mode": run["mode"], "transport": run["transport"],
            "verdict": run["verdict"], "status": run["status"], "reason": run["reason"],
            "network_transport_enabled": False, "live_target_contacted": False,
        },
        "scope_and_accounts": {
            "origin": run["scope"]["origin"], "hostname": run["scope"]["hostname"],
            "port": run["scope"]["port"], "scope_sha256": run["scope"]["scope_sha256"],
            "written_authorization_reference": run["scope"]["written_authorization_reference"],
            "accounts": run["scope"]["accounts"], "request_budget": run["scope"]["request_budget"],
            "note": "Synthetic offline scenario label; this is not organizer authorization.",
        },
        "endpoint_inventory": run["inventory"],
        "bola_evidence": {
            "resource_type": run["recipe"]["resource_type"],
            "endpoint": run["recipe"]["detail"],
            "policy": run["policy"], "verdict": run["verdict"], "reason": run["reason"],
            "checklist": run["checklist"], "ownership": run["evidence"]["ownership"],
            "disclosure": run["evidence"]["disclosure"], "setup": run["setup"],
        },
        "outcome": {
            "verdict": run["verdict"], "reason": run["reason"], "remediation": run["remediation"],
            "secured_endpoint": secured,
            "skipped_or_inconclusive": run["verdict"] in ("SKIPPED", "INCONCLUSIVE"),
        },
        "constraints": run["constraints"],
        "limitations": run["limitations"],
    }


def render_scenario_report(run):
    scenario = run["scenario_id"]
    return environment.get_template("scenario.html").render(
        run=run, sections=build_scenario_sections(run), json_block=_json,
        reproduce=(f'curl -sS -X POST "http://127.0.0.1:8000/api/scenario-scans" '
                  f'-H "content-type: application/json" -d \'{{"scenario_id": "{scenario}"}}\''),
        report_url=f'http://127.0.0.1:8000/api/scenario-scans/{run["id"]}/report?view=sections')
