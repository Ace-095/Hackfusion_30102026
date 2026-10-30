"""Render offline authentication reports; JSON sections and HTML share one run."""
import json

from canarygate.report.scenario import environment

CLAIMS_STATEMENT = ("JWT claims are decoded without verification to build a tampered token; "
                    "decoding is not verification and never proves identity, privilege or policy. "
                    "Verdicts rest on the recorded API behaviour. claims are not verified.")


def _json(value):
    return json.dumps(value, indent=2, ensure_ascii=True, sort_keys=True)


def build_authentication_sections(run):
    """Project one stored, integrity-checked authentication run into report sections.

    This is an authentication-specific projection, not the frozen nine-section
    P0 report contract.
    """
    summary = run["summary"]
    return {
        "executive_summary": {
            "scenario_id": run["scenario_id"], "title": run["title"], "mode": run["mode"],
            "transport": run["transport"], "scheme": run["scheme"], "status": run["status"],
            "summary": summary, "network_transport_enabled": False, "live_target_contacted": False,
        },
        "scope_and_accounts": {
            "origin": run["scope"]["origin"], "hostname": run["scope"]["hostname"],
            "port": run["scope"]["port"], "scope_sha256": run["scope"]["scope_sha256"],
            "written_authorization_reference": run["scope"]["written_authorization_reference"],
            "accounts": run["scope"]["accounts"], "request_budget": run["scope"]["request_budget"],
            "note": "Synthetic offline scenario label; this is not organizer authorization.",
        },
        "authentication_checks": run["checks"],
        "outcome": {
            "summary": summary,
            "executed": [check["id"] for check in run["checks"] if check["verdict"] != "SKIPPED"],
            "confirmed": [check["id"] for check in run["checks"] if check["verdict"] == "CONFIRMED"],
            "suspected": [check["id"] for check in run["checks"] if check["verdict"] == "SUSPECTED"],
            "inconclusive": [check["id"] for check in run["checks"] if check["verdict"] == "INCONCLUSIVE"],
            "skipped": [check["id"] for check in run["checks"] if check["verdict"] == "SKIPPED"],
            "statement": ("Only checks whose evidence established an authentication effect are CONFIRMED; "
                          "SKIPPED and INCONCLUSIVE results are not clean results."),
        },
        "claims_policy": {
            "claims_unverified": run["claims_unverified"],
            "signature_verification": run["signature_verification"],
            "statement": CLAIMS_STATEMENT,
        },
        "constraints": run["constraints"],
        "limitations": run["limitations"],
    }


def render_authentication_report(run):
    scenario = run["scenario_id"]
    return environment.get_template("authentication.html").render(
        run=run, sections=build_authentication_sections(run), json_block=_json,
        reproduce=(f'curl -sS -X POST "http://127.0.0.1:8000/api/authentication-scans" '
                   f'-H "content-type: application/json" -d \'{{"scenario_id": "{scenario}"}}\''),
        report_url=f'http://127.0.0.1:8000/api/authentication-scans/{run["id"]}/report?view=sections')
