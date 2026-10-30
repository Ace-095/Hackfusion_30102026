"""Render offline validation reports; JSON sections and HTML share one run."""
import hashlib
import json

from canarygate.evidence.redaction import canonical_json
from canarygate.report.scenario import environment

STATEMENT = ("Only checks whose recorded evidence established a specific weakness are CONFIRMED. "
             "Acceptance without a verified effect is SUSPECTED at most, and SKIPPED or "
             "INCONCLUSIVE results are not clean results.")


def _json(value):
    return json.dumps(value, indent=2, ensure_ascii=True, sort_keys=True)


def build_validation_sections(run):
    """Project one stored, integrity-checked validation run into report sections.

    This is a validation-specific projection, not the frozen nine-section P0
    report contract.
    """
    summary = run["summary"]
    scope = run["scope"]
    origin = f'{scope["scheme"]}://{scope["hostname"]}:{scope["port"]}'
    return {
        "executive_summary": {
            "scenario_id": run["scenario_id"], "title": run["title"], "mode": run["mode"],
            "status": run["status"], "transport": run["transport"], "summary": summary,
            "network_transport_enabled": run["network_transport_enabled"],
            "live_target_contacted": False,
        },
        "scope_and_accounts": {
            "origin": origin, "hostname": scope["hostname"], "port": scope["port"],
            "scope_sha256": hashlib.sha256(canonical_json(scope).encode("utf-8")).hexdigest(),
            "written_authorization_reference": scope["written_authorization_reference"],
            "accounts": scope["accounts"], "request_budget": scope["request_budget"],
            "accounting": {"requests_sent": run["requests_sent"],
                           "blocked_by_guard": run["blocked_by_guard"],
                           "budget_remaining": run["budget_remaining"]},
            "note": "Synthetic offline scenario label; this is not organizer authorization.",
        },
        "check_results": run["checks"],
        "outcome": {
            "summary": summary,
            "executed": [check["id"] for check in run["checks"] if check["verdict"] != "SKIPPED"],
            "confirmed": [check["id"] for check in run["checks"] if check["verdict"] == "CONFIRMED"],
            "suspected": [check["id"] for check in run["checks"] if check["verdict"] == "SUSPECTED"],
            "inconclusive": [check["id"] for check in run["checks"] if check["verdict"] == "INCONCLUSIVE"],
            "skipped": [check["id"] for check in run["checks"] if check["verdict"] == "SKIPPED"],
            "statement": STATEMENT,
        },
        "limitations": run["limitations"],
    }


def render_validation_report(run):
    scenario = run["scenario_id"]
    return environment.get_template("validation.html").render(
        run=run, sections=build_validation_sections(run), json_block=_json,
        reproduce=(f'curl -sS -X POST "http://127.0.0.1:8000/api/validation-scans" '
                   f'-H "content-type: application/json" -d \'{{"scenario_id": "{scenario}"}}\''),
        report_url=f'http://127.0.0.1:8000/api/validation-scans/{run["id"]}/report?view=sections')
