"""Render TargetLab BOLA reports; JSON sections and HTML share one stored run."""
import json

from canarygate.report.scenario import environment

STATEMENT = ("This run made real HTTPS requests to the loopback TargetLab and reached its verdict "
             "through the existing read-BOLA oracle: verified private ownership, verified owner "
             "baselines in both directions, a cross-account request whose response carried the "
             "owner's private marker, and a checked denial on the secure route. It is controlled "
             "validation of our own lab, not live-organizer validation. The lab's declared ground "
             "truth was compared with the finished verdicts afterwards and was never an input to "
             "the decision.")


def _json(value):
    return json.dumps(value, indent=2, ensure_ascii=True, sort_keys=True)


def build_lab_bola_sections(run):
    """Project one stored, integrity-checked TargetLab BOLA run into report sections."""
    return {
        "executive_summary": {
            "scenario_id": run["scenario_id"], "title": run["title"], "mode": run["mode"],
            "status": run["status"], "verdict": run["verdict"], "reason": run["reason"],
            "summary": run["summary"], "transport": run["transport"]["mode"],
            "network_transport_enabled": run["transport"]["network_transport_enabled"],
            "live_target_contacted": run["transport"]["live_target_contacted"],
            "ground_truth_matched": f'{run["ground_truth"]["matched"]}/6',
            "statement": STATEMENT,
        },
        "scope_and_transport": {
            "origin": run["scope"]["origin"], "mode": run["scope"]["mode"],
            "hostname": run["scope"]["hostname"], "port": run["scope"]["port"],
            "written_authorization_reference": run["scope"]["written_authorization_reference"],
            "request_budget": run["scope"]["request_budget"],
            "accounts": run["scope"]["accounts"],
            "expected_policy": run["scope"].get("expected_policy", {}),
            "tls_verification": run["transport"]["tls_verification"],
            "destination": run["transport"]["destination"],
            "redirects": run["transport"]["redirects"], "retries": run["transport"]["retries"],
            "dns": run["transport"]["dns"],
        },
        "ownership": {"declared_policy": run["policy"], "recipe": run["recipe"],
                      **run["ownership"]},
        "checks": run["checks"],
        "ground_truth": dict(run["ground_truth"]),
        "constraints": {**run["constraints"],
                        "note": ("Loopback-only; redirects refused; no retries; pinned test CA; "
                                 "no external DNS; production networking disabled.")},
        "limitations": run["limitations"],
    }


def render_lab_bola_report(run):
    return environment.get_template("lab_bola.html").render(
        run=run, sections=build_lab_bola_sections(run), json_block=_json,
        reproduce=(f'curl -sS -X POST "http://127.0.0.1:8000/api/lab-bola-scans" '
                   f'-H "content-type: application/json" -d \'{{"port": {run["transport"]["port"]}}}\''
                   f'   # requires a running TargetLab and CANARYGATE_TARGETLAB_CA'),
        report_url=f'http://127.0.0.1:8000/api/lab-bola-scans/{run["id"]}/report?view=sections',
        lab_url=f'https://127.0.0.1:{run["transport"]["port"]}/docs')
