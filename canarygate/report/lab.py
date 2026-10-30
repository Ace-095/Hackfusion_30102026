"""Render TargetLab evidence reports; JSON sections and HTML share one stored run."""
import json

from canarygate.report.scenario import environment

STATEMENT = ("This run executed real HTTPS requests against the loopback TargetLab. It is "
             "controlled validation of our own test target, not live-organizer validation: "
             "the destination was the literal address 127.0.0.1, TLS was verified against a "
             "test-only CA with hostname checking on, redirects were refused, nothing was "
             "retried, and no external DNS lookup was performed. The evidence below is bounded "
             "to status codes and booleans; response bodies, tokens and passwords were never "
             "stored. No BOLA or SCI verdict is produced at this checkpoint.")


def _json(value):
    return json.dumps(value, indent=2, ensure_ascii=True, sort_keys=True)


def build_lab_sections(run):
    """Project one stored, integrity-checked TargetLab run into report sections."""
    return {
        "executive_summary": {
            "scenario_id": run["scenario_id"], "title": run["title"], "mode": run["mode"],
            "status": run["status"], "checks": len(run["checks"]),
            "summary": run["summary"], "transport": run["transport"]["mode"],
            "network_transport_enabled": run["transport"]["network_transport_enabled"],
            "production_networking": run["transport"]["production_networking"],
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
        "checks": run["checks"],
        "constraints": {**run["constraints"], "note": ("Loopback-only; redirects refused; no retries; "
                                                       "test CA pinned; production networking disabled.")},
        "limitations": run["limitations"],
    }


def render_lab_report(run):
    return environment.get_template("lab.html").render(
        run=run, sections=build_lab_sections(run), json_block=_json,
        reproduce=(f'curl -sS -X POST "http://127.0.0.1:8000/api/lab-scans" '
                   f'-H "content-type: application/json" -d \'{{"port": {run["transport"]["port"]}}}\''
                   f'   # requires a running TargetLab and CANARYGATE_TARGETLAB_CA'),
        report_url=f'http://127.0.0.1:8000/api/lab-scans/{run["id"]}/report?view=sections',
        lab_url=f'https://127.0.0.1:{run["transport"]["port"]}/docs')
