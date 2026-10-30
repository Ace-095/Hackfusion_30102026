"""Render the fixture report with local Jinja2 templates and autoescaping."""
import json

from jinja2 import Environment, PackageLoader, select_autoescape

environment = Environment(loader=PackageLoader("canarygate.report", "templates"),
                          autoescape=select_autoescape(["html", "xml"]))


def _json(value):
    return json.dumps(value, indent=2, ensure_ascii=True)


def render_fixture_report(run: dict, observation_set: dict) -> str:
    secured = []
    if run["verdict"] == "SAFE":
        secured.append(run["endpoint"] + " — cross-user denial observed")
    secured.extend(check["id"] + " — " + check["reason"] for check in run["checks"]
                   if check["verdict"] == "SAFE" and check["category"] != "Disclosure")
    if not secured:
        secured.append("None observed in this fixture run")
    checks = {category: [check for check in run["checks"] if check["category"] == category]
              for category in ("Authentication", "Input validation", "Disclosure")}
    return environment.get_template("fixture.html").render(
        run=run, observations=observation_set, checks=checks, secured=secured,
        json_block=_json,
        new_scan='curl -sS -X POST "http://127.0.0.1:8000/api/scan"',
        retrieve=f'curl -sS "http://127.0.0.1:8000/api/reports/{run["id"]}?include_observations=true"')
