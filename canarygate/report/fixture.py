"""Render the fixture report with local Jinja2 templates and autoescaping."""
import json
from collections import Counter

from jinja2 import Environment, PackageLoader, select_autoescape

environment = Environment(loader=PackageLoader("canarygate.report", "templates"),
                          autoescape=select_autoescape(["html", "xml"]))


def _json(value):
    return json.dumps(value, indent=2, ensure_ascii=True)


def build_fixture_sections(run: dict) -> dict:
    """Derive both report formats from the same minimized, stored fixture run.

    This is a partial one-cell matrix, not a claim of full P0 report coverage.
    Legacy missing fields are not inferred from other evidence.
    """
    bola = {"id": "READ-BOLA", "category": "Authorization", "verdict": run["verdict"],
            "reason": run["reason"], "endpoint": run["endpoint"], "actor": run["actor"],
            "role": run["account_role"], "target_resource": run["target_resource"],
            "verified_owner": run["verified_owner"], "expected_access": run["expected_access"],
            "expected_source": run["expected_source"], "evidence": run["evidence"],
            "checklist": run.get("bola_checklist", {}), "remediation": run["remediation"]}
    checks = []
    for check in run["checks"]:
        item = dict(check)
        evidence = check.get("evidence")
        item["endpoint"] = (evidence["method"] + " " + evidence["path"]) if evidence else "Not recorded"
        checks.append(item)
    all_results = [bola] + checks
    counts = {name: sum(item["verdict"] == name for item in all_results)
              for name in ("CONFIRMED", "SUSPECTED", "SAFE", "INCONCLUSIVE", "SKIPPED")}
    by_category = {}
    for item in all_results:
        by_category.setdefault(item["category"], Counter())[item["verdict"]] += 1
    findings = {category: [item for item in all_results if item["category"] == category
                           and item["verdict"] in ("CONFIRMED", "SUSPECTED")]
                for category in ("Authentication", "Authorization", "Input validation", "Disclosure")}
    secured = []
    checklist = run.get("bola_checklist", {})
    if (bola["verdict"] == "SAFE" and checklist.get("verified_denial") is True
            and checklist.get("response_checked") is True and checklist.get("policy_denies_access") is True
            and run["evidence"]["disclosure"] is not None):
        secured.append(bola)
    secured.extend(item for item in checks if item["verdict"] == "SAFE" and item["evidence"] is not None
                   and item["category"] in ("Authentication", "Input validation")
                   and (item["id"] not in ("AUTHN-01", "AUTHN-02", "AUTHN-03")
                        or item["evidence"]["checklist"].get("denial_body_checked") is True))
    return {
        "executive_summary": {"mode": "fixture", "bola_verdict": run["verdict"],
                              "verdict_counts": counts, "category_counts": {k: dict(v) for k, v in by_category.items()}},
        "scope_accounts_seeding": {"scope": run["constraints"]["scope"], "scope_hash": run["scope_hash"],
                                   "accounts": run["setup"]["accounts"],
                                   "actor_role": {"actor": run["actor"], "role": run["account_role"]},
                                   "other_roles": "NOT_RECORDED", "setup": run["setup"]},
        "endpoint_inventory": run["inventory"],
        "findings": findings,
        "secured_endpoints": secured,
        "skipped_and_inconclusive": [item for item in all_results if item["verdict"] in ("SKIPPED", "INCONCLUSIVE")],
        "authorization_matrix": {"coverage": "partial_fixture", "cells": [{
            key: run[key] for key in ("endpoint", "actor", "target_resource", "expected_access", "expected_source", "verdict")}]},
        "manual_interventions_and_inferences": {"status": "NOT_RECORDED", "interventions": None, "inferences": None},
        "constraint_checklist": run["constraints"],
    }


def render_fixture_report(run: dict, observation_set: dict) -> str:
    checks = {category: [check for check in run["checks"] if check["category"] == category]
              for category in ("Authentication", "Input validation", "Disclosure")}
    return environment.get_template("fixture.html").render(
        run=run, observations=observation_set, checks=checks,
        sections=build_fixture_sections(run),
        json_block=_json,
        new_scan='curl -sS -X POST "http://127.0.0.1:8000/api/scan"',
        retrieve=f'curl -sS "http://127.0.0.1:8000/api/reports/{run["id"]}?include_observations=true"')
