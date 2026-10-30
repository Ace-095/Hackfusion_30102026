"""Frozen nine-section report, severity/remediation mapping and authorization matrix.

Offline and synthetic: every run used here is a recorded bundled scenario.
"""
import json

import pytest

from canarygate.report.matrix import (COLUMNS, build_authorization_matrix, build_matrix,
                                      cell_state, cells_from_runs)
from canarygate.report.p0 import (P0_SECTION_KEYS, REMEDIATION_CATALOG, build_p0_sections,
                                  curl_for, severity_for)

SECRETS = ("synthetic-alpha-private", "synthetic-beta-private", "fixture-token",
           "offline-opaque-token", "eyJhbGciOiJIUzI1NiJ9")


def scenario_run(scenario_id="synthetic-vulnerable"):
    from canarygate.scan.scenarios import build_scenario, execute_offline_scenario
    return execute_offline_scenario(build_scenario(scenario_id))


def authentication_run(scenario_id="synthetic-jwt-sub-confirmed"):
    from canarygate.scan import auth_scenarios
    from canarygate.scan.auth_generic import run_authentication_scan
    plan = auth_scenarios.build_auth_scenario(scenario_id)
    runner = auth_scenarios.runner_for(plan)
    try:
        return run_authentication_scan(runner, plan)
    finally:
        runner.close()


def validation_run(scenario_id="synthetic-validation-weak"):
    from canarygate.scan import validation_scenarios
    from canarygate.scan.validation_generic import run_offline_validation
    plan = validation_scenarios.build_validation_scenario(scenario_id)
    runner = validation_scenarios.runner_for(plan)
    try:
        return run_offline_validation(plan, runner)
    finally:
        runner.close()


# ---------------------------------------------------------------- nine sections


@pytest.mark.parametrize("kind,run_factory", [("scenario", scenario_run),
                                              ("authentication", authentication_run),
                                              ("validation", validation_run)])
def test_report_contains_exactly_the_frozen_nine_sections(kind, run_factory):
    sections = build_p0_sections(kind, run_factory())
    assert tuple(sections) == P0_SECTION_KEYS
    assert len(sections) == 9


def test_executive_summary_counts_by_verdict_and_category():
    sections = build_p0_sections("authentication", authentication_run())
    summary = sections["executive_summary"]
    assert summary["run_kind"] == "authentication"
    assert summary["verdict_counts"]["CONFIRMED"] == 1
    assert sum(summary["verdict_counts"].values()) == 8
    assert summary["category_counts"]["Authentication"]["CONFIRMED"] == 1
    assert summary["live_target_contacted"] is False
    assert summary["network_transport_enabled"] is False


def test_scope_and_rules_state_the_engagement_and_limits():
    sections = build_p0_sections("validation", validation_run())
    scope = sections["scope_and_rules"]
    assert scope["origin"].startswith("https://")
    assert len(scope["scope_sha256"]) == 64
    assert scope["accounts"] and scope["request_budget"] > 0
    assert scope["seeding_rung"] == "NOT_APPLICABLE_OFFLINE_RECORDED_RESPONSES"
    assert "not organizer authorization" in scope["rules_of_engagement"].lower()


def test_endpoint_inventory_reports_expected_access_and_source():
    sections = build_p0_sections("validation", validation_run())
    inventory = sections["endpoint_inventory"]
    assert inventory and all({"method", "path", "parameters", "security", "expected_access",
                              "expected_source"} <= set(item) for item in inventory)
    assert any(item["path"] == "/login" for item in inventory)


# ---------------------------------------------------------------- findings


def test_scenario_finding_is_complete_and_explains_its_verdict():
    sections = build_p0_sections("scenario", scenario_run())
    findings = sections["findings"]["Authorization"]
    assert len(findings) == 1
    finding = findings[0]
    required = {"id", "category", "timestamp", "endpoint", "severity", "verdict", "reason",
                "account", "role", "target_resource", "verified_owner", "request", "response",
                "expected", "observed", "expectation_source", "evidence_checklist", "curl",
                "remediation", "remediation_key", "evidence_sha256"}
    assert required <= set(finding)
    assert finding["verdict"] == "CONFIRMED" and finding["severity"] == "High"
    assert finding["reason"] and finding["expectation_source"] == "offline scenario policy"
    assert finding["remediation_key"] == "bola" and finding["remediation"] in REMEDIATION_CATALOG.values()
    assert len(finding["evidence_sha256"]) == 64


def test_authentication_findings_cover_every_check_and_keep_skip_reasons():
    run = authentication_run("synthetic-jwt-opaque")
    sections = build_p0_sections("authentication", run)
    findings = sections["findings"]["Authentication"]
    assert len(findings) == 8
    skipped = [item for item in findings if item["verdict"] == "SKIPPED"]
    assert skipped and all(item["reason"] for item in skipped)
    assert sections["skipped_and_inconclusive"], "skipped checks must be listed explicitly"


def test_confirmed_findings_always_carry_a_catalog_remediation():
    findings = build_p0_sections("validation", validation_run())["findings"]
    confirmed = [item for category in findings.values() for item in category
                 if item["verdict"] == "CONFIRMED"]
    assert confirmed
    for item in confirmed:
        assert item["remediation_key"] in REMEDIATION_CATALOG
        assert item["remediation"] == REMEDIATION_CATALOG[item["remediation_key"]]


def test_severity_mapping_is_fixed_and_never_invented():
    assert severity_for("Authorization", "READ-BOLA", "CONFIRMED") == "High"
    assert severity_for("Authentication", "AUTHN-01", "CONFIRMED") == "High"
    assert severity_for("Authentication", "AUTHN-08", "CONFIRMED") == "High"
    assert severity_for("Authentication", "AUTHN-04a", "CONFIRMED") == "Medium"
    assert severity_for("Authentication", "AUTHN-05", "CONFIRMED") == "Medium"
    assert severity_for("Disclosure", "DISC-02", "CONFIRMED") == "Medium"
    assert severity_for("Input validation", "INPUT-06", "CONFIRMED") == "Low"
    for verdict in ("SAFE", "SUSPECTED", "INCONCLUSIVE", "SKIPPED"):
        assert severity_for("Authorization", "READ-BOLA", verdict) is None


def test_remediation_catalog_has_one_entry_per_finding_type():
    assert set(REMEDIATION_CATALOG) == {"bola", "bfla", "missing_authentication",
                                        "token_validation", "input_validation", "verbose_errors",
                                        "excessive_data_exposure", "headers"}


# ---------------------------------------------------------------- redaction


def test_curl_reproduction_uses_placeholders_and_never_a_real_credential():
    run = scenario_run()
    sections = build_p0_sections("scenario", run)
    curls = [item["curl"] for category in sections["findings"].values() for item in category]
    assert curls
    for command in curls:
        assert command.startswith("curl ")
        assert "$TOKEN_A" in command or "$TOKEN_B" in command or "no credential" in command
    text = json.dumps(sections)
    for secret in SECRETS:
        assert secret not in text
    assert curl_for("GET", "/records/rb", actor="account-a") == \
        'curl -sS -X GET "$BASE/records/rb" -H "Authorization: Bearer $TOKEN_A"'


def test_reports_never_contain_fixture_secrets_or_tokens():
    for kind, run in (("scenario", scenario_run()), ("validation", validation_run()),
                      ("authentication", authentication_run())):
        text = json.dumps(build_p0_sections(kind, run))
        for secret in SECRETS:
            assert secret not in text, (kind, secret)


# ---------------------------------------------------------------- matrix


def test_cell_state_mapping_is_fixed():
    assert cell_state("SAFE") == "green"
    assert cell_state("CONFIRMED") == "red"
    assert cell_state("SUSPECTED") == "orange"
    assert cell_state("INCONCLUSIVE") == "hatched"
    assert cell_state("SKIPPED") == "hatched"
    assert cell_state(None) == "grey"


def test_matrix_exposes_untested_cells_instead_of_hiding_them():
    matrix = build_matrix([{"endpoint": "GET /records/{id}", "method": "GET", "path": "/records/{id}",
                            "column": "other_account_resource", "verdict": "CONFIRMED",
                            "reason": "cross-account read", "expected_access": "owner-only",
                            "expected_source": "offline scenario policy",
                            "source_ref": "scenario:synthetic-vulnerable"}])
    assert matrix.columns == list(COLUMNS)
    assert len(matrix.rows) == 1
    cells = {cell.column: cell for cell in matrix.rows[0].cells}
    assert cells["other_account_resource"].state == "red"
    assert cells["other_account_resource"].tested is True
    assert cells["anonymous"].tested is False and cells["anonymous"].state == "hatched"
    assert cells["anonymous"].reason
    assert matrix.coverage.tested == 1 and matrix.coverage.untested == 3
    assert "partial" in matrix.coverage.statement.lower()
    assert matrix.live_target_contacted is False


def test_matrix_states_only_what_was_observed():
    matrix = build_matrix([
        {"endpoint": "GET /profile", "method": "GET", "path": "/profile", "column": "anonymous",
         "verdict": "SAFE", "reason": "checked denial", "expected_access": "authenticated",
         "expected_source": "offline scenario scope", "source_ref": "auth:synthetic-jwt-secure"},
        {"endpoint": "GET /profile", "method": "GET", "path": "/profile", "column": "role",
         "verdict": "SUSPECTED", "reason": "accepted without capability",
         "expected_access": "user", "expected_source": "offline scenario scope",
         "source_ref": "auth:synthetic-jwt-role-confirmed"},
    ])
    cells = {cell.column: cell for cell in matrix.rows[0].cells}
    assert cells["anonymous"].state == "green"
    assert cells["role"].state == "orange"
    assert matrix.coverage.by_state["hatched"] == 2


def test_matrix_is_built_from_stored_runs_and_counts_non_contributors():
    scenario = scenario_run()
    auth = authentication_run()
    validation = validation_run()
    cells, notes = cells_from_runs([scenario], [auth], [validation])
    assert cells and any(cell["column"] == "other_account_resource" for cell in cells)
    assert any(cell["column"] == "anonymous" for cell in cells)
    assert notes["validation"] == 1
    assert notes["authentication"] == 1 and notes["scenario"] == 1
    matrix = build_authorization_matrix([scenario], [auth], [validation])
    assert matrix.rows and matrix.coverage.untested > 0
    assert matrix.coverage.not_contributing["validation_runs"] == 1
    assert sum(matrix.verdict_counts.values()) > 0
    text = matrix.model_dump_json()
    for secret in SECRETS:
        assert secret not in text


def test_matrix_never_presents_untested_columns_as_passing():
    matrix = build_authorization_matrix([scenario_run("synthetic-secure")], [], [])
    assert matrix.rows
    for row in matrix.rows:
        for cell in row.cells:
            if not cell.tested:
                assert cell.state == "hatched" and cell.verdict is None
