"""Mechanical P0 acceptance audit: registry, references, evidence classes, API reachability.

This is not a coverage tool. Every row names the frozen requirement, the code that
implements it, the tests that exercise it, and the kind of environment those tests
use. The audit fails when a reference dangles, when an implemented requirement has
no test, when a partial/missing row hides its gap, or when a test file has no
declared evidence class. It also proves that report/matrix requirements are
reachable through the real FastAPI application.

Run: `.venv/bin/python tools/p0_audit.py [--json PATH]`. Exit code 1 on failure.
"""
from __future__ import annotations

import argparse
import importlib
import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

EVIDENCE_LABELS = {
    "fixture": "in-process fixture runner/target; no socket is created",
    "mocked_http": "disabled guarded HTTPX transport with fake socket/TLS objects",
    "recorded_offline": "bounded recorded synthetic transcript, no sockets",
    "recorded_offline_authentication": "recorded authentication probe transcript, no sockets",
    "recorded_offline_validation": "recorded input/disclosure transcript, no sockets",
    "in_process_api": "FastAPI TestClient against a temporary SQLite file",
    "unit": "pure function/type tests; no transport at all",
    "real_networking": "opens a real connection (must be empty for P0)",
}

STATUSES = ("implemented", "partial", "missing", "unreachable")


@dataclass(frozen=True)
class Requirement:
    id: str
    area: Literal["safety", "detection", "reporting", "integration"]
    frozen: str
    statement: str
    implementation: tuple[str, ...]
    tests: tuple[str, ...]
    evidence: str
    status: str
    gap: str | None = None
    api_routes: tuple[tuple[str, str], ...] = field(default_factory=tuple)


# Every test file in the suite, with the environment it actually uses. A new test
# file that is not classified here fails the audit, so no test can silently claim
# an environment it does not use.
TEST_EVIDENCE = {
    "tests/integration/test_auth_checks.py": "fixture",
    "tests/integration/test_authentication_scenario.py": "recorded_offline_authentication",
    "tests/integration/test_checkpoint27_acceptance.py": "fixture",
    "tests/integration/test_checkpoint27_redaction.py": "unit",
    "tests/integration/test_enum_validation.py": "fixture",
    "tests/integration/test_generic_fixture_pipeline.py": "fixture",
    "tests/integration/test_generic_scenario_scan.py": "recorded_offline",
    "tests/integration/test_independent_validation_profiles.py": "fixture",
    "tests/integration/test_input_disclosure.py": "fixture",
    "tests/integration/test_observation_reports.py": "fixture",
    "tests/integration/test_offline_scan.py": "fixture",
    "tests/integration/test_p0_acceptance.py": "fixture",
    "tests/integration/test_p0_audit.py": "in_process_api",
    "tests/integration/test_p0_consistency.py": "recorded_offline",
    "tests/integration/test_p0_report_api.py": "recorded_offline",
    "tests/integration/test_sci_scenarios.py": "recorded_offline",
    "tests/security/test_sci_decisions.py": "unit",
    "tests/integration/test_read_bola_oracle.py": "fixture",
    "tests/integration/test_resource_enumeration.py": "fixture",
    "tests/integration/test_sensitive_disclosure.py": "fixture",
    "tests/integration/test_spec_inspection.py": "in_process_api",
    "tests/integration/test_sqlite_persistence.py": "fixture",
    "tests/integration/test_validation_scenario.py": "recorded_offline_validation",
    "tests/integration/test_verified_ownership.py": "fixture",
    "tests/security/test_authentication_probes.py": "recorded_offline_authentication",
    "tests/security/test_authorized_policy.py": "unit",
    "tests/security/test_authorized_scope.py": "unit",
    "tests/security/test_fixture_guard.py": "fixture",
    "tests/security/test_generic_guarded_bola.py": "mocked_http",
    "tests/security/test_httpx_boundary.py": "mocked_http",
    "tests/security/test_input_validation_probes.py": "recorded_offline_validation",
    "tests/security/test_live_disabled.py": "mocked_http",
    "tests/security/test_p0_adversarial_regression.py": "recorded_offline",
    "tests/security/test_p0_report.py": "recorded_offline",
    "tests/security/test_pinned_reader.py": "mocked_http",
    "tests/security/test_scope_classifications.py": "unit",
    "tests/security/test_shared_safety_policy.py": "mocked_http",
    "tests/unit/test_authentication.py": "unit",
    "tests/unit/test_contracts.py": "unit",
    "tests/unit/test_fixture_storage.py": "unit",
    "tests/unit/test_jwt_metadata.py": "unit",
    "tests/unit/test_observation_storage.py": "unit",
    "tests/unit/test_redaction_adversarial.py": "unit",
    "tests/unit/test_sensitive_disclosure_oracles.py": "unit",
    "tests/unit/test_spec_parser.py": "unit",
    "tests/unit/test_validation_oracles.py": "unit",
}

REQUIREMENTS = (
    Requirement(
        "S1", "safety", "§11", "Every outbound request passes the central policy guard",
        ("canarygate.guard.policy:check_common", "canarygate.guard.run_guard:RunSafetyGuard",
         "canarygate.guard.safety_guard:SafetyGuard"),
        ("tests/security/test_shared_safety_policy.py::test_both_boundaries_call_the_shared_policy_and_raise_the_same_violation",
         "tests/security/test_shared_safety_policy.py::test_common_policy_rejects_prohibited_methods_unknown_actors_and_exhausted_budget",
         "tests/security/test_shared_safety_policy.py::test_prohibited_methods_never_reach_fixture_handler_or_offline_transcript"),
        "mocked_http", "implemented"),
    Requirement(
        "S2", "safety", "§11", "Exact host/port allow-list, literal IP pinning, TLS hostname kept",
        ("canarygate.network.boundary:GuardedReadRunner", "canarygate.guard.run_guard:RunSafetyGuard"),
        ("tests/security/test_pinned_reader.py::test_requires_literal_organizer_ip_and_valid_private_credentials",
         "tests/security/test_pinned_reader.py::test_pins_socket_and_retains_tls_hostname_and_host_header",
         "tests/security/test_pinned_reader.py::test_ip_v6_pinning_and_tls_hostname"),
        "mocked_http", "partial",
        "Pinning is proven over socketpairs with the transport disabled; an approved-resolver "
        "flow and use against a real organizer target do not exist."),
    Requirement(
        "S3", "safety", "§11", "Redirects are never followed",
        ("canarygate.network.guarded_httpx", "canarygate.guard.run_guard"),
        ("tests/security/test_pinned_reader.py::test_httpx_redirect_cannot_follow_even_with_insecure_caller_configuration",
         "tests/security/test_pinned_reader.py::test_redirect_is_observed_but_not_followed"),
        "mocked_http", "implemented"),
    Requirement(
        "S4", "safety", "§10 §21", "Destructive and unlisted state-changing operations never execute",
        ("canarygate.guard.policy", "canarygate.scope.authorized"),
        ("tests/security/test_pinned_reader.py::test_unlisted_or_destructive_requests_never_connect",
         "tests/security/test_authorized_scope.py::test_destructive_classification_is_only_metadata_and_does_not_create_a_transport",
         "tests/security/test_fixture_guard.py::test_forbidden_requests_never_reach_handler"),
        "mocked_http", "implemented"),
    Requirement(
        "S5", "safety", "§21", "Sequential execution and one shared request budget",
        ("canarygate.guard.run_guard", "canarygate.guard.safety_guard"),
        ("tests/security/test_pinned_reader.py::test_sequential_execution_and_budget_under_concurrency",
         "tests/security/test_pinned_reader.py::test_shared_run_budget_across_two_httpx_runners",
         "tests/security/test_fixture_guard.py::test_concurrent_callers_are_serialized_and_share_budget"),
        "mocked_http", "implemented"),
    Requirement(
        "S6", "safety", "§10 §21", "Login only for the exact authorized operation, never retried",
        ("canarygate.accounts", "canarygate.guard.run_guard"),
        ("tests/security/test_pinned_reader.py::test_login_cannot_retry_or_use_unapproved_user_or_path",
         "tests/security/test_pinned_reader.py::test_guarded_login_binds_exact_operation_and_keeps_secrets_out_of_result",
         "tests/security/test_pinned_reader.py::test_rejected_login_retry_does_not_consume_additional_budget"),
        "mocked_http", "partial",
        "Login is proven only against the disabled guarded prototype and synthetic pre-provisioned "
        "scenario credentials; no supplied organizer credentials were ever used."),
    Requirement(
        "S7", "safety", "§21", "Scope file is the sole target authority; never base_url or public DNS",
        ("canarygate.scope.authorized", "canarygate.seed.recipe"),
        ("tests/security/test_scope_classifications.py::test_scope_is_sole_target_authority_and_recipe_rejects_secrets_and_base_url",
         "tests/security/test_authorized_scope.py::test_scope_requires_explicit_destination_approval_without_dns_fallback"),
        "unit", "implemented"),
    Requirement(
        "S8", "safety", "§11 §21", "Production networking is disabled before socket or DNS",
        ("canarygate.network.guarded_httpx", "canarygate.scan.offline"),
        ("tests/security/test_live_disabled.py::test_live_get_is_disabled_before_socket_or_dns",
         "tests/security/test_live_disabled.py::test_direct_transport_call_cannot_bypass_disabled_gate"),
        "mocked_http", "implemented"),
    Requirement(
        "S9", "safety", "§12", "Credentials and bodies are redacted before persistence and reporting",
        ("canarygate.evidence.redaction",),
        ("tests/integration/test_validation_scenario.py::test_sensitive_values_are_redacted_before_persistence",
         "tests/integration/test_authentication_scenario.py::test_credentials_never_reach_storage_or_reports",
         "tests/integration/test_checkpoint27_redaction.py::test_nested_headers_cookies_tokens_errors_and_debug_do_not_reach_outputs_or_sqlite"),
        "unit", "implemented"),
    Requirement(
        "S11", "safety", "§11", "Every supported execution path is bound to the same guard and scope",
        ("canarygate.scan.offline:OfflineGuardedRunner", "canarygate.scan.auth_runner",
         "canarygate.scan.validation_runner"),
        ("tests/integration/test_generic_scenario_scan.py::test_safety_cannot_be_bypassed_by_direct_runner_or_plan_construction",
         "tests/security/test_authentication_probes.py::test_scope_must_explicitly_permit_each_crafted_probe",
         "tests/security/test_input_validation_probes.py::test_runner_requires_a_declared_body_and_a_scoped_authentication_operation"),
        "recorded_offline", "implemented"),
    Requirement(
        "S10", "safety", "§21", "Stored evidence is integrity-checked and tampering fails closed",
        ("canarygate.database.scenario_store", "canarygate.database.auth_store",
         "canarygate.database.validation_store"),
        ("tests/integration/test_generic_scenario_scan.py::test_scenario_runs_survive_restart_and_detect_tampering",
         "tests/integration/test_authentication_scenario.py::test_runs_survive_restart_and_tampering_fails_closed",
         "tests/integration/test_validation_scenario.py::test_tampered_validation_run_is_rejected"),
        "recorded_offline", "implemented"),
    Requirement(
        "D1", "detection", "§5", "Endpoint inventory from an OpenAPI document",
        ("canarygate.spec.parser",),
        ("tests/unit/test_spec_parser.py::test_security_inheritance_and_overrides",
         "tests/unit/test_spec_parser.py::test_local_reference_resolution_and_parameter_override",
         "tests/unit/test_spec_parser.py::test_unsafe_or_unresolved_references_are_rejected"),
        "unit", "partial",
        "Subset parser, not full OpenAPI semantics; an uploaded document cannot drive a scan."),
    Requirement(
        "D2", "detection", "§6", "Expected access and its provenance are recorded per endpoint",
        ("canarygate.api.schemas:InventoryEndpoint",),
        ("tests/unit/test_spec_parser.py::test_security_inheritance_and_overrides",
         "tests/security/test_p0_report.py::test_endpoint_inventory_reports_expected_access_and_source"),
        "unit", "partial",
        "Only public/authenticated are derived from OpenAPI; owner-only comes from the synthetic "
        "policy and there is no general policy ingestion or inference confirmation."),
    Requirement(
        "D3", "detection", "§7", "Accounts and roles are established before checks",
        ("canarygate.accounts", "canarygate.scan.auth_generic"),
        ("tests/integration/test_offline_scan.py::test_full_fixture_api_pipeline_cannot_open_network",
         "tests/integration/test_generic_scenario_scan.py::test_scenario_verdicts_survive_the_application"),
        "fixture", "partial",
        "Two synthetic pre-provisioned accounts only; no role inventory, API-key/cookie onboarding "
        "or supplied credentials."),
    Requirement(
        "D4", "detection", "§7", "Read-BOLA CONFIRMED needs verified ownership plus private disclosure",
        ("canarygate.oracles.read_bola:evaluate_read_bola", "canarygate.seed.registry"),
        ("tests/integration/test_read_bola_oracle.py::test_confirmed_requires_both_evidence_parts",
         "tests/integration/test_read_bola_oracle.py::test_unverified_ownership_is_inconclusive",
         "tests/integration/test_read_bola_oracle.py::test_nonprivate_resources_cannot_auto_confirm",
         "tests/integration/test_read_bola_oracle.py::test_verified_denial_requires_checked_body_and_expected_denial"),
        "fixture", "implemented"),
    Requirement(
        "D5", "detection", "§7", "Exactly five verdicts, with SKIPPED and INCONCLUSIVE always explicit",
        ("canarygate.models.result:Verdict",),
        ("tests/security/test_p0_report.py::test_report_contains_exactly_the_frozen_nine_sections",
         "tests/integration/test_authentication_scenario.py::test_skipped_checks_stay_explicit_and_never_become_safe",
         "tests/integration/test_authentication_scenario.py::test_inconclusive_results_do_not_claim_absence_of_vulnerability"),
        "recorded_offline", "implemented"),
    Requirement(
        "D6", "detection", "§8", "AUTHN-01/02/03 missing, malformed and wrong-scheme credentials",
        ("canarygate.oracles.authentication", "canarygate.offline.auth_checks"),
        ("tests/integration/test_auth_checks.py::test_actual_probe_responses_determine_auth_verdicts",
         "tests/integration/test_p0_acceptance.py::test_auth_denial_with_unchecked_or_leaking_body_is_not_safe"),
        "fixture", "partial",
        "Fixed fixture credentials and one denial contract; no generic scheme or credential discovery."),
    Requirement(
        "D7", "detection", "§8", "AUTHN-04a/04b/05/06/08 tampering, alg:none, logout and API key",
        ("canarygate.oracles.authn_probes", "canarygate.scan.auth_generic"),
        ("tests/security/test_authentication_probes.py::test_subject_tampering_requires_an_observable_identity_change",
         "tests/security/test_authentication_probes.py::test_role_tampering_requires_an_observed_admin_capability",
         "tests/security/test_authentication_probes.py::test_alg_none_acceptance_is_never_safe",
         "tests/security/test_authentication_probes.py::test_logout_reuse_reports_behaviour_and_never_confirms",
         "tests/integration/test_authentication_scenario.py::test_authentication_verdicts_through_the_application"),
        "recorded_offline_authentication", "partial",
        "JWT claims are used only as crafted inputs, never verified; no live session, admin "
        "endpoint or supplied credentials."),
    Requirement(
        "D8", "detection", "§9", "INPUT-05/06/07 extra property, malformed JSON, special characters",
        ("canarygate.oracles.validation", "canarygate.scan.validation_generic"),
        ("tests/security/test_input_validation_probes.py::test_extra_property_acceptance_is_suspected_until_an_effect_is_observed",
         "tests/security/test_input_validation_probes.py::test_malformed_json_acceptance_is_suspected_not_safe",
         "tests/security/test_input_validation_probes.py::test_special_characters_validation_error_and_ordinary_rejection_are_safe",
         "tests/integration/test_validation_scenario.py::test_input_checks_execute_declared_probes_and_record_their_status"),
        "recorded_offline_validation", "partial",
        "Recorded synthetic bodies only; the exact authentication POST is the only injection point "
        "and no production parser is exercised."),
    Requirement(
        "D9", "detection", "§9", "DISC-01–06 stack trace, internals, sensitive data, excess fields, headers, enumeration",
        ("canarygate.oracles.disclosure", "canarygate.scan.validation_generic"),
        ("tests/integration/test_validation_scenario.py::test_disclosure_checks_rest_on_recorded_read_evidence",
         "tests/security/test_input_validation_probes.py::test_disclosure_signals_detect_only_bounded_signatures",
         "tests/security/test_input_validation_probes.py::test_enumeration_comparison_requires_two_usable_error_responses",
         "tests/security/test_input_validation_probes.py::test_disclosure_header_signals_require_a_version_or_debug_header"),
        "recorded_offline_validation", "partial",
        "Signature-based detection over recorded bodies: fixed pattern list, top-level-only schema "
        "comparison, no timing analysis, no nested schema comparison."),
    Requirement(
        "D10", "detection", "§12", "One remediation catalog entry per finding type",
        ("canarygate.report.p0:REMEDIATION_CATALOG",),
        ("tests/security/test_p0_report.py::test_remediation_catalog_has_one_entry_per_finding_type",
         "tests/security/test_p0_report.py::test_confirmed_findings_always_carry_a_catalog_remediation"),
        "recorded_offline", "implemented"),
    Requirement(
        "D11", "detection", "§7", "BFLA role-versus-policy checks",
        (), (), "unit", "missing",
        "No BFLA implementation exists; the report shows role coverage as a single "
        "role-escalation probe only."),
    Requirement(
        "D12", "detection", "§15", "Live validation against an organizer-authorized target",
        (), (), "real_networking", "missing",
        "Production transport is disabled by design; no live target has been contacted, so live "
        "readiness is not established."),
    Requirement(
        "R1", "reporting", "§12", "Exactly the nine frozen report sections in fixed order",
        ("canarygate.report.p0:P0_SECTION_KEYS", "canarygate.report.p0:build_p0_sections"),
        ("tests/security/test_p0_report.py::test_report_contains_exactly_the_frozen_nine_sections",
         "tests/integration/test_p0_report_api.py::test_frozen_nine_sections_are_available_for_every_run_kind"),
        "recorded_offline", "implemented"),
    Requirement(
        "R2", "reporting", "§12", "Findings name the redacted resource type and verified owner",
        ("canarygate.report.p0:redacted_target_resource", "canarygate.report.p0:redacted_verified_owner"),
        ("tests/security/test_p0_report.py::test_confirmed_bola_finding_names_a_redacted_resource_and_verified_owner",
         "tests/security/test_p0_report.py::test_unverified_ownership_is_never_reported_as_a_verified_owner",
         "tests/security/test_p0_report.py::test_verified_ownership_is_reported_even_when_the_verdict_is_inconclusive"),
        "recorded_offline", "implemented"),
    Requirement(
        "R3", "reporting", "§12", "Fixed severity mapping, no CVSS",
        ("canarygate.report.p0:severity_for",),
        ("tests/security/test_p0_report.py::test_severity_mapping_is_fixed_and_never_invented",),
        "recorded_offline", "implemented"),
    Requirement(
        "R4", "reporting", "§12", "Secured endpoints section only lists checked, expected denials",
        ("canarygate.report.p0:build_p0_sections",),
        ("tests/integration/test_generic_scenario_scan.py::test_secure_scan_reports_checked_denial_and_skipped_scan_reports_reason",
         "tests/integration/test_authentication_scenario.py::test_skipped_checks_stay_explicit_and_never_become_safe"),
        "recorded_offline", "implemented"),
    Requirement(
        "R5", "reporting", "§12", "Skipped and inconclusive checks are reported with reasons",
        ("canarygate.report.p0:build_p0_sections",),
        ("tests/integration/test_authentication_scenario.py::test_skipped_checks_stay_explicit_and_never_become_safe",
         "tests/integration/test_validation_scenario.py::test_malformed_or_hostile_responses_never_read_as_safe"),
        "recorded_offline", "implemented"),
    Requirement(
        "R6", "reporting", "§12", "Manual interventions and inferred items are recorded with sources",
        ("canarygate.report.p0:build_p0_sections",),
        ("tests/integration/test_p0_report_api.py::test_frozen_nine_sections_are_available_for_every_run_kind",),
        "recorded_offline", "implemented"),
    Requirement(
        "R7", "reporting", "§21", "Constraint checklist is printed in every report",
        ("canarygate.report.p0:build_p0_sections",),
        ("tests/integration/test_p0_report_api.py::test_frozen_nine_sections_are_available_for_every_run_kind",),
        "recorded_offline", "implemented"),
    Requirement(
        "R8", "reporting", "§13", "Matrix uses the five cell states and never hides untested cells",
        ("canarygate.report.matrix:cell_state", "canarygate.report.matrix:build_authorization_matrix"),
        ("tests/security/test_p0_report.py::test_cell_state_mapping_is_fixed",
         "tests/security/test_p0_report.py::test_matrix_exposes_untested_cells_instead_of_hiding_them",
         "tests/security/test_p0_report.py::test_matrix_never_presents_untested_columns_as_passing"),
        "recorded_offline", "implemented"),
    Requirement(
        "R9", "reporting", "§13", "Historical merge keeps the worst observation and both sources",
        ("canarygate.report.matrix:_merge",),
        ("tests/integration/test_p0_report_api.py::test_authorization_matrix_aggregates_stored_runs_and_keeps_gaps_visible",
         "tests/integration/test_p0_report_api.py::test_matrix_reports_clean_coverage_when_the_only_run_is_secure"),
        "recorded_offline", "implemented"),
    Requirement(
        "R10", "integration", "§12 §13", "Reports and matrix are reachable through the real application",
        ("canarygate.api.app:create_app",),
        ("tests/integration/test_p0_report_api.py::test_frozen_nine_sections_are_available_for_every_run_kind",
         "tests/integration/test_p0_report_api.py::test_p0_view_rejects_unknown_requests_and_never_leaks_secrets"),
        "in_process_api", "implemented",
        None,
        (("GET", "/api/scenario-scans/{run_id}/report"),
         ("GET", "/api/authentication-scans/{run_id}/report"),
         ("GET", "/api/validation-scans/{run_id}/report"),
         ("GET", "/api/authorization-matrix"))),
    Requirement(
        "R11", "integration", "§12", "Legacy fixture report cannot contradict the P0 report",
        ("canarygate.report.fixture", "canarygate.api.app:create_app"),
        ("tests/integration/test_p0_consistency.py::test_legacy_and_p0_reports_never_share_a_run_or_a_claim",),
        "recorded_offline", "implemented"),
    Requirement(
        "C1", "detection", "SCI", "SCI decision rules separate interaction, individual and noise",
        ("canarygate.oracles.interaction:decide", "canarygate.oracles.interaction:Baseline",
         "canarygate.oracles.interaction:Combined"),
        ("tests/security/test_sci_decisions.py::test_both_controls_pass_and_the_combination_leaks_data",
         "tests/security/test_sci_decisions.py::test_an_already_failing_control_prevents_a_confirmed_interaction",
         "tests/security/test_sci_decisions.py::test_a_response_change_without_security_impact_is_never_confirmed",
         "tests/security/test_sci_decisions.py::test_incomplete_baseline_is_inconclusive"),
        "unit", "implemented"),
    Requirement(
        "C2", "detection", "SCI", "Combined exchanges execute through one guarded runner and scope",
        ("canarygate.scan.interaction_runner:OfflineInteractionRunner",
         "canarygate.scan.interaction_generic:InteractionOrchestrator"),
        ("tests/integration/test_sci_scenarios.py::test_interaction_scenarios_execute_through_the_application",
         "tests/integration/test_sci_scenarios.py::test_unpermitted_interaction_is_blocked_by_the_guard_not_simulated",
         "tests/integration/test_sci_scenarios.py::test_budget_exhaustion_is_reported_and_never_confirmed"),
        "recorded_offline", "implemented"),
    Requirement(
        "C3", "reporting", "SCI", "SCI runs persist, survive restart and reject tampering",
        ("canarygate.database.interaction_store:InteractionStore",),
        ("tests/integration/test_sci_scenarios.py::test_runs_survive_restart_and_tampered_payloads_are_rejected",),
        "recorded_offline", "implemented"),
    Requirement(
        "C4", "reporting", "SCI", "SCI findings appear in the frozen nine-section report",
        ("canarygate.report.p0:_interaction_findings", "canarygate.report.interaction:build_interaction_sections"),
        ("tests/integration/test_sci_scenarios.py::test_confirmed_interaction_explains_both_baselines_and_redacts_the_secret",),
        "recorded_offline", "implemented"),
    Requirement(
        "C5", "reporting", "SCI", "SCI stays distinguishable in the authorization matrix",
        ("canarygate.report.matrix:cells_from_interactions",),
        ("tests/integration/test_sci_scenarios.py::test_interaction_findings_are_distinguishable_in_the_matrix",),
        "recorded_offline", "implemented"),
    Requirement(
        "C6", "safety", "SCI", "SCI evidence is redacted before persistence and reporting",
        ("canarygate.evidence.redaction:redact", "canarygate.database.interaction_store:InteractionStore"),
        ("tests/integration/test_sci_scenarios.py::test_confirmed_interaction_explains_both_baselines_and_redacts_the_secret",),
        "recorded_offline", "implemented"),
    Requirement(
        "C7", "integration", "SCI", "SCI is reachable through the application API",
        ("canarygate.api.app:create_app",),
        ("tests/integration/test_sci_scenarios.py::test_interaction_scenarios_execute_through_the_application",
         "tests/integration/test_sci_scenarios.py::test_api_rejects_unknown_scenarios_and_widened_payloads"),
        "in_process_api", "implemented",
        None,
        (("POST", "/api/interaction-scans"),
         ("GET", "/api/interaction-scans/{run_id}"),
         ("GET", "/api/interaction-scans/{run_id}/report"))),
    Requirement(
        "A1", "integration", "§15", "The acceptance audit itself is reproducible and complete",
        ("tools.p0_audit:run_audit",),
        ("tests/integration/test_p0_audit.py::test_audit_is_clean_and_covers_every_test_file",
         "tests/integration/test_p0_audit.py::test_every_requirement_row_is_well_formed",
         "tests/integration/test_p0_audit.py::test_windows_style_test_paths_are_normalised"),
        "in_process_api", "implemented"),
)


class AuditError(RuntimeError):
    pass


def collect_node_ids() -> set[str]:
    result = subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q"],
                            cwd=ROOT, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise AuditError(f"pytest collection failed:\n{result.stdout[-2000:]}{result.stderr[-2000:]}")
    return {line.strip() for line in result.stdout.splitlines() if "::" in line}


def check_symbol(reference: str) -> None:
    module_name, _, attr = reference.partition(":")
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:  # pragma: no cover - reported, not swallowed
        raise AuditError(f"{reference}: cannot import {module_name}: {exc}") from exc
    if attr and not hasattr(module, attr):
        raise AuditError(f"{reference}: {module_name} has no attribute {attr}")


def check_test(reference: str, node_ids: set[str]) -> None:
    matches = [node for node in node_ids if node == reference or node.startswith(reference + "[")]
    if not matches:
        raise AuditError(f"{reference}: no collected test matches this node id")


def check_test_file(reference: str) -> None:
    path = reference.split("::", 1)[0].replace("\\", "/")
    if path not in TEST_EVIDENCE:
        raise AuditError(f"{reference}: test file {path} has no declared evidence class")


def app_routes() -> dict[str, set[str]]:
    from canarygate.api.app import create_app

    with tempfile.TemporaryDirectory() as folder:
        app = create_app(Path(folder) / "audit.sqlite3")
        return {route.path: set(getattr(route, "methods", ()) or ()) for route in app.routes}


def run_audit() -> dict:
    node_ids = collect_node_ids()
    routes = app_routes()
    failures: list[str] = []
    rows = []

    # POSIX separators keep the registry identical on Windows and Linux.
    test_files = {path.relative_to(ROOT).as_posix() for path in (ROOT / "tests").rglob("test_*.py")}
    for path in sorted(test_files - set(TEST_EVIDENCE)):
        failures.append(f"unclassified test file: {path}")
    for path, label in TEST_EVIDENCE.items():
        if label not in EVIDENCE_LABELS:
            failures.append(f"{path}: unknown evidence label {label}")
        if label == "real_networking":
            failures.append(f"{path}: declares real networking, which P0 must not use")

    for requirement in REQUIREMENTS:
        row_failures: list[str] = []
        if requirement.status not in STATUSES:
            row_failures.append(f"unknown status {requirement.status}")
        if requirement.evidence not in EVIDENCE_LABELS:
            row_failures.append(f"unknown evidence label {requirement.evidence}")
        if requirement.status in {"partial", "missing", "unreachable"} and not requirement.gap:
            row_failures.append("partial/missing/unreachable row must state its gap")
        if requirement.status in {"implemented", "partial", "unreachable"} and not requirement.implementation:
            row_failures.append("implemented requirement has no implementation reference")
        if requirement.status in {"implemented", "partial"} and not requirement.tests:
            row_failures.append("implemented requirement has no test")
        for reference in requirement.implementation:
            try:
                check_symbol(reference)
            except AuditError as exc:
                row_failures.append(str(exc))
        for reference in requirement.tests:
            try:
                check_test_file(reference)
                check_test(reference, node_ids)
            except AuditError as exc:
                row_failures.append(str(exc))
        for method, path in requirement.api_routes:
            if path not in routes or method not in routes[path]:
                row_failures.append(f"route {method} {path} is not served by the application")
        if requirement.api_routes and requirement.status == "unreachable":
            row_failures.append("row claims unreachable but declares API routes")
        failures.extend(f"{requirement.id}: {item}" for item in row_failures)
        rows.append({
            "id": requirement.id, "area": requirement.area, "frozen": requirement.frozen,
            "statement": requirement.statement, "status": requirement.status,
            "evidence": requirement.evidence, "gap": requirement.gap,
            "implementation": list(requirement.implementation), "tests": list(requirement.tests),
            "api_routes": [f"{m} {p}" for m, p in requirement.api_routes],
            "failures": row_failures,
        })

    statuses = {status: sum(row["status"] == status for row in rows) for status in STATUSES}
    return {
        "requirements": len(rows), "statuses": statuses,
        "rows": rows, "failures": failures,
        "test_files": len(test_files), "collected_tests": len(node_ids),
        "api_routes_checked": sum(len(r.api_routes) for r in REQUIREMENTS),
        "real_networking_tests": [p for p, label in TEST_EVIDENCE.items() if label == "real_networking"],
    }


def render(report: dict) -> str:
    lines = [f"P0 audit: {report['requirements']} requirements, "
             f"{report['collected_tests']} collected tests, {report['test_files']} test files",
             "status: " + ", ".join(f"{k}={v}" for k, v in report["statuses"].items()),
             f"api routes checked: {report['api_routes_checked']}", ""]
    lines.append(f"{'id':<4}{'status':<13}{'evidence':<32}statement")
    for row in report["rows"]:
        lines.append(f"{row['id']:<4}{row['status']:<13}{row['evidence']:<32}{row['statement']}")
    if report["failures"]:
        lines.append("\nFAILURES:")
        lines.extend(f"  - {item}" for item in report["failures"])
    else:
        lines.append("\nno dangling references, unclassified tests or unreachable API claims")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    report = run_audit()
    print(render(report))
    if args.json:
        args.json.write_text(json.dumps(report, indent=2) + "\n")
    return 1 if report["failures"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
