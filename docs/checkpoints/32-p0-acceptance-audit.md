# Checkpoint 32 — full P0 acceptance audit

**Decision: the complete frozen P0 scope is NOT ACCEPTED. The offline subset we
actually ship is ACCEPTED WITH LIMITATIONS.** Nothing in this document claims
live validation, production readiness or BFLA coverage. The audit exists to make
that distinction checkable rather than rhetorical.

## Method

The audit is a repository artifact, not prose. `tools/p0_audit.py` holds 35
requirement rows derived from the frozen sections (6, 7, 8, 9, 10, 11, 12, 13,
21). Each row names the implementation symbols, the pytest node ids that exercise
them, the evidence class of those tests, and — when it is not implemented — the
gap. The tool fails when:

- an implementation module or symbol does not import;
- a cited test node id is not collected by pytest;
- a test file has no declared evidence class (so no test can silently claim an
  environment it does not use);
- any test file declares `real_networking` (P0 has none);
- an implemented requirement has no test;
- a partial, missing or unreachable row does not state its gap;
- a requirement that claims API reachability is not served by the real FastAPI
  application.

`tests/integration/test_p0_audit.py` runs the audit and asserts it is clean, so
the audit cannot rot. Running it now:

```text
P0 audit: 35 requirements, 709 collected tests, 44 test files
status: implemented=24, partial=9, missing=2, unreachable=0
api routes checked: 4
```

Tests-first was respected for the one behavioural defect found: the new
`target_resource` / `verified_owner` tests were written and failed before the
projection was changed.

## Stage A — requirement-by-requirement audit

### What the audit found

1. **A real frozen-spec defect, now fixed.** §12 item 4 requires every finding to
   name the **target resource and verified owner**. The checkpoint-31 report
   emitted `NOT_RECORDED` for both, justified by identifier minimisation. That
   was privacy-conscious but non-compliant: §7 requires ownership evidence to be
   reported, and §12 requires the fields. The report now emits a redacted
   representation derived only from stored facts — resource type, the verified
   owner account (the non-requesting account when exactly two accounts are
   authorized), "ownership verified" only when `ownership_verified` and
   `owner_baseline` are both true, and the identifier withheld. Unverified runs
   say `NOT_VERIFIED` and never name an owner. No raw identifier is exposed and
   no identifier is invented. Covered by R2 and three tests.
2. **AUTHN-07 is implemented but unreachable with the bundled scopes.** The
   public-health check runs only when the scope declares an exact
   `GET /public-health` operation with `expected_access: public`. No bundled
   scenario declares it, so the default run honestly reports SKIPPED. This is
   reported as Partial, not presented as working coverage.
3. **An uploaded OpenAPI document cannot drive a scan.** `POST /api/spec/upload`
   and `GET /api/endpoints` expose inspection only; the scan workflows use their
   bundled plans. D1/D2 stay Partial for that reason.
4. **BFLA and live validation are missing, not "pending".** No BFLA code or route
   exists; production transport is disabled and no organizer target has been
   contacted. These are the two rows that keep the full gate closed.
5. **Test environments are classified, with one honest caveat.** All 44 test
   files carry an evidence class (fixture, mocked HTTP, the three recorded-offline
   classes, in-process API, unit). Classification is per file, and a few files are
   genuinely mixed — `test_generic_scenario_scan.py` also drives a mocked HTTPX
   boundary but is labelled by its primary transport. No test file is labelled
   `real_networking`; the audit fails if one appears.

### The requirement table

`E` is the declared evidence class. `Gap` is mandatory for partial/missing rows.

| ID | § | Status | Evidence | Requirement | Implementation | Tests | Gap |
|---|---|---|---|---|---|---|---|
| S1 | §11 | implemented | mocked_http | Every outbound request passes the central policy guard | `canarygate.guard.policy:check_common`<br>`canarygate.guard.run_guard:RunSafetyGuard`<br>`canarygate.guard.safety_guard:SafetyGuard` | `test_both_boundaries_call_the_shared_policy_and_raise_the_same_violation`<br>`test_common_policy_rejects_prohibited_methods_unknown_actors_and_exhausted_budget`<br>`test_prohibited_methods_never_reach_fixture_handler_or_offline_transcript` | — |
| S2 | §11 | partial | mocked_http | Exact host/port allow-list, literal IP pinning, TLS hostname kept | `canarygate.network.boundary:GuardedReadRunner`<br>`canarygate.guard.run_guard:RunSafetyGuard` | `test_requires_literal_organizer_ip_and_valid_private_credentials`<br>`test_pins_socket_and_retains_tls_hostname_and_host_header`<br>`test_ip_v6_pinning_and_tls_hostname` | Pinning is proven over socketpairs with the transport disabled; an approved-resolver flow and use against a real organizer target do not exist. |
| S3 | §11 | implemented | mocked_http | Redirects are never followed | `canarygate.network.guarded_httpx`<br>`canarygate.guard.run_guard` | `test_httpx_redirect_cannot_follow_even_with_insecure_caller_configuration`<br>`test_redirect_is_observed_but_not_followed` | — |
| S4 | §10 §21 | implemented | mocked_http | Destructive and unlisted state-changing operations never execute | `canarygate.guard.policy`<br>`canarygate.scope.authorized` | `test_unlisted_or_destructive_requests_never_connect`<br>`test_destructive_classification_is_only_metadata_and_does_not_create_a_transport`<br>`test_forbidden_requests_never_reach_handler` | — |
| S5 | §21 | implemented | mocked_http | Sequential execution and one shared request budget | `canarygate.guard.run_guard`<br>`canarygate.guard.safety_guard` | `test_sequential_execution_and_budget_under_concurrency`<br>`test_shared_run_budget_across_two_httpx_runners`<br>`test_concurrent_callers_are_serialized_and_share_budget` | — |
| S6 | §10 §21 | partial | mocked_http | Login only for the exact authorized operation, never retried | `canarygate.accounts`<br>`canarygate.guard.run_guard` | `test_login_cannot_retry_or_use_unapproved_user_or_path`<br>`test_guarded_login_binds_exact_operation_and_keeps_secrets_out_of_result`<br>`test_rejected_login_retry_does_not_consume_additional_budget` | Login is proven only against the disabled guarded prototype and synthetic pre-provisioned scenario credentials; no supplied organizer credentials were ever used. |
| S7 | §21 | implemented | unit | Scope file is the sole target authority; never base_url or public DNS | `canarygate.scope.authorized`<br>`canarygate.seed.recipe` | `test_scope_is_sole_target_authority_and_recipe_rejects_secrets_and_base_url`<br>`test_scope_requires_explicit_destination_approval_without_dns_fallback` | — |
| S8 | §11 §21 | implemented | mocked_http | Production networking is disabled before socket or DNS | `canarygate.network.guarded_httpx`<br>`canarygate.scan.offline` | `test_live_get_is_disabled_before_socket_or_dns`<br>`test_direct_transport_call_cannot_bypass_disabled_gate` | — |
| S9 | §12 | implemented | unit | Credentials and bodies are redacted before persistence and reporting | `canarygate.evidence.redaction` | `test_sensitive_values_are_redacted_before_persistence`<br>`test_credentials_never_reach_storage_or_reports`<br>`test_nested_headers_cookies_tokens_errors_and_debug_do_not_reach_outputs_or_sqlite` | — |
| S11 | §11 | implemented | recorded_offline | Every supported execution path is bound to the same guard and scope | `canarygate.scan.offline:OfflineGuardedRunner`<br>`canarygate.scan.auth_runner`<br>`canarygate.scan.validation_runner` | `test_safety_cannot_be_bypassed_by_direct_runner_or_plan_construction`<br>`test_scope_must_explicitly_permit_each_crafted_probe`<br>`test_runner_requires_a_declared_body_and_a_scoped_authentication_operation` | — |
| S10 | §21 | implemented | recorded_offline | Stored evidence is integrity-checked and tampering fails closed | `canarygate.database.scenario_store`<br>`canarygate.database.auth_store`<br>`canarygate.database.validation_store` | `test_scenario_runs_survive_restart_and_detect_tampering`<br>`test_runs_survive_restart_and_tampering_fails_closed`<br>`test_tampered_validation_run_is_rejected` | — |
| D1 | §5 | partial | unit | Endpoint inventory from an OpenAPI document | `canarygate.spec.parser` | `test_security_inheritance_and_overrides`<br>`test_local_reference_resolution_and_parameter_override`<br>`test_unsafe_or_unresolved_references_are_rejected` | Subset parser, not full OpenAPI semantics; an uploaded document cannot drive a scan. |
| D2 | §6 | partial | unit | Expected access and its provenance are recorded per endpoint | `canarygate.api.schemas:InventoryEndpoint` | `test_security_inheritance_and_overrides`<br>`test_endpoint_inventory_reports_expected_access_and_source` | Only public/authenticated are derived from OpenAPI; owner-only comes from the synthetic policy and there is no general policy ingestion or inference confirmation. |
| D3 | §7 | partial | fixture | Accounts and roles are established before checks | `canarygate.accounts`<br>`canarygate.scan.auth_generic` | `test_full_fixture_api_pipeline_cannot_open_network`<br>`test_scenario_verdicts_survive_the_application` | Two synthetic pre-provisioned accounts only; no role inventory, API-key/cookie onboarding or supplied credentials. |
| D4 | §7 | implemented | fixture | Read-BOLA CONFIRMED needs verified ownership plus private disclosure | `canarygate.oracles.read_bola:evaluate_read_bola`<br>`canarygate.seed.registry` | `test_confirmed_requires_both_evidence_parts`<br>`test_unverified_ownership_is_inconclusive`<br>`test_nonprivate_resources_cannot_auto_confirm`<br>`test_verified_denial_requires_checked_body_and_expected_denial` | — |
| D5 | §7 | implemented | recorded_offline | Exactly five verdicts, with SKIPPED and INCONCLUSIVE always explicit | `canarygate.models.result:Verdict` | `test_report_contains_exactly_the_frozen_nine_sections`<br>`test_skipped_checks_stay_explicit_and_never_become_safe`<br>`test_inconclusive_results_do_not_claim_absence_of_vulnerability` | — |
| D6 | §8 | partial | fixture | AUTHN-01/02/03 missing, malformed and wrong-scheme credentials | `canarygate.oracles.authentication`<br>`canarygate.offline.auth_checks` | `test_actual_probe_responses_determine_auth_verdicts`<br>`test_auth_denial_with_unchecked_or_leaking_body_is_not_safe` | Fixed fixture credentials and one denial contract; no generic scheme or credential discovery. |
| D7 | §8 | partial | recorded_offline_authentication | AUTHN-04a/04b/05/06/08 tampering, alg:none, logout and API key | `canarygate.oracles.authn_probes`<br>`canarygate.scan.auth_generic` | `test_subject_tampering_requires_an_observable_identity_change`<br>`test_role_tampering_requires_an_observed_admin_capability`<br>`test_alg_none_acceptance_is_never_safe`<br>`test_logout_reuse_reports_behaviour_and_never_confirms`<br>`test_authentication_verdicts_through_the_application` | JWT claims are used only as crafted inputs, never verified; no live session, admin endpoint or supplied credentials. |
| D8 | §9 | partial | recorded_offline_validation | INPUT-05/06/07 extra property, malformed JSON, special characters | `canarygate.oracles.validation`<br>`canarygate.scan.validation_generic` | `test_extra_property_acceptance_is_suspected_until_an_effect_is_observed`<br>`test_malformed_json_acceptance_is_suspected_not_safe`<br>`test_special_characters_validation_error_and_ordinary_rejection_are_safe`<br>`test_input_checks_execute_declared_probes_and_record_their_status` | Recorded synthetic bodies only; the exact authentication POST is the only injection point and no production parser is exercised. |
| D9 | §9 | partial | recorded_offline_validation | DISC-01–06 stack trace, internals, sensitive data, excess fields, headers, enumeration | `canarygate.oracles.disclosure`<br>`canarygate.scan.validation_generic` | `test_disclosure_checks_rest_on_recorded_read_evidence`<br>`test_disclosure_signals_detect_only_bounded_signatures`<br>`test_enumeration_comparison_requires_two_usable_error_responses`<br>`test_disclosure_header_signals_require_a_version_or_debug_header` | Signature-based detection over recorded bodies: fixed pattern list, top-level-only schema comparison, no timing analysis, no nested schema comparison. |
| D10 | §12 | implemented | recorded_offline | One remediation catalog entry per finding type | `canarygate.report.p0:REMEDIATION_CATALOG` | `test_remediation_catalog_has_one_entry_per_finding_type`<br>`test_confirmed_findings_always_carry_a_catalog_remediation` | — |
| D11 | §7 | missing | unit | BFLA role-versus-policy checks | — | — | No BFLA implementation exists; the report shows role coverage as a single role-escalation probe only. |
| D12 | §15 | missing | real_networking | Live validation against an organizer-authorized target | — | — | Production transport is disabled by design; no live target has been contacted, so live readiness is not established. |
| R1 | §12 | implemented | recorded_offline | Exactly the nine frozen report sections in fixed order | `canarygate.report.p0:P0_SECTION_KEYS`<br>`canarygate.report.p0:build_p0_sections` | `test_report_contains_exactly_the_frozen_nine_sections`<br>`test_frozen_nine_sections_are_available_for_every_run_kind` | — |
| R2 | §12 | implemented | recorded_offline | Findings name the redacted resource type and verified owner | `canarygate.report.p0:redacted_target_resource`<br>`canarygate.report.p0:redacted_verified_owner` | `test_confirmed_bola_finding_names_a_redacted_resource_and_verified_owner`<br>`test_unverified_ownership_is_never_reported_as_a_verified_owner`<br>`test_verified_ownership_is_reported_even_when_the_verdict_is_inconclusive` | — |
| R3 | §12 | implemented | recorded_offline | Fixed severity mapping, no CVSS | `canarygate.report.p0:severity_for` | `test_severity_mapping_is_fixed_and_never_invented` | — |
| R4 | §12 | implemented | recorded_offline | Secured endpoints section only lists checked, expected denials | `canarygate.report.p0:build_p0_sections` | `test_secure_scan_reports_checked_denial_and_skipped_scan_reports_reason`<br>`test_skipped_checks_stay_explicit_and_never_become_safe` | — |
| R5 | §12 | implemented | recorded_offline | Skipped and inconclusive checks are reported with reasons | `canarygate.report.p0:build_p0_sections` | `test_skipped_checks_stay_explicit_and_never_become_safe`<br>`test_malformed_or_hostile_responses_never_read_as_safe` | — |
| R6 | §12 | implemented | recorded_offline | Manual interventions and inferred items are recorded with sources | `canarygate.report.p0:build_p0_sections` | `test_frozen_nine_sections_are_available_for_every_run_kind` | — |
| R7 | §21 | implemented | recorded_offline | Constraint checklist is printed in every report | `canarygate.report.p0:build_p0_sections` | `test_frozen_nine_sections_are_available_for_every_run_kind` | — |
| R8 | §13 | implemented | recorded_offline | Matrix uses the five cell states and never hides untested cells | `canarygate.report.matrix:cell_state`<br>`canarygate.report.matrix:build_authorization_matrix` | `test_cell_state_mapping_is_fixed`<br>`test_matrix_exposes_untested_cells_instead_of_hiding_them`<br>`test_matrix_never_presents_untested_columns_as_passing` | — |
| R9 | §13 | implemented | recorded_offline | Historical merge keeps the worst observation and both sources | `canarygate.report.matrix:_merge` | `test_authorization_matrix_aggregates_stored_runs_and_keeps_gaps_visible`<br>`test_matrix_reports_clean_coverage_when_the_only_run_is_secure` | — |
| R10 | §12 §13 | implemented | in_process_api | Reports and matrix are reachable through the real application | `canarygate.api.app:create_app` | `test_frozen_nine_sections_are_available_for_every_run_kind`<br>`test_p0_view_rejects_unknown_requests_and_never_leaks_secrets` | — |
| R11 | §12 | implemented | recorded_offline | Legacy fixture report cannot contradict the P0 report | `canarygate.report.fixture`<br>`canarygate.api.app:create_app` | `test_legacy_and_p0_reports_never_share_a_run_or_a_claim` | — |
| A1 | §15 | implemented | in_process_api | The acceptance audit itself is reproducible and complete | `tools.p0_audit:run_audit` | `test_audit_is_clean_and_covers_every_test_file`<br>`test_every_requirement_row_is_well_formed` | — |

## Stage B — adversarial regression

Nine tests in `tests/security/test_p0_adversarial_regression.py`, run against the
real API with sockets and DNS patched to fail. They iterate **all 17 bundled
synthetic scenarios** (6 read-BOLA, 7 authentication, 4 validation).

| Test | Property proved | False result it would catch |
|---|---|---|
| `test_every_reported_finding_carries_the_stored_verdict` | Report verdicts are a multiset-preserving projection of stored verdicts; ids unique | A projection that upgrades, drops or duplicates a result |
| `test_unperformed_checks_are_never_reported_as_safe` | SKIPPED/INCONCLUSIVE are listed exactly, never in the secured section, always with a reason | An unperformed check reading as a pass |
| `test_confirmed_bola_needs_complete_evidence_and_a_remediation` | CONFIRMED requires all six BOLA evidence flags, the trusted policy source, High severity and a remediation; non-CONFIRMED has neither severity nor remediation | A CONFIRMED with incomplete ownership/disclosure evidence |
| `test_no_report_or_store_contains_a_fixture_secret` | No scenario token, password, API key, canary or JWT prefix in any JSON report, HTML report, matrix response or SQLite bytes | A secret reaching persistence or a report |
| `test_matrix_cannot_show_green_for_a_confirmed_cell` | Green ⇒ tested and SAFE; red ⇒ CONFIRMED; only five states; SAFE observations really exist | A matrix that paints a confirmed cell green |

The corpus deliberately contains CONFIRMED, SAFE, SUSPECTED, INCONCLUSIVE and
SKIPPED runs, so these are not vacuous: the CONFIRMED BOLA case and at least one
green cell are asserted to exist.

## Stage C — cross-component consistency

Six tests in `tests/integration/test_p0_consistency.py` create fixture, scenario,
authentication and validation runs in one database and compare every layer:

| Test | What it pins down |
|---|---|
| `test_legacy_and_p0_reports_never_share_a_run_or_a_claim` | Fixture and P0 reports serve disjoint run ids and modes; the legacy HTML is not the frozen contract; cross-endpoint ids 404 |
| `test_report_counts_are_derived_from_the_stored_run` | Per-kind verdict counts equal the stored checks; findings equal stored verdicts; explicit list length equals SKIPPED+INCONCLUSIVE; secured ⊆ SAFE |
| `test_report_matrix_never_looks_worse_than_the_aggregate` | Every per-run cell is ≤ the aggregate cell under red>orange>green>grey>hatched, and every endpoint appears in the aggregate |
| `test_matrix_coverage_maths_holds_and_every_gap_is_explained` | `cells = rows × columns`, `tested + untested = cells`, by-state sums match, hatched cells have no verdict and a reason, non-hatched cells were tested |

The first test is what turns "the legacy report cannot contradict the new one"
from an assertion into evidence: the two contracts cannot even see each other's
runs.

## Stage D — the acceptance decision

| # | Audit question | Answer | Evidence |
|---|---|---|---|
| 1 | Every P0 requirement has an implementation reference | Yes for 33 of 35 rows; BFLA and live validation have none and say so | Audit table |
| 2 | Every implemented requirement has a test that exercises it | Yes — 33 rows cite collected node ids; the tool fails otherwise | `tools/p0_audit.py`, `test_p0_audit.py` |
| 3 | Every test declares fixtures / mocks / real networking | Yes, 44 of 44 files; zero real networking | `TEST_EVIDENCE`, audit failure on unclassified files |
| 4 | No unperformed check is marked SAFE | Proven across all 17 scenarios, both at oracle and report level | Stage B |
| 5 | No incomplete BOLA evidence produces CONFIRMED | Proven at the oracle (existing) and at the report projection (new) | Stage B, R2/D4 |
| 6 | No credential or secret reaches persistence or reports | Proven across every scenario, JSON + HTML + SQLite bytes | Stage B |
| 7 | Safety restrictions apply to every supported execution path | Eight safety rows, each bound to tests; every runner validates scope and authorizes immediately before release | S1–S11 |
| 8 | Nine report sections consistent across scan types | Same ordered keys, same finding contract, counts equal stored runs | R1, Stage C |
| 9 | The matrix cannot misrepresent coverage | Untested cells explicit, worse-state merge, green/red invariants, coverage maths | R8/R9, Stages B–C |
| 10 | The legacy fixture report cannot contradict the P0 report | Disjoint run spaces, disjoint modes, cross-ids 404, not the frozen contract | R11, Stage C |

### Verdict

- **Offline P0 subset — ACCEPTED WITH LIMITATIONS.** Read-BOLA, AUTHN-01–08,
  INPUT-05/06/07 and DISC-01–06 execute through one guarded recorded transport,
  persist with integrity checks, and render the frozen nine-section report and an
  honest matrix. 709 tests pass; the audit has no dangling references.
- **Complete frozen P0 — NOT ACCEPTED.** BFLA is absent; live/organizer
  validation is absent; nine requirements are partial (pinned reader not used
  live, login only synthetic, OpenAPI subset, no general policy ingestion,
  synthetic accounts, fixed credential/denial contracts, signature-based
  disclosure, recorded bodies only).
- **Production-ready live scanner — NOT CLAIMED.** The transport is disabled.

What would change the decision: an approved organizer target and credentials, a
live run whose evidence passes the same oracles, BFLA implementation, and general
policy ingestion. None of those exist today, and none should be simulated.

## Results

- `.venv/bin/python tools/run_ci_tests.py` → **709 passed** (689 + 20 new: 3
  report-field tests, 6 consistency, 9 adversarial, 2 audit).
- `python -m compileall -q canarygate tests tools` clean.
- Audit exit code 0; 35 requirements, 24 implemented, 9 partial, 2 missing, 0
  unreachable.
- CI: to be recorded after the commit is pushed.

## Limitations of this audit

- Evidence classes are per file, not per test; mixed files are labelled by their
  primary transport (stated above).
- The audit checks that cited tests are *collected*, not that each one is strong;
  the test bodies and the adversarial/consistency suites carry that weight.
- "Implemented" means the offline behaviour is implemented and tested, not that
  the frozen requirement is complete for a live target — the Partial rows and the
  gate verdict carry that distinction.
- No BFLA work was started. No detection behaviour was added in this checkpoint:
  the only code change is the report field required by §12.
