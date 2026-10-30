# CanaryGate v3.2 — P0 acceptance audit (checkpoint 32)

**Gate: NOT ACCEPTED.** This is an implementation/test audit, not a claim of
production readiness or live validation. Tests below use synthetic fixtures,
mocked HTTP, or in-process socketpairs; no target scanner traffic was sent to
VAmPI, crAPI, an organizer API, or the internet. The public API can only run
its bundled fixture and bundled synthetic offline scenarios (read-BOLA and
authentication). Production networking remains disabled. “Partial” means specific tested behavior exists,
not that the frozen requirement is complete. Checkpoint 27 added the shared
fixture/mocked-HTTPX ownership registry and oracle; checkpoint 28 connects that
generic path to the application through a bounded recorded transport, SQLite
persistence, API access and consistent JSON/HTML scenario reports. Checkpoint 29
adds AUTHN-04a/04b/05/06/08 as guarded probes over the same recorded transport,
with explicit SKIPPED/INCONCLUSIVE outcomes. Checkpoint 30 adds INPUT-05/06/07
and DISC-01–06 on the same transport. Checkpoint 31 adds the frozen nine-section
P0 report for the scenario, authentication and validation workflows, plus an
aggregated authorization matrix that keeps untested cells visible and records
manual interventions and inferences honestly. Checkpoint 32 audits 35 frozen
requirements mechanically (`tools/p0_audit.py`, self-tested), adds adversarial and
cross-component consistency suites, and fixes the one behavioural defect the audit
found: §12 requires a target resource and verified owner, which are now reported as
a redacted representation instead of `NOT_RECORDED`. The decision is unchanged in
substance: the offline subset is accepted with limitations; complete frozen P0 is
not accepted. The recorded transport is still
synthetic data, not live validation, and no live target has been contacted.
The user-directed `docs/SAFETY_ADDENDUM.md` overrides the recipe target and
classification/DNS details in the frozen document.

Tests are named below so their assertions can be inspected; a test name alone
is not proof of broader coverage. Run all with `.venv/bin/python tools/run_ci_tests.py`.

## Evidence and test-type convention

| Label | What it means here |
|---|---|
| Fixture | In-process `FixtureRunner`/`FixtureTarget`; no socket is created. Used by R1/R2/R4/R5/R6/R7/R9/R10 and all persisted-report tests. |
| Mocked HTTP | Disabled `GuardedHTTPXTransport` with fake HTTP/TLS/socket objects; DNS functions fail the test if called. Used by R3/R5/C1–C3/recipe/adversarial-17–21 and the transport-reuse test. |
| Recorded offline | `OfflineGuardedRunner` releases bounded synthetic transcript responses after `RunSafetyGuard`; no sockets exist. Used by the scenario API/persistence/report tests. |
| Recorded offline authentication | `OfflineAuthRunner` releases probe responses only where the validated scope declares that probe, after the same `RunSafetyGuard`; no sockets exist. Used by the authentication API/persistence/report tests. |
| Recorded offline validation | `OfflineValidationRunner` releases one recorded response per scope-declared input probe and bounded reads after the same `RunSafetyGuard`; no sockets exist. Used by the validation API/persistence/report tests. |
| Report projection | `canarygate/report/{p0,matrix}.py` and `templates/p0.html` derive the frozen nine sections and the authorization matrix from stored runs; no new request is made. |
| Real networking | **None.** No cited test opens a live connection, resolves a public name, scans VAmPI/crAPI or contacts an organizer target. |

## Implementation index

| Area | Primary source files | Test type |
|---|---|---|
| R1 inventory / R2 access provenance | `canarygate/spec/parser.py`, `canarygate/offline/scan.py` | Fixture; parser unit inputs |
| R3 accounts/roles/login | `canarygate/accounts/*`, `canarygate/offline/target.py`, `canarygate/network/{guarded_httpx,boundary}.py`, `canarygate/scan/offline.py` | Fixture; mocked HTTP; recorded offline pre-provisioned synthetic credentials |
| R4 authentication | `canarygate/offline/auth_checks.py`, `canarygate/oracles/authentication.py`, `canarygate/oracles/authn_probes.py`, `canarygate/scan/auth_{transcript,runner,plan,generic,scenarios,models}.py` | Fixture; decode-only unit tests; recorded offline authentication |
| R5 read-BOLA | `canarygate/seed/registry.py`, `canarygate/oracles/read_bola.py`, `canarygate/scan/{generic,offline,plan,transcript,scenarios}.py` | Fixture; mocked HTTP; recorded offline workflow |
| R6 input validation | `canarygate/offline/input_checks.py`, `canarygate/oracles/validation.py`, `canarygate/scan/validation_{transcript,runner,plan,models,generic,scenarios}.py` | Fixture; recorded offline validation |
| R8 report / §13 matrix | `canarygate/report/{p0,matrix,fixture,scenario,authentication,validation}.py` | Recorded offline workflow; report projection |
| R7 disclosure | `canarygate/oracles/disclosure.py`, `canarygate/evidence/redaction.py` | Fixture; redaction unit inputs |
| R8 evidence/storage | `canarygate/evidence/{redaction,observations}.py`, `canarygate/database/{store,scenario_store}.py`, `canarygate/scan/models.py` | Fixture and recorded offline; SQLite temp files |
| R9/R10 verdicts and remediation | `canarygate/offline/scan.py`, `canarygate/report/{fixture,scenario}.py` | Fixture; recorded offline |
| C1–C3 guard/limits/traffic | `canarygate/guard/{policy,safety_guard,run_guard,authorized_preflight}.py`, `canarygate/network/{boundary,guarded_httpx}.py`, `canarygate/scan/offline.py`, `canarygate/scope/*` | Fixture; mocked HTTP; recorded offline |
| Recipe/ownership/pagination | `canarygate/seed/{recipe,registry}.py` | Fixture; mocked HTTP |
| Reports | `canarygate/report/{fixture,scenario}.py`, `canarygate/report/templates/{fixture,scenario}.html`, `canarygate/api/{app,schemas}.py` | Fixture and recorded offline; API `TestClient` |
| End-to-end | `canarygate/offline/scan.py`, `canarygate/scan/{generic,scenarios,auth_generic,auth_scenarios}.py`, `canarygate/api/app.py`, `canarygate/database/{store,scenario_store,auth_store}.py` | Fixture and recorded offline; API `TestClient`; sockets/DNS blocked |


## Frozen section 4 / traceability requirements

| Requirement | Status | Implementation and actual evidence / remaining gap |
|---|---|---|
| R1 OpenAPI inventory | Partial | `spec/parser.py`; `tests/unit/test_spec_parser.py::test_security_inheritance_and_overrides`, `test_local_reference_resolution_and_parameter_override`, `test_unsafe_or_unresolved_references_are_rejected`; inspection endpoint is in-memory (`test_spec_inspection.py`). Subset parser, not full OpenAPI semantic validation; uploaded document cannot drive a scan. |
| R2 expected access and provenance | Partial | Inventory records public/authenticated from OpenAPI, not object/role policy (`test_security_inheritance_and_overrides`). Owner-only source is a trusted synthetic fixture policy; general policy ingestion/confirmation and inferred-rule workflow absent. |
| R3 accounts and roles/login | Partial | Bundled two-account simulated fixture login; `test_offline_scan.py::test_full_fixture_api_pipeline_cannot_open_network`. The disabled guarded HTTPX prototype tests exact login and identity controls (`test_pinned_reader.py`). Checkpoint 28's offline scenario uses pre-provisioned synthetic credentials and two guarded profile controls through the API (`test_generic_scenario_scan.py`), not a login flow. Real supplied credentials, API-key/cookie workflows, role coverage and supplied-target execution remain absent. |
| R4 authentication | Partial | AUTHN table below. Only specific fixture checks run; no generic authentication suite. |
| R5 Read-BOLA | Partial | Fixture registry + two-part oracle (`test_verified_ownership.py`, `test_read_bola_oracle.py`), shared with mocked HTTPX and the recorded offline workflow. Checkpoint 28 runs six scenarios through `POST /api/scenario-scans` and persists/reports them (`test_generic_scenario_scan.py::test_scenario_verdicts_survive_the_application`, `test_confirmed_scan_is_explained_consistently_in_both_reports`). `test_confirmed_requires_both_evidence_parts` and `test_verified_denial_requires_checked_body_and_expected_denial` still govern evidence. The policy source and denial contract remain synthetic; there is no supplied-target operation selection, no general policy ingestion and no BFLA. |
| R6 validation | Partial | INPUT table below. |
| R7 disclosure | Partial | DISC table below. |
| R8 evidence/redaction/storage | Partial | Fixture evidence summaries, SQLite restart/integrity (`test_sqlite_persistence.py`) and the checkpoint-27 redaction regressions remain. Checkpoint 28 adds a strict scenario evidence schema (phase, actor/role, method, path template, status, allowlisted flags, hash), a separate `scenario_runs` table with payload/evidence checks, restart/tamper tests and a no-secrets assertion over JSON, HTML and SQLite bytes (`test_generic_scenario_scan.py`). Raw bodies, tokens and identifiers are not stored. Arbitrary live secrets, encodings and log sinks remain unproven; hashes are not signatures. |
| R9 vulnerable vs secured | Partial | Fixture five persisted verdicts (`test_generic_fixture_pipeline.py`) and checkpoint-26 authentication-history checks remain. Checkpoint 28's scenario API yields CONFIRMED, SAFE, two INCONCLUSIVE cases and two SKIPPED cases (`test_scenario_verdicts_survive_the_application`), with consistent secured/skipped reporting (`test_secure_scan_reports_checked_denial_and_skipped_scan_reports_reason`). No general endpoint/role coverage or live target. |
| R10 remediation | Partial | Findings have fixture-specific remediation strings; tests `test_auth_checks.py::test_actual_probe_responses_determine_auth_verdicts`, `test_input_disclosure.py::test_disclosure_checks_detect_observed_signatures_without_leaking_raw_details`, `test_p0_acceptance.py::test_debug_header_is_detected_without_storing_value`. No complete centralized catalog or all-check coverage. |
| C1–C3 central guard, limits and prohibited traffic | Partial | Fixture `SafetyGuard` and guarded `RunSafetyGuard` now both call `canarygate/guard/policy.check_common` for prohibited methods, actors/methods and budgets. Tests prove the shared call and identical violations (`test_shared_safety_policy.py`), and that prohibited methods never reach the fixture handler or recorded transcript. Exact fixture query/classification rules and validated-scope operation rules remain scope-specific layers; there is still no single unified guard class. The HTTPX transport remains disabled, no DNS/live test exists, and the approved-resolver flow is unimplemented. |
| Recipe, ownership, pagination, setup gates | Partial | Recipe rejects `base_url`/embedded passwords (`test_scope_classifications.py::test_scope_is_sole_target_authority_and_recipe_rejects_secrets_and_base_url`). Two private lists, peer exclusions and owner reads checked in `test_verified_ownership.py`; selectors/four-page cap/termination/budget checked in `test_generic_fixture_pipeline.py`. The same collector now serves mocked guarded HTTPX, binding the evidence to the exact recipe and requester and failing closed on hidden pagination metadata (`test_generic_guarded_bola.py`). Only narrow list/selector semantics; no general known-ID/creation/registration bootstrap, roles/login are synthetic, and no endpoint orchestrates the generic path. |
| End-to-end acceptance and independently authorized validation | Partial | Fixture workflows remain in `test_offline_scan.py`, `test_p0_acceptance.py`, `test_checkpoint27_acceptance.py`. Checkpoint 28 adds a generic offline workflow from validated scope/recipe/transcript through guarded reads, the shared oracle, SQLite and both reports (`test_generic_scenario_scan.py`). It uses recorded synthetic responses, not an uploaded spec or organizer target. Real target and VAmPI/crAPI have not been scanned; live readiness is not claimed. |

## Individual authentication checks (§8)

Statuses below are fixture-only, decode-only unit tests, or recorded offline
authentication runs, and are therefore **partial**, unless explicitly marked
missing. No row uses real networking. AUTHN-07's scoped synthetic health helper
is not present in the bundled fixture inventory, so the default run honestly
reports SKIPPED.

| ID | Status | Executed and tested behavior / gap |
|---|---|---|
| AUTHN-01 | Partial | Missing bearer on Alice's protected fixture item; bypass, denial, empty/redirect and scope/size cases in `test_auth_checks.py`. Unexpected, malformed, duplicate-key, private-leaking denial bodies are INCONCLUSIVE (`test_p0_acceptance.py::test_auth_denial_with_unchecked_or_leaking_body_is_not_safe`). |
| AUTHN-02 | Partial | Fixed malformed fixture bearer, same tests and denial-body safeguards; no generic token mechanism. |
| AUTHN-03 | Partial | Fixed wrong-scheme fixture credential, same tests; no generic scheme discovery. |
| AUTHN-04a | Partial | Recorded offline probe: `craft_token` retains the original signature and changes `sub` only; the decision needs an observable identity change (`test_authentication_probes.py::test_subject_tampering_requires_an_observable_identity_change`). `synthetic-jwt-sub-confirmed` is CONFIRMED with `identity_effect: target` through `POST /api/authentication-scans` (`test_authentication_scenario.py::test_scenario_verdicts_through_the_application`). No live target, no signature verification, no supplied credentials. |
| AUTHN-04b | Partial | Same crafting path for `role`; only an observed admin capability confirms, acceptance without capability is SUSPECTED, and a missing admin endpoint is INCONCLUSIVE (`test_role_tampering_requires_an_observed_admin_capability`). `synthetic-jwt-role-confirmed` is CONFIRMED through the API. No live admin endpoint and no signature verification. |
| AUTHN-05 | Partial | Unsigned `alg:none` token with an empty signature (`test_crafting_a_role_token_and_an_alg_none_token`); checked denial is SAFE, acceptance with an honoured identity is CONFIRMED, acceptance without an observable effect is SUSPECTED, and neither is ever SAFE (`test_alg_none_acceptance_is_never_safe`). Recorded offline only. |
| AUTHN-06 | Partial | Reported behaviour only: checked post-logout rejection is SAFE, a still-accepted token is SUSPECTED (never CONFIRMED), and an API without a declared logout is SKIPPED with an explicit reason (`test_logout_reuse_reports_behaviour_and_never_confirms`, `test_skipped_checks_stay_explicit_and_never_become_safe`). The logout POST is a recorded synthetic response; no live session is destroyed. |
| AUTHN-07 | Partial | Optional exact `/public-health` fixture operation: only declared public, scoped GET, missing credentials, 200 **and exact known body** can pass; wrong body/status is inconclusive and unscoped/undeclared is skipped before mock handler (`test_p0_acceptance.py::test_public_endpoint_check_is_scoped_and_not_just_http_200`). Not generic, and the bundled OpenAPI/scope does not declare it. |
| AUTHN-08 | Partial | API-key scheme only: missing and invalid keys must both be rejected for SAFE; either accepted with an identity is CONFIRMED; a non-API-key scheme is SKIPPED (`test_api_key_decision_uses_the_strictest_of_both_observations`, `synthetic-api-key`, `synthetic-api-key-accepted`). Recorded offline only. |

## Input and disclosure (§9)

Evidence type: synthetic fixture responses only; no row uses real networking.

| ID | Status | Evidence and limitation |
|---|---|---|
| INPUT-01 | Partial | Fixture `/search` required-limit omission + valid control; `test_input_disclosure.py::test_input_verdicts_follow_actual_scoped_fixture_responses`. Not generic. |
| INPUT-02 | Partial | Fixed wrong type on same query; same tests. |
| INPUT-03 | Partial | Fixed enum-invalid request only when exact matching schema exists; `test_enum_validation.py::test_enum_result_uses_actual_response_and_stays_offline` and `test_ambiguous_or_inapplicable_enum_is_skipped_without_probe`. |
| INPUT-04 | Partial | Fixed numeric out-of-range only; overlong strings not implemented; same input tests. |
| INPUT-05 | Partial | Declared `extra_property` probe on the exact authentication POST; a field-specific bounded 400/422 is SAFE and acceptance is SUSPECTED (no persistence checks in the MVP), requiring a verified control response (`test_validation_scenario.py::test_input_checks_execute_declared_probes_and_record_their_status`, `test_input_validation_probes.py::test_extra_property_acceptance_is_suspected_until_an_effect_is_observed`). Recorded synthetic responses only; no live operation was ever sent a body. |
| INPUT-06 | Partial | Declared `malformed_json` probe; a bounded parse error is SAFE and acceptance is SUSPECTED. A body containing traceback text or an oversized error is INCONCLUSIVE, never SAFE (`test_malformed_json_error_bodies_that_leak_internals_are_inconclusive`, `test_malformed_or_hostile_responses_never_read_as_safe`). Recorded synthetic only; no production parser is exercised. |
| INPUT-07 | Partial | Declared `special_characters` probe observing error handling only: a bounded validation error or an ordinary invalid-credential rejection is SAFE, acceptance or a 5xx is SUSPECTED, an ambiguous status is INCONCLUSIVE. Injected characters are quote, angle-bracket and NUL-like strings in a recorded fixture (`test_special_characters_validation_error_and_ordinary_rejection_are_safe`). No exploitation or data extraction is attempted. |
| DISC-01 | Partial | Bounded stack-trace signature scanned on a recorded error read; an observed signature is CONFIRMED and a complete clean scan is SAFE (`test_disclosure_checks_rest_on_recorded_read_evidence`, `synthetic-validation-weak`). Only the fixed signature name is recorded, never the raw text. |
| DISC-02 | Partial | SQLSTATE, JSON-escaped Unix source path and server-version signatures; detection is signature-based, not a general internals classifier (`test_disclosure_signals_detect_only_bounded_signatures`). Recorded synthetic error bodies only. |
| DISC-03 | Partial | Bounded JSON traversal with name-based sensitive fields plus three conservative value patterns (JWT, private-key header, provider key prefixes); an incomplete traversal is INCONCLUSIVE and only signal names are stored (`test_sensitive_values_are_detected_by_pattern_without_returning_them`, `test_sensitive_json_scan_is_bounded_and_reports_incompleteness`). Pattern coverage is a fixed list, not general secret detection. |
| DISC-04 | Partial | Top-level excess keys compared only against an explicitly closed simple response schema; a missing or open schema is SKIPPED with a reason and a non-object response is INCONCLUSIVE (`test_excess_field_comparison_needs_a_closed_simple_schema`). No nested or composed schema comparison. |
| DISC-05 | Partial | Server/version, `x-powered-by` and debug header names scanned on a recorded read; an observed header is CONFIRMED and a clean scan is SAFE (`test_disclosure_header_signals_require_a_version_or_debug_header`). Only signature names are stored; header values are not persisted or reported. |
| DISC-06 | Partial | Existing/nonexistent error comparison on two scoped reads: identical bounded 4xx bodies are SAFE, differing bodies are CONFIRMED, and a 2xx on the denied resource or any 5xx is INCONCLUSIVE (`test_enumeration_comparison_requires_two_usable_error_responses`, `test_malformed_or_hostile_responses_never_read_as_safe`). No timing, header or generic resource discovery. |

## Nine HTML and JSON report sections (§12)

Evidence type: stored recorded runs; the projection makes no request.

`?view=p0` on `/api/scenario-scans/{id}/report`, `/api/authentication-scans/{id}/report`
and `/api/validation-scans/{id}/report` returns exactly the frozen nine sections
in order (`build_p0_sections`, validated by `P0ReportSections`, which rejects a
missing, extra or reordered section). `format=html` renders the same projection
with a five-verdict legend. The legacy fixture `?view=sections` view keeps its
earlier partial projection and is not reclassified.

| # / section | Status and remaining gap |
|---|---|
| 1 Executive | Implemented for the three offline workflows: counts by verdict, category, severity, finding count and the no-live-target statement (`test_p0_report_api.py::test_frozen_nine_sections_are_available_for_every_run_kind`). Still synthetic-only data. |
| 2 Scope and rules | Implemented: origin/host/port, scope hash, written reference, accounts, budget, rules of engagement, seeding rung `NOT_APPLICABLE_OFFLINE_RECORDED_RESPONSES`; no organizer-supplied scope exists to hash. |
| 3 Inventory | Implemented: scenario runs use their stored inventory; authentication and validation runs derive it from validated scope operations with expected access and source (`test_report_groups_validation_findings_and_maps_severity`). No uploaded-spec inventory is scanned. |
| 4 Findings and remediation | Implemented: per-finding id, timestamp, endpoint, severity (fixed mapping), verdict, exact reason, account/role, expectation and source, observed bounded facts, evidence digest, curl with `$TOKEN_A` placeholders and a catalog remediation for CONFIRMED (`test_confirmed_findings_always_carry_a_catalog_remediation`, `test_curl_reproduction_uses_placeholders_and_never_a_real_credential`). Request/response bodies are not retained and the report says so. The target resource and verified owner are reported as a redacted representation: resource type, the verified owner account (only when ownership and the owner baseline are proven) and an explicitly withheld identifier; unverified runs say `NOT_VERIFIED` and name no owner (`test_confirmed_bola_finding_names_a_redacted_resource_and_verified_owner`, `test_unverified_ownership_is_never_reported_as_a_verified_owner`). |
| 5 Secured endpoints | Implemented: only SAFE findings with recorded evidence, and denial-based authentication checks additionally require `denial_body_checked`; safe endpoints are listed with the observed handling. |
| 6 Skipped/inconclusive | Implemented with the exact reason per check, including SKIPPED authentication checks and SKIPPED schema comparison. |
| 7 Authorization matrix | Partial: aggregated four-column matrix over stored runs with tested/untested counts, per-state counts and explicit untested cells; `own_resource` is grey because only the owner baseline is observed, and role coverage is limited to the role-escalation probe. No drill-down UI and no live coverage (`test_authorization_matrix_aggregates_stored_runs_and_keeps_gaps_visible`). |
| 8 Manual interventions/inferences | Implemented as recorded structure: `status: RECORDED`, `manual_intervention_required: false`, empty interventions for offline runs, and explicit inferences/assumptions with their sources (expected-access source, identity mapping, denial contract, identifier minimisation). No fabricated bootstrap history. |
| 9 Constraint checklist | Implemented from stored counters: allow-list, blocked count, zero out-of-scope/redirect/destructive/external/creation values with their sources, redaction yes, local assets yes, scope hash, offline mode. Production constraints remain unverified because no live run exists. |

## Frozen §15 adversarial tests and added checks 20–21

Evidence type: fixtures, mocked HTTP or fake sockets; none use real networking.

| # | Status | Real assertion / gap |
|---|---|---|
| 1 Reflected canary | Partial | `test_scope_classifications.py::test_reflected_resource_id_cannot_confirm_private_data` and `test_read_bola_oracle.py::test_masked_empty_or_identifier_baseline_cannot_confirm` cover ID-derived markers, not arbitrary attacker-controlled input reflection. |
| 2 Public ID/status | Partial | `test_scope_classifications.py::test_metadata_or_reflected_resource_id_is_not_private_disclosure`. Fixture only. |
| 3 Shared/public | Partial | `test_verified_ownership.py::test_shared_or_public_resources_are_recorded_but_never_private_verified`. Fixture only. |
| 4 Unknown permission | Partial | `test_offline_scan.py::test_unknown_policy_cannot_be_confirmed_even_with_disclosure`. Fixture only. |
| 5 BFLA without endpoint names | Missing | BFLA not implemented (P1 feature, but listed among frozen validation tests). |
| 6 Failed seeding | Partial | `test_offline_scan.py::test_verdict_depends_on_observed_evidence`, `test_auth_checks.py::test_skipped_setup_does_not_report_unrun_probes_safe`. Fixture only. |
| 7 OpenAPI inheritance/override | Partial | `test_spec_parser.py::test_security_inheritance_and_overrides` checks supported subset. |
| 8 Redirect/out-of-scope before connection | Partial | `test_fixture_guard.py::test_forbidden_requests_never_reach_handler`, `test_pinned_reader.py::test_redirect_is_observed_but_not_followed`; prototype mocks/socketpairs only, disabled in production. |
| 9 DELETE/destructive/unauthorized writes | Partial | `test_scope_classifications.py::test_operation_classification_blocks_destructive_and_unknown_get_before_transport`, `test_fixture_guard.py::test_forbidden_requests_never_reach_handler`; no enabled live boundary. |
| 10 Tokens redacted in reports | Partial | Synthetic values asserted in `test_offline_scan.py` and nested sentinels in `test_generic_fixture_pipeline.py`; arbitrary live redaction unproven. |
| 11 Secure mocked responses | Partial | `test_generic_fixture_pipeline.py::test_nested_paginated_end_to_end_confirms_and_secured_denial` and `test_p0_acceptance.py::test_nine_section_html_json_consistency_and_coverage`. Only exercised fixture controls, not every possible target. |
| 12 No cleanup; created resources left | Partial | Fixture runs no cleanup and no creation. Behavior after approved creation cannot be tested because creation is unimplemented. |
| 13 Unverified ownership | Partial | `test_read_bola_oracle.py::test_unverified_ownership_is_inconclusive`, registry tests. Fixture only. |
| 14 Missing identity | Partial | `test_verified_ownership.py::test_missing_second_account_or_token_fails_before_requests`; scanner skipped setup tests. Fixture only. |
| 15 Accepted modified JWT/no effect is SUSPECTED | Missing | Actual JWT modification and behavior comparison unimplemented. `inspect_jwt_metadata` is decode-only and never produces a verdict. |
| 16 Password/token redaction everywhere | Partial | Fixture recipe/scope reject passwords; nested alternate keys, cookies, headers, debug/error strings and synthetic sentinels are tested through JSON, HTML, observations, logs and SQLite (`test_redaction_adversarial.py`, `test_checkpoint27_redaction.py`). Only known names/patterns and known-shape fixture data are covered; arbitrary live secrets, encodings and log sinks are not proven. |
| 17 Exact host/port including alternate IPs | Partial | Guard tests and mocked pinned reader tests; checkpoint 27's generic proof path uses the same pinned transport with fake sockets. Integrated real-target execution remains disabled. |
| 18 Offline cannot network; no redirects | Partial | `test_scope_classifications.py::test_fixture_mode_uses_no_dns_resolver_or_network_connection` and fixture guard tests block connect/DNS; generic tests fail on DNS and use fake sockets. Production transport still lacks an approved live acceptance run. |
| 19 No state-changing retry | Partial | `test_scope_classifications.py::test_authentication_post_is_not_retried_on_error`, prototype login tests; no other state-changing operations execute. |
| 20 Classified destructive/unknown GET blocked | Partial | `test_scope_classifications.py::test_operation_classification_blocks_destructive_and_unknown_get_before_transport` covers fixture; prototype tests likewise, not an enabled integration. |
| 21 No public DNS / offline network | Partial | Fixture no DNS test above; approved-resolver-based live execution not implemented. |

## Checkpoint 29 authentication status

| Requirement | Status | Evidence and remaining gap |
|---|---|---|
| Frozen AUTHN definitions used, not inferred | Implemented | §8 rows and verdict table quoted in `docs/checkpoints/29-authentication-checks.md`; the skip wording matches the frozen text (`test_skip_reasons_are_the_frozen_spec_wording`). |
| AUTHN-04a/04b/05 crafted-token probes | Partial | `canarygate/oracles/authn_probes.py` + `canarygate/scan/auth_runner.py`; probes are declared per exact scoped operation and authorized by `AuthorizedPreflight` before release. Recorded offline only; no signature verification or key material. |
| AUTHN-06 logout reuse | Partial | Executes only when the plan declares a scoped POST logout and a pre-logout identity baseline; otherwise SKIPPED. Behavioural observation, never CONFIRMED. |
| AUTHN-08 API key | Partial | Missing and invalid keys both required to reject before SAFE; combined with the strictest precedence. Only the API-key scenarios exercise it. |
| Claims explicitly unverified | Implemented | Every run carries `claims_unverified: true` and `signature_verification: "not_performed"`; evidence stores a coarse identity effect, never a claim value (`test_reports_project_every_check_consistently`). |
| Malformed responses cannot be SAFE | Implemented | Exact denial-body contract; non-object/unobservable bodies are INCONCLUSIVE; mutated responses fail provenance and become INCONCLUSIVE (`test_malformed_probe_bodies_cannot_become_safe`, `test_unverifiable_probe_response_marks_only_that_check_inconclusive`). |
| Persistence, API and reports | Partial | `authentication_runs` with payload hash, `POST/GET /api/authentication-scans`, `?view=sections`, `?format=html`; restart/tamper and JSON/HTML consistency tests. Authentication-specific projection, not the frozen nine-section report. |
| Credential redaction | Partial | Tokens, crafted tokens, API keys and raw bodies absent from the run, sections, HTML and raw SQLite bytes (`test_credentials_never_reach_storage_or_reports`). Known-shape synthetic data only. |
| Production networking | Disabled | The offline runner has no socket, DNS, redirect or retry; CI and tests patch `socket.connect`/`getaddrinfo` to fail. |
| Live/supplied-target authentication | Missing | No organizer target, no supplied tokens, no live session; readiness is not claimed. |

## Checkpoint 28 generic workflow status

| Requirement | Status | Evidence and remaining gap |
|---|---|---|
| Orchestrator connects scope/recipe/guarded reads/ownership/oracle | Partial | `canarygate/scan/generic.py::run_generic_scan`, exercised through `POST /api/scenario-scans`. The same orchestrator runs over mocked HTTPX in `test_same_orchestrator_runs_over_mocked_httpx_boundary`; only recorded runs are persistable. |
| One safety-policy contract at every boundary | Partial | `check_common` is called by both `SafetyGuard` and `AuthorizedPreflight`; `test_shared_safety_policy.py` proves shared violations and no-execution blocks. Scope-specific layers and separate classes remain; production execution is disabled. |
| Persistence of generic verdicts | Partial | `scenario_runs` stores minimized, hashed runs; restart and tamper tests in `test_generic_scenario_scan.py`. No signing, no generic live-data evidence. |
| API visibility | Partial | `POST/GET /api/scenario-scans`, `/report?view=sections`, `/report?format=html`. Only six bundled synthetic scenario ids; no user target/transcript. |
| Consistent HTML/JSON evidence | Partial | Both derive from `build_scenario_sections`; `test_confirmed_scan_is_explained_consistently_in_both_reports` compares verdict, checklist and evidence. Seven sections, not the nine-section contract. |
| Acceptance outcomes through the workflow | Partial | CONFIRMED, SAFE, INCONCLUSIVE (metadata and leaky denial), SKIPPED (pagination limit and guard block) in `test_scenario_verdicts_survive_the_application`. Synthetic responses only. |
| Production/live scanning | Missing | Disabled transport, no DNS pinning execution, no organizer approval, no supplied-target scan. |
| Remaining P0 checks | Missing | Checkpoint 32's audit (`tools/p0_audit.py`, 35 rows) records 24 implemented, 9 partial, 2 missing and 0 unreachable. BFLA and live/organizer validation are the missing rows. The frozen nine-section report, the authorization-matrix view and manual-intervention capture are implemented for the three offline workflows; optional disclosure depth (DISC-03 patterns beyond the fixed list, DISC-04 nested schemas, DISC-06 timing) remains Partial. |


## Checkpoint 32 acceptance audit

`tools/p0_audit.py` is the machine-checked counterpart of this document. It maps
every frozen requirement to implementation symbols, collected test node ids and a
declared evidence class, verifies that the claimed API routes are served by the
real application, and fails on any dangling reference, unclassified test file,
implemented requirement without a test, or partial/missing row without a stated
gap. `tests/integration/test_p0_audit.py` runs it and asserts it is clean.

| Result | Count |
|---|---|
| Requirements audited | 35 |
| Implemented (offline behaviour, tested) | 24 |
| Partial (gap stated) | 9 |
| Missing | 2 — BFLA, live/organizer validation |
| Unreachable through the application API | 0 |
| Test files with a declared evidence class | 44 of 44 |
| Test files declaring real networking | 0 |

Stage B adds nine adversarial tests over all 17 bundled scenarios (no false SAFE,
no CONFIRMED without complete evidence, no secret in reports or SQLite, no green
cell for a confirmed observation). Stage C adds six cross-component tests
(per-run report counts equal stored runs, per-run matrix never worse than the
aggregate, coverage maths, legacy/P0 disjointness). Details and the full table:
`docs/checkpoints/32-p0-acceptance-audit.md`.

**Gate: still NOT ACCEPTED for complete frozen P0.** The offline subset is
accepted with documented limitations; live validation and BFLA remain absent and
must not be simulated.

## Checkpoint 33 — SCI (security control interaction)

SCI is additive and does not change any row above. Seven requirements were added
to `tools/p0_audit.py` (C1–C7) covering the decision oracle, the guarded combined
execution, persistence/tamper, the frozen nine-section report, matrix
distinguishability, redaction and API reachability.

| Result | Count |
|---|---|
| Requirements audited | 42 |
| Implemented | 31 |
| Partial (gap stated) | 9 |
| Missing | 2 — BFLA, live/organizer validation |
| Unreachable through the application API | 0 |
| Test files with a declared evidence class | 46 of 46 |
| Collected tests | 760 |
| Test files declaring real networking | 0 |

SCI adds 33 tests: `tests/security/test_sci_decisions.py` (14, decision
precedence) and `tests/integration/test_sci_scenarios.py` (19, all ten bundled
scenarios through `TestClient(create_app(tmp sqlite))` with sockets patched to
fail). Ten scenarios cover cases A–H of the SCI acceptance list plus the two
extra interaction kinds; expected verdicts are `CONFIRMED` (A, redaction, AUTHN+AUTHZ,
INPUT+DISCLOSURE), `SAFE` (B), `INCONCLUSIVE` (C, D), `SKIPPED` (E, F) and
`SUSPECTED` (H). Details: `docs/checkpoints/33-sci-interaction.md`; interfaces
frozen in `docs/INTERFACE_FREEZE.md`.

Regression work in this checkpoint found and fixed one reporting defect: an
endpoint could appear in `secured_endpoints` while a sibling check was `CONFIRMED`
on it in the same report (`GET /profile`, AUTHN-04a). `_secured()` now excludes
such endpoints; no verdict rule changed. Cross-component tests also prove that a
`CONFIRMED` authorization finding reaches a red matrix cell, and that every red
cell is backed by a `CONFIRMED` finding in a contributing run.

**Gate unchanged: NOT ACCEPTED for complete frozen P0.** The offline subset,
now including SCI, is accepted with documented limitations; live validation and
BFLA remain absent and must not be simulated.

## Checkpoint 34 — TargetLab (not a P0 capability)

`targetlab/` is a deliberately vulnerable loopback-only API with two accounts,
private resources, a BOLA route, an interaction-vulnerable route, a secure route
and OpenAPI. It is a **validation target**, not a scanner feature: it changes no
P0 requirement, no verdict and no gate. Its 19 tests are classified
`in_process_api` so the audit still accounts for every test file, and the suite
total is now 779. Scanning the lab from CanaryGate is not implemented; that is
checkpoint 35, and it must not weaken the production guard.

## Next blocking work

1. Milestone 30 is complete in code: INPUT-05/06/07 and DISC-01–06 execute
   through `POST /api/validation-scans`; the narrow depth recorded per row above
   is the remaining limitation and is not a live-data claim.
2. Milestone 31 is complete in code: the frozen nine sections, an aggregated
   authorization matrix with visible gaps and recorded manual interventions/
   inferences are served for the scenario, authentication and validation
   workflows. The matrix remains partial offline coverage, not a live grid.
3. Milestone 32: full P0 regression and acceptance audit against the frozen
   specification, including an adversarial pass over the report claims. Do not
   claim P0.
4. Only after production guard/DNS/secret review and explicit written organizer
   authorization, run supplied-target acceptance and record scope and results.
