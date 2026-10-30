# CanaryGate v3.2 — P0 acceptance audit (checkpoint 28)

**Gate: NOT ACCEPTED.** This is an implementation/test audit, not a claim of
production readiness or live validation. Tests below use synthetic fixtures,
mocked HTTP, or in-process socketpairs; no target scanner traffic was sent to
VAmPI, crAPI, an organizer API, or the internet. The public API can only run
its bundled fixture and six bundled synthetic offline scenarios. Production
networking remains disabled. “Partial” means specific tested behavior exists,
not that the frozen requirement is complete. Checkpoint 27 added the shared
fixture/mocked-HTTPX ownership registry and oracle; checkpoint 28 connects that
generic path to the application through a bounded recorded transport, SQLite
persistence, API access and consistent JSON/HTML scenario reports. The recorded
transport is still synthetic data, not live validation, and no live target has
been contacted.
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
| Real networking | **None.** No cited test opens a live connection, resolves a public name, scans VAmPI/crAPI or contacts an organizer target. |

## Implementation index

| Area | Primary source files | Test type |
|---|---|---|
| R1 inventory / R2 access provenance | `canarygate/spec/parser.py`, `canarygate/offline/scan.py` | Fixture; parser unit inputs |
| R3 accounts/roles/login | `canarygate/accounts/*`, `canarygate/offline/target.py`, `canarygate/network/{guarded_httpx,boundary}.py`, `canarygate/scan/offline.py` | Fixture; mocked HTTP; recorded offline pre-provisioned synthetic credentials |
| R4 authentication | `canarygate/offline/auth_checks.py`, `canarygate/oracles/authentication.py` | Fixture; decode-only unit tests |
| R5 read-BOLA | `canarygate/seed/registry.py`, `canarygate/oracles/read_bola.py`, `canarygate/scan/{generic,offline,plan,transcript,scenarios}.py` | Fixture; mocked HTTP; recorded offline workflow |
| R6 input validation | `canarygate/offline/input_checks.py`, `canarygate/oracles/validation.py` | Fixture |
| R7 disclosure | `canarygate/oracles/disclosure.py`, `canarygate/evidence/redaction.py` | Fixture; redaction unit inputs |
| R8 evidence/storage | `canarygate/evidence/{redaction,observations}.py`, `canarygate/database/{store,scenario_store}.py`, `canarygate/scan/models.py` | Fixture and recorded offline; SQLite temp files |
| R9/R10 verdicts and remediation | `canarygate/offline/scan.py`, `canarygate/report/{fixture,scenario}.py` | Fixture; recorded offline |
| C1–C3 guard/limits/traffic | `canarygate/guard/{policy,safety_guard,run_guard,authorized_preflight}.py`, `canarygate/network/{boundary,guarded_httpx}.py`, `canarygate/scan/offline.py`, `canarygate/scope/*` | Fixture; mocked HTTP; recorded offline |
| Recipe/ownership/pagination | `canarygate/seed/{recipe,registry}.py` | Fixture; mocked HTTP |
| Reports | `canarygate/report/{fixture,scenario}.py`, `canarygate/report/templates/{fixture,scenario}.html`, `canarygate/api/{app,schemas}.py` | Fixture and recorded offline; API `TestClient` |
| End-to-end | `canarygate/offline/scan.py`, `canarygate/scan/{generic,scenarios}.py`, `canarygate/api/app.py`, `canarygate/database/{store,scenario_store}.py` | Fixture and recorded offline; API `TestClient`; sockets/DNS blocked |


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

All statuses below are fixture-only (or decode-only unit tests) and therefore
**partial**, unless explicitly marked missing. No row uses real networking. AUTHN-07's scoped synthetic health helper is not present in the
bundled fixture inventory, so the default run honestly reports SKIPPED.

| ID | Status | Executed and tested behavior / gap |
|---|---|---|
| AUTHN-01 | Partial | Missing bearer on Alice's protected fixture item; bypass, denial, empty/redirect and scope/size cases in `test_auth_checks.py`. Unexpected, malformed, duplicate-key, private-leaking denial bodies are INCONCLUSIVE (`test_p0_acceptance.py::test_auth_denial_with_unchecked_or_leaking_body_is_not_safe`). |
| AUTHN-02 | Partial | Fixed malformed fixture bearer, same tests and denial-body safeguards; no generic token mechanism. |
| AUTHN-03 | Partial | Fixed wrong-scheme fixture credential, same tests; no generic scheme discovery. |
| AUTHN-04a | Missing | Strict JWT-format heuristic and SKIPPED reasons in `test_authentication.py`; checkpoint 27 added bounded, unverified claim metadata (`inspect_jwt_metadata`, `test_jwt_metadata.py`) but no sub-tampering probe or effective-identity oracle. |
| AUTHN-04b | Missing | Same format/skip behavior and metadata helper; no role-tampering probe or observable admin-capability check. |
| AUTHN-05 | Missing | JWT heuristic and skip only; no `alg:none` probe. Metadata decoding never verifies a signature or authorizes a request. |
| AUTHN-06 | Missing | Explicitly SKIPPED; no logout/reuse test. No unapproved logout is sent. |
| AUTHN-07 | Partial | Optional exact `/public-health` fixture operation: only declared public, scoped GET, missing credentials, 200 **and exact known body** can pass; wrong body/status is inconclusive and unscoped/undeclared is skipped before mock handler (`test_p0_acceptance.py::test_public_endpoint_check_is_scoped_and_not_just_http_200`). Not generic, and the bundled OpenAPI/scope does not declare it. |
| AUTHN-08 | Missing | Explicitly SKIPPED; no missing/invalid API-key probe. |

## Input and disclosure (§9)

Evidence type: synthetic fixture responses only; no row uses real networking.

| ID | Status | Evidence and limitation |
|---|---|---|
| INPUT-01 | Partial | Fixture `/search` required-limit omission + valid control; `test_input_disclosure.py::test_input_verdicts_follow_actual_scoped_fixture_responses`. Not generic. |
| INPUT-02 | Partial | Fixed wrong type on same query; same tests. |
| INPUT-03 | Partial | Fixed enum-invalid request only when exact matching schema exists; `test_enum_validation.py::test_enum_result_uses_actual_response_and_stays_offline` and `test_ambiguous_or_inapplicable_enum_is_skipped_without_probe`. |
| INPUT-04 | Partial | Fixed numeric out-of-range only; overlong strings not implemented; same input tests. |
| INPUT-05 | Missing | Extra JSON property SKIPPED before any request; no approved JSON-accepting operation or separate authorization. |
| INPUT-06 | Missing | Malformed JSON SKIPPED before any request; no approved JSON-accepting operation. |
| INPUT-07 | Missing | Special characters SKIPPED; no declared scalar string field with an independently approved literal probe. |
| DISC-01 | Partial | Narrow traceback signature in sampled search responses; `test_input_disclosure.py::test_disclosure_checks_detect_observed_signatures_without_leaking_raw_details`. |
| DISC-02 | Partial | Limited SQLSTATE and Unix-path signatures, same tests; not general internals detection. |
| DISC-03 | Partial | Bounded JSON name-based sensitive-field detection (`test_sensitive_disclosure.py::test_actual_response_contents_drive_disclosure_verdicts_without_leaking`); incomplete patterns/internal flags and response coverage. |
| DISC-04 | Partial | Top-level extra keys only for explicitly closed simple fixture JSON schemas; `test_sensitive_disclosure.py`; no general schema comparison. |
| DISC-05 | Partial | Narrow version/debug header names in sampled fixture responses; `test_p0_acceptance.py::test_debug_signal_is_retained_and_redacted_in_stored_sections`; header values not retained. Not comprehensive. |
| DISC-06 | Partial | One predeclared synthetic existing/nonexistent pair, compare status, content type and body in memory; `test_resource_enumeration.py::test_known_synthetic_resource_comparison_uses_real_guarded_responses`. No generic enumeration, timing or arbitrary headers. |

## Nine HTML and JSON report sections (§12)

Evidence type: fixture `TestClient`/SQLite only; no real networking.

The opt-in JSON section view (`?view=sections`) and HTML now use one projection
of the same stored, integrity-checked fixture run. The legacy default JSON and
observation bundle remain unchanged. `test_p0_acceptance.py::test_nine_section_html_json_consistency_and_coverage`
compares all nine JSON section values with parsed HTML for confirmed, safe,
inconclusive and skipped fixture outcomes, with sockets/DNS blocked; the
budget test checks a safety-blocked report. Scenario runs use a separate
seven-section projection (`executive_summary`, `scope_and_accounts`,
`endpoint_inventory`, `bola_evidence`, `outcome`, `constraints`, `limitations`);
it is not the full frozen nine-section contract. A heading is not a complete feature:

| # / section | Status and remaining gap |
|---|---|
| 1 Executive | Partial: fixture counts by verdict/category; no wider run coverage. |
| 2 Scope/accounts/seeding | Partial: fixture scope/hash, recorded accounts, actor role and setup; other roles explicitly NOT_RECORDED, no full rules-of-engagement or general rung history. |
| 3 Inventory | Partial: persisted fixture inventory including security/access/source; uploaded inventory is not scanned. |
| 4 Findings/remediation | Partial: grouped fixture findings and available redacted evidence/reasons/remediation; not all required fields/severity, general reproductions, full request/response or all catalog entries. The mock target cannot be replayed with curl. |
| 5 Secured endpoints | Partial: fixture SAFE checks with evidence; BOLA requires the recorded denial checklist. Legacy BOLA/authentication SAFE records without the relevant denial checklist are not promoted to secured (`test_legacy_safe_verdict_without_checklist_is_not_reclassified_as_secured`, `test_auth_secure_section_requires_recorded_denial_body_check`). Not general coverage. |
| 6 Skipped/inconclusive | Partial: fixture entries and reasons, including BOLA and guard blocking; not an exhaustive catalog of every disallowed target operation. |
| 7 Authorization matrix | Partial: one observed fixture cross-user cell explicitly labeled `partial_fixture`; no anonymous/own/other/role grid or drill-down. |
| 8 Manual interventions/inferences | Missing capture: section says NOT_RECORDED, never fabricates a clean bootstrap. |
| 9 Constraint checklist | Partial: fixture counters and scope hash; production constraints unverified. |

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
| Remaining P0 checks | Missing | AUTHN-04a/04b/05/06/08, INPUT-05–07, full DISC coverage, role/endpoint matrix and manual-intervention capture. |

## Next blocking work

1. Milestone 29: remaining P0 authentication checks — crafted-token behavior
   only where separately authorized, plus logout/API-key applicability — with
   SKIPPED/INCONCLUSIVE instead of inferred SAFE.
2. Milestone 30: remaining input-validation and disclosure checks, including an
   approved JSON/string operation and broader output coverage.
3. Milestone 31: complete the report contract — nine sections for generic runs,
   full authorization matrix and manual-intervention/inference capture.
4. Milestone 32: full P0 regression and acceptance audit. Do not claim P0.
5. Only after production guard/DNS/secret review and explicit written organizer
   authorization, run supplied-target acceptance and record scope and results.
