# CanaryGate v3.2 — P0 acceptance audit (checkpoint 27)

**Gate: NOT ACCEPTED.** This is an implementation/test audit, not a claim of
production readiness or live validation. Tests below use synthetic fixtures,
mocked HTTP, or in-process socketpairs; no target scanner traffic was sent to
VAmPI, crAPI, an organizer API, or the internet. The public API can only run
its bundled fixture. Production networking remains disabled. “Partial” means
specific tested behavior exists, not that the frozen requirement is complete.
Checkpoint 27 added a shared fixture/mocked-HTTPX ownership registry and oracle
path, broader redaction regressions and a JWT metadata helper. The generic path
is exercised by tests with fake sockets; it is **not** wired into the API,
persistence or reports, and no live target has been contacted.
The user-directed `docs/SAFETY_ADDENDUM.md` overrides the recipe target and
classification/DNS details in the frozen document.

Tests are named below so their assertions can be inspected; a test name alone
is not proof of broader coverage. Run all with `.venv/bin/python tools/run_ci_tests.py`.

## Frozen section 4 / traceability requirements

| Requirement | Status | Implementation and actual evidence / remaining gap |
|---|---|---|
| R1 OpenAPI inventory | Partial | `spec/parser.py`; `tests/unit/test_spec_parser.py::test_security_inheritance_and_overrides`, `test_local_reference_resolution_and_parameter_override`, `test_unsafe_or_unresolved_references_are_rejected`; inspection endpoint is in-memory (`test_spec_inspection.py`). Subset parser, not full OpenAPI semantic validation; uploaded document cannot drive a scan. |
| R2 expected access and provenance | Partial | Inventory records public/authenticated from OpenAPI, not object/role policy (`test_security_inheritance_and_overrides`). Owner-only source is a trusted synthetic fixture policy; general policy ingestion/confirmation and inferred-rule workflow absent. |
| R3 accounts and roles/login | Partial | Bundled two-account simulated login; `test_offline_scan.py::test_full_fixture_api_pipeline_cannot_open_network`. The disabled guarded HTTPX prototype tests exact login and identity controls (`test_pinned_reader.py`). Checkpoint 27 also feeds two guarded profile controls into the shared ownership collector (`test_generic_guarded_bola.py::test_generic_guarded_runner_feeds_same_oracle`), using mocked sockets. This is not connected to the API/scan; real supplied credentials, API-key/cookie workflows, role coverage and supplied-target execution remain absent. |
| R4 authentication | Partial | AUTHN table below. Only specific fixture checks run; no generic authentication suite. |
| R5 Read-BOLA | Partial | Fixture registry + two-part oracle (`test_verified_ownership.py`, `test_read_bola_oracle.py`), now shared with mocked guarded HTTPX (`test_generic_guarded_bola.py::test_generic_guarded_runner_feeds_same_oracle`). `test_confirmed_requires_both_evidence_parts` checks prerequisites and separate evidence; `test_verified_denial_requires_checked_body_and_expected_denial` checks a denial, not status alone. Confirmed/safe/inconclusive outcomes, forged responses, invalid provenance, unknown owner, missing baseline, shared/public resources and pagination are adversarial (`test_generic_guarded_bola.py`, `test_checkpoint27_acceptance.py`). Still fixture-policy/denial-contract specific, not orchestrated by a supplied target, not persisted for the generic path, and no BFLA. |
| R6 validation | Partial | INPUT table below. |
| R7 disclosure | Partial | DISC table below. |
| R8 evidence/redaction/storage | Partial | `test_offline_scan.py::test_full_fixture_api_pipeline_cannot_open_network` verifies hashed fixture evidence summaries; `test_sqlite_persistence.py` covers restart/integrity. Checkpoint 27 added alternate key, nested array, header, cookie, token, error and debug-string redaction tests (`test_redaction_adversarial.py`) and an end-to-end JSON/HTML/SQLite/log sentinel test (`test_checkpoint27_redaction.py`). Raw bodies are not stored and stored evidence is narrowed to known schema fields; arbitrary live secrets, URLs, headers, logs and encodings remain unproven. Hashes are not signatures. |
| R9 vulnerable vs secured | Partial | Fixture confirmed vs checked denial and five persisted verdicts tested in `test_generic_fixture_pipeline.py::test_all_five_verdicts_and_redacted_fixture_reports_without_network`; checked authentication denial and historical SAFE handling tested in `test_p0_acceptance.py`. No general endpoint/role coverage. |
| R10 remediation | Partial | Findings have fixture-specific remediation strings; tests `test_auth_checks.py::test_actual_probe_responses_determine_auth_verdicts`, `test_input_disclosure.py::test_disclosure_checks_detect_observed_signatures_without_leaking_raw_details`, `test_p0_acceptance.py::test_debug_header_is_detected_without_storing_value`. No complete centralized catalog or all-check coverage. |
| C1–C3 central guard, limits and prohibited traffic | Partial | Fixture `SafetyGuard` before mock transport; exact host/port/query, classification, budget and sequential calls tested in `test_scope_classifications.py`, `test_fixture_guard.py`. Disabled prototype `GuardedHTTPX` enforces its guard immediately before mocked TLS/socket creation, and tests pinning, quotas, halting, deadlines and no DNS in `test_pinned_reader.py`; `test_live_disabled.py` confirms production remains disabled. Checkpoint 27 made hidden pagination headers fail closed through the guarded boundary (`test_generic_guarded_bola.py::test_hidden_pagination_header_cannot_prove_list_completeness`). The fixture and prototype still have separate execution guards and are not one production boundary; resource creation is not executed and the approved-resolver flow remains unimplemented. |
| Recipe, ownership, pagination, setup gates | Partial | Recipe rejects `base_url`/embedded passwords (`test_scope_classifications.py::test_scope_is_sole_target_authority_and_recipe_rejects_secrets_and_base_url`). Two private lists, peer exclusions and owner reads checked in `test_verified_ownership.py`; selectors/four-page cap/termination/budget checked in `test_generic_fixture_pipeline.py`. The same collector now serves mocked guarded HTTPX, binding the evidence to the exact recipe and requester and failing closed on hidden pagination metadata (`test_generic_guarded_bola.py`). Only narrow list/selector semantics; no general known-ID/creation/registration bootstrap, roles/login are synthetic, and no endpoint orchestrates the generic path. |
| End-to-end acceptance and independently authorized validation | Partial | Bundled OpenAPI/scope/recipe through two mock logins and SQLite JSON/HTML in `test_offline_scan.py`, `test_p0_acceptance.py`, `test_checkpoint27_acceptance.py`. The latter exercises confirmed, secured, incomplete-evidence, malformed-response, authentication-denial and pagination-limit outcomes, and checks both reports and redaction. Generic mocked HTTPX has a component-level proof path but no scanner orchestration, persistence or report integration. Real target and VAmPI/crAPI have not been scanned. |

## Individual authentication checks (§8)

All statuses below are fixture-only and therefore **partial**, unless explicitly
marked missing. AUTHN-07's scoped synthetic health helper is not present in the
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

The opt-in JSON section view (`?view=sections`) and HTML now use one projection
of the same stored, integrity-checked fixture run. The legacy default JSON and
observation bundle remain unchanged. `test_p0_acceptance.py::test_nine_section_html_json_consistency_and_coverage`
compares all nine JSON section values with parsed HTML for confirmed, safe,
inconclusive and skipped fixture outcomes, with sockets/DNS blocked; the
budget test checks a safety-blocked report. A heading is not a complete feature:

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

## Checkpoint 27 generic proof-path status

| Requirement | Status | Evidence and remaining gap |
|---|---|---|
| One ownership algorithm for fixture and guarded HTTPX | Partial | `collect_fixture_ownership` and `collect_guarded_ownership` share `_collect_ownership`; two profile controls precede private lists, peer exclusion and owner reads. Tests use fake HTTP/TLS/socket objects. |
| One two-part oracle for both sources | Partial | `evaluate_read_bola` consumes either source; fixture header checks or guarded request-metadata provenance are selected explicitly. No second authorization engine. |
| Strict confirmation prerequisites | Partial | `test_generic_guarded_bola.py::test_generic_guarded_runner_feeds_same_oracle` verifies CONFIRMED/SAFE/INCONCLUSIVE; missing/unverified baselines, shared/public models, unknown policy and malformed denials cannot confirm or become SAFE. |
| Response provenance and mutation resistance | Partial | Guarded responses are recorded ephemerally; identity, path, status, body hash and pagination-metadata state must match. Forgery/mutation tests exist. This is an in-process invariant, not cryptographic attestation. |
| Generic persistence and reports | Missing | Generic oracle output is not stored or rendered; only fixture runs reach SQLite/JSON/HTML. |
| API/orchestration for generic runs | Missing | No supplied-target scan is exposed by the API; production networking remains disabled. |
| Evidence redaction | Partial | Bounded fixture schema plus broader key/pattern redaction tested through SQLite, JSON, HTML, observations and logs. Not universal. |
| JWT metadata | Partial | Decode-only, bounds-checked, non-authoritative metadata; crafted-token checks remain missing/SKIPPED. |

## Next blocking work

1. Build a generic scan orchestrator that connects recipe/spec/scope, guarded
   reads, ownership, the shared oracle, persistence and reports **without**
   enabling production networking. The current generic proof path is tested at
   component level only.
2. Complete remaining P0 checks: crafted JWT behavior where separately
   authorized, INPUT-05–07 with an approved JSON/string operation, broader
   DISC/output coverage, and the role/endpoint matrix. Keep inapplicable checks
   SKIPPED and ambiguous results INCONCLUSIVE.
3. Reconcile the fixture `SafetyGuard` and `RunSafetyGuard` into one reviewed
   execution boundary and complete production guard/DNS/secret review; no live
   execution is enabled meanwhile.
4. Only after production guard/secret review and explicit written organizer
   authorization, run supplied-target acceptance and record scope and results.
