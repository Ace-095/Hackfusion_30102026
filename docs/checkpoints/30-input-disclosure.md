# Checkpoint 30 — remaining P0 input validation and information disclosure

**P0 remains NOT ACCEPTED.** This checkpoint implements INPUT-05, INPUT-06,
INPUT-07 and DISC-01…DISC-06 inside the offline application workflow introduced
in checkpoint 28 and extended in checkpoint 29. Every check runs against
recorded synthetic responses: no live target, socket, DNS lookup, redirect or
organizer approval is involved, and production networking remains disabled.

## Requirement definitions used

Definitions are taken verbatim from the frozen specification (§9) and were not
inferred:

| ID | Frozen requirement | Expected |
|---|---|---|
| INPUT-05 | Unexpected extra JSON property, report acceptance; no persistence checks in the MVP | Rejected, or acceptance reported |
| INPUT-06 | Malformed JSON body | Rejected |
| INPUT-07 | Special characters in string fields (quote, angle bracket, null-like strings), observing error handling only | Rejected or handled as an ordinary error |
| DISC-01 | Stack trace or framework error text | Absent |
| DISC-02 | Verbose errors revealing internals (paths, SQL fragments, library versions) | Absent |
| DISC-03 | Sensitive fields by name and pattern | Absent |
| DISC-04 | Excess fields beyond the spec's response schema | Absent |
| DISC-05 | Server, version and debug headers | Absent |
| DISC-06 | Different error messages for existing versus nonexistent resources | Identical |

The frozen judgement rule from the same section is applied unchanged: payloads
never attempt exploitation, data extraction or state damage, and every judgement
rests on the status code, the error body and consistency with the spec.

## Architecture

```
POST /api/validation-scans {scenario_id}
  -> bundled synthetic plan (AuthorizedScope + read transcript + probe transcript)
  -> OfflineValidationRunner (same recorded transport, same RunSafetyGuard)
       authorize_authentication(actor, url, input_probe=<declared probe>)  before release
       authorize(actor, GET, url)                                         before each read
  -> pure decision oracles (oracles.validation, oracles.disclosure)
  -> minimized evidence (probe, path, status, signal names, booleans)
  -> SQLite `validation_runs` (payload + SHA-256, redaction required)
  -> GET run | ?view=sections | ?format=html
```

The only body-carrying operation in the model is the exact authentication POST.
Rather than accept a free-form body, the validated scope gains `input_probes` on
that one operation (`control`, `extra_property`, `malformed_json`,
`special_characters`). `AuthorizedPreflight.check` rejects a probe the scope did
not declare in the same decision as actor, method, URL and budget, and
`RunSafetyGuard` tracks `(actor, probe)` attempts so a login is never retried
and each probe releases exactly one recorded response. A second, body-capable
execution path was rejected.

Each released response must verify against the same run guard (actor, probe,
path, method, status, request-body hash, response-content hash). A submission or
read that cannot be verified makes its check INCONCLUSIVE; it can never become
SAFE.

## Checks and decision rules

| Check | Operation probed | SAFE | CONFIRMED | SUSPECTED | INCONCLUSIVE / SKIPPED |
|---|---|---|---|---|---|
| INPUT-05 | `extra_property` on the login POST | field-specific bounded 400/422, plus verified control | acceptance with an observed effect (not reachable in this MVP) | accepted, no effect observed | unclear body, internal-detail error, oversized error, missing control |
| INPUT-06 | `malformed_json` on the login POST | bounded parse error 400/422, plus verified control | — | accepted | unclear body, internal-detail error, oversized error, other status |
| INPUT-07 | `special_characters` on the login POST | bounded validation error or ordinary 401 rejection | — | accepted or 5xx | ambiguous status, internal-detail error |
| DISC-01 | recorded error read | no stack-trace signature | stack-trace signature observed | — | untrusted response |
| DISC-02 | recorded error read | no internals signature | SQLSTATE / escaped source path / version signature | — | untrusted response |
| DISC-03 | recorded identity read | no name or pattern signal and complete traversal | name signal or value-pattern signal | — | incomplete traversal (`INCONCLUSIVE`) |
| DISC-04 | recorded identity read | no excess top-level field against a closed schema | excess field | — | open/absent schema → `SKIPPED` |
| DISC-05 | recorded identity read | no version/debug header | version or debug header | — | untrusted response |
| DISC-06 | existing versus nonexistent read | identical bounded 4xx bodies | differing bounded 4xx bodies | — | non-4xx, 5xx or unusable body |

## Bundled offline scenarios

| Scenario | INPUT-05 | INPUT-06 | INPUT-07 | DISC-01 | DISC-02 | DISC-03 | DISC-04 | DISC-05 | DISC-06 |
|---|---|---|---|---|---|---|---|---|---|
| `synthetic-validation-secure` | SAFE | SAFE | SAFE | SAFE | SAFE | SAFE | SAFE | SAFE | SAFE |
| `synthetic-validation-weak` | SUSPECTED | SUSPECTED | SUSPECTED | CONFIRMED | CONFIRMED | CONFIRMED | CONFIRMED | CONFIRMED | CONFIRMED |
| `synthetic-validation-unobservable` | INCONCLUSIVE | INCONCLUSIVE | SAFE | SAFE | SAFE | SAFE | SKIPPED | CONFIRMED | INCONCLUSIVE |
| `synthetic-validation-malformed-responses` | SUSPECTED | INCONCLUSIVE | INCONCLUSIVE | SAFE | SAFE | INCONCLUSIVE | INCONCLUSIVE | SAFE | INCONCLUSIVE |

The matrix is asserted end-to-end through the API in
`tests/integration/test_validation_scenario.py::test_validation_verdicts_through_the_application`.

## Requirement-to-test mapping

| Requirement | Test |
|---|---|
| INPUT-05 field-specific rejection is the only SAFE path | `test_input_validation_probes.py::test_extra_property_rejection_requires_a_field_specific_bounded_error` |
| INPUT-05 acceptance is SUSPECTED, effect required for CONFIRMED | `test_extra_property_acceptance_is_suspected_until_an_effect_is_observed` |
| INPUT-05 internal error text never counts as SAFE | `test_extra_property_internal_error_text_is_never_counted_as_safe` |
| INPUT-06 bounded parse error only | `test_malformed_json_rejection_requires_a_bounded_parse_error` |
| INPUT-06 acceptance is not SAFE | `test_malformed_json_acceptance_is_suspected_not_safe` |
| INPUT-06 leaking or oversized errors are INCONCLUSIVE | `test_malformed_json_error_bodies_that_leak_internals_are_inconclusive` |
| INPUT-06 unexpected statuses are INCONCLUSIVE | `test_malformed_json_unexpected_statuses_are_inconclusive` |
| INPUT-07 validation error and ordinary rejection are SAFE | `test_special_characters_validation_error_and_ordinary_rejection_are_safe` |
| INPUT-07 acceptance or server error is not SAFE | `test_special_characters_acceptance_or_server_error_is_not_safe` |
| INPUT-07 ambiguous status is INCONCLUSIVE | `test_special_characters_ambiguous_responses_are_inconclusive` |
| DISC-06 identical/differing error responses | `test_identical_error_responses_are_safe_and_different_ones_confirm_enumeration` |
| DISC-06 requires two usable 4xx bodies | `test_enumeration_comparison_requires_two_usable_error_responses` |
| DISC-01/02 signature detection | `test_disclosure_signals_detect_only_bounded_signatures` |
| DISC-05 header signatures | `test_disclosure_header_signals_require_a_version_or_debug_header` |
| DISC-01/02/05 verdict conservatism | `test_signal_verdict_confirms_observation_and_never_guesses` |
| DISC-03 SAFE requires complete traversal | `test_sensitive_field_verdict_requires_complete_traversal_for_safe` |
| DISC-03 name-based detection and redacted values | `test_sensitive_json_scan_reports_nested_secrets_and_ignores_redaction` |
| DISC-03 pattern detection without returning values | `test_sensitive_values_are_detected_by_pattern_without_returning_them` |
| DISC-03 bounded traversal | `test_sensitive_json_scan_is_bounded_and_reports_incompleteness` |
| DISC-04 closed schema only | `test_excess_field_comparison_needs_a_closed_simple_schema` |
| Probes only on the exact authentication POST | `test_input_probes_are_only_permitted_on_the_exact_authentication_post` |
| Scope without declared probes fails closed | `test_scope_without_declared_input_probes_rejects_them_fail_closed`, `test_scope_without_declared_probes_cannot_run_the_validation_flow` |
| Preflight rejects unknown or combined probe kinds | `test_preflight_rejects_unknown_or_combined_probe_kinds` |
| Each declared probe executes at most once per actor | `test_run_guard_allows_each_declared_input_probe_at_most_once` |
| Transcript rejects unknown, duplicate, oversized or hostile entries | `test_transcript_rejects_unknown_duplicate_oversized_or_hostile_entries` |
| Transcript digest covers the recorded bodies | `test_transcript_digest_changes_with_the_recorded_body` |
| Runner requires a declared body and a scoped login | `test_runner_requires_a_declared_body_and_a_scoped_authentication_operation` |
| Mutated response or repeated submission is rejected | `test_runner_rejects_mutated_responses_and_repeated_submissions` |
| Probe without a recorded response is refused | `test_runner_refuses_probes_missing_from_the_recorded_transcript` |
| Unverifiable submissions can never be SAFE | `test_unverifiable_submissions_never_produce_safe_input_verdicts` |
| Unverifiable reads can never be SAFE | `test_unverifiable_reads_never_produce_safe_disclosure_verdicts` |
| Budget exhaustion degrades to INCONCLUSIVE | `test_budget_exhaustion_degrades_to_inconclusive_without_leaking_requests` |
| No request body reaches evidence | `test_orchestrator_never_carries_request_bodies_into_evidence` |
| Run is redacted and confirmed findings carry remediation | `test_validation_run_is_redacted_before_it_is_returned` |
| INPUT probes actually execute through the API | `test_validation_scenario.py::test_input_checks_execute_declared_probes_and_record_their_status` |
| DISC checks rest on recorded read evidence | `test_disclosure_checks_rest_on_recorded_read_evidence` |
| Malformed/hostile responses never read as SAFE | `test_malformed_or_hostile_responses_never_read_as_safe` |
| JSON and HTML reports explain every check | `test_report_sections_and_html_explain_every_check` |
| Sensitive values are redacted before persistence | `test_sensitive_values_are_redacted_before_persistence` |
| Tampered stored run is rejected | `test_tampered_validation_run_is_rejected` |
| Unknown scenario/run and bad views fail closed | `test_unknown_scenarios_and_runs_fail_closed` |
| Accounting invariant per scenario | `test_every_scenario_reports_completed_enforced_accounting` |

## Evidence that checks execute

Each stored check carries `request_probes` and bounded `evidence`, so an
unexecuted check is visibly different from an executed one. Live local run
(uvicorn on port 8013, `POST /api/validation-scans`, 2026-10-30):

| Scenario | Requests sent | Blocked by guard | Budget remaining | JSON summary | HTML size |
|---|---|---|---|---|---|
| `synthetic-validation-secure` | 11 | 0 | 13 | 9 SAFE | 10 906 bytes |
| `synthetic-validation-weak` | 10 | 0 | 14 | 6 CONFIRMED, 3 SUSPECTED | 11 655 bytes |

Observed evidence for `synthetic-validation-weak`: `INPUT-05 {probe:
extra_property, path: /login, status: 200}`, `INPUT-06 {probe: malformed_json,
path: /login, status: 200}`, `INPUT-07 {probe: special_characters, path: /login,
status: 200}`, `DISC-01 {path: /errors/trace, status: 500}`, `DISC-02 {path:
/errors/internal, status: 400}`, `DISC-03 {path: /profile, status: 200, signals:
[name, pattern]}`, `DISC-04 {path: /profile, status: 200, excess_fields: true}`,
`DISC-05 {path: /profile, status: 200}`, `DISC-06 {known_status: 403,
unknown_status: 404}`.

## Adversarial checks

- Responses that are not JSON, are nested beyond the traversal depth bound, use
  an open response schema, answer a denied resource with 200, or return an
  oversized or traceback-bearing error body never produce SAFE; the
  `synthetic-validation-malformed-responses` scenario and the oracle unit tests
  cover each shape.
- Transcript entries with unknown probe names, query strings, non-allow-listed
  statuses, control characters in header values, repeated `(actor, path,
  probe)` keys or bodies over 64 KiB are rejected before a run starts.
- A probe not declared by the scope is blocked by the shared preflight and
  counted in `blocked_by_guard`; a probe repeated in one run is blocked by the
  run guard.
- A stored payload edited in SQLite fails the payload hash check and the API
  returns a generic 500.
- Credentials and bodies remain unpersisted: the store rejects a payload that is
  not already redacted, and tests assert that fixture secrets, tokens and
  request bodies do not appear in the API response, the stored payload or the
  HTML report.

## VS Code demo

```sh
.venv/bin/python -m uvicorn canarygate.api.app:app --host 127.0.0.1 --port 8000

curl -sS -X POST http://127.0.0.1:8000/api/validation-scans \
  -H "content-type: application/json" -d '{"scenario_id": "synthetic-validation-weak"}'
curl -sS "http://127.0.0.1:8000/api/validation-scans/<id>/report?view=sections"
curl -sS "http://127.0.0.1:8000/api/validation-scans/<id>/report?format=html"
```

Then open the HTML report URL and show the per-check evidence column: probe name,
recorded status, disclosure signal names and the enumeration status pair.

## Results

- Local: `.venv/bin/python tools/run_ci_tests.py` → **662 passed** (53 new tests:
  40 in `tests/security/test_input_validation_probes.py`, 13 in
  `tests/integration/test_validation_scenario.py`).
- `python -m compileall -q canarygate tests` remains clean.
- CI: to be recorded after the checkpoint commit is pushed.

## Remaining gaps

- DISC-03 pattern coverage is a fixed, conservative list (JWT, private-key
  header, provider key prefixes); it is not general secret detection.
- DISC-04 compares top-level keys only, against an explicitly closed simple
  schema; nested or composed schemas are not compared.
- DISC-06 has no timing, header or generic resource-discovery analysis.
- INPUT-05 reports acceptance only; no persistence or state effect is verified
  in this MVP, so CONFIRMED is unreachable for that check by design.
- All evidence is recorded synthetic data; no live, organizer or lab target has
  been contacted. P0 remains unaccepted, and BFLA, the frozen nine-section
  report, the full authorization matrix and manual-intervention capture remain
  outstanding.
