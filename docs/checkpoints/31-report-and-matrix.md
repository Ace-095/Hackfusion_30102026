# Checkpoint 31 — frozen nine-section report and authorization matrix

**P0 remains NOT ACCEPTED.** This checkpoint turns the stored results of the
scenario (checkpoint 28), authentication (checkpoint 29) and validation
(checkpoint 30) workflows into the frozen report contract and an authorization
matrix. It adds no detection: every value is projected from runs already stored
in SQLite, and no request is made while building or rendering a report.

## Requirement definitions used

From the frozen specification §12 and §13, not inferred:

| # | Frozen requirement |
|---|---|
| 1 | Executive summary: counts by verdict and category |
| 2 | Scope and rules of engagement, accounts and roles, seeding rung, scope hash |
| 3 | Endpoint inventory: method, path, parameters, security, expected access, source |
| 4 | Findings by category with timestamp, endpoint, severity, verdict, exact reason, account and role, target resource and verified owner, request/response (redacted), expected vs observed with source, evidence checklist, curl reproduction, remediation, evidence SHA-256 |
| 5 | Secured endpoints that passed, with the observed denial or correct handling |
| 6 | Skipped and inconclusive tests with reasons |
| 7 | Authorization matrix (§13) |
| 8 | Manual interventions and inferred items |
| 9 | Constraint checklist (§21) |
| §12 | Severity is a fixed mapping (High: confirmed BOLA/BFLA/missing auth; Medium: confirmed disclosure or auth weakness; Low: validation/information), with one remediation catalog entry per finding type |
| §13 | Rows are endpoints; columns are anonymous, own resource, another account's resource and role; cells are green/red/orange/grey/hatched and the matrix is a view over stored results |

## What is now served

| Surface | Behaviour |
|---|---|
| `GET /api/scenario-scans/{id}/report?view=p0` | Frozen nine sections for a stored read-BOLA run |
| `GET /api/authentication-scans/{id}/report?view=p0` | Frozen nine sections for a stored authentication run |
| `GET /api/validation-scans/{id}/report?view=p0` | Frozen nine sections for a stored validation run |
| `...&format=html` | The same projection as HTML with a five-verdict legend |
| `GET /api/authorization-matrix` | Aggregated matrix over every stored run, with tested/untested counts and explicit untested cells |

`P0ReportSections` is a strict model: a missing, extra or reordered section is a
construction error, so a report cannot silently drift from the frozen order.

## Design decisions

**A projection, not a second pipeline.** `canarygate/report/p0.py` normalises the
three stored run shapes into one finding shape, then groups findings into the
four frozen categories and derives the nine sections. Authentication and
validation runs do not store a plan inventory, so section 3 is derived from the
validated scope operations and labelled with that source instead of inventing a
spec inventory. The validation workflow's internal category "Information
disclosure" is mapped to the frozen "Disclosure".

**Fixed severity and one remediation catalog.** `severity_for` returns High,
Medium, Low or nothing, exactly as §12 states; no CVSS engine. Each finding
references one of eight catalog keys, and a CONFIRMED finding must carry that
catalog text.

**Nothing invented where evidence was minimised.** Request and response bodies
are not stored, so section 4 states "not retained" instead of fabricating them.
Target resource and verified owner are reported as `NOT_RECORDED` for read-BOLA
runs because identifiers are minimised by design; the corresponding assumption
appears in section 8. curl reproductions use `$TOKEN_A`/`$TOKEN_B` placeholders
and never a real credential.

**The matrix shows gaps.** Rows come from the union of stored inventories/scope
operations and observed cells, so an endpoint that was never authorization-tested
still appears — fully hatched. Untested cells carry `tested: false`, no verdict
and a reason. `own_resource` is grey (spec: "observed only; expectation
unknown") because only the owner baseline is observed, and `role` is limited to
the role-escalation probe. When two stored runs disagree, the worse observation
wins and both reasons and both source runs are shown, so a clean run can never
hide a finding.

**Manual interventions are recorded, not decorated.** Offline runs require no
manual step, so the section states `status: RECORDED`,
`manual_intervention_required: false`, an empty intervention list (plus setup and
guard-block entries when present) and explicit inferences with their sources:
expected-access source, identity mapping, denial contract and identifier
minimisation. The section never claims a clean bootstrap it did not perform.

**Constraint checklist from stored counters.** All thirteen frozen items are
present with a source per item. Values that are structurally zero for an offline
run (out-of-scope, redirects, destructive, external, creation) are reported with
the mechanism that enforces them, and the mode is labelled offline.

## Requirement-to-test mapping

| Requirement | Test |
|---|---|
| Exactly the nine frozen sections, in order, for all three kinds | `test_p0_report.py::test_report_contains_exactly_the_frozen_nine_sections`, `test_p0_report_api.py::test_frozen_nine_sections_are_available_for_every_run_kind` |
| Executive counts by verdict and category | `test_executive_summary_counts_by_verdict_and_category` |
| Scope, rules of engagement, seeding rung, scope hash | `test_scope_and_rules_state_the_engagement_and_limits` |
| Endpoint inventory with expected access and source | `test_endpoint_inventory_reports_expected_access_and_source`, `test_report_groups_validation_findings_and_maps_severity` |
| Complete finding fields and evidence digest | `test_scenario_finding_is_complete_and_explains_its_verdict` |
| Every authentication check appears, SKIPPED reasons preserved | `test_authentication_findings_cover_every_check_and_keep_skip_reasons` |
| CONFIRMED findings carry a catalog remediation | `test_confirmed_findings_always_carry_a_catalog_remediation` |
| Fixed severity mapping, no CVSS | `test_severity_mapping_is_fixed_and_never_invented` |
| Eight remediation catalog entries | `test_remediation_catalog_has_one_entry_per_finding_type` |
| curl uses placeholders, never a credential | `test_curl_reproduction_uses_placeholders_and_never_a_real_credential`, `test_p0_view_rejects_unknown_requests_and_never_leaks_secrets` |
| No fixture secret or token in any report | `test_reports_never_contain_fixture_secrets_or_tokens`, `test_html_report_shows_all_five_verdicts_and_every_section` |
| Matrix state mapping | `test_cell_state_mapping_is_fixed` |
| Untested cells are explicit and hatched | `test_matrix_exposes_untested_cells_instead_of_hiding_them`, `test_matrix_never_presents_untested_columns_as_passing` |
| Matrix from stored runs, non-contributors counted | `test_matrix_is_built_from_stored_runs_and_counts_non_contributors` |
| Worst observation wins when runs disagree | `test_authorization_matrix_aggregates_stored_runs_and_keeps_gaps_visible` |
| Clean coverage when the only run is secure | `test_matrix_reports_clean_coverage_when_the_only_run_is_secure` |
| All five verdicts visible in HTML, all nine headings | `test_html_report_shows_all_five_verdicts_and_every_section` |
| Unknown view/run fail closed | `test_p0_view_rejects_unknown_requests_and_never_leaks_secrets` |

## Evidence from a live local run

Four runs created through the API (uvicorn, temporary SQLite, 2026-10-30):

| Run | Findings | Verdicts | Severity | Secured | Skipped/inconclusive | HTML |
|---|---|---|---|---|---|---|
| scenario `synthetic-vulnerable` | 1 | 1 CONFIRMED | 1 High | 0 | 0 | 16 668 B |
| authentication `synthetic-jwt-sub-confirmed` | 8 | 1 CONFIRMED, 6 SAFE, 1 SKIPPED | 1 Medium | 6 | 1 | 24 086 B |
| validation `synthetic-validation-weak` | 9 | 6 CONFIRMED, 3 SUSPECTED | 6 Medium | 0 | 0 | 19 708 B |

Aggregated matrix after adding `synthetic-secure` as well: 9 endpoint rows,
4 of 36 cells tested, 32 explicitly untested (`hatched 32, grey 1, green 2,
red 1`), `not_contributing.validation_runs = 1`. The `/records/{id}` row shows
`ANOTHER ACCOUNT'S RESOURCE = red` with both stored observations:
"Verified ownership and cross-user private baseline disclosure | The endpoint
denied the cross-user read with a checked denial body".

The authentication report lists six secured endpoints (AUTHN-01/02/03 with a
checked denial plus AUTHN-04a/04b/05 SAFE) and one SKIPPED check (AUTHN-08) with
its reason. The validation report lists six CONFIRMED disclosure findings, each
with `remediation_key` `verbose_errors`, `excessive_data_exposure` or `headers`
and a computed evidence digest, and three SUSPECTED input checks with no severity
because they are not confirmed.

## Adversarial checks

- `P0ReportSections` rejects a missing, extra or reordered section, so the report
  cannot silently omit a section.
- An unknown `view` returns 400 and an unknown run id returns 404 on every kind.
- Untested cells cannot carry a verdict: the `MatrixCell` model rejects
  `tested: false` with a verdict, and rejects a tested cell without a verdict
  unless it is the grey "observed only" state.
- Merging two runs keeps the worse state and both reasons, so a secure run stored
  after a vulnerable run cannot turn a red cell green.
- Report JSON and HTML are asserted free of synthetic secrets, fixture tokens and
  JWT-shaped strings.
- The report is read-only: `GET ...?view=p0` performs no request, and the tests
  patch sockets and DNS to fail.

## VS Code demo

```sh
.venv/bin/python -m uvicorn canarygate.api.app:app --host 127.0.0.1 --port 8000

curl -sS -X POST http://127.0.0.1:8000/api/validation-scans \
  -H "content-type: application/json" -d '{"scenario_id": "synthetic-validation-weak"}'
curl -sS "http://127.0.0.1:8000/api/validation-scans/<id>/report?view=p0"
curl -sS "http://127.0.0.1:8000/api/validation-scans/<id>/report?view=p0&format=html"
curl -sS "http://127.0.0.1:8000/api/authorization-matrix"
```

Open the HTML page and walk the nine headings, then show the matrix endpoint: the
hatched cells are the coverage gaps, and each row names the run that produced it.

## Results

- Local: `.venv/bin/python tools/run_ci_tests.py` → **689 passed** (27 new: 18 in
  `tests/security/test_p0_report.py`, 9 in
  `tests/integration/test_p0_report_api.py`).
- `python -m compileall -q canarygate tests` remains clean.
- CI on `cc4edbb` (run `41065574034`): `tests (ubuntu-latest, 3.11)` and
  `tests (windows-latest, 3.11)` both succeeded on the first attempt.
- Wheel build: 99 files, including `templates/p0.html`.

## Remaining gaps

- The matrix is partial offline coverage: no anonymous/own/other/role grid exists
  for a live target, `own_resource` is grey, and role coverage is only the
  role-escalation probe. This is deliberately visible, not smoothed over.
- Section 4 reports `NOT_RECORDED` for target resource and verified owner in
  read-BOLA findings because identifiers are minimised; restoring them would
  require a deliberate evidence-model change.
- The legacy fixture report keeps its earlier partial projection; it was not
  rebuilt on the new builder.
- BFLA, live/organizer validation and the full P0 regression audit remain
  outstanding. P0 is not accepted.
