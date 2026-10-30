# Checkpoint 29 — remaining P0 authentication checks

**P0 remains NOT ACCEPTED.** This checkpoint implements AUTHN-04a, AUTHN-04b,
AUTHN-05, AUTHN-06 and AUTHN-08 as guarded probes inside the offline
application workflow introduced in checkpoint 28. They execute against recorded
synthetic responses: no live target, socket, DNS lookup or organizer approval is
involved, and production networking remains disabled.

Decoding a JWT is **not** verification, and neither is evidence that an API
enforces authorization. The run records `claims_unverified: true` and
`signature_verification: "not_performed"`, and every verdict rests on observed
recorded API behaviour.

## Requirement definitions used

The exact definitions come from the frozen specification (§8) and were not
inferred:

| ID | Frozen requirement | Expected |
|---|---|---|
| AUTHN-04a | Account A's valid JWT with `sub` changed to Account B's ID, original signature retained, sent to an identity-revealing endpoint | Rejected; acceptance only matters if the effective identity changes |
| AUTHN-04b | Account A's valid JWT with `role` changed to `admin`, original signature retained, sent separately to an admin-only endpoint | Rejected; acceptance only matters if admin capability is observed |
| AUTHN-05 | `alg: none` token | Rejected |
| AUTHN-06 | Token from account A used after logout, if the API has logout | Report observed behaviour |
| AUTHN-08 | Missing or invalid API key (when the scheme is API key) | Rejected |

Frozen verdict rules applied here:

- a checked 401/403 is the only SAFE outcome;
- an accepted crafted token with no observable effect is SUSPECTED, never SAFE;
- an accepted `sub` change that shows Account B's identity is CONFIRMED;
- an accepted `role` change that grants the scoped admin capability is CONFIRMED;
- a missing identity/admin endpoint is INCONCLUSIVE, never SAFE;
- a non-JWT token is SKIPPED with the frozen wording.

## Architecture

```
POST /api/authentication-scans {scenario_id}
  -> bundled synthetic plan (AuthorizedScope + scheme + probe transcript)
  -> OfflineAuthRunner (same recorded transport, same RunSafetyGuard)
       authorize(actor, GET, url, probe=<declared probe>)  before release
       authorize_authentication(actor, url)                before logout release
  -> pure decision oracle (one function per check family)
  -> minimized evidence (status, coarse identity/capability effect, checklist)
  -> SQLite `authentication_runs` (payload + SHA-256)
  -> GET run | ?view=sections | ?format=html
```

The probe is authorised where the written scope declares it on that exact
operation (`AuthorizedOperation.auth_probes`). `AuthorizedPreflight` enforces it
in the same decision as method, actor, URL and budget, so a crafted token cannot
be sent because a caller picked another code path. The offline runner adds no
socket, redirect or retry, and `authorize_authentication` still permits only the
single declared POST logout per actor per run.

## Checks and decision rules

| Check | Probe | SAFE | CONFIRMED | SUSPECTED | INCONCLUSIVE / SKIPPED |
|---|---|---|---|---|---|
| AUTHN-01 | no credential | checked denial | 200 + observed identity | — | 200 without observable identity / other |
| AUTHN-02 | malformed credential | checked denial | 200 + observed identity | — | as above |
| AUTHN-03 | wrong auth scheme | checked denial | 200 + observed identity | — | as above |
| AUTHN-04a | JWT `sub` → account B, original signature | checked denial | identity becomes account B | accepted, identity still A (or unexpected) | identity unobservable; non-JWT → SKIPPED |
| AUTHN-04b | JWT `role` → admin, original signature | checked denial | admin capability granted | accepted, capability absent | capability unobservable; no admin endpoint → INCONCLUSIVE; non-JWT → SKIPPED |
| AUTHN-05 | `alg:none`, signature removed | checked denial | unsigned token accepted with honoured identity | accepted, no observable identity | non-JWT → SKIPPED |
| AUTHN-06 | logout, then token reuse | token rejected after logout | never (observation only) | token still accepted | no logout → SKIPPED; baseline/behaviour unclear |
| AUTHN-08 | missing and invalid API key | both rejected | either accepted with identity | either accepted without identity | scheme is not API key → SKIPPED |

`denial_body_checked` is only true when the body exactly equals the plan's
declared denial contract; a denial carrying extra fields is INCONCLUSIVE.

## Bundled offline scenarios

| Scenario | Scheme | Result |
|---|---|---|
| `synthetic-jwt-secure` | bearer JWT | 7 SAFE, AUTHN-08 SKIPPED |
| `synthetic-jwt-sub-confirmed` | bearer JWT | AUTHN-04a CONFIRMED, 6 SAFE |
| `synthetic-jwt-role-confirmed` | bearer JWT | AUTHN-04b CONFIRMED, 6 SAFE |
| `synthetic-jwt-no-observability` | bearer JWT | 6 INCONCLUSIVE, AUTHN-05 SUSPECTED, AUTHN-08 SKIPPED |
| `synthetic-jwt-opaque` | opaque bearer | AUTHN-01/02/03 SAFE, AUTHN-04a/04b/05/06/08 SKIPPED |
| `synthetic-api-key` | API key | AUTHN-01/02/03/08 SAFE, JWT/logout SKIPPED |
| `synthetic-api-key-accepted` | API key | AUTHN-08 CONFIRMED, others SAFE/SKIPPED |

The tokens are synthetic placeholders. The JWT signature segment is fixed test
data: the project has no key material, never verifies it, and never claims the
crafted token is validly signed or that a decoded claim proves anything.

## Requirement-to-test mapping

| Requirement | Tests | Type |
|---|---|---|
| AUTHN-04a `sub` tampering | `test_subject_tampering_requires_an_observable_identity_change`, `test_scenario_verdicts_through_the_application[synthetic-jwt-sub-confirmed]`, `test_confirmed_authentication_findings_explain_observed_effect` | recorded offline |
| AUTHN-04b `role` tampering | `test_role_tampering_requires_an_observed_admin_capability`, `test_scenario_verdicts_through_the_application[synthetic-jwt-role-confirmed]` | recorded offline |
| AUTHN-05 `alg:none` | `test_alg_none_acceptance_is_never_safe`, `test_scenario_verdicts_through_the_application[synthetic-jwt-no-observability]` | recorded offline |
| AUTHN-06 logout reuse | `test_logout_reuse_reports_behaviour_and_never_confirms`, `test_skipped_checks_stay_explicit_and_never_become_safe`, `test_scenario_verdicts_through_the_application[synthetic-jwt-secure]` | recorded offline |
| AUTHN-08 API key | `test_api_key_decision_uses_the_strictest_of_both_observations`, `test_scenario_verdicts_through_the_application[synthetic-api-key, synthetic-api-key-accepted]` | recorded offline |
| Token crafting | `test_crafting_keeps_the_original_signature_and_only_changes_the_claim`, `test_crafting_a_role_token_and_an_alg_none_token`, `test_crafting_rejects_tokens_that_are_not_supported_jwts` | unit |
| Probe permission | `test_scope_must_explicitly_permit_each_crafted_probe`, `test_probe_requires_a_recorded_response_and_a_scoped_path`, `test_direct_construction_and_unscoped_probes_fail_closed` | unit / recorded offline |
| Guard and budget | `test_probe_release_is_blocked_when_the_run_budget_is_exhausted`, `test_probe_responses_carry_provenance_and_detect_mutation` | unit / recorded offline |
| Malformed responses | `test_denial_body_must_match_the_declared_contract_exactly`, `test_malformed_probe_bodies_cannot_become_safe`, `test_unverifiable_probe_response_marks_only_that_check_inconclusive` | unit / recorded offline |
| Redaction | `test_credentials_never_reach_storage_or_reports` | recorded offline + SQLite bytes |
| API/UI consistency | `test_reports_project_every_check_consistently`, `test_runs_survive_restart_and_tampering_fails_closed` | recorded offline |
| Fail-closed orchestration | `test_orchestrator_rejects_a_runner_built_from_a_different_transcript`, `test_authentication_orchestrator_marks_failures_inconclusive` | unit |

## Evidence that checks execute

Each stored run carries `summary.executed` and
`sections.outcome.executed`, the list of checks that were not skipped. Executed
checks carry evidence: probe name, HTTP status, coarse identity/capability
effect, denial-body check flag, and an integrity hash. SKIPPED and INCONCLUSIVE
checks retain an explicit reason; neither is reported as a clean result.

Example (recorded offline, `synthetic-jwt-sub-confirmed`):
`AUTHN-04a CONFIRMED — the modified sub claim changed the effective identity to
the second account`, evidence `status 200`, `identity_effect: "target"`.

## Adversarial checks

- The API accepts only a bundled `scenario_id`; a supplied token, target URL or
  extra field is rejected with 422, and an unknown scenario with 404.
- A runner built from a different recorded transcript is rejected before any
  request.
- Probes not declared on the exact scoped operation are rejected by the shared
  preflight and counted as guard-blocked; `requests_sent` does not advance.
- A probe response whose bytes changed after release fails provenance and the
  affected check becomes INCONCLUSIVE; other checks still run.
- A 200 with a non-object or unobservable body never becomes SAFE.
- Credentials, tokens, crafted tokens, API keys and raw bodies are absent from
  the stored run, JSON sections, HTML and the raw SQLite file.
- Database payload tampering returns a generic 500, not a finding.

## VS Code demo

```sh
.venv/bin/python tools/run_ci_tests.py
.venv/bin/python -m uvicorn canarygate.api.app:app --host 127.0.0.1 --port 8000
```

In a second terminal:

```sh
curl -sS -X POST http://127.0.0.1:8000/api/authentication-scans \
  -H "content-type: application/json" -d '{"scenario_id": "synthetic-jwt-sub-confirmed"}'
curl -sS "http://127.0.0.1:8000/api/authentication-scans/<id>/report?view=sections"
curl -sS "http://127.0.0.1:8000/api/authentication-scans/<id>/report?format=html"
```

Repeat with `synthetic-jwt-no-observability` (INCONCLUSIVE/SUSPECTED) and
`synthetic-jwt-opaque` (SKIPPED reasons) to show that missing evidence is not
presented as a clean result.

## Results

- Local full suite: **609 passed**, one third-party Starlette/AnyIO warning.
- New tests: 69 (50 security/unit, 19 application-level).
- CI run `41060771387` on commit `27fd836` passed both `tests (ubuntu-latest,
  3.11)` and `tests (windows-latest, 3.11)` on the first attempt.
- Wheel build (87 files) includes `canarygate/report/templates/authentication.html`.

## Remaining gaps

- No live target, organizer scope execution, DNS pinning or production network
  path; the guarded HTTPX transport remains disabled.
- Checks run only over bundled recorded scenarios, not over a supplied target
  and not orchestrated with authentication/input/disclosure in one run.
- No signature verification, key material, algorithm-confusion or expiry-forgery
  tests; claims remain explicitly unverified.
- AUTHN-06 reports observed behaviour only; it never confirms a weakness.
- The report is an authentication-specific projection, not the frozen
  nine-section contract; the authorization matrix and manual-intervention
  capture remain outstanding.
- INPUT-05–07, remaining DISC coverage and BFLA are untouched by this checkpoint.
