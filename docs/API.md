# Provisional fixture API — frontend handoff

These routes and schemas are **draft**, not approved or frozen. The v3.2
specification and user safety addendum are available in this repository but the
API has not completed full conformance or team review. The current schemas are
at `/openapi.json`. Swagger/ReDoc are disabled because their default assets use
external CDNs. The API is unauthenticated and uses a local fixture-only SQLite
database: run only locally, never expose it as a multi-user service.

Fixture scan responses identify `mode: "fixture"`; they are not live results.
The separate specification-inspection response uses `mode: "inventory_only"` and
never runs a scan.
`POST /api/scan` takes no configuration or target, executes the bundled synthetic
fixture synchronously, and returns the completed result (201). Runs persist
across restarts in `.canarygate/fixture.sqlite3` by default, or the file specified
by `CANARYGATE_DB_PATH`. The fixture target is not exposed as a network service. The local CLI
`python -m canarygate.demo` exercises these routes; see `VS_CODE_DEMO.md`.

| Route | Current response / behavior |
| --- | --- |
| `GET /api/health` | `{"status":"ok","mode":"fixture","live_scanning":false}` |
| `POST /api/spec/upload` | Inspect raw UTF-8 YAML/JSON locally; returns `SpecInspection`, does not select a target or start a scan |
| `GET /api/endpoints` | Fixture inventory, parameters, OpenAPI auth requirements/provenance |
| `GET /api/setup/status` | Most recent fixture setup, or null before the first run |
| `POST /api/scan` | Synchronously run bundled fixture, return `FixtureRun` |
| `GET /api/scan/{id}` | `FixtureRun`, or 404 |
| `GET /api/scan/{id}/observations` | Minimized ownership observation set, or 404 |
| `GET /api/findings` | `{mode, findings: [FixtureRun, ...]}` |
| `GET /api/matrix` | `{mode, cells: [...]}` for runs; not a full authorization matrix |
| `GET /api/reports/{id}?format=json` | `FixtureRun`, or 404; `json` is the default |
| `POST /api/scenario-scans` | Sync offline generic scenario scan; body `{scenario_id}`; returns `ScenarioRun` (201) |
| `GET /api/scenario-scans/{id}` | `ScenarioRun`, or 404 |
| `GET /api/scenario-scans/{id}/report?view=sections` | Scenario section JSON for the same stored run |
| `GET /api/scenario-scans/{id}/report?format=html` | HTML scenario report from the same sections |
| `POST /api/authentication-scans` | Sync offline authentication scan; body `{scenario_id}`; returns `AuthenticationRun` (201) |
| `GET /api/authentication-scans/{id}` | `AuthenticationRun`, or 404 |
| `GET /api/authentication-scans/{id}/report?view=sections` | Authentication section JSON for the same stored run |
| `GET /api/authentication-scans/{id}/report?format=html` | HTML authentication report from the same sections |
| `POST /api/validation-scans` | Sync offline input-validation and disclosure scan; body `{scenario_id}`; returns `ValidationRun` (201) |
| `GET /api/validation-scans/{id}` | `ValidationRun`, or 404 |
| `GET /api/validation-scans/{id}/report?view=sections` | Validation section JSON for the same stored run |
| `GET /api/validation-scans/{id}/report?format=html` | HTML validation report from the same sections |
| `GET /api/scenario-scans/{id}/report?view=p0` | Frozen nine-section P0 report for the stored run |
| `GET /api/authentication-scans/{id}/report?view=p0` | Frozen nine-section P0 report for the stored run |
| `GET /api/validation-scans/{id}/report?view=p0` | Frozen nine-section P0 report for the stored run |
| `GET /api/authorization-matrix` | Aggregated §13 matrix over all stored runs with untested cells and coverage counts |
| `GET /api/reports/{id}?include_observations=true` | Opt-in JSON bundle `{run, observation_set}`; default response stays `FixtureRun` |
| `GET /api/reports/{id}?format=html` | Local Jinja2 HTML fixture report with observations; unknown formats return 400 |

## Specification inspection (provisional)

Send the file as the **raw HTTP body**, not multipart form data. Accepted content
types are `application/yaml`, `application/x-yaml`, `text/yaml`, `text/plain`,
`application/json` and `application/octet-stream`; only UTF-8 is supported.
Compressed bodies are rejected. Example from the repository root (local API on
port 8000):

```sh
curl -sS -H 'Content-Type: application/yaml' --data-binary @canarygate/offline/fixture.yaml http://127.0.0.1:8000/api/spec/upload
```

The response contains `mode: "inventory_only"`, `live_scanning: false`, the
SHA-256 of the original bytes, `endpoint_count`, `endpoints` and a limitation
message. Status 415 means unsupported content type or encoding, 413 means the
128 KiB input limit was exceeded, and 422 means malformed or unsupported input.
Error responses are generic and do not echo the document.

This is a **bounded OpenAPI 3.0/3.1 subset**, not full OpenAPI validation: it
requires a `paths` mapping, uses safe YAML, rejects duplicate keys, YAML merge
keys, unsupported scalar types, cyclic aliases, remote/file references and
unresolved references. Local JSON-pointer references and operation-level
parameter/security overrides are supported. Expansion, parameter, endpoint and
serialized-inventory sizes are bounded. YAML response status keys such as `200`
are accepted. Authentication requirements are not ownership or role policy;
none of this grants permission to contact a host. The spec's `servers` values
are ignored as target authority.

Uploads are processed in memory and are not persisted, selected for `/api/scan`,
or used by `/api/endpoints`. That route and the scanner remain tied to the
bundled offline fixture. Only send synthetic or authorized specifications; the
response can include parameter details supplied in the document, and this is not
a production secret-redaction system. API contracts remain provisional.

## Fixture scan contracts

`FixtureRun` includes ID, time, status, actor/role, endpoint, target resource,
verified owner, expected access and provenance, setup/readiness states, verdict,
reason, remediation, scope/spec hashes, a captured endpoint inventory and
fixture-only counters. `bola_checklist` is an additive boolean map recording
the fixture oracle prerequisites and observations for each new verdict; false
means not established. A stored pre-checkpoint run returns an empty map (not
recorded), and the existing contracts remain provisional. `checks` contains
per-test authentication, validation and disclosure verdicts, evidence and skip
reasons; AUTHN-01/02/03 run only after their prerequisites and when the fixture
scope explicitly permits them. JWT-specific checks are skipped for opaque tokens.
INPUT-01/02/03/04 and DISC-01/02/03/04/05 normally cover five fixed fixture
responses, not all possible inputs or disclosures. INPUT-03 sends only the exact
scoped `limit=9` after a valid `limit=1` control and a compatible declared enum;
it is SKIPPED when those prerequisites are absent. If an applicable probe cannot
be executed, absence-based disclosure results are INCONCLUSIVE. DISC-03 detects a narrow allowlist of
sensitive JSON field names with unmasked string values; DISC-04 compares only
top-level fields against an explicitly closed fixture response schema. An
undocumented field is SUSPECTED, not automatically a confirmed security weakness.
Missing schemas, unsupported response types or partial coverage are INCONCLUSIVE.
DISC-06 separately compares the missing-auth response for Alice's verified fixture
resource with one predeclared, known-absent synthetic ID. It compares only status,
content type and body bytes in memory; differing responses are SUSPECTED, never
a confirmed enumeration vulnerability. Other headers and timing are not checked.
A missing baseline or blocked probe is SKIPPED; an oversized, redirect or server
error response is INCONCLUSIVE. The comparison stores statuses and a Boolean,
not raw error messages or response hashes. The fixture runner clears cookies
between requests, and baselines with cookies or proxy authorization are rejected.
No live resource guessing is enabled.
The remaining unimplemented checks are explicitly SKIPPED. Evidence has separately
named `ownership` and `disclosure` entries. Each is nullable and includes a
redacted request/response summary, account, role, time, status, verification
checklist and SHA-256 of the redacted summary. These are minimized summaries, not
complete captured HTTP traffic; there are no raw bodies or credentials. Use the
schema endpoint for exact fields and enum values. Missing evidence does not mean
that a check passed.

The observation-set response is `{mode, run_id, coverage, observations}`. `coverage`
is `RECORDED` when the set was saved (including an empty set if setup stopped
before discovery), or `NOT_RECORDED` when no observation row exists (normally runs saved before this checkpoint).
The absence of a row cannot distinguish a legacy run from a deleted observation set. The
ordered, individually hashed records cover the attempted discovery lists, owner
baselines and cross-user read. Nullable assertions indicate checks not performed;
false match means the expected match was not observed, not that an ambiguous
response proves security. Only synthetic actor names, methods/paths and IDs,
status codes, bounded allowlisted list/item metadata and Boolean comparisons are
stored. Authorization is redacted; response headers, arbitrary strings and private
values are not stored. Lists are limited to 20 displayed items and carry the total
count and a truncation flag. The assertion is calculated on the full fixture
response, so a truncated minimized observation is not independently exhaustive.

The JSON report's opt-in bundle is additive; existing run, findings, matrix and
default report contracts have not changed. The HTML report renders the stored
observations and provides a command to start **a new** local scan, plus a command
to retrieve the stored report. The mock target is in-process, not a curl endpoint.

Report, observation-set and per-observation checksums are verified when the
corresponding stored data is retrieved. A corrupt record yields a generic 500 instead of a finding; these unkeyed hashes
are not signatures or protection against a database writer who can recompute
them. Stored evidence is a minimized fixture summary, not full raw traffic.

The observation table is an additive, narrowly scoped migration, not a general
database migration system. There is no scan configured from an uploaded spec, real authentication setup,
asynchronous progress, live scan, general evidence viewer or complete report yet.
Handle 501, 404, 500 and null states rather than presenting placeholder data as completed
scans. The fixture redactor is not approved for live credentials or real data.

### Fixture nine-section projection (checkpoint 26)

`GET /api/reports/{id}?view=sections` returns `{mode, run_id, sections}`;
`sections` contains `executive_summary`, `scope_accounts_seeding`,
`endpoint_inventory`, `findings`, `secured_endpoints`,
`skipped_and_inconclusive`, `authorization_matrix`,
`manual_interventions_and_inferences`, and `constraint_checklist`. HTML uses the
same projection. The default JSON and `?include_observations=true` bundle are
unchanged. The section view and observation bundle cannot be combined; fetch
observations separately. The one-cell matrix is labeled `partial_fixture` and
manual interventions/inferences are `NOT_RECORDED`, not an empty claim. Existing
BOLA and authentication records without the relevant denial checklist are not promoted to secured endpoints.
This is fixture-only, not a complete v3.2 report or live-evidence contract.


## Generic offline scenario scans (checkpoint 28)

`POST /api/scenario-scans` accepts exactly `{"scenario_id": "<bundled-id>"}`.
There is no field for a target, host, URL, transcript or credentials; unknown
scenario ids return 404 and unexpected fields return 422. The bundled ids are
`synthetic-vulnerable`, `synthetic-secure`, `synthetic-metadata`,
`synthetic-leaky-denial`, `synthetic-pagination-limit` and
`synthetic-guard-block`.

The response `mode` is `offline_scenario`, `transport` is
`offline_transcript`, and `network_transport_enabled` is always `false`. Runs
are stored in the same local SQLite file in a separate `scenario_runs` table and
survive restarts. The response is a minimized scenario run: scope label and
hash, accounts/roles, recipe selectors, trusted synthetic policy, setup statuses,
hashed ownership/disclosure evidence, the ten-key read-BOLA checklist, verdict,
reason, remediation, request counters and limitations. Raw bodies, tokens,
transcript contents and resource identifiers are not stored.

`GET /api/scenario-scans/{id}/report?view=sections` returns
`{mode, id, run_id, sections}` where sections are `executive_summary`,
`scope_and_accounts`, `endpoint_inventory`, `bola_evidence`, `outcome`,
`constraints` and `limitations`. The HTML report renders the same projection, so
verdicts and evidence do not diverge between formats. This is a
scenario-specific report, not the complete frozen nine-section P0 report.

`verified_denial` is false for a CONFIRMED disclosure because disclosure and
denial are alternatives; CONFIRMED requires the ownership and disclosure
prerequisites, not every checklist boolean. Stored payload/evidence hashes detect
accidental or naive database changes and yield a generic 500; they are not
signatures. The API remains local-only and unauthenticated: do not expose it.


## Offline authentication scans (checkpoint 29)

`POST /api/authentication-scans` accepts exactly
`{"scenario_id": "<bundled-id>"}`. There is no field for a token, header,
credential, target or transcript; unknown ids return 404 and unexpected fields
return 422. Bundled ids are `synthetic-jwt-secure`,
`synthetic-jwt-sub-confirmed`, `synthetic-jwt-role-confirmed`,
`synthetic-jwt-no-observability`, `synthetic-jwt-opaque`, `synthetic-api-key`
and `synthetic-api-key-accepted`.

Every run carries the eight P0 authentication checks in canonical order:
`AUTHN-01`, `AUTHN-02`, `AUTHN-03`, `AUTHN-04a`, `AUTHN-04b`, `AUTHN-05`,
`AUTHN-06` and `AUTHN-08`. `mode` is `offline_authentication`, `transport` is
`offline_transcript`, `network_transport_enabled` is `false`,
`claims_unverified` is `true` and `signature_verification` is
`"not_performed"`.

Checks that cannot apply are SKIPPED with an explicit reason: a non-JWT token
skips AUTHN-04a/04b/05 with the frozen wording, an API without a declared logout
skips AUTHN-06, and a non-API-key scheme skips AUTHN-08. An accepted crafted
token with no observable effect is SUSPECTED or INCONCLUSIVE, never SAFE.
`summary.executed` and `sections.outcome.executed` list the checks that actually
executed.

Runs are stored in `authentication_runs` with a payload hash and survive
restarts; tampering yields a generic 500. Evidence is minimized to probe name,
status, coarse identity/capability effect and checklist flags: no tokens,
crafted tokens, API keys, headers or raw bodies are stored or returned.
`GET .../report?view=sections` returns `executive_summary`,
`scope_and_accounts`, `authentication_checks`, `outcome`, `claims_policy`,
`constraints` and `limitations`; the HTML report renders the same projection.
This is an authentication-specific report, not the frozen nine-section contract.
The API remains local-only and unauthenticated: do not expose it.

## Offline input-validation and disclosure scans (checkpoint 30)

`POST /api/validation-scans` accepts exactly `{"scenario_id": "<bundled-id>"}`.
There is no field for a target, body, header, credential or transcript; unknown
ids return 404 and unexpected fields return 422. Bundled ids are
`synthetic-validation-secure`, `synthetic-validation-weak`,
`synthetic-validation-unobservable` and
`synthetic-validation-malformed-responses`.

Every run carries nine checks in canonical order: `INPUT-05`, `INPUT-06`,
`INPUT-07`, `DISC-01`, `DISC-02`, `DISC-03`, `DISC-04`, `DISC-05` and `DISC-06`.
`mode` is `offline_validation`, `transport` is `offline_transcript`,
`network_transport_enabled` is `false` and `policy_source` is
`offline validation scenario policy`.

Body-carrying probes are possible only because the validated scope declares
`input_probes` on the exact authentication POST: `control`, `extra_property`,
`malformed_json` and `special_characters`. Each declared probe is authorised by
the shared run guard immediately before its recorded response is released and
may execute at most once per actor per run. No other operation accepts a body.
A check whose recorded response cannot be verified in the same run is
INCONCLUSIVE; a check whose comparison cannot be performed at all (no declared
response schema) is SKIPPED with the reason.

`request_probes` lists the probes a check actually executed, and `evidence`
carries only bounded facts: the probe or path, the recorded status, the
disclosure signal names, an excess-field boolean and the two enumeration
statuses. Request bodies, response bodies and credentials are never stored,
returned or reported. SAFE and CONFIRMED input verdicts additionally require a
verified control response showing that the operation accepts valid input.

Runs are stored in `validation_runs` with a payload hash; tampering yields a
generic 500 and a stored payload that is not already redacted is rejected.
`GET .../report?view=sections` returns `executive_summary`,
`scope_and_accounts`, `check_results`, `outcome` and `limitations`; the HTML
report renders the same projection. This is a validation-specific report, not
the frozen nine-section contract. The API remains local-only and
unauthenticated: do not expose it.

## Frozen P0 report and authorization matrix (checkpoint 31)

`?view=p0` on any of the three scan report endpoints returns the frozen nine
sections in order: `executive_summary`, `scope_and_rules`,
`endpoint_inventory`, `findings`, `secured_endpoints`,
`skipped_and_inconclusive`, `authorization_matrix`,
`manual_interventions_and_inferences` and `constraint_checklist`. Findings are
grouped into `Authentication`, `Authorization`, `Input validation` and
`Disclosure`. Each finding carries its id, category, timestamp, endpoint,
severity (fixed mapping, no CVSS), verdict, exact reason, account and role,
target resource and verified owner, expected vs observed with the expectation's
source, evidence checklist, a curl reproduction using `$TOKEN_A`/`$TOKEN_B`
placeholders, a catalog remediation for CONFIRMED results and an evidence
SHA-256. Request and response bodies were never stored, so those fields state
that they were not retained instead of inventing content.
`?view=p0&format=html` renders the same projection with a five-verdict legend.
Section values come from stored runs only; building a report performs no
request.

`GET /api/authorization-matrix` aggregates every stored scenario,
authentication and validation run into the §13 grid: rows are endpoints,
columns are `anonymous`, `own_resource`, `other_account_resource` and `role`,
cells are `green` (SAFE), `red` (CONFIRMED), `orange` (SUSPECTED), `grey`
(observed only, no expectation) or `hatched` (SKIPPED/INCONCLUSIVE/not tested).
Untested cells are always present with `tested: false`, no verdict and a reason,
and `coverage` reports tested/untested counts, per-state counts, the non-
contributing run counts and a statement that coverage is partial and offline.
When stored runs disagree, the worse observation wins and both reasons and both
sources are shown. A clean run stored after a vulnerable run cannot turn a red
cell green.

Manual interventions are recorded rather than decorated: offline runs state
`status: RECORDED`, `manual_intervention_required: false`, an intervention list
(setup status and guard-block entries when present) and explicit inferences with
their sources. The constraint checklist carries all thirteen §21 items with a
source per item. The report is deliberately conservative: read-BOLA findings
report the resource type and verified owner account while withholding the
identifier; ownership is only claimed when the stored checklist proves it, and an
unverified run says `NOT_VERIFIED` instead of naming an owner.

## SCI interaction scans (checkpoint 33)

An SCI run tests whether two individually correct controls fail *together*. It is
served alongside the other workflows and reuses the same frozen report, matrix and
verdict vocabulary.

`POST /api/interaction-scans`

```json
{"scenario_id": "synthetic-sci-authz-input-confirmed"}
```

`scenario_id` must be one of the bundled synthetic ids; anything else is `404`.
There is no way to supply paths, methods, accounts, bodies or a target — the plan
is built server-side from the bundled registry and validated against the scope.

Response (`InteractionRun`, also returned by `GET /api/interaction-scans/{run_id}`):

| Field | Meaning |
|---|---|
| `scenario_id`, `title` | Which bundled scenario ran. |
| `interaction_kind` | `AUTHZ+INPUT_VALIDATION`, `AUTHN+AUTHZ` or `INPUT_VALIDATION+INFORMATION_DISCLOSURE`. |
| `controls` | The two participating control names. |
| `baselines[]` | `id`, `control`, `endpoint`, `action`, `probe`, `verdict`, `reason`, `observable`, `evidence`, `evidence_sha256`. |
| `combined` | `endpoint`, `action`, `probe`, `executed`, `permitted`, `verified`, `status`, `impact`, `observed`. |
| `verdict` | One of the five global verdicts; `attribution` explains it. |
| `attribution` | `interaction_induced`, `individual_failure`, `incomplete_baseline`, `unverified_evidence`, `ambiguous_impact`, `no_demonstrated_impact`, `no_failure`, `not_permitted`. |
| `remediation_key`, `remediation` | Present only for `CONFIRMED`: `sci_authorization`, `sci_authentication` or `sci_disclosure`. |
| `checklist` | The eight confirmation flags. |
| `transcript_sha256` | Hash of the bounded recorded transcript. |
| `requests_sent`, `blocked_by_guard`, `budget_remaining` | Budget accounting. |
| `network_transport_enabled` | Always `false`. |
| `limitations[]` | What this run does not prove. |

`GET /api/interaction-scans/{run_id}/report`

- `format=json|html`, `view=run|sections|p0`.
- `sections` returns `executive_summary`, `scope_and_accounts`, `baselines`,
  `combined`, `decision` (including the plain-language `STATEMENT`), `limitations`.
- `p0` returns the frozen nine sections. The SCI finding is `SCI-01` with
  `finding_kind: "interaction"` and an `interaction` object holding the kind,
  participating controls, per-baseline outcomes, combined outcome, attribution,
  `why_not_individual` and checklist. Ordinary findings keep the default
  `finding_kind: "single_control"` and a `null` `interaction` object, which is how
  the frontend must keep the two apart.

`GET /api/authorization-matrix` also aggregates interaction runs. Interaction
cells carry `source_ref: "interaction:<scenario_id>"` and never mark a cell green
or red unless the interaction verdict maps to that state. An
`INPUT_VALIDATION+INFORMATION_DISCLOSURE` interaction contributes no cell; the
endpoint remains `untested` because no authorization claim was made.

All interaction responses are offline synthetic data. `POST` performs no network
request: the runner releases recorded responses only after
`RunSafetyGuard.execution()` permits the exact actor/method/path.

## TargetLab evidence scans (checkpoint 35)

These routes talk to a **locally running TargetLab over TLS** and are the only
place in the API where a socket is opened. They are not live-organizer scanning:
the destination is pinned to `127.0.0.1`, the scope mode is `local_lab`, and
production networking stays disabled.

`POST /api/lab-scans`

```json
{"port": 8765, "request_budget": 12}
```

`port` is the loopback port TargetLab is listening on (1024–65535);
`request_budget` is 7–40. No host, hostname, path, account or credential may be
supplied. Requires the environment variable `CANARYGATE_TARGETLAB_CA` to point at
the test-only certificate; without it the API answers `400` and stores nothing.
If the lab is unreachable, or a request is refused (redirect, TLS failure, size
cap, budget), the API answers `502` and stores nothing.

The run (`LabRun`) records `transport` metadata (`destination: "127.0.0.1"`,
`tls_verification: "pinned_test_ca_with_hostname_check"`, `redirects: "refused"`,
`retries: "none"`, `dns: "not_used"`, `network_transport_enabled: true`,
`production_networking: false`), seven `checks` with `{id, endpoint, actor,
status, observation, verified, evidence, evidence_sha256}`, a `summary`,
`constraints` (`requests_sent`, `blocked_by_guard`, `budget_remaining`, `halted`)
and `limitations`.

`observation` is descriptive, not a verdict: `allowed_owner`, `allowed_other`,
`denied`, `unexpected_status`, `unverified`, `blocked_by_guard`. No BOLA or SCI
verdict is produced at this checkpoint.

- `GET /api/lab-scans/{run_id}` — the stored run.
- `GET /api/lab-scans/{run_id}/report?view=sections` — executive summary, scope and
  transport, checks, constraints, limitations.
- `GET /api/lab-scans/{run_id}/report?format=html` — the same projection, headed
  "Controlled validation, not live validation".

Evidence is bounded to status codes and booleans. Credentials, tokens, headers
and response bodies are never stored, returned or reported.

## TargetLab read-BOLA validation (checkpoint 36)

These routes perform real HTTPS requests to a running TargetLab and reach a
verdict through the existing read-BOLA oracle. They are **controlled validation**
against our own loopback lab, not live-organizer scanning.

`POST /api/lab-bola-scans`

```json
{"port": 8765, "request_budget": 20}
```

`port` is 1024–65535 and `request_budget` is 16–40 (the workflow needs 18
requests). No host, path, account or credential may be supplied; the resource
declarations and policy are constants in `canarygate/scan/lab_bola_scenarios.py`.
Requires `CANARYGATE_TARGETLAB_CA`; without it the API answers `400`. If the lab is
unreachable, refuses TLS, or never returns a single response, the API answers
`502` and stores nothing.

The run (`LabBolaRun`) contains:

| Field | Meaning |
|---|---|
| `verdict`, `reason` | Run-level verdict: `CONFIRMED` if any check confirmed, else `INCONCLUSIVE`/`SUSPECTED`/`SKIPPED`, else `SAFE`. |
| `checks[6]` | `LAB-BOLA-01…06` with `direction` (`owner_baseline`, `cross_account`, `cross_account_secure`), `endpoint`, `actor`, `owner`, `status`, `verdict`, `reason`, `checklist`, bounded `evidence`, `evidence_sha256`, and `remediation` only when confirmed. |
| `ownership` | Per endpoint: `status`, `reason`, verified identities, baselines and cross-list isolation. Resource identifiers are withheld. |
| `summary` | `confirmed`/`safe`/`suspected`/`inconclusive`/`skipped` counts over the six checks. |
| `ground_truth` | `rows` comparing each check with the declared lab table, plus `evaluated_after_verdicts: true` and `used_as_decision_input: false`. |
| `transport` | `destination: "127.0.0.1"`, `tls_verification: "pinned_test_ca_with_hostname_check"`, `redirects: "refused"`, `retries: "none"`, `dns: "not_used"`, `network_transport_enabled: true`, `live_target_contacted: false`. |
| `constraints` | `requests_sent`, `blocked_by_guard`, `budget_remaining`, `halted`, `redirects_observed: 0`, `destructive_requests_executed: 0`. |

- `GET /api/lab-bola-scans/{run_id}` — the stored run.
- `GET /api/lab-bola-scans/{run_id}/report?view=sections` — executive summary,
  scope and transport, ownership, checks, ground truth, constraints, limitations.
- `GET /api/lab-bola-scans/{run_id}/report?view=p0` — the frozen nine sections with
  one finding per check (`Authorization`, severity `High` when confirmed,
  remediation key `bola`).
- `GET /api/lab-bola-scans/{run_id}/report?format=html` — either projection as HTML.

`GET /api/authorization-matrix` also aggregates these runs: the vulnerable route
appears as a red `other_account_resource` cell and the secure route as a green one,
both labelled `lab_bola:<scenario>[:route]` so they stay distinguishable from
offline scenario and SCI cells.

## TargetLab control-interaction validation (checkpoint 37)

Real HTTPS requests to a running TargetLab, decided by the existing SCI engine.
**Controlled validation** of our own loopback lab, not live-organizer scanning.

`POST /api/lab-sci-scans`

```json
{"port": 8765, "request_budget": 16}
```

`port` is 1024–65535 and `request_budget` is 8–40; the interaction needs 11
requests, so a smaller budget degrades to `INCONCLUSIVE` rather than a verdict.
No host, path, account or credential may be supplied. Requires
`CANARYGATE_TARGETLAB_CA` (`400` without it); a refused, redirected or
unreachable lab answers `502` and stores nothing.

The run is an `InteractionRun` with `mode: "targetlab_sci"`:

| Field | Meaning |
|---|---|
| `verdict`, `attribution` | `CONFIRMED`/`interaction_induced` only when both baselines passed, the combined read verified, and it disclosed the owner's marker. |
| `baselines[2]` | `SCI-AUTHZ` (guarded read denied) and `SCI-AUTHN` (rejected login), each with `evidence.sequence`, `status`, `verified`. |
| `combined` | `GET /records/{id}/guarded` after the rejected login: `status`, `impact`, `verified`. |
| `disclosure` | `marker_matches_owner_baseline`, `marker_withheld`, actor/owner. No marker value is stored. |
| `ownership` | registry result: verified identities, owner baselines, cross-list isolation; identifiers withheld. |
| `transport` | `destination: "127.0.0.1"`, pinned test CA, redirects refused, no retries, no DNS, `live_target_contacted: false`. |
| `network_transport_enabled`, `integration_origin` | `true` and `loopback_lab`; an offline run cannot claim either. |

- `GET /api/lab-sci-scans/{run_id}` — the stored run.
- `GET /api/lab-sci-scans/{run_id}/report?view=sections[&reset=<proof_id>]` —
  executive summary, scope and transport, baselines, combined, decision,
  disclosure, ownership, **evaluation** (ground truth scored after the run) and
  limitations. An attached reset proof appears as `reset_verification`; a proof
  from another port is refused with `400`.
- `GET /api/lab-sci-scans/{run_id}/report?view=p0` — the frozen nine sections with
  one `SCI-01` finding (category `Authorization`, `High` when confirmed,
  remediation key `sci_authentication`).
- `GET /api/lab-sci-scans/{run_id}/report?format=html` — either projection as HTML.

`POST /api/lab-sci-resets` — the same body. Records a separate four-check proof
that a rejected login sets the lab condition and a successful login clears it. It
uses two guarded runs (7 + 1 requests) because a run may authenticate an account
only once. Results are `proven`/`not_proven`; this is a scenario outcome, not a
security verdict. `GET /api/lab-sci-resets/{proof_id}` returns it.

`GET /api/authorization-matrix` aggregates these runs too: the guarded route
appears as a red `other_account_resource` cell labelled `lab_sci:targetlab-sci`.
