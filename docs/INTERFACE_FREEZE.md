# Backend interface freeze (checkpoint 33, phase 1)

Purpose: SCI (security control interaction) is added **on top of** the working
offline P0 build. Before writing any SCI code, the interfaces that carry scan
orchestration, authentication, authorization, input validation, disclosure,
safety policy, evidence/provenance, persistence, API and reporting were audited
and frozen. This document records what exists today, what SCI is allowed to
reuse, and where an additive change would be a compatibility risk.

Frozen means: no signature below changes without updating this document, the
tests that pin it, and the frontend contract in `docs/API.md`. Nothing here
authorises live scanning; production networking stays disabled and no target
outside the synthetic offline transcripts is reachable.

## 1. Orchestration

| Interface | Location | Contract |
|---|---|---|
| `build_scenario(scenario_id)` | `canarygate/scan/scenarios.py` | Known id → validated `ScenarioPlan`; raises `KeyError` for anything else. |
| `execute_offline_scenario(plan)` | `canarygate/scan/scenarios.py` | Runs one bundled read-BOLA scenario and returns a **dict** (historical shape, unchanged). |
| `run_authentication_scan(runner, plan)` | `canarygate/scan/auth_generic.py` | Returns an authentication run object. |
| `run_offline_validation(plan, runner, *, store=None)` | `canarygate/scan/validation_generic.py` | Returns a `ValidationRun`; optional store write. |
| `ValidationOrchestrator` | `canarygate/scan/validation_generic.py` | Per-check orchestration over the shared runner. |

SCI adds `run_offline_interaction(plan, runner, *, store=None)` in
`canarygate/scan/interaction_generic.py` with the same shape: a validated plan
plus a runner, one run object out. It does **not** modify any of the four
interfaces above.

## 2. Authentication and authorization

| Interface | Location | Contract |
|---|---|---|
| `AuthorizedScope` | `canarygate/scope/authorized.py` | The single target authority: origin, hostname, port, accounts, operations, budgets. |
| `AuthorizedPreflight.check(actor, method, url, *, probe=None, input_probe=None)` | `canarygate/guard/authorized_preflight.py` | Exact-string method/URL/actor check, optional single probe, consumes one budget unit. |
| `AuthorizedPreflight.remaining` | same | Remaining budget, read under a lock. |
| `RunSafetyGuard.authorize`, `.authorize_authentication`, `.execution()`, `.remaining` | `canarygate/guard/run_guard.py` | Fail-closed run state; `execution()` is held across the complete operation. |

These are reused verbatim by the SCI runner. SCI never constructs its own
allow-list, never calls a transport directly, and never retries.

## 3. Read-BOLA and disclosure oracles

`canarygate/oracles/` holds pure decision functions (no I/O):

- `credential_rejection_decision(...) -> (verdict, reason)`
- `disclosure_signals(...)`, `signal_verdict(...)`
- `input_verdict(...)`, `extra_property_decision(...)`, `malformed_json_decision(...)`,
  `special_characters_decision(...)`

SCI's decision engine (`canarygate/oracles/interaction.py:decide`) is a new,
additive oracle in the same style: `Baseline`/`Combined` inputs in, `Decision`
out, no I/O, no new global verdict — it returns one of the frozen five.

## 4. Evidence, provenance and redaction

- Evidence is hashed with `canarygate/evidence/redaction.py:digest` and every
  persisted run carries SHA-256 fields that are recomputed after redaction.
- `redact(value)` removes sensitive keys, known credential patterns and the
  built-in synthetic secrets (extended in CP33 with `sci-interaction-secret-value`).
- `prepare_for_storage(report)` validates hashes, minimises and re-hashes;
  `verify_evidence(report)` raises `EvidenceIntegrityError` on mismatch.
- Runners prove provenance: an accepted response must be the object the runner
  recorded for that exact actor/path/status, with a matching body hash
  (`verifies_recorded_read`, `verifies_recorded_submission`,
  `verifies_combined_read`). Caller-made copies fail closed.

## 5. Persistence

| Store | Table | Guarantees |
|---|---|---|
| `ScenarioStore` | `scenario_runs` | file-only SQLite, re-validate + redact + hash on save, integrity error on tamper. |
| `AuthenticationStore` | `authentication_runs` | same pattern. |
| `ValidationStore` | `validation_runs` | same pattern. |
| `InteractionStore` (new) | `interaction_runs` | same pattern plus a 512 KB payload cap and UUID-shaped id regex on `get`. |

All four expose `initialize()`, `save(run)`, `get(run_id)` and `list()`.
`create_app` initialises all four against one database path.

## 6. API

Existing routes are unchanged: `POST /api/scans`, `POST /api/authentication-scans`,
`POST /api/validation-scans`, each with `GET /{id}`, `GET /{id}/checks` (where
present) and `GET /{id}/report` (`format=json|html`, `view=run|sections|p0`),
plus `GET /api/authorization-matrix`.

SCI adds, without touching those handlers:

- `POST /api/interaction-scans` → `InteractionRun`
- `GET /api/interaction-scans/{run_id}` → `InteractionRun`
- `GET /api/interaction-scans/{run_id}/report` → run, sections, P0 or HTML

`GET /api/authorization-matrix` now also aggregates interaction runs. That is a
widening of an existing response, not a schema break: every previously served
row/cell keeps its shape, and interaction cells use `source_ref`
`interaction:<scenario-id>`.

## 7. Reporting

Frozen contract: `P0_SECTION_KEYS` (nine sections, in order), `CATEGORIES` (four),
`VERDICTS` (five), `REMEDIATION_CATALOG`, `build_p0_sections(kind, run)`,
`build_p0_report(kind, run)`, `render_p0_report(kind, run)`.

CP33 changes are additive only:

- `MODES` gains `interaction -> offline_interaction`.
- `REMEDIATION_CATALOG` gains `sci_authorization`, `sci_authentication`,
  `sci_disclosure`. The frozen eight keys are untouched.
- Findings gain two optional keys, `finding_kind` (`"ordinary"` by default,
  `"interaction"` for SCI) and `interaction` (the participating controls,
  per-baseline outcomes, combined outcome, attribution and checklist).
- `MatrixCell`/`MatrixRow`/`AuthorizationMatrix` keep their fields; interaction
  cells fill the existing `source_ref`/`reason` fields.

## 8. Compatibility risks and mitigations

| Risk | Mitigation |
|---|---|
| An SCI verdict could be mistaken for an individual BOLA finding. | `finding_kind` + `interaction` payload; separate SCI finding ids (`SCI-01`); matrix `source_ref` prefix `interaction:`. |
| Widening `REMEDIATION_CATALOG` could break the "one entry per finding type" test. | The test now pins eleven keys, including the three SCI keys, and requires distinct texts. |
| Reusing the validation runner could double-execute a request. | The SCI runner subclasses `OfflineValidationRunner` and keeps one-shot semantics per `(actor, path, probe)` via the transcript's uniqueness rule. |
| New routes could bypass the guard. | SCI routes only accept a scenario **id**; the plan is built server-side from the bundled registry and every leg passes `RunSafetyGuard` immediately before release. |
| A new store could accept unredacted data. | `InteractionStore` re-validates the model and calls `redact()` before hashing and writing. |
| The matrix could silently claim SCI coverage. | An `INPUT_VALIDATION+INFORMATION_DISCLOSURE` interaction produces **no** cell; the endpoint stays `untested` because no authorization claim was made. |

## 9. Frozen verdict rules (unchanged)

`CONFIRMED`, `SUSPECTED`, `SAFE`, `INCONCLUSIVE`, `SKIPPED`, with the existing
confirmation rules for BOLA (verified cross-account private ownership plus
separate private-disclosure evidence), authentication, input validation and
disclosure. SCI does not add a sixth verdict and does not relax any of them: a
SCI `CONFIRMED` additionally requires all eight checklist flags, including that
neither participating control already failed on its own.

## 10. Additive interface: `local_lab` (checkpoint 35)

- `AuthorizedScope.mode` gains `"local_lab"`. `competition` and `approved_lab`
  keep their rules and additionally reject loopback destinations.
- `canarygate.scope.authorized.TARGETLAB_OPERATIONS` is a fixed constant mapping
  the only permitted method/path pairs to their classification.
- `canarygate.network.targetlab.TargetLabTransport` / `TargetLabRunner` implement
  the same guard contract (`RunSafetyGuard.authorize*` immediately before the
  socket) with a pinned test CA and a literal `127.0.0.1` destination.
- `POST /api/lab-scans` and the `lab_runs` table are new; no existing route, table
  or model changed.

## 11. Additive interface: lab read-BOLA (checkpoint 36)

- `canarygate.oracles.read_bola.trusted_policy_source(runner)` and the constant
  `TARGETLAB_POLICY_SOURCE` (`"targetlab declared record policy"`). The oracle's
  rules are unchanged; only the source it accepts is resolved per transport.
- `canarygate.scan.lab_bola_scenarios` declares the two resources, the policy and
  the *evaluation-only* `EXPECTED_VERDICTS` table.
- `canarygate.scan.lab_bola.run_lab_bola_scan(plan, runner, *, store=None)` — the
  only new orchestration; it imports the shared oracle and registry.
- `POST /api/lab-bola-scans` and the `lab_bola_runs` table are new. The matrix gains
  `cells_from_lab_bola` and an optional `lab_bola_runs` argument; every existing
  caller keeps its behaviour.

## 12. Additive interface: lab control-interaction (checkpoint 37)

- `InteractionRun` gains one mode (`targetlab_sci`) and three optional evidence
  blocks (`transport`, `ownership`, `disclosure`) plus `integration_origin`. An
  offline run is rejected if it enables networking or carries lab evidence; a lab
  run is rejected unless it declares the literal `127.0.0.1`.
- `canarygate.oracles.interaction.decide` now requires one baseline per declared
  control. No other rule changed.
- Scope vocabulary gains one declared input probe, `wrong_password`, permitted
  only on the exact authentication `POST`.
- `canarygate.scan.lab_sci.run_lab_sci_scan(plan, runner, *, store=None)` and
  `run_lab_sci_reset(plan, runner_a, runner_b)` — orchestration around the shared
  engines.
- New tables `lab_sci_runs` and `lab_sci_resets`; new routes
  `POST/GET /api/lab-sci-scans*` and `POST/GET /api/lab-sci-resets*`.
- `cells_from_interactions` takes optional `prefix`/`origin` so real and offline
  cells stay distinguishable; `build_authorization_matrix` takes `lab_sci_runs`.
