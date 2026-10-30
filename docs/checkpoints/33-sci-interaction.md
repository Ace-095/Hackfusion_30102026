# Checkpoint 33 — security control interaction (SCI)

An interaction vulnerability is the one a single-control scanner structurally
misses: authorization and input validation each behave correctly when tested
alone, yet the *combination* leaks another account's data. This checkpoint adds
that capability to the existing offline build without changing the frozen P0
verdict rules.

**Scope reality.** Everything here runs on bundled synthetic offline transcripts.
`network_transport_enabled` is `False` on every run, the sockets are never opened,
and no VAMPI/crAPI/organizer/public target was contacted. These are not live
findings and the reports say so.

## Phase order (as directed)

1. Freeze and document the existing backend interfaces — `docs/INTERFACE_FREEZE.md`.
2. Frontend integration against the real API — `docs/API.md` (the SCI routes and
   the two new finding keys are the whole contract; no second security engine in
   the browser).
3. Implement SCI additively.
4. Demonstrate SCI independently of the three core demos (confirmed BOLA,
   secured endpoint, inconclusive).

Nothing in phases 1–2 changed behaviour: the freeze document found zero blocking
incompatibilities, so no P0 route, model, store or verdict rule was modified.

## Architecture

```
InteractionPlan (validated against AuthorizedScope)
   ├── BaselineAction × 2..4   one per participating control
   └── CombinedAction          the interaction leg, with a declared impact
        │
        ▼
InteractionTranscript (GET-only, exact paths, unique (actor, path, probe),
                        ≤8 entries, 64 KB/body, 256 KB total, sha256)
        │
        ▼
OfflineInteractionRunner (extends OfflineValidationRunner)
        │  every leg → RunSafetyGuard.execution() → prose check → recorded response
        ▼
InteractionOrchestrator
        ├── baselines: record expected access policy + provenance, verify identity,
        │   verify ownership where the control needs it, bound the response, and
        │   prove the control was *observable*
        └── combined: only if the guard permits the exact endpoint, the probes were
            previously accepted, the budget remains and provenance verifies
        ▼
oracles/interaction.py:decide  →  InteractionRun (one of the five frozen verdicts)
        ▼
InteractionStore (SQLite) → /api/interaction-scans → nine-section P0 report,
                            HTML report, authorization matrix
```

### Interaction planner

Supported kinds, declared per scenario, never assumed for every endpoint:

| Kind | Controls | Example endpoint |
|---|---|---|
| `AUTHZ+INPUT_VALIDATION` (primary) | Authorization, Input validation | `GET /admin/users` after `POST /login` probe |
| `AUTHN+AUTHZ` | Authentication, Authorization | `GET /records/rb` with a credential probe |
| `INPUT_VALIDATION+INFORMATION_DISCLOSURE` | Input validation, Disclosure | `GET /errors/trace` after a malformed probe |

The planner (`scan/interaction_plan.py`) validates every path/method against the
scope's operations, requires an `INPUT_PROBE_NAMES` probe where a control needs
one, and refuses a combined leg whose impact contract is missing. A kind that the
scope does not declare is a plan error, not a silently skipped test.

### Decision engine

`canarygate/oracles/interaction.py:decide` is pure: `Baseline`/`Combined` in,
`Decision` out. Precedence:

| Condition | Verdict | Attribution |
|---|---|---|
| The guard refused the combination | `SKIPPED` | `not_permitted` |
| A baseline is already `CONFIRMED` | `INCONCLUSIVE` | `individual_failure` |
| A baseline was not observable | `INCONCLUSIVE` | `incomplete_baseline` |
| The combination never executed | `SKIPPED` | `not_permitted` |
| Provenance did not verify | `INCONCLUSIVE` | `unverified_evidence` |
| The impact could not be classified | `INCONCLUSIVE` | `ambiguous_impact` |
| 3 impacts, all baselines `SAFE`, 8/8 checklist | `CONFIRMED` | `interaction_induced` |
| Impact present, some baseline not `SAFE` | `SUSPECTED` | `unproven_impact` |
| Any 4xx from the combination | `SAFE` | `no_failure` |
| Anything else | `SUSPECTED` | `no_demonstrated_impact` |

No sixth global verdict exists. `CONFIRMED` requires the eight checklist flags:
both baselines observable and passing, identities distinct, ownership verified
where applicable, combined response verified against the recorded object, a
declared impact observed, scope respected, and the explanation cannot be reduced
to an already-failing individual control.

## Offline acceptance scenarios (A–H)

All ten bundled scenarios execute end to end through `POST /api/interaction-scans`
and are asserted in `tests/integration/test_sci_scenarios.py`.

| Scenario id | Case | Kind | Verdict | Attribution |
|---|---|---|---|---|
| `synthetic-sci-authz-input-confirmed` | A — pass + pass → leak | AUTHZ+INPUT | `CONFIRMED` | `interaction_induced` |
| `synthetic-sci-authz-input-secure` | B — pass + pass → secure | AUTHZ+INPUT | `SAFE` | `no_failure` |
| `synthetic-sci-individual-failure` | C — one control already fails | AUTHZ+INPUT | `INCONCLUSIVE` | `individual_failure` |
| `synthetic-sci-incomplete-baseline` | D — baseline not observable | AUTHZ+INPUT | `INCONCLUSIVE` | `incomplete_baseline` |
| `synthetic-sci-unpermitted` | E — outside the scope | AUTHZ+INPUT | `SKIPPED` | `not_permitted` |
| `synthetic-sci-budget-exhausted` | F — budget exhausted | AUTHZ+INPUT | `SKIPPED` | `not_permitted` |
| `synthetic-sci-secret-redaction` | G — sensitive value must never persist | AUTHZ+INPUT | `CONFIRMED` | `interaction_induced` |
| `synthetic-sci-variation` | H — response varies, no security impact | AUTHZ+INPUT | `SUSPECTED` | `no_demonstrated_impact` |
| `synthetic-sci-authn-authz` | second kind | AUTHN+AUTHZ | `CONFIRMED` | `interaction_induced` |
| `synthetic-sci-input-disclosure` | third kind | INPUT+DISCLOSURE | `CONFIRMED` | `interaction_induced` |

Case E and F are deliberately `SKIPPED` rather than `INCONCLUSIVE`: the guard
refused or the budget ran out **before** the combined exchange, so there is no
evidence to weigh. Case G's sentinel `sci-interaction-secret-value` is absent from
the run JSON, the section report, the P0 report, the HTML report, the matrix and
the raw SQLite bytes, and `redact()` is separately proved to rewrite that sentinel
even under a non-sensitive key.

## Reporting and persistence

- `interaction_runs` table, payload SHA-256, re-validation and `redact()` on save,
  512 KB cap, UUID-shaped id regex, `EvidenceIntegrityError` on tamper (surfaced
  as a generic 500).
- Nine-section P0 report: `MODE = offline_interaction`, one `SCI-01` finding with
  `finding_kind: "interaction"`, a `interaction` block (kind, controls, per-baseline
  outcomes, combined outcome, attribution, `why_not_individual`), the SCI
  remediation, and a `curl` reproduction using `$TOKEN_A`/`$TOKEN_B`.
- Category mapping: `AUTHZ+INPUT_VALIDATION` and `AUTHN+AUTHZ` → `Authorization`;
  `INPUT_VALIDATION+INFORMATION_DISCLOSURE` → `Disclosure`.
- Matrix: interaction runs add cells with `source_ref = interaction:<scenario>`, so
  a judge can tell an SCI result from an ordinary BOLA result. A
  `INPUT_VALIDATION+INFORMATION_DISCLOSURE` interaction adds **no** cell and the
  endpoint stays `untested`, because it makes no authorization claim.

## Tests

| File | Tests | What it pins |
|---|---|---|
| `tests/security/test_sci_decisions.py` | 14 | Every precedence branch: CONFIRMED needs all eight flags, individual failure wins over interaction, incomplete baseline and unverified evidence are INCONCLUSIVE, 4xx is SAFE, variation is never CONFIRMED, guard refusal is SKIPPED. |
| `tests/integration/test_sci_scenarios.py` | 19 | All ten scenarios through `TestClient(create_app(tmp sqlite))` with sockets patched to fail; restart persistence; tamper → 500; redaction in every projection and in the raw database file; matrix distinguishability; P0 `finding_kind`; unknown scenario → 404; over-wide payload → 422. |

`tools/p0_audit.py` gains seven SCI requirements (C1–C7) with implementation
symbols, collected test node ids and an evidence class, so the audit fails if any
SCI claim loses its test.

## Limitations (honest)

1. Offline synthetic transcripts only. No live target, no lab, no organizer API.
   SCI is not live validation.
2. The planner supports the three declared kinds; it does not enumerate
   combinations automatically for arbitrary endpoint pairs.
3. Only GET legs are combined with one bounded probe (`INPUT_PROBE_NAMES`). No
   POST/PUT/PATCH/DELETE combination is supported; destructive operations are
   unreachable by construction.
4. Interaction coverage is per scenario, not a full matrix: one scenario
   contributes one cell (or none for the disclosure kind).
5. SCI findings are reported as a single `SCI-01` finding per run, not one finding
   per participating control; the participating controls live inside
   `interaction.controls` so the frontend can render them separately.

## Judge demo (independent of the three core demos)

```bash
.venv/bin/python -m pytest tests/integration/test_sci_scenarios.py tests/security/test_sci_decisions.py -q
.venv/bin/python -m canarygate.api            # or: uvicorn canarygate.api.app:app
```

1. `POST /api/interaction-scans` with `{"scenario_id": "synthetic-sci-authz-input-confirmed"}`
   → `CONFIRMED`, `attribution: interaction_induced`, `requests_sent: 4`, budget 8 left.
2. `GET /api/interaction-scans/{id}/report?view=sections` → the two passing
   baselines (`AUTHZ-01`, `INPUT-07`) and the leaking combination side by side.
3. `GET /api/interaction-scans/{id}/report?view=p0` → `SCI-01`,
   `finding_kind: interaction`, `sci_authorization` remediation.
4. `GET /api/authorization-matrix` → the cell carries `source_ref:
   interaction:synthetic-sci-authz-input-confirmed`, visibly different from a
   BOLA cell.
5. Re-run with `synthetic-sci-individual-failure` → `INCONCLUSIVE`, showing the
   engine refuses to call an interaction when a control already failed.
6. Re-run with `synthetic-sci-authz-input-secure` → `SAFE`, showing no false
   positive on a secure endpoint.

**Gate:** SCI is implemented additively and executes real combined scenarios
through the application. It is not a live-validation claim and does not change the
P0 acceptance decision: the offline subset is accepted with limitations, complete
frozen P0 (BFLA, live validation) is not accepted.
