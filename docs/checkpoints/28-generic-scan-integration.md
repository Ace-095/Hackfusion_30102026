# Checkpoint 28 — generic offline scan integration

**P0 remains NOT ACCEPTED.** Checkpoint 28 makes the generic read-BOLA proof
path part of the application workflow: a validated scope and resource recipe
drive a guarded, recorded offline transport; the shared ownership registry and
one BOLA oracle produce the verdict; the run is persisted in SQLite and exposed
through JSON section and HTML reports.

It is still **offline**. There is no live target, socket, DNS lookup, organizer
approval, or production network execution. Recorded synthetic responses are not
live validation, and authentication/input/disclosure checks are not part of this
workflow. See [`docs/P0_ACCEPTANCE_MATRIX.md`](../P0_ACCEPTANCE_MATRIX.md).

## Architecture

```
POST /api/scenario-scans {scenario_id}
  -> bundled synthetic plan (AuthorizedScope + exact operations + recipe + transcript)
  -> OfflineGuardedRunner
       RunSafetyGuard.check_common on every read, immediately before release
  -> shared ownership registry (two profile controls, bounded lists,
       cross-account exclusion, two owner baselines)
  -> shared read-BOLA oracle (CONFIRMED / SUSPECTED / SAFE / INCONCLUSIVE / SKIPPED)
  -> scenario evidence (minimized, hashed)
  -> SQLite `scenario_runs` (payload + SHA-256)
  -> GET run | ?view=sections | ?format=html
```

The same orchestrator (`canarygate.scan.generic.run_generic_scan`) also accepts
the disabled guarded HTTPX runner in tests, proving the decision engine is not
fixture- or transcript-specific. Only recorded-transcript runs satisfy
`ScenarioRun` and can be persisted; the mocked HTTPX result is rejected.

## Shared safety-policy contract

`canarygate/guard/policy.py` defines the prohibitions both execution boundaries
must share: prohibited methods (DELETE/PUT/PATCH/TRACE/CONNECT), unknown actors,
non-allowlisted methods, invalid metadata and exhausted budgets. Both
`SafetyGuard` (fixture) and `AuthorizedPreflight` (guarded HTTPX and offline
replay) call `check_common` before their scope-specific checks.

Tests prove:

- both guards raise the same `SafetyPolicyViolation` and call the shared
  function (`test_both_boundaries_call_the_shared_policy_and_raise_the_same_violation`);
- prohibited methods never reach the fixture handler or the recorded
  transcript;
- direct runner use cannot skip the guard; blocked requests do not consume the
  request budget or increment `requests_sent`;
- the HTTPX transport still checks the guard immediately before socket work,
  and the offline runner immediately before releasing a recorded response.

The scope models remain separate: fixture queries/auth probes and
authorized-operation classifications are scope-specific layers on top of the
common contract. This is not yet a single unified class, and no production
network path is enabled.

## Bundled offline scenarios

| Scenario | Verdict | Requests | Blocked | What it proves |
|---|---|---:|---:|---|
| `synthetic-vulnerable` | CONFIRMED | 7 | 0 | ownership + baseline + cross-account private disclosure |
| `synthetic-secure` | SAFE | 7 | 0 | exact checked 403 denial, no private marker |
| `synthetic-metadata` | INCONCLUSIVE | 7 | 0 | 200 without private data does not confirm |
| `synthetic-leaky-denial` | INCONCLUSIVE | 7 | 0 | a 403 carrying private data is not SAFE |
| `synthetic-pagination-limit` | SKIPPED | 3 | 0 | unterminated pagination cannot verify ownership |
| `synthetic-guard-block` | SKIPPED | 6 | 1 | budget guard blocks the cross-account read |

All six run through the API with sockets/DNS blocked in tests.

## Why the verdict is defensible

For CONFIRMED, the report exposes the same checklist and evidence used by the
decision:

- `private_resource`, `distinct_accounts`, `ownership_verified`,
  `owner_baseline`, `private_baseline`;
- `attacker_request`, `response_checked`, `private_disclosure`;
- `policy_denies_access` and `verified_denial`.

Ownership evidence records the owner-namespace baseline status and flags
`both_owner_baselines` and `cross_list_isolation`. Disclosure evidence records
the cross-account status, `attacker_request`, `response_checked`,
`private_disclosure` and `verified_denial`. `verified_denial` is false for a
CONFIRMED disclosure because denial and disclosure are alternatives. Both
evidence summaries are hashed; raw bodies, tokens and resource identifiers are
not stored.

## Adversarial checks

- API rejects unknown scenario ids (404) and any extra field such as a supplied
  target URL (422).
- Paths/actors outside the exact scope are rejected before transcript release;
  `requests_sent` stays 0 and `blocked_by_guard` increments.
- Transcripts reject duplicate entries, redirect/server-error statuses,
  unscoped actors, unscoped paths and oversized bodies.
- Constructing `run_generic_scan` with an arbitrary object fails closed.
- A mocked HTTPX result can be evaluated but cannot pass the persistence model
  or enter `scenario_runs`.
- Stored payload tampering returns a generic 500, not a finding.

## VS Code demo

From the repository root (Windows: `.venv\Scripts\python`):

```sh
.venv/bin/python tools/run_ci_tests.py
.venv/bin/python -m uvicorn canarygate.api.app:app --host 127.0.0.1 --port 8000
```

In a second terminal:

```sh
curl -sS -X POST http://127.0.0.1:8000/api/scenario-scans \
  -H "content-type: application/json" -d '{"scenario_id": "synthetic-vulnerable"}'
# Copy the returned id, then view the same evidence in both formats:
curl -sS "http://127.0.0.1:8000/api/scenario-scans/<id>"
curl -sS "http://127.0.0.1:8000/api/scenario-scans/<id>/report?view=sections"
curl -sS "http://127.0.0.1:8000/api/scenario-scans/<id>/report?format=html"
```

The judge-facing three outcomes:

```sh
for s in synthetic-vulnerable synthetic-secure synthetic-metadata; do
  curl -sS -X POST http://127.0.0.1:8000/api/scenario-scans \
    -H "content-type: application/json" -d "{\"scenario_id\": \"$s\"}" |
    .venv/bin/python -c "import json,sys; r=json.load(sys.stdin); print(r['scenario_id'], r['verdict'], r['reason'])"
done
```

Expected: CONFIRMED with ownership and disclosure evidence; SAFE with a checked
denial; INCONCLUSIVE because the response did not prove private disclosure or a
verified denial.

## Tests and results

New tests:

- `tests/integration/test_generic_scenario_scan.py` (16 cases): all six
  scenarios through the API, persistence/restart/tamper, report consistency,
  redaction, plan/runner bypass attempts and transport re-use with mocked HTTPX.
- `tests/security/test_shared_safety_policy.py` (7 cases): shared contract,
  both guards calling it, prohibited methods, budget exhaustion and unscoped
  access.

Local full suite: **539 passed**, one third-party Starlette/AnyIO
`DeprecationWarning`. `git diff --check` clean. Isolated wheel build includes
the new scenario template (77 files).

CI run `41057738033` on commit `743c59a` (repeat `41058504145` on `71397bd`) passed both
`tests (ubuntu-latest, 3.11)` and `tests (windows-latest, 3.11)`. The first two
CI attempts failed on Windows only: the new test patched `socket.connect`
before Starlette's `TestClient` started, and Windows asyncio connects a loopback
socketpair while creating its event loop. The guard is now installed after
client startup and scoped to each client block, matching the existing offline
tests. CI also now uploads pytest output as an artifact and emits failing test
names as check annotations, because job logs are not retrievable from this
environment.

## Remaining gaps

- No live target, organizer scope execution, DNS pinning or production network
  path; the guarded HTTPX transport remains disabled.
- No generic orchestration of authentication/input/disclosure checks; AUTHN,
  INPUT and DISC statuses are unchanged.
- Scenario report is a seven-section, scenario-specific projection; the full
  nine-section report, complete authorization matrix and manual-intervention
  capture remain incomplete.
- Redaction remains known-shape and schema-bounded; no universal live-data
  claim.
- The shared contract is one policy layer, not one unified guard class.
