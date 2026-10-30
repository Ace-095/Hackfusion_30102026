# Checkpoint 40 — the five-minute judge experience

**Goal:** stop adding backend surface and make the existing one demonstrable. A
judge who has never seen CanaryGate should be able, in five minutes and without
being taught the API, to fill the nine-cell matrix, open any cell and see the
request that produced it, and understand why six cells are `CONFIRMED` while the
secure route is `SAFE`.

**Result:** `/ui/lab/matrix` now carries **RUN FULL AUTHORIZATION
DEMONSTRATION** — one port, the catalog's three coverage pairs, three ordinary
sequential runs, a result page that claims coverage only when the rebuilt matrix
has no untested cell, and a shared cell grid whose detail panel shows the
requesting account, the owner, the asset, expected vs actual access, status,
verdict, run id, evidence id, evidence hash, lab instance, the four boolean
flags, the oracle's remediation, and the secure route's own digest and 403.

No oracle, scope rule, verdict rule, transport rule or stored verdict changed.

## Phase 1 — full coverage demonstration

| Artifact | Purpose |
|---|---|
| `POST /ui/actions/lab-demo-run` | Reads `coverage_pairs` from `GET /api/lab-catalog`, runs each pair through `start_lab_bola_scan` in order, rebuilds the matrix, renders `lab_demo_result.html` |
| `_coverage_outcomes()` | Records `{actor, owner, ok, run_id, verdict, confirmed, requests_sent, budget}` per pair, or the backend's own refusal detail; a refused pair never stops the loop but never yields a cell either |
| `partials/matrix_grid.html` | The one implementation of the 3×3 grid, shared by the matrix page and the result page |
| `lab_demo_result.html` | Coverage verdict, four counts, per-pair outcome table, the grid, and what the page is and is not |
| `tests/integration/test_ui_lab_pages.py` | 13 cases: the form, the run, the stored runs, the refusal, four rejected ports, secrets |

Guarantees the tests enforce:

- a non-numeric or out-of-range port answers `422` **before** any run and stores
  nothing;
- the three pairs come from the catalog (the form posts only `port`);
- three runs are stored as ordinary `LabBolaRun` documents — six checks, a scope
  with a budget, the same port — reachable through `GET /api/lab-bola-scans/{id}`;
- "all nine cells have stored evidence" appears only when `untested == 0`;
- a refused demonstration says "coverage is incomplete", shows `0 / 3`, names the
  backend's refusal and leaves nine untested cells.

## Phase 2 — evidence experience

Every cell links to `?cell=<requester>:<asset>`. The detail panel is built only
from the matrix payload: no value is recomputed in the template, and a cell with
no evidence renders "No stored check answers this combination. It stays
untested — not SAFE." New in this checkpoint: asset type, evidence id
(`<run id>#<check id>`), lab instance, the private-disclosure / verified-denial /
owner-baseline booleans through the yes/no/not-recorded renderer, the oracle's
remediation text for confirmed cells, and the secure counterpart's own check id
and digest (previously the digest was invisible there).

## Phase 3 — vulnerable versus secure

The comparison table now prints, for both routes, the check id and the first
twelve characters of that check's own evidence hash, next to its own status and
verdict. The two routes are never merged: a `CONFIRMED` cell is always shown with
the secure route's `SAFE` / `403` beside it, and the page states that the six
confirmed results describe the deliberately vulnerable route — they are not
evidence that the secure configuration is vulnerable. `docs/UI.md` §5 rule 9 puts
that in the UI's honesty rules.

## Phase 4 — demonstration reset

The reset panel existed; what was missing was the boundary in words a judge can
check. It now states that the reset does not reset, delete or rewrite the
read-BOLA matrix, that it is a separate controlled execution, and that the grid
above does not change when the proof runs. The two operations are still distinct
routes — `POST /api/lab-sci-resets` versus `POST /api/lab-bola-scans` — and the
page never implies otherwise.

## Phase 5 — reliability

| Problem | Change |
|---|---|
| Port-based staleness | TargetLab publishes `X-Lab-Instance` (16 hex, per process) on every response and `instance_id` in `/health`; the transport records `scope.lab_instance`; the matrix compares instance ids when both sides publish one and falls back to the port only when one does not |
| Timestamp tie-break | `created_at` is stored with microseconds, so three consecutive demo runs order chronologically without the `rowid` tie-break; the tie-break stays as the final deterministic rule |
| Partial coverage | The demonstration reports each pair's outcome and never counts a requested run as evidence |
| Superseded evidence | Unchanged in behaviour: newest run wins, older runs stay listed, `sources`/`superseded_runs`/`stale` stay in the payload |

The oracle and the stored verdicts were not touched.

## Verification (measured at this checkpoint)

```
$ .venv/bin/python -m pytest -q
1079 passed, 1 warning in 104.62s
$ .venv/bin/python tools/p0_audit.py
P0 audit: 58 requirements, 1079 collected tests, 64 test files
status: implemented=47, partial=9, missing=2, unreachable=0
loopback-only test files: 11
api routes checked: 17
no dangling references, unclassified tests or unreachable API claims
$ .venv/bin/python tools/demo.py
ALL CONSISTENCY CHECKS PASSED (142 invariants over 17 surfaces)
$ .venv/bin/python tools/browser_smoke.py --jsdom /tmp/browser-harness
19/19 browser checks passed
$ .venv/bin/python tools/consistency_audit.py --database <db with 3 BOLA runs>
runs checked: 3  projections rebuilt: 7  invariants: 220
asset matrix rebuilt offline: 9 tested, 0 untested, 6 CONFIRMED, 3 SAFE
ALL STORED RUNS INTACT AND CONSISTENT
```

A live probe of the API (fresh database, real TLS lab) produced exactly the
reference matrix: `mallapa→sakshi`, `sakshi→harsha`, `harsha→mallapa` ⇒ 9 tested,
6 `CONFIRMED`, 3 `SAFE`, `runs_considered: 3`, `lab_instances: 1`, 0 stale,
3 duplicated cells; an empty database produced 9 untested cells and no verdict.

## Remaining limitations

- The demonstration is three runs of one pair each; a judge who runs it twice
  regenerates the same nine cells and the older runs become `superseded`.
- Coverage is defined by the catalog's three pairs. A different demo tenant would
  need a different coverage set, and the page reads it rather than assuming it.
- `lab_instances` counts ids seen in the runs considered, not labs contacted; a
  lab that never publishes the header (older builds) is still compared by port.
- The reset proof does not clear the BOLA scan history, by design. A judge who
  wants a clean grid needs a fresh database, which is stated on the page.
- `D11` (BFLA) and `D12` (live validation) remain missing; P0 is still
  *incomplete*.
