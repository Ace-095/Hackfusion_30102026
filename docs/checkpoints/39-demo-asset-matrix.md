# Checkpoint 39 — the demo asset matrix, built from stored evidence

**Goal:** give a judge one screen that answers "did you really try every
combination of the three accounts and the three private assets?" without adding a
second detection engine, without hardcoding an expected verdict, and without ever
letting a missing result read as `SAFE`.

**Result:** `GET /api/lab-matrix` and `/ui/lab/matrix` project the stored read-BOLA
runs onto the nine combinations. Three coverage runs produce **9 tested / 6
CONFIRMED / 3 SAFE / 0 untested** with 3 duplicated cells visible; an empty
database produces 9 untested cells with no verdict at all. Full suite: **1055
passed**. Demo: **142 invariants over 17 surfaces**. Browser smoke: **19/19**.

No oracle, scope rule, verdict rule, transport rule or stored payload changed.

## What was added

| Artifact | Purpose |
|---|---|
| `canarygate/scan/lab_matrix_models.py` | Strict pydantic contract for the matrix: two states, five verdicts, evidence and secure-counterpart blocks, summary arithmetic |
| `canarygate/scan/lab_matrix.py` | `build_lab_matrix(runs)`: a projection of stored checks onto the nine cells; no socket, no ground truth, no verdict |
| `GET /api/lab-matrix` | The matrix as JSON, read-only |
| `/ui/lab/matrix` | The 3×3 grid, per-cell evidence panel, vulnerable-vs-secure table, coverage pairs, reset panel |
| `tests/unit/test_lab_matrix_rules.py` | 10 tests: states, verdict mapping, direction, summary arithmetic, stale/duplicate accounting |
| `tests/integration/test_lab_matrix.py` | 7 tests over real loopback TLS: empty, single run, coverage trio, duplicates, staleness, read-only stability, no lab traffic |
| `tests/integration/test_ui_lab_pages.py` | 6 added page tests: empty, populated, selected cell, untested cell, reset wording, no secret leak |

## The contract, in one table

| Concept | Values | Enforced by |
|---|---|---|
| cell state | `tested`, `untested` | untested ⇒ no verdict, reason, evidence, sources, staleness; `actual_access == "no_evidence"` |
| check verdict | `CONFIRMED`, `SUSPECTED`, `SAFE`, `INCONCLUSIVE`, `SKIPPED` | copied from the stored check; a cell whose verdict differs from its evidence is refused |
| observed access | `private_record_returned`, `denied`, `not_attempted`, `unverified_response`, `no_evidence` | derived from the stored booleans in a fixed order, and re-derived by the validator |
| direction | `owner_baseline`, `cross_account` | diagonal cells must come from an owner baseline, off-diagonal from a cross-account check |
| secure counterpart | same run, `LAB-BOLA-05/06`, never on a diagonal cell | cross-cell validator |

## The nine combinations, and where each cell comes from

| Requester | Own asset (owner baseline) | Cross-account attempts |
|---|---|---|
| `mallapa` | `MKT-2026-041` ← `LAB-BOLA-01` | `BRD-2026-018` ← `LAB-BOLA-03` (+`05`), `ADS-2026-027` |
| `sakshi` | `BRD-2026-018` ← `LAB-BOLA-02` | `MKT-2026-041` ← `LAB-BOLA-04` (+`06`), `ADS-2026-027` |
| `harsha` | `ADS-2026-027` | `MKT-2026-041`, `BRD-2026-018` |

One run answers four cells: two owner baselines, one cross direction and its secure
twin. That is why the catalog's `coverage_pairs` are three unordered pairs and not
six: `mallapa→sakshi`, `sakshi→harsha`, `harsha→mallapa`. The remaining three
ordered pairs re-answer the same cells from the other direction; those duplicates
are counted (`duplicated_cells`) and listed (`superseded_runs`) rather than hidden.

## Three answers the matrix work had to give first

**Why six ordered pairs if one run checks both directions?** Because a run records
*both* directions and *both* routes for the pair it selects, so the minimum set of
runs that answers all nine combinations is the three unordered pairs. The other
three ordered pairs are accepted by the API and produce duplicate evidence for the
same cells; the matrix shows that duplication instead of pretending it did not
happen. All nine combinations map to runs and evidence ids in
`tests/integration/test_lab_matrix.py::test_three_coverage_runs_answer_all_nine_cells`.

**Why 15 extra tests and not 16?** The checkpoint added 17 test definitions and
removed 2 that only described the old pair-based page, for a net +15 at the time of
the question. After the matrix UI tests the net is +23 (1032 → 1055).

**Are the offline P0 identities, recipes, digests and expected evidence
unchanged?** Yes. The three demo identities apply to the demo tenant only
(TargetLab, playground, lab evidence). The offline fixture keeps `alice`/`bob` as a
frozen dataset: `scope.yaml`, `canarygate/offline`, `oracles`, `seed`,
`report/fixture.py`, `report/p0.py` and `tests/fixtures` are untouched, and the
fixture `/api/scan` output is byte-equal after stripping volatile fields
(`scope_hash=8303ccb3…`, `spec_hash=32e048cf…`, verdict `CONFIRMED`).

## Measured behaviour (fresh database each time)

| Scenario | Result |
|---|---|
| no stored run | 9 untested, 0 verdicts, summary `tested: 0` |
| one run (`mallapa`→`sakshi`) | 4 tested / 5 untested, 2 CONFIRMED, 2 SAFE |
| three coverage runs | 9 tested, 6 CONFIRMED, 3 SAFE, `duplicated_cells: 3`, `runs_considered: 3` |
| second lab instance on another port | `stale_cells: 3`, `ports` sorted unique |
| `GET /api/lab-matrix` twice | identical except `generated_at`; no socket opened, no lab request |
| stored runs rebuilt offline (`tools/consistency_audit.py`) | same nine cells, 220 invariants, all intact |

## What this checkpoint does not claim

- It is not live BOLA validation. The matrix describes the loopback TargetLab only,
  and the page says so.
- It is not a second detection engine. Every verdict on the matrix is a stored
  check's verdict; the aggregator has no `if` that can create one.
- It is not complete coverage of the offline P0. `D11` (BFLA) and `D12` (live
  validation) remain missing, and the matrix says nothing about either.
- It does not reset the lab as part of a scan. The reset proof is a separate
  controlled execution, reachable from the matrix page and labelled as such.

## Verification

```
$ .venv/bin/python -m pytest tests/unit/test_lab_matrix_rules.py \
      tests/integration/test_lab_matrix.py -q
17 passed

$ .venv/bin/python -m pytest tests -q
1055 passed

$ .venv/bin/python tools/browser_smoke.py --jsdom <harness>
19/19 browser checks passed

$ .venv/bin/python tools/demo.py
ALL CONSISTENCY CHECKS PASSED (142 invariants over 17 surfaces)

$ .venv/bin/python tools/consistency_audit.py --database <db with 3 coverage runs>
runs checked: 3  projections rebuilt: 7  invariants: 220
asset matrix rebuilt offline: 9 tested, 0 untested, 6 CONFIRMED, 3 SAFE
ALL STORED RUNS INTACT AND CONSISTENT
```
