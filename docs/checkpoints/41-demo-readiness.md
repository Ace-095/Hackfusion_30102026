# Checkpoint 41 — demonstration readiness

**Goal:** prove the five-minute demonstration is reliable and repeatable before a
judge touches it. No new engine, no new verdict, no change to the frozen fixture,
the oracles, the `RunSafetyGuard`, the API contracts or TargetLab's isolation.

**Result:** eight scenarios validated against a real loopback-TLS TargetLab, each
on its own fresh database, plus a release check that includes a clean wheel
installation. Three new integration tests make the two most fragile scenarios
"partial failure" and "repeated demonstration" permanent. Full suite: **1082
passed**.

## What was added

| Artifact | Purpose |
|---|---|
| `targetlab/testing.py:GatedLabTlsServer` | The real lab behind a byte-forwarding loopback gate; after `cut_after` connections the listener closes, so the next request is refused exactly as it would be after the lab process exits. The TLS session is end-to-end between CanaryGate and the lab — the certificate, the protocol and the responses are the lab's own |
| `tests/integration/test_ui_lab_pages.py` | Three tests: an interrupted demonstration, a repeated demonstration, and a connection failure that must never read as `SAFE`; the cell-detail test now also asserts identity, asset, evidence id, remediation, lab instance and redaction |
| `tests/integration/test_ui_lab_pages.py::test_the_cell_detail_shows_the_run_check_and_both_routes` | Extended: the panel must show the requester, the owner, the asset, `<run>#<check>`, the oracle's remediation and the lab instance, and must leak no lab secret |

The gate is a test helper only. `canarygate` does not import it, the lab
application is unchanged, and the demonstration still runs through the ordinary
`POST /api/lab-bola-scans` handler.

## The eight scenarios

Each was run as a script against a real `LabTlsServer` with
`CANARYGATE_TARGETLAB_CA` set, and each on a **fresh database** so no earlier run
could mask the result.

**1. Fresh database.** `GET /api/lab-matrix` → 9 cells, `tested: 0`,
`untested: 9`, `runs_considered: 0`, every `verdict` `null`. The page renders
`0 / 9`, the words "Untested is not SAFE", and nine "no stored check" cells. No
old evidence is presented as current because there is no evidence to present.

**2. Successful full demonstration.** `POST /ui/actions/lab-demo-run` → `200`;
matrix `tested: 9`, `confirmed: 6`, `safe: 3`, `untested: 0`,
`runs_considered: 3`, three distinct runs cited, every cited run resolvable
through `/api/lab-bola-scans/{id}` with six checks. The page claims "All nine
cells have stored evidence" only after that reconstruction.

**3. Partial failure.** The gate closes after 36 connections — exactly the two
completed runs at 18 requests each. Result: `2 / 3` pairs stored, matrix
`tested: 7`, `untested: 2`, `runs_considered: 2`; the page says "Coverage is
incomplete", names the pair, and prints the backend's own refusal
("TargetLab could not be reached; no evidence was stored"). The two untested
cells are exactly the ones the missing pair would have answered:
`mallapa × ADS-2026-027` and `harsha × MKT-2026-041`. Both stored runs remain
complete and retrievable.

**4. Repeated demonstration.** Two full demonstrations on one database:
`runs_considered: 3 → 6`, `tested: 9`, `duplicated_cells: 9`,
`stale_cells: 0`. Every cell cites a run from the newest batch, every cell lists
the older run in `superseded_runs`, and two consecutive `GET /api/lab-matrix`
calls return identical `evidence_id`s — the selection is deterministic.

**5. Wrong port or unavailable TargetLab.** Port `999` → `422` with the range
sentence, nothing stored. A closed high port → `200` result page that says
"Coverage is incomplete", `0 / 3`, "not stored"; the matrix keeps `tested: 0`,
`safe: 0`, every verdict `null`, and the page makes no coverage claim. A
connection failure is never a verdict.

**6. Evidence inspection.** For `mallapa × BRD-2026-018`: run id, `LAB-BOLA-03`,
HTTP `200`, `CONFIRMED`, requester `mallapa`, owner `sakshi`, the evidence SHA-256,
the lab instance, and the oracle's remediation text are all on the panel; the
secure twin `LAB-BOLA-05`, `403`, `SAFE` is shown with its own digest; the cited
check exists in the stored run with the same digest; and no lab password, token,
private marker or trace marker appears on any surface.

**7. Browser validation.** jsdom: **19/19** checks over the live pages, including
the matrix grid, the selected-cell link and "no page-level script error". A real
browser engine is **not installable in this sandbox** (no Chromium/Firefox
binary, and the Playwright CDN is outside the allowed egress), so real-browser
visual, responsive, keyboard and focus behaviour was **not** verified here and is
not claimed. What is verified: the pages carry a viewport meta, all interactive
elements are native controls without negative tabindex, and `app.css` has a
global `:focus-visible` outline — but that is a static check, not a browser test.
A live preview is served from the workspace so a human can check the rendering
directly; that is a manual check, not an automated one.

**8. Release verification.**

```
$ .venv/bin/python -m pytest -q
1082 passed, 1 warning in 135.73s
$ .venv/bin/python tools/p0_audit.py
P0 audit: 58 requirements, 1082 collected tests, 64 test files
status: implemented=47, partial=9, missing=2, unreachable=0
$ .venv/bin/python tools/demo.py
ALL CONSISTENCY CHECKS PASSED (142 invariants over 17 surfaces)
$ .venv/bin/python tools/browser_smoke.py --jsdom /tmp/browser-harness
19/19 browser checks passed
$ .venv/bin/python tools/consistency_audit.py --database <3 BOLA runs>
runs checked: 3  projections rebuilt: 7  invariants: 220
asset matrix rebuilt offline: 9 tested, 0 untested, 6 CONFIRMED, 3 SAFE
ALL STORED RUNS INTACT AND CONSISTENT
$ .venv/bin/python -m build --wheel          # canarygate-0.1.0-py3-none-any.whl
$ python3 -m venv /tmp/cleanvenv && /tmp/cleanvenv/bin/pip install dist/canarygate-0.1.0-py3-none-any.whl
$ cd /tmp && /tmp/cleanvenv/bin/python -c "..."   # imports from site-packages
canarygate /tmp/cleanvenv/lib/python3.11/site-packages/canarygate/__init__.py
/ui/lab/matrix 200 26717     /ui/lab 200 26412
/api/lab-matrix 200 4234     /api/lab-catalog 200 2785
/ui/static/css/app.css 200 36765
bad-port demo: 422 True
```

The wheel contains 175 files, including `ui/templates/lab_demo_result.html`,
`ui/templates/partials/matrix_grid.html` and the vendored HTMX. Installing it in
an empty virtualenv outside the checkout serves every page and asset from
`site-packages`, so the packaging is not relying on the repository tree. TargetLab
itself is not part of the wheel (by design — the scanner never imports the lab),
so a demonstration from a wheel needs the lab started from a checkout.

## What was preserved

- Frozen offline P0 fixture: untouched; its tests still pass and its `/api/scan`
  payload is byte-equal modulo volatile fields.
- BOLA and SCI oracles: untouched.
- `RunSafetyGuard`: untouched; every demonstration request still passes through it
  immediately before the connection.
- API contracts: unchanged — the demonstration calls the same
  `POST /api/lab-bola-scans` handler, and no schema gained or lost a field.
- TargetLab isolation: the lab still binds loopback only; the gate forwards only
  to `127.0.0.1`.

## Remaining limitations and blockers

- **Real-browser verification is not done** and cannot be done in this sandbox.
  Everything visual rests on jsdom plus a human looking at the live preview.
- Partial failure is proven for a lab that *disappears*. A lab that answers with
  individual failed requests (as opposed to refusing connections) yields a stored
  run with `SKIPPED`/`INCONCLUSIVE` checks, which is a different outcome from the
  one asserted here — it is honest, but the demonstration page shows it as a
  stored run rather than as a missing pair.
- The gate depends on one TCP connection per request (`Connection: close`). If the
  transport ever pooled connections, its cut point would need re-deriving.
- `D11` (BFLA) and `D12` (live validation) remain missing; P0 stays *incomplete*.
  Nothing here claims BFLA coverage, arbitrary live-API validation or production
  readiness.
