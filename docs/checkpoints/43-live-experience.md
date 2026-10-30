# Checkpoint 43 — cinematic entry, live execution, interactive dashboard

**Goal:** make CanaryGate feel like a product a judge can operate alone — a cinematic
entrance, a configuration screen that explains itself, a loading screen showing
what is actually happening, and a dashboard where every visual leads to evidence.

**Result at this milestone:** the landing page is a 15-second canvas showreel; the
workspace is a four-step form with one button; pressing it opens a live execution
screen whose feed is produced by the transport itself; and the dashboard is a set
of linked analytics built from stored data.

## 1. Real progress, at last (the important change)

The previous milestone could only show recorded stages because the backend ran a
scan synchronously. That limitation is now removed without touching the API:

| Piece | What it does |
|---|---|
| `TargetLabTransport(..., observer=cb)` | Called **after** each exchange with `{actor, method, path, status, elapsed_ms, requests_sent}`. It sees a completed response, returns nothing, and its exceptions are swallowed |
| `canarygate/ui/execution.py` | Runs an assessment on a worker thread using the same `build_bola_plan` / `build_sci_plan`, `TargetLabRunner`, oracle functions and stores as the JSON API; records every observed request plus real boundaries ("Pair 2 of 3", "stored") |
| `POST /ui/actions/run-assessment` | Validates the port and the catalog pair, starts the job, redirects to the loading screen |
| `GET /ui/execution/{job_id}` | The engine screen: current operation, requester → API → resource diagram, stage list, event feed |
| `GET /ui/execution/{job_id}/events?since=N` | The transcript as JSON; read-only, in-memory, gone when the job leaves the registry |

**What is guaranteed:**

- one event per request, carrying the lab's own status (a secure-route refusal
  shows `403`, an owner read shows `200`);
- the streamed request count equals the stored run's `constraints.requests_sent`
  (18 for one pair, 54 for the demonstration);
- the run is stored by the same `run_lab_bola_scan` path, so `/api/lab-bola-scans`
  and `/api/lab-matrix` read exactly what a synchronous call would have produced;
- a refused lab produces an `error` event, zero request events, zero stored runs,
  and a page that says "Assessment did not complete";
- an observer that raises cannot break a scan (tested), and an observer that is
  not callable is ignored.

## 2. The landing page

A canvas showreel over the same HTML story: network formation (0–3 s), request
packets along edges (3–6 s), an authorization boundary with a refused request
(6–9 s), evidence fragments assembling into a report card (9–12 s), brand glow
(12–15 s). The headline, both calls to action and **Skip intro** are usable from
the first frame; Escape skips; `prefers-reduced-motion` draws the final frame once;
the animation pauses when the tab is hidden and stops after 15 s. No status code,
verdict or number is drawn — the sequence is abstract on purpose, so it cannot be
mistaken for a result.

Where no canvas exists (jsdom, canvas-disabled browsers) the CSS/SVG scene is used
and the page is pinned to its finished state — tested.

## 3. The workspace

Four labelled steps (specification → environment → accounts → tests) on one page,
with the recommended full demonstration pre-selected, the port defaulted to 8765,
and every account, asset and role read from `GET /api/lab-catalog`. One submit
button. Specification inspection stays labelled "inventory only — no security scan
performed".

## 4. The dashboard

| Block | Data | Links to |
|---|---|---|
| Status KPIs | inventory size, matrix coverage, confirmed findings, "new run" | assessment, endpoints, matrix, findings |
| Authorization matrix | `GET /api/lab-matrix` via the shared grid partial | each cell → its evidence |
| Verdict distribution | run-level verdicts across offline + lab stores | findings / scan history |
| Evidence accounting | stored runs, checks, checks with an evidence hash | — |
| Ownership proof | catalog accounts + stored owner baselines | matrix cell evidence |
| Request-to-disclosure proof | latest BOLA run's stored flags + secure twin | the exact check anchors |
| Execution timeline | latest BOLA run's stages | run detail |
| Reports / history | report index, recent runs | reports, scans, lab |

Every block navigates; nothing is a decorative chart. A bar's width is
`count / total`, computed in the template from counts the backend supplied.

## 5. Verification

```
$ .venv/bin/python -m pytest -q
1098 passed, 1 warning in 112.43s
$ .venv/bin/python tools/p0_audit.py
P0 audit: 58 requirements, 1098 collected tests, 65 test files
status: implemented=47, partial=9, missing=2, unreachable=0
$ .venv/bin/python tools/demo.py
ALL CONSISTENCY CHECKS PASSED (142 invariants over 17 surfaces)
$ .venv/bin/python tools/browser_smoke.py --jsdom /tmp/browser-harness
29/29 browser checks passed
$ .venv/bin/python tools/consistency_audit.py --database <3 BOLA runs>
ALL STORED RUNS INTACT AND CONSISTENT
```

Browser smoke grew from 19 to 29 checks: the landing page (one headline, no form,
skip works, no external asset, no page error) and the workspace (three kinds, the
assessment action, the inventory-only label, port default, no external asset, no
page error).

A live HTTP run of the whole journey (uvicorn, real lab, no TestClient): POST →
303 → 62 events → 3 stored runs → 54 requests → matrix 9 tested / 0 untested.

## 6. Not built / not claimed

- **Server-sent events** — polling a three-second job is sufficient and simpler;
  the endpoint is already structured for a stream if it is ever wanted.
- **Per-endpoint findings analytics and historical comparison charts** — the
  backend still exposes no aggregation for them, and the dashboard shows only
  counts it can prove.
- **Real-browser visual verification** — jsdom has no layout engine; the canvas
  sequence is checked structurally and by a human on the live preview.
- `D11` (BFLA) and `D12` (live validation) remain missing; P0 stays *incomplete*.
