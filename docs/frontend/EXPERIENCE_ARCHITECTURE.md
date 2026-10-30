# CanaryGate frontend experience — architecture report (CP42)

**Status:** written before implementation, against `dba075e` (1,082 tests, P0 audit
47 implemented / 9 partial / 2 missing, PR #4 open and unmerged).

This is the required inventory and plan. Every claim below was read out of the
code at that commit, not from the checkpoint summaries. Implementation phases that
shipped in this milestone are marked **[shipped]**; everything else is explicitly
**not built yet**.

---

## 1. What exists today

### 1.1 UI pages (all server-rendered Jinja2, one router, no SPA)

| Route | Template | Purpose | Source of truth |
|---|---|---|---|
| `/` | — | 307 redirect to `/ui/` | — |
| `/ui/` | `dashboard.html` | Health, gates, latest run, counts, lab cards | `health`, `endpoints`, `setup`, `findings`, three lab stores |
| `/ui/endpoints` | `endpoints.html` | Offline endpoint inventory + which runs touched each row | `GET /api/endpoints`, stored runs |
| `/ui/findings` | `findings.html` | Verdict-filtered findings list | `GET /api/findings` |
| `/ui/scans`, `/ui/scans/{id}` | `scans.html`, `scan_detail.html` | Stored offline fixture runs | `GET /api/findings`, `GET /api/scan/{id}` |
| `/ui/scans/{id}/evidence`, `/report`, `/replay` | `evidence`, `report_view`, `replay` | Observational evidence, section report, replay | api handlers |
| `/ui/suites`, `/ui/suites/{family}/{id}` | `suites.html`, `suite_run.html` | Four offline scenario families | api handlers |
| `/ui/matrix` | `matrix.html` | Offline endpoint × access-class matrix | `GET /api/matrix` |
| `/ui/lab` | `lab.html` | TargetLab entry: CA readiness, three workflows, stored lab runs | `GET /api/lab-catalog` + three lab stores |
| `/ui/lab/matrix` | `lab_matrix.html` | 3×3 account × asset matrix, cell evidence, reset panel | `GET /api/lab-matrix`, `GET /api/lab-catalog` |
| `/ui/lab/bola/{id}` | `lab_bola.html` | Six checks, ownership, comparison, constraints | `GET /api/lab-bola-scans/{id}` |
| `/ui/lab/sci/{id}` | `lab_sci.html` | Two baselines + combined action | `GET /api/lab-sci-scans/{id}` |
| `/ui/lab/reset/{id}` | `lab_reset.html` | RESET-01…04 | `GET /api/lab-sci-resets/{id}` |
| `/ui/spec` | `spec.html` | OpenAPI upload / paste / inspect | `POST /api/spec/upload`, `canarygate.spec.parser` |
| `/ui/reports`, `/ui/reports/lookup` | `reports.html` | Report index and lookup | api report handlers |
| `/ui/configure`, `/ui/setup` | `configure.html`, `setup.html` | Read-only configuration and readiness | `GET /api/setup/status` |

**Actions** (form posts that call the API handlers in-process and then redirect):
`fixture-scan`, `scenario-scan`, `authentication-scan`, `validation-scan`,
`interaction-scan`, `lab-bola-scan`, `lab-sci-scan`, `lab-sci-reset`,
`spec-inspect`, `lab-demo-run`.

### 1.2 Backend API (36 routes, unchanged by this milestone)

Health, spec upload, endpoints, setup status, fixture scan, four scenario
families, reports, `lab-catalog`, `lab-scans`, `lab-bola-scans`, `lab-sci-scans`,
`lab-sci-resets`, `lab-matrix`, `authorization-matrix`, `reports/{run_id}`.
Every lab route requires `CANARYGATE_TARGETLAB_CA` and reaches only
`127.0.0.1` through `RunSafetyGuard`.

### 1.3 Frontend components

`base.html` shell (topbar, sidebar `NAV_GROUPS`, local-evidence banner, footer),
`_macros.html` (`page_head`, `verdict_badge`, `status_badge`, `stat`, `empty`,
`icon`, `kv`, `verdict_legend`, `journey`, `tri`), one hand-written stylesheet
(`static/css/app.css`, ~37 KB, token-based dark system), `app.js` (nav toggle,
table filter, disclosure), vendored HTMX. No framework, no build step, no CDN.

### 1.4 Data available for each requested dashboard section

| Requested section | Available today | Gap |
|---|---|---|
| Executive metrics | `GET /api/endpoints`, `GET /api/findings` counts, `GET /api/lab-matrix` summary, lab stores | A single endpoint that reports "endpoints tested / evidence records / authorization coverage" across datasets does **not** exist; the UI computes them from the payloads above |
| 3×3 matrix | `GET /api/lab-matrix` (tested/untested, evidence ids, secure twin, stale, superseded) | none |
| Verdict distribution | counts over stored runs (five verdicts preserved) | per-endpoint grouping needs the offline run rows; already available on `/ui/endpoints` |
| Findings by endpoint | offline runs name concrete paths; `/ui/endpoints` maps them onto inventory rows | TargetLab findings are per-check, not per-inventory-endpoint; no mapping endpoint exists |
| Historical comparison | every stored run plus `superseded_runs` | no time-series endpoint; computing a chart would mean inventing a metric |
| Ownership proof | `ownership` block of a BOLA run (verified identities, baselines, cross-list isolation) | no per-identity entity; the UI can only draw what a run stored |
| Disclosure proof | `checks[LAB-BOLA-03/04]` + `private_disclosure` + `evidence` + secure twin | none — this is fully derivable from stored evidence |
| Execution timeline | stored checks with per-check status/verdict; run `created_at` | **no per-stage timestamps and no live events** (see §3) |
| Reports | HTML/JSON projections for every family; nine-section P0 report | none |

## 2. Proposed page structure (and what shipped)

| New page | URL | Data | Status |
|---|---|---|---|
| Landing | `/` | static copy + CSS/SVG motion; links only | **[shipped]** |
| Assessment workspace | `/ui/assessment` | `GET /api/lab-catalog`, `GET /api/lab-matrix`, spec-inspection card, existing action routes | **[shipped]** |
| Live execution view | `/ui/execution/{job_id}` (+ `/events`) | real transport events from the running job | **[shipped]** |
| Recorded execution view | section on `/ui/lab/bola/{id}` | stored checks, labelled as recorded | **[shipped]** |
| Dashboard | `/ui/` | matrix, verdict distribution, ownership map, disclosure proof, timeline, reports | **[shipped]** |
| Disclosure proof | section on `/ui/lab/bola/{id}` and in the matrix cell panel | stored check evidence + secure twin | **[shipped]** |
| Ownership proof | section on `/ui/lab/bola/{id}` | run `ownership` block | **[shipped]** |
| Demo accounts | `/ui/lab/accounts` (rendered from the catalog) | `GET /api/lab-catalog` | **[shipped]** |
| Server-sent events | — | not needed; polling the job transcript is enough for a three-second demonstration | **not built (not required)** |
| Per-endpoint findings, historical chart | — | needs new backend aggregation endpoints | **not built** |

Old URLs are preserved; the nav adds the new entries beside them, so nothing that
worked at `dba075e` stops working.

## 3. Progress telemetry feasibility

**What exists.** `POST /api/lab-bola-scans` is synchronous: it builds the plan,
runs it through `run_lab_bola_scan(plan, runner)` and returns the stored run.
There are no progress events, no job ids and no per-stage timestamps. The runner
issues one HTTPS request per call (`Connection: close`), and each check's status,
verdict and evidence hash are only meaningful once the run is stored.

**Options, in order of preference.**

1. **Observer hook + SSE (recommended, not built).** Add an optional
   `observer=` keyword to the internal `start_lab_bola_scan` function (the HTTP
   route keeps passing nothing) and wrap `TargetLabRunner.request` so each real
   request emits `{actor, method, path, status, at}`. A UI route would run the
   scan in a worker thread and stream those events as `text/event-stream`.
   This is genuine telemetry — every event is a request that already happened —
   and it touches neither the oracle, the guard, nor the stored schema. It needs:
   a new UI route, an SSE client in `app.js`, a no-JS fallback (today's POST →
   redirect), and tests proving the streamed sequence equals the stored checks.
2. **Job-status endpoint.** Same observer, polled every second. Simpler than SSE,
   but adds a job registry and a lifetime question (when is a job forgotten?).
3. **Recorded stages only (what shipped).** The execution view is rendered from
   the stored run: authentication, baselines, cross-account attempt, disclosure
   verification and the secure-route denial, each with its real status, verdict
   and evidence hash, and a banner that says the run is complete and this view is
   recorded, not streamed.

**Decision, revised.** Option 1 shipped, in its simplest honest form: the
transport takes an optional `observer` callback that is invoked *after* an exchange
completes, with the actor, method, path, the lab's status code and the measured
duration. `canarygate/ui/execution.py` runs an assessment on a worker thread with
that callback attached and exposes `GET /ui/execution/{job_id}/events?since=N`;
the page polls it and appends what arrived. No SSE was needed, and no percentage is
invented — every line in the feed is either a completed request or a boundary the
runner actually reached ("Pair 2 of 3", "stored").

The observer cannot influence a scan: it is called after the response is final,
its return value is ignored, its exceptions are swallowed, and it receives no
credential. `tests/lab/test_targetlab_observer.py` pins all three properties, and
`tests/integration/test_ui_lab_pages.py` proves the streamed request count equals
the stored run's `requests_sent` (18 for one pair, 54 for the demonstration).

The stored-run pages keep the recorded timeline as well, so the same evidence is
readable after the job has left memory.

## 4. Data-integrity rules enforced by this milestone

- Every account, asset, pair and role comes from `GET /api/lab-catalog`.
- Every verdict, status, hash and id on every new page comes from a stored run or
  the matrix payload; no template computes a verdict.
- Untested stays untested; `INCONCLUSIVE`/`SKIPPED` are never rendered as `SAFE`.
- The landing page makes no security claim about any system and contains no data.
- The workspace never starts a scan on page load; only explicit form posts do.
- Specification inspection is labelled "inventory only — no security scan
  performed" wherever it appears.

## 5. Migration and verification

Routes are additive; the only behavioural change to an existing route is `/`,
which now renders the landing page instead of redirecting to `/ui/`. Links from
the landing page go to `/ui/`, so the old entry point still works in one click.

Verification for this milestone: full pytest, `tools/p0_audit.py`,
`tools/browser_smoke.py` (jsdom), `tools/demo.py`, `tools/consistency_audit.py`,
CI on ubuntu-latest and windows-latest, and the live preview on port 8000.

## 6. Known limits of this milestone

- No live progress; see §3 for the two credible mechanisms and why neither is
  shipped yet.
- No per-endpoint finding aggregation or historical chart: the backend has no
  endpoint that answers those questions, and inventing one in the template would
  violate the "no frontend verdict" rule.
- Motion is CSS/SVG only; jsdom cannot verify visual rendering, so the cinematic
  sequence is verified structurally (elements present, reduced-motion rules
  present, skip control present) and by a human looking at the preview.
