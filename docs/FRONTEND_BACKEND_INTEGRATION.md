# Frontend and backend integration

Status: **integrated and verified on this branch** (`arena/80050ed6-hackfusion-30102026`).
The interface from `arena/a1fe3757-hackfusion-30102026` is served by the checkpoint-38
backend, calls its handlers in the same process, and adds no security logic of its
own. 1017 tests passed at integration time (head after checkpoint 39: 1055); the P0
audit is clean at 58 rows / 63 test files / 0 failures.

| Question | Answer |
| --- | --- |
| Is the UI preserved? | Yes: same framework, layout, components, navigation, CSS and assets. Only connectivity, new pages for workflows the frontend predated, and copy that had become inaccurate were changed. |
| Are the results real? | Yes. Every verdict, count, status, hash and section on screen is read from a stored run through the backend's own handler. There is no mock data, no sample verdict and no "demo mode". |
| Is security logic duplicated? | No. The UI has no oracle, no policy, no transport and no `httpx`/`socket` import. It renders fields and links to backend artefacts. Two static tests enforce this. |
| Does the end-to-end flow work? | Yes: submit a scan from a page, land on the stored run, open its report and see the matrix update — without calling the API by hand. |
| Is anything faked? | No. Where the backend has no capability (BFLA, live targets, listing endpoints, severity) the UI says so instead of inventing it. |
| Is it release-verified? | CI green on Ubuntu and Windows at the PR head; the wheel installs and serves the UI from a clean venv; a DOM-level journey passes 17/17 against a real server and lab. Real-browser rendering is still unproven — see §14. |

---

## 1. What was reused, and what "preserved" means here

The frontend branch is a **server-rendered Jinja2 + vendored HTMX application**, not
a single-page app. There is no package manager, no bundler, no client-side router and
no `fetch()` call: pages are rendered on the server, and forms post to the same
process. This matters for the brief, which was written assuming a JS client and a
separate dev server. The integration keeps the actual design instead of replacing it.

Taken across unchanged in behaviour:

| Area | Files | Note |
| --- | --- | --- |
| Templates | `canarygate/ui/templates/**` (23 pages + 5 partials) | Layout, macros, page structure, navigation, banners |
| Styling | `canarygate/ui/static/css/app.css`, `replay.css` | Design tokens, dark theme, responsive and print rules |
| Behaviour | `canarygate/ui/static/js/app.js`, `replay.js` | Mobile nav, table filter, copy buttons, print, busy state |
| Vendored library | `static/vendor/htmx.min.js` + licence | No CDN, no external request |
| Replay engine | `canarygate/ui/replay.py` | Flight recorder for stored evidence |
| Routes | `canarygate/ui/routes.py` | Extended, not rewritten; every original route kept |
| Tests | `tests/integration/test_ui_pages.py`, `test_ui_replay_adapter.py` | Kept and extended (44 tests) |

Deliberate changes, all of them connectivity or accuracy:

1. **Nav** gained one entry (`TargetLab validation`) because three backend workflows
   (read-BOLA, control interaction, reset proof) had no page at all.
2. **Banner and footer** said "Fixture-only build". That stopped being true once the
   loopback lab is reachable, so they now say *offline + loopback lab, live scanning
   off* and name the two kinds of evidence separately. One assertion in
   `test_ui_pages.py` was updated to the new wording.
3. **Test suites** grew from two families to four (validation and interaction were
   added), with a stored-run list per family.
4. **Reports** lists stored runs for all six families alongside the existing
   open-by-id form, because the UI can enumerate the local stores server-side.
5. **Matrix** gained the backend's real authorization matrix next to the existing
   fixture grid, including its five cell states and `source_ref` provenance.

Nothing was redesigned: no new colour, type, spacing or component vocabulary. The
only CSS added is 16 lines at the end of `app.css`, giving the backend matrix's five
cell states a tint from the existing tokens. `app.js`, `replay.js` and
`replay.css` are byte-identical to the frontend branch.

## 2. How the two sides are joined

```
browser ──HTTP──► FastAPI app (one process)
                    ├── /api/*   JSON handlers (unchanged contract)
                    ├── /ui/*    HTML router  ── calls the same Python handlers
                    └── /ui/static/*  local CSS/JS/HTMX
```

`canarygate/ui/app.py` calls `canarygate.api.app.create_app()` and then mounts a
static directory and one router:

```python
application = create_backend_app(database_path) if database_path else create_backend_app()
application.mount("/ui/static", StaticFiles(directory=STATIC_ROOT), name="ui-static")
application.include_router(ui_router)
```

Consequences that the integration relies on:

- **Same origin.** The browser talks only to this app, so no CORS middleware is
  needed and none was added. The existing app registers no middleware at all; adding
  a permissive one would have widened an unauthenticated local server for no reason.
- **Same stores.** `create_app` puts nine stores on `app.state`; the UI reads them
  exactly like the JSON routes do (`_store(request, kind)`).
- **Same handlers.** `canarygate/ui/routes.py` imports `canarygate.api.app` and calls
  `health()`, `endpoints()`, `setup_status()`, `findings()`, `scan()`,
  `matrix()`, `authorization_matrix()`, the per-family scan and report handlers
  named in the `SUITE_FAMILIES` / `LAB_FAMILIES` tables, and the nine `start_*`
  functions the forms post to. There is one implementation of every rule.
- **Same database.** `CANARYGATE_DB_PATH` (or the default `.canarygate/fixture.sqlite3`)
  configures both surfaces; nothing is duplicated.
- **Backend entrypoint still works alone.** `python -m uvicorn canarygate.api.app:app`
  serves JSON only and 404s `/ui/`.

### Why there is no frontend "API client layer"

The brief asked for a centralised communication layer with a base URL, timeouts and
service modules. In a server-rendered app those responsibilities already sit in one
place — the adapter module `canarygate/ui/routes.py`:

| Concern | Where it lives |
| --- | --- |
| Base URL / origin | not applicable: calls are in-process function calls |
| Transport, timeouts | the backend's own transport (guarded HTTPX) — the UI never opens a socket |
| Response parsing | handler return values (pydantic models) or `JSONResponse` decoded in `_sections()` |
| Error normalisation | `_guard()` → HTML error page with the backend's status code and detail |
| Service functions | `SUITE_FAMILIES` / `LAB_FAMILIES` tables + `_suite_run`, `_lab_run`, `_lab_sections`, `_suite_sections` |
| Types | the backend's pydantic models; the UI adds `_Record`, a dict that renders missing optional keys as empty |

Adding a JS `fetch()` layer would have meant a second HTTP hop, a second origin and a
second error model for no benefit, and would have moved validation into the browser.
The forms validate only what the user types (port range, scenario id, document size);
every security decision stays behind the handler boundary.

## 3. API inventory and its UI consumer

34 method+path operations are public JSON. `UI` below names the page or action that
uses each one; `—` means no page uses it, and the reason is in §9.

| Method | Route | Purpose | UI consumer |
| --- | --- | --- | --- |
| GET | `/api/health` | mode + `live_scanning=false` | dashboard stat |
| POST | `/api/spec/upload` | inspect an OpenAPI document in memory | — (the UI calls the same parser directly from `/ui/spec`, see §9) |
| GET | `/api/endpoints` | fixture inventory with provenance | `/ui/endpoints`, `/ui/matrix`, dashboard |
| GET | `/api/setup/status` | last setup gates | `/ui/setup`, dashboard |
| POST | `/api/scan` | run the bundled fixture | dashboard "Run fixture scan" |
| GET | `/api/scan/{id}` | one fixture run | `/ui/scans/{id}`, evidence, replay, report |
| GET | `/api/scan/{id}/observations` | minimized ownership observations | `/ui/scans/{id}/evidence`, replay |
| GET | `/api/findings` | all fixture runs | dashboard, `/ui/scans`, `/ui/findings` |
| GET | `/api/matrix` | fixture-derived cells | `/ui/matrix` (grid + recorded cells) |
| GET | `/api/reports/{id}` | fixture report (run / sections / bundle / HTML) | `/ui/scans/{id}/report`, `/ui/reports` links |
| POST | `/api/scenario-scans` | read-BOLA transcript run | `/ui/suites` → `/ui/suites/read-bola/{id}` |
| GET | `/api/scenario-scans/{id}` | one scenario run | suite detail, replay, report |
| GET | `/api/scenario-scans/{id}/report` | its sections / HTML / P0 | `/ui/suites/read-bola/{id}/report` |
| POST | `/api/authentication-scans` | authentication transcript run | `/ui/suites` → detail |
| GET | `/api/authentication-scans/{id}` | one authentication run | suite detail, replay, report |
| GET | `/api/authentication-scans/{id}/report` | sections / HTML / P0 | `/ui/suites/authentication/{id}/report` |
| POST | `/api/validation-scans` | input/disclosure transcript run | `/ui/suites` → detail |
| GET | `/api/validation-scans/{id}` | one validation run | suite detail, replay, report |
| GET | `/api/validation-scans/{id}/report` | sections / HTML / P0 | `/ui/suites/validation/{id}/report` |
| POST | `/api/interaction-scans` | offline SCI run | `/ui/suites` → detail |
| GET | `/api/interaction-scans/{id}` | one SCI run | suite detail, replay, report |
| GET | `/api/interaction-scans/{id}/report` | sections / HTML / P0 | `/ui/suites/interaction/{id}/report` |
| POST | `/api/lab-scans` | CP34 lab evidence workflow | — (superseded by the two focus workflows, §9) |
| GET | `/api/lab-scans/{id}` | one lab run | — |
| GET | `/api/lab-scans/{id}/report` | sections / HTML | — |
| POST | `/api/lab-bola-scans` | real HTTPS read-BOLA on the lab | `/ui/lab` form → `/ui/lab/bola/{id}` |
| GET | `/api/lab-bola-scans/{id}` | one lab read-BOLA run | lab detail page, dashboard |
| GET | `/api/lab-bola-scans/{id}/report` | sections / HTML / P0 | `/ui/lab/bola/{id}/report` |
| POST | `/api/lab-sci-scans` | real HTTPS SCI on the lab | `/ui/lab` form → `/ui/lab/sci/{id}` |
| GET | `/api/lab-sci-scans/{id}` | one lab SCI run | lab detail page, dashboard |
| GET | `/api/lab-sci-scans/{id}/report` | sections / HTML / P0 (with `reset=`) | `/ui/lab/sci/{id}/report` |
| POST | `/api/lab-sci-resets` | separate two-runner reset proof | `/ui/lab` form → `/ui/lab/reset/{id}` |
| GET | `/api/lab-sci-resets/{proof_id}` | one reset proof | reset proof page |
| GET | `/api/authorization-matrix` | partial coverage over stored runs | `/ui/matrix` ("Backend authorization matrix") |

### UI routes added or extended (30 in total)

| Route | Kind | Backend call |
| --- | --- | --- |
| `GET /ui/` | page | `health`, `endpoints`, `setup_status`, `findings`, three lab stores |
| `GET /ui/endpoints`, `/ui/setup`, `/ui/scans`, `/ui/scans/{id}`, `/ui/scans/{id}/evidence`, `/ui/scans/{id}/replay`, `/ui/scans/{id}/report` | pages | unchanged from the frontend branch |
| `GET /ui/findings`, `/ui/configure`, `/ui/spec`, `/ui/static/*` | pages / assets | unchanged |
| `GET /ui/suites` | page | all four suite stores (lists) + registries |
| `GET /ui/suites/{family}/{id}` | page | `scenario_scan` / `authentication_scan` / `validation_scan` / `interaction_scan` |
| `GET /ui/suites/{family}/{id}/replay` | page | `build_replay(family, run)` |
| `GET /ui/suites/{family}/{id}/report` | page | `*_report(view="sections")` |
| `GET /ui/lab` | page | three lab stores + CA readiness |
| `GET /ui/lab/{family}/{id}` | page | `lab_bola_scan` / `lab_sci_scan` / `lab_sci_reset` |
| `GET /ui/lab/{family}/{id}/report` | page | `lab_bola_report` / `lab_sci_report` (sections); the reset family has no section report, so `/ui/lab/reset/{id}/report` is a 404 |
| `GET /ui/reports` | page | fixture runs + four suite stores + three lab stores |
| `GET /ui/reports/lookup` | redirect | validates a UUID, then 303s to the family page |
| `POST /ui/actions/fixture-scan` | action | `start_scan` |
| `POST /ui/actions/scenario-scan`, `…/authentication-scan`, `…/validation-scan`, `…/interaction-scan` | actions | the four `start_*_scan` handlers |
| `POST /ui/actions/lab-bola-scan`, `…/lab-sci-scan`, `…/lab-sci-reset` | actions | `start_lab_bola_scan`, `start_lab_sci_scan`, `start_lab_sci_reset` |
| `POST /ui/actions/spec-inspect` | action | `parse_inventory` (in memory, nothing persisted) |

Every action also works without JavaScript (plain POST → 303 → page). With HTMX it
returns a fragment instead. No action route accepts a host, path, credential or
expected verdict.

## 4. Configuration

The application reads two environment variables. There is no `.env` loader and no
secret in the repository; `.env.example` documents them for copy/paste.

| Variable | Used by | Effect when absent |
| --- | --- | --- |
| `CANARYGATE_DB_PATH` | `create_app` | defaults to `.canarygate/fixture.sqlite3` |
| `CANARYGATE_TARGETLAB_CA` | lab routes only | every lab scan returns **400** and stores nothing; the UI shows the refusal |

What is deliberately **not** configured from the browser: the target host, the port
allow-list, accounts, credentials, the spec, the recipe, any budget beyond the
bounds the models already declare (BOLA 16–40, SCI 8–40), or the verdict. All of it
is built by the backend from the validated scope.

## 5. Workflows, page by page

| Workflow (brief §6) | Where | What actually happens |
| --- | --- | --- |
| A. Dashboard | `/ui/` | health (`mode=fixture`, `live_scanning=false`), endpoint count, stored run count, readiness gates, verdict distribution, five recent runs, and the latest loopback verdicts per lab workflow. No sample numbers; empty states say "not recorded". |
| B. Scan configuration | `/ui/configure`, `/ui/suites`, `/ui/lab` | The only configurable inputs are the ones the models accept: a bundled scenario id (a dropdown from the registry) and a lab port (1024–65535), plus the optional request budget the models already bound (BOLA 16–40, default 20; SCI 8–40, default 16). `/ui/configure` shows the bundled scope/recipe/spec read-only, with secrets redacted. |
| C. BOLA scanning | `/ui/lab` → `/ui/lab/bola/{id}` | POSTs the port to `/ui/actions/lab-bola-scan`; the backend builds the plan, runs six checks over real HTTPS, and stores the run. The page shows each check's id, direction, actor→owner, endpoint, HTTP status, verdict, reason and evidence hash; the summary counts; the 10-key checklist; transport; constraints; ground truth scored after the verdicts; limitations. |
| D. SCI scanning | `/ui/lab` → `/ui/lab/sci/{id}` | Same pattern: both control baselines with their own verdicts and statuses (403, 401), the combined action (200, `private_data`), the attribution (`interaction_induced`), the eight-key checklist, ownership/disclosure evidence, and links to reset proofs on the same port. The 403→401→200 sequence is read from stored evidence; the page never writes it itself. |
| E. Lab validation restrictions | `/ui/lab`, `/ui/lab/reset/{id}` | The browser posts a port; the app performs the guarded requests with a pinned test CA to `127.0.0.1`. The lab's passwords, tokens and private markers never reach the browser (asserted in three tests). A missing CA is a 400 page; an unreachable lab is a 502 page and stores nothing. |
| F. Scan results | `/ui/scans`, `/ui/suites/{family}/{id}`, `/ui/lab/*`, `/ui/findings` | Consistent shape: id, family, timestamp, mode, verdict or status, per-check rows, evidence summaries, request accounting, limitations. All five verdicts render with distinct badges; `SKIPPED` and `INCONCLUSIVE` never look like `SAFE`. |
| G. Reports | `/ui/**/report`, `/ui/reports` | The in-app view renders the backend's own nine-section projection (`?view=sections`) for all six families; every page links to the backend's HTML and JSON (`view=run`, `view=sections`, `view=p0` where supported). |
| H. Authorization matrix | `/ui/matrix` | Two tables: the backend's authorization matrix (rows × `anonymous/own_resource/other_account_resource/role`, five states, `source_ref` per cell, coverage statement, by-state counts) and the fixture-run grid. Untested cells read "not tested"/"not assessed" and are hatched; none is ever rendered as SAFE. |

## 6. Feature connectivity audit

Statuses: **COMPLETE** (exists, connected, tested), **PARTIAL** (connected with a
stated limitation), **NOT CONNECTED** (exists in the backend but no UI path),
**NOT SUPPORTED** (no backend capability).

| Feature | UI exists | Backend API exists | Connected | Tested | Status |
| --- | --- | --- | --- | --- | --- |
| Health / mode on dashboard | yes | `GET /api/health` | yes | yes | COMPLETE |
| Fixture scan button | yes | `POST /api/scan` | yes | yes | COMPLETE |
| Fixture run list, detail, evidence, replay | yes | `/api/findings`, `/api/scan/{id}`, `/observations` | yes | yes | COMPLETE |
| Fixture nine-section report + HTML/JSON | yes | `GET /api/reports/{id}` | yes | yes | COMPLETE |
| Read-BOLA scenario scan | yes | `POST /api/scenario-scans` | yes | yes | COMPLETE |
| Authentication scenario scan | yes | `POST /api/authentication-scans` | yes | yes | COMPLETE |
| Input/disclosure scenario scan | yes (new) | `POST /api/validation-scans` | yes | yes | COMPLETE |
| Control-interaction scenario scan | yes (new) | `POST /api/interaction-scans` | yes | yes | COMPLETE |
| Suite run listing per family | yes (new) | — (reads the store) | yes | yes | PARTIAL — enumerates the local store server-side; there is no JSON list endpoint |
| Lab read-BOLA scan | yes (new) | `POST /api/lab-bola-scans` | yes | yes | COMPLETE (loopback lab only) |
| Lab control-interaction scan | yes (new) | `POST /api/lab-sci-scans` | yes | yes | COMPLETE (loopback lab only) |
| Reset proof | yes (new) | `POST /api/lab-sci-resets` | yes | yes | COMPLETE (separate two-runner scenario) |
| Lab detail pages with transport + constraints | yes (new) | `GET /api/lab-*` | yes | yes | COMPLETE |
| Lab section reports | yes (new) | `…/report?view=sections` | yes | yes | COMPLETE |
| Backend authorization matrix | yes (new) | `GET /api/authorization-matrix` | yes | yes | COMPLETE |
| Fixture matrix grid | yes | `GET /api/matrix` | yes | yes | COMPLETE (fixture runs only, says so) |
| Findings list | yes | `GET /api/findings` | yes | yes | COMPLETE |
| Endpoint inventory | yes | `GET /api/endpoints` | yes | yes | COMPLETE |
| Setup/readiness | yes | `GET /api/setup/status` | yes | yes | COMPLETE |
| Spec inspection | yes | `POST /api/spec/upload` equivalent parser | yes | yes | PARTIAL — inventory only, nothing persisted, cannot drive a scan |
| Bundled configuration view | yes | — (reads package files) | yes | yes | PARTIAL — read-only by design |
| CP34 lab evidence workflow | no | `POST /api/lab-scans` | no | backend only | NOT CONNECTED — superseded by the two focus workflows |
| BFLA role vs policy | no | no | no | — | NOT SUPPORTED (`D11` missing) |
| Live/organizer target scanning | no | no (production transport disabled) | no | — | NOT SUPPORTED (`D12` missing) |
| Severity / CVSS ranking | no | no | no | — | NOT SUPPORTED |
| Async job progress / cancel | no | no | no | — | NOT SUPPORTED — scans are synchronous |
| Authentication of the app itself | no | no | no | — | NOT SUPPORTED — local single-user server |

## 7. Backend changes, and why

The integration needed one class of change: **seven report endpoints declared a
response model that excluded the value they already returned.**

`GET /api/{scenario-scans,authentication-scans,validation-scans,interaction-scans,lab-scans,lab-bola-scans,lab-sci-scans}/{id}/report`
returns the stored run when `view=run` (the documented default) and a section
projection when `view=sections`. The handlers were correct; the annotations only
allowed the section model, so FastAPI rejected the run and answered **500**. Every
frontend that followed the documentation hit this on its first call.

```diff
-@router.get("/api/scenario-scans/{run_id}/report", response_model=ScenarioSectionReport, ...)
+@router.get("/api/scenario-scans/{run_id}/report",
+            response_model=ScenarioRun | ScenarioSectionReport, ...)
```

Nothing else in the backend changed: no verdict rule, oracle, guard, transport,
store, schema or route was touched. The evidence that the change is a fix rather
than a behaviour change:

- before: `GET …/report` → 500 `{"detail":"…"}`; `?view=sections` → 200; `?format=html` → 200
- after: `GET …/report` → 200 with `id` equal to the requested run; the other two unchanged
- regression: `tests/integration/test_ui_backend_contract.py::test_default_json_report_view_returns_the_run_for_every_family`
  covers all four offline families, `test_ui_lab_pages.py::test_default_json_report_view_still_serves_the_run`
  covers the lab family, and the CP38 demo/consistency checks still pass.

## 8. Testing

`1017 passed` on this branch at integration time (916 before it; 1055 at head after
checkpoint 39). The 101 UI tests are
registered with an evidence class in `tools/p0_audit.py`, so the audit fails if one
silently disappears.

| File | Tests | Environment (audit label) | What it proves |
| --- | --- | --- | --- |
| `tests/integration/test_ui_pages.py` | 28 | `in_process_api` | Every original page renders, actions store what the API returns, no credentials in HTML, HTMX fragments vs redirects, spec inspection bounded, replay behaviour, accessibility basics |
| `tests/integration/test_ui_replay_adapter.py` | 16 | `in_process_api` | The flight recorder orders real events and refuses to invent a timeline for transcript runs |
| `tests/integration/test_ui_backend_contract.py` | 33 | `in_process_api` | For all four offline families: action → stored run → page matches API; sections report matches API; default JSON view 200; matrix matches `/api/authorization-matrix`; listings; empty states; HTML errors; SKIPPED and INCONCLUSIVE keep their own badges, counted against the API; no verdict assignment in templates; no `httpx`/`socket`/`decide` in the UI |
| `tests/integration/test_ui_lab_pages.py` | 24 | `loopback_tls` | Real TLS lab: BOLA/SCI/reset pages show the API's verdicts and statuses; missing CA is 400; unreachable lab is 502 and stores nothing; invalid ports/budgets are 422; unknown ids are HTML 404; no lab secret in any page; dashboard/reports reflect stored runs |

What each kind of test does **not** prove:

- The 101 tests assert served HTML, not rendering in a real browser. There is no
  headless browser in this environment: no pixel regression, no screen-reader audit,
  no keyboard-only pass. The markup is server-rendered, so this covers content and
  structure, not visual correctness.
- `in_process_api` tests use FastAPI's `TestClient` against a temporary SQLite file:
  no socket, no real server, no latency.
- `loopback_tls` tests are real HTTPS **to our own lab**. They prove the wiring and
  the rendering; they say nothing about a live or organizer target.
- The suite cannot prove that the app is *useful* to a human, only that every control
  reaches the handler it claims to reach.

### Automated end-to-end proof

`tests/integration/test_ui_backend_contract.py` is the end-to-end test in this
architecture: it starts the real app, submits each form, follows the redirect, and
compares the page with the JSON API for the same run id. The loopback twin does the
same against the real TLS lab, and the CP38 demonstration
(`.venv/bin/python tools/demo.py`) still exercises four stages end to end with
`ALL CONSISTENCY CHECKS PASSED (73 invariants over 16 surfaces)`.

### Live two-process check

Both processes were started with exactly the commands in §10 and driven over real
HTTP, because a `TestClient` run cannot prove the entry point, the static mount or
uvicorn's startup:

| Step | Observed result |
| --- | --- |
| `GET /` | 307 → `/ui/` |
| 19 page, asset and JSON GETs (every page, both static bundles, `/api/authorization-matrix`, `/openapi.json`) | all 200, and **zero** `src`/`href` references to another origin |
| `POST /ui/actions/fixture-scan` | 303 → `/ui/scans/{id}`; the page, its report page and `/api/reports/{id}?view=run` all 200; report id equals the run id; verdict CONFIRMED, 22 checks |
| `POST /ui/actions/lab-bola-scan` on port 8765 | 303 → the stored run: six checks, 2 CONFIRMED / 4 SAFE, ground truth present, `production_networking: false` |
| `POST /ui/actions/lab-sci-scan` | 303 → CONFIRMED (`interaction_induced`); 403, 401 and 200 all present on the page |
| `POST /ui/actions/lab-sci-reset` | 303 → `proven`; RESET-01…04 = 403 / 401 / 200 / 403 |
| `GET /api/authorization-matrix` | `partial_offline`, 16 rows / 64 cells / 5 tested, hatched untested cells |
| Eight lab secrets (passwords, tokens, private markers, key header) | absent from every page fetched |
| Bad input | port 70000 → 422; a just-closed high port → 502 "no evidence was stored"; unknown run id and unknown family → 404 |
| HTMX | an `HX-Request` POST returns a 1.7 KB fragment with no `<!doctype>` |

`canarygate.demo` (the CLI that drives the documented JSON routes) also ran against
that same server and produced its HTML and JSON report links, so the interface and
the pre-existing CLI share one backend rather than competing.

## 9. What is still not connected, and why

| Item | Why it stays out |
| --- | --- |
| CP34 `/api/lab-scans` workflow | It is the earlier, coarser lab-evidence run. The two focus workflows (read-BOLA, control interaction) cover the same transport with sharper evidence; adding a third lab UI would multiply pages without adding proof. It remains available as JSON. |
| `POST /api/spec/upload` | The UI uses the same `parse_inventory` function directly (so the document never leaves the process). An uploaded document cannot configure or start a scan — that is a backend capability gap, not a UI omission. |
| List endpoints for suite/lab runs | The JSON API has none. The UI enumerates the local stores server-side and says so on the page; it does not claim an endpoint. |
| BFLA, live targets, severity, async jobs, app authentication | No backend capability. The UI must not invent them. `D11` and `D12` remain **missing** in the audit. |
| CSRF protection | No cookies, no sessions, no authentication: the server is local and single-user. Adding CSRF belongs with any future authentication work, not before it. |
| Browser-level E2E (Playwright) | Not available in this environment; the 3 acceptance checks in §11 are the manual substitute. |

## 10. Running the complete application

Two terminals; the lab is a separate process because it is a separate program.

**Terminal 1 — the deliberately vulnerable loopback lab (only needed for lab scans):**

```bash
.venv/bin/python -m targetlab --port 8765 \
    --tls-cert tests/fixtures/tls/targetlab-cert.pem \
    --tls-key tests/fixtures/tls/targetlab-key.pem
# targetlab: DELIBERATELY VULNERABLE test API on https://127.0.0.1:8765 (loopback only, do not deploy)
```

**Terminal 2 — the application (UI + JSON API in one process):**

```bash
# Linux / macOS
CANARYGATE_TARGETLAB_CA=tests/fixtures/tls/targetlab-cert.pem \
CANARYGATE_DB_PATH=.canarygate/canarygate.sqlite3 \
.venv/bin/python -m uvicorn canarygate.ui.app:app --host 127.0.0.1 --port 8000
```

```powershell
# Windows PowerShell
$env:CANARYGATE_TARGETLAB_CA = "tests/fixtures/tls/targetlab-cert.pem"
$env:CANARYGATE_DB_PATH = ".canarygate/canarygate.sqlite3"
.\.venv\Scripts\python.exe -m uvicorn canarygate.ui.app:app --host 127.0.0.1 --port 8000
```

Open **http://127.0.0.1:8000/ui/**. The port in the lab forms must be the port
TargetLab is listening on (8765 above).

A first run, in order: Dashboard → **Run fixture scan** → open the run, its evidence
and its report → **Test suites** → run one scenario from each family
(`synthetic-vulnerable`, `synthetic-jwt-sub-confirmed`,
`synthetic-validation-weak`, `synthetic-sci-authz-input-confirmed`) →
**TargetLab validation** → enter `8765` and run read-BOLA, then control interaction,
then the reset proof → **Authorization matrix** → **Reports**.

One-command alternatives that need no terminals:

```bash
.venv/bin/python tools/demo.py          # four stages, own lab, fresh database, consistency checks
.venv/bin/python -m canarygate.demo     # drives the documented API routes
```

The server is local-only and unauthenticated. Do not bind it to a public interface,
do not put it behind a shared proxy, and do not present fixture, transcript or
loopback results as live-target findings.

## 11. The three checks a reviewer should run

**1. No fake results.** Every verdict on screen traces to a stored run.

```bash
# No template may hard-code or derive a verdict; no 200 may become a result.
.venv/bin/python -m pytest tests/integration/test_ui_backend_contract.py \
    -k "never_assign or never_make_network or renders_the_api_outcome" -v

# Manually: run a scan twice, then compare the page with the API.
.venv/bin/python tools/demo.py --keep      # prints the database path
```

**2. No duplicated security logic.** The UI cannot decide anything:

```bash
# Fails loudly if the UI ever imports a client, opens a socket or grows a decide().
.venv/bin/python -m pytest tests/integration/test_ui_backend_contract.py \
    -k "never_assign or never_make_network" -v

# The same check by hand: one match, and it is a docstring sentence about the lab.
grep -rn "httpx\|socket\|def decide" canarygate/ui/routes.py
```

**3. Real end-to-end execution.** With both terminals running: open `/ui/`, click
**Run fixture scan**, land on `/ui/scans/{id}`, open the report, then run a TargetLab
workflow and see its verdict, evidence and report — no `curl`, no API call by hand.

## 12. Commit history of the integration

| Commit | Contents |
| --- | --- |
| `ed237db` | Import the frontend branch's UI (`canarygate/ui/**`, `docs/UI.md`, its two test files) and connect every stored workflow; widen the seven report response models |
| `d61f3b0` | This document, `.env.example`, the `docs/UI.md` update, the `canarygate.ui` package data that lets a built wheel serve the UI, the README and demo-walkthrough corrections, and the two structural accessibility tests for the pages the integration added |

Reviewable as **PR #4** against `main`. The frontend branch is untouched and remains
the recovery point; nothing was merged into it, reset or force-pushed, and this
branch was pushed as a new branch rather than rewritten.

## 13. Limitations, stated once

1. The interface is local and unauthenticated. Anyone who can reach the port can run
   a scan; the pages say so.
2. Lab workflows require a separately started TargetLab and a CA path. Without them
   the UI refuses with a 400/502 page rather than pretending to scan.
3. Scans are synchronous. `hx-disabled-elt` disables the submit button while a
   request is in flight, so a double click cannot start two runs in a browser with
   JavaScript. Without JavaScript a double submit stores two runs: there is no
   server-side de-duplication, no job queue and no cancel. That is stated rather
   than papered over.
4. There is no browser-rendering test. The visual design is the collaborator's and was
   not changed; correctness here means content, not pixels.
5. The UI inherits the backend's honesty limits: nine partial requirements and two
   missing ones (`D11` BFLA, `D12` live validation). No page suggests otherwise.
6. The matrix's `role` column only reflects what a role probe actually observed; it is
   not a BFLA assessment.

## 14. Release readiness

Feature work is frozen. Each row below is a check a reviewer can repeat.

| Check | Result | How |
| --- | --- | --- |
| CI on the PR head | **green on both jobs** — `tests (ubuntu-latest, 3.11)` and `tests (windows-latest, 3.11)` completed success on `a589ba0` | checks tab of PR #4 |
| Full local suite | 1055 passed | `.venv/bin/python -m pytest tests -q` |
| Requirement audit | 58 rows, 0 failures; 47 implemented · 9 partial · 2 missing · 0 unreachable | `.venv/bin/python tools/p0_audit.py` |
| Clean installation | wheel built and installed into a fresh venv outside the repo; UI and API launched from `site-packages` and served every page, both static bundles and the JSON API; a form scan stored a run whose page, report and `?view=run` JSON all answered 200; a lab scan without a CA answered 400 | commands below |
| Browser-level journey | **17/17** checks in a DOM with scripts and HTMX, against a real uvicorn server and the real TLS lab | `.venv/bin/python tools/browser_smoke.py --jsdom /tmp/browser-harness` |
| Demo rehearsal from clean state | `ALL CONSISTENCY CHECKS PASSED (73 invariants over 16 surfaces)` | `.venv/bin/python tools/demo.py` |

### Clean installation

```bash
.venv/bin/python -m pip wheel . --no-deps -w /tmp/wheel
python3 -m venv /tmp/clean-venv
/tmp/clean-venv/bin/pip install /tmp/wheel/canarygate-0.1.0-py3-none-any.whl
cd /tmp && CANARYGATE_DB_PATH=/tmp/clean.sqlite3 \
  /tmp/clean-venv/bin/python -m uvicorn canarygate.ui.app:app --host 127.0.0.1 --port 8100
```

What that proved, beyond "it starts": the wheel carries 40 `canarygate/ui` files, so
templates, CSS and the vendored HTMX load from `site-packages` rather than the
source tree; the packaged app serves `/ui/`, `/ui/lab`, `/ui/matrix`, both static
bundles, `/api/health` and `/openapi.json`; and the lab refusal is intact in the
wheel (400, nothing stored). **The wheel deliberately does not ship `targetlab`** —
a deliberately vulnerable test API does not belong in an installed product, so lab
workflows run from a source checkout. Before this branch the wheel shipped no
interface at all.

### Browser-level journey

`tools/browser_smoke.py` starts its own TargetLab and app on free ports, drives the
real pages in jsdom with scripts enabled, and then compares the DOM with what the
API stored. It checks:

* the dashboard renders, the local-evidence banner is present, no `src`/`href`
  points at another origin, and htmx 2.0.4 has initialised;
* the page's own JavaScript runs: the nav toggle flips `aria-expanded` true → false,
  and the endpoint table filter hides all four non-matching rows;
* the fixture form posts through HTMX, the returned fragment swaps into
  `#scan-panel`, and the link it produces opens a stored run whose report page the
  browser then loads;
* the three TargetLab forms post through HTMX and the pages they lead to carry all
  six `LAB-BOLA` ids, a summary **equal** to `/api/lab-bola-scans/{id}`'s summary,
  the SCI evidence at 403 / 401 / 200 with `interaction_induced`, and `proven` with
  RESET-01…04;
* the matrix page shows partial coverage and all four column labels;
* no page emits a script error.

Limits, stated plainly: jsdom has no layout or paint step, so this proves script
execution, DOM state, HTMX round-trips and link wiring — not pixels, CSS cascade,
focus rings or print output. A real browser is not installable in this environment:
there is no Chromium or Firefox binary, `libnss3`, `libnspr4`, `libnssutil3`,
`libatk-1.0` and `libcups` are absent, and there is no root to install them. The
script treats a missing node/jsdom as "cannot run here" (exit 2 with instructions),
never as a pass.

### What remains unproven

1. Rendering, layout, focus and print across real browsers.
2. Detection against any API the team did not write (`D12`).
3. BFLA (`D11`).
4. Concurrency: the server is single-user, scans are synchronous, and nothing has
   been load-tested or run in parallel.
5. Anything about a deployed environment — there is no authentication, no TLS
   termination and no CSRF protection, by design and by statement.
