# Local frontend (Jinja2 + vendored HTMX)

This document is the frontend handoff for the current backend checkpoint. It
describes what the UI does, which backend route feeds every number on every page,
what is deliberately missing, and which backend contracts would be needed to go
further. Nothing here changes the backend's security posture: the API remains
unauthenticated, fixture-only and local.

The UI is a **view layer**. It owns no findings, no verdicts and no sample data.
If the backend cannot establish something, the page says so.

---

## 1. What exists now

| Layer | Implementation | Notes |
| --- | --- | --- |
| Rendering | Jinja2 server-side templates | No client-side framework, no build step, no bundler |
| Interactions | Vendored HTMX 2.0.4 (`canarygate/ui/static/vendor/htmx.min.js`) | Every action also works as a plain form POST without JavaScript |
| Styling | Hand-written CSS (`static/css/app.css`) | Dark console theme, responsive, print styles |
| Behaviour | ~120 lines of vanilla JS (`static/js/app.js`) | Mobile nav, table filter, file-into-textarea, busy/error feedback |
| Assets | Served by the app itself at `/ui/static/...` | No CDN, no web fonts, no analytics, no external requests |
| Data | `canarygate.api.app` handlers called **in-process** | The UI never re-implements a verdict or a counter |

Pages: dashboard, endpoint inventory, setup & readiness, read-BOLA scan list, scan
detail, evidence/observations, authorization matrix, reports, test suites, suite
run detail, spec inspection, error page. The UI is mounted at `/ui/`; `/`
redirects there.

## 2. File map

```
canarygate/ui/
├── __init__.py            # package docstring only
├── routes.py              # HTML routes, form actions, view helpers
├── templating.py          # Jinja2 environment, filters (verdict/status badges, JSON, tri-state)
├── templates/
│   ├── base.html          # shell: banner, navigation, footer, local assets
│   ├── _macros.html       # badges, key/value rows, evidence card, constraints panel, report links
│   ├── dashboard.html     # health, gates, latest verdict, verdict distribution, recent runs
│   ├── endpoints.html     # inventory: expected access + provenance + declared auth
│   ├── setup.html         # three readiness gates + account states + BOLA coverage
│   ├── scans.html         # stored fixture runs (Verifiable list from /api/findings)
│   ├── scan_detail.html   # verdict, two-part evidence, 10-key checklist, checks, constraints
│   ├── evidence.html      # minimized observations behind the verdict
│   ├── matrix.html        # run-derived authorization cells
│   ├── reports.html       # links to backend-generated HTML/JSON reports
│   ├── suites.html        # read-BOLA + authentication scenario runners
│   ├── suite_run.html     # scenario run / authentication run detail
│   ├── spec.html          # in-memory OpenAPI inspection
│   ├── error.html         # HTML error page (real HTTP status, no JSON body in the page)
│   └── partials/          # HTMX fragments: fixtures scan result, suite result, spec result, error
└── static/
    ├── css/app.css
    ├── js/app.js
    └── vendor/htmx.min.js, vendor/htmx.LICENSE
```

The only change outside `canarygate/ui/` is four lines inside `create_app()` in
`canarygate/api/app.py`:

```python
from canarygate.ui.routes import router as ui_router
from canarygate.ui.templating import STATIC_ROOT
application.mount("/ui/static", StaticFiles(directory=STATIC_ROOT), name="ui-static")
application.include_router(ui_router)
```

The import is inside the function on purpose. `canarygate/ui/routes.py` imports
`canarygate.api.app` lazily (one helper, `_api()`), so the UI can call the API
handlers without a circular import at module load time.

## 3. How the UI talks to the backend

The UI runs inside the same process as the JSON API. A page handler does not make
an HTTP request to itself; it calls the route handler function, passing the same
`store` objects the API would inject:

```python
def _runs(request):
    return _api().findings(store=request.app.state.store)["findings"]
```

Why this shape:

* **One source of truth.** `start_scan`, `scenario_scan`, `matrix`, `findings`
  etc. are the API. If their behaviour changes, the UI changes with them. If a
  handler is renamed, the UI fails loudly in tests instead of silently drifting.
* **No duplicated orchestration.** The UI never decides when to run an oracle,
  how to classify a verdict or which counters to show; it renders the returned
  objects.
* **No hidden network.** No loopback HTTP calls, no second port, no proxy config.

Trade-off: the UI is coupled to Python handler signatures rather than to HTTP.
That is acceptable for a local, single-process tool; if the UI ever moves to a
separate deployment, replace `_api()` with an HTTP client and keep the same
view-model code.

### Status-code handling

| Backend result | UI behaviour |
| --- | --- |
| 200 / 201 | Render the page (or HTMX fragment) |
| 404 (`unknown run`, unknown scenario id) | HTML error page with HTTP 404, or a red inline fragment |
| 422 (invalid selection / bad spec) | HTML error page with HTTP 422 |
| 413 (oversized document) | HTML error page with HTTP 413 |
| 415 (wrong content type) | HTML error page with HTTP 415 |
| 500 (`integrity verification`, `storage unavailable`) | HTML error page with HTTP 500 explaining that the backend refused to use a corrupt record |

`_page(..., http_status=...)` sets the real response status, so an error page is
never served as a misleading 200. Unexpected exceptions are not swallowed: they
surface as a server error and stay visible in logs.

### Actions and progressive enhancement

| Action route | Backend caller | Without JS | With HTMX |
| --- | --- | --- | --- |
| `POST /ui/actions/fixture-scan` | `api.start_scan` | 303 → `/ui/scans/{id}` | fragment in `#scan-panel` |
| `POST /ui/actions/scenario-scan` | `api.start_scenario_scan` | 303 → `/ui/suites/read-bola/{id}` | fragment in `#suite-panel` |
| `POST /ui/actions/authentication-scan` | `api.start_authentication_scan` | 303 → `/ui/suites/authentication/{id}` | fragment in `#suite-panel` |
| `POST /ui/actions/spec-inspect` | `spec.parser.parse_inventory` | full `/ui/spec` page with result | fragment in `#spec-panel` |
| `GET /ui/reports/lookup` | — (validates then redirects) | 303 to the suite run | same |

Forms are parsed by `_form_fields()` in `routes.py`, which reads a urlencoded body
directly. That avoids adding `python-multipart` as a dependency; the body is
capped at 384 KiB and the document itself at the parser's 128 KiB limit.

## 4. Page-by-page map

| Page | Purpose | Data displayed | Backend route(s) | Actions | Error / empty states |
| --- | --- | --- | --- | --- | --- |
| `/ui/` dashboard | One-screen truth about the backend | health, endpoint count, stored run count, readiness gates, latest verdict + reason, verdict distribution, 5 recent runs | `GET /api/health`, `GET /api/endpoints`, `GET /api/setup/status`, `GET /api/findings` | run fixture scan | "No fixture scan has been recorded yet", "No verdict yet", "No stored runs" |
| `/ui/endpoints` | Inventory with expected access and provenance | method, path, expected access, source, declared auth requirement, parameters | `GET /api/endpoints` | — (link to spec inspection) | "The inventory is empty" |
| `/ui/setup` | Readiness and what blocks a verdict | strategy, per-account authentication, resources, ownership verification, BOLA coverage, reason | `GET /api/setup/status` | run fixture scan | "Setup has not been evaluated"; warn banner when a gate is not SUCCESS |
| `/ui/scans` | Stored fixture runs | per run: time, endpoint, actor, target, verified owner, expected access, ownership gate, verdict | `GET /api/findings` | run fixture scan, filter table | "No fixture run stored yet" |
| `/ui/scans/{id}` | The evidence page for one run | verdict + reason, remediation, run metadata, expected access vs outcome, setup gates, ownership evidence, disclosure evidence, 10-key checklist, all checks, constraint counters, inventory snapshot | `GET /api/scan/{id}` | open backend report, open observations | 404 page; "Checklist not recorded for this run"; "No evidence was recorded for this part" |
| `/ui/scans/{id}/evidence` | Minimized observations behind the verdict | coverage, per-observation phase/actor/request/response summary/assertions/SHA-256 | `GET /api/scan/{id}/observations` | JSON bundle | `NOT_RECORDED` banner; "No observations to show" |
| `/ui/matrix` | Run-derived authorization cells | endpoint, actor, target, expected access + source, verdict, run link | `GET /api/matrix` | — | "The matrix is empty" + explicit "partial matrix" warning |
| `/ui/reports` | Canonical reports | stored runs with links to HTML, JSON run, JSON sections, JSON + observations | `GET /api/findings` (links go to `/api/reports/...`) | open suite run by id | "No reports yet"; documented missing list endpoints |
| `/ui/suites` | Bundled offline transcripts | scenario ids from backend registries (auth titles come from the plans) | `POST /api/scenario-scans`, `POST /api/authentication-scans` | run read-BOLA / authentication scenario | inline 404/422 fragment; empty catalog state |
| `/ui/suites/read-bola/{id}` | Scenario detail | verdict, reason, remediation, scope, recipe, policy, both evidence parts, 10-key checklist, constraints, inventory, limitations | `GET /api/scenario-scans/{id}` | backend HTML/JSON report | 404 page; "No evidence recorded for this phase" |
| `/ui/suites/authentication/{id}` | Authentication detail | title, scheme, `claims_unverified`, `signature_verification`, summary counts, all 8 checks with evidence, scope, constraints, limitations | `GET /api/authentication-scans/{id}` | backend HTML/JSON report | 404 page; SKIPPED checks show their reason |
| `/ui/spec` | Inspect an OpenAPI document without scanning | document SHA-256, endpoint count, inventory with expected access/provenance | in-memory `parse_inventory` (same subset parser as `POST /api/spec/upload`) | paste or load file, inspect | 422 invalid, 413 too large, 415 wrong type |

## 5. Honesty rules encoded in the UI

1. Every page carries the fixture banner and the footer states
   `backend mode fixture · live scanning disabled`.
2. No page invents a finding, a score, a percentage or a verdict. Verdict names
   appear only where the backend returned them (the dashboard legend lists the
   five possible labels with zero counts — they are labels, not results).
3. `SKIPPED` is rendered as "not tested", with its backend reason. `INCONCLUSIVE`
   is never folded into `SAFE`.
4. `NOT_RECORDED` observation coverage, empty `bola_checklist` and missing evidence
   are shown as gaps, with an explanation that absence is not a pass.
5. A three-state renderer (`yes` / `no` / `not recorded`) is used for every
   boolean so that "not performed" cannot look like "false" or "true".
6. Runtime counters are the backend's own (`requests_sent`, `blocked_by_guard`,
   `redirects_followed`, `out_of_scope_requests_executed`, …), including zeroes.
7. There is no mock-data mode. Nothing in the UI reads from a fixture file that
   the backend did not serve.

## 6. Backend gaps this frontend ran into

Each item below is a **proposal that needs backend-owner approval and
implementation**. Until then the UI either shows a documented gap or omits the
feature; none of them are faked.

| # | Missing capability | Frontend component affected | Current behaviour | Proposed minimal contract |
| --- | --- | --- | --- | --- |
| G1 | No list endpoint for scenario runs | `/ui/suites`, `/ui/reports` | Only "open by run id" (`/ui/reports/lookup`) | `GET /api/scenario-scans?limit=50` → `{mode, runs: [{id, created_at, scenario_id, verdict, status}]}` |
| G2 | No list endpoint for authentication runs | `/ui/suites`, `/ui/reports` | Only "open by run id" | `GET /api/authentication-scans?limit=50` → `{mode, runs: [{id, created_at, scenario_id, title, status, summary}]}` |
| G3 | `POST /api/scan` runs synchronously and takes no configuration | dashboard, `/ui/scans` | Button blocks until the run completes; no progress, no cancel | Async job contract: `POST /api/scan-jobs` → 202 `{job_id}`, `GET /api/scan-jobs/{id}` → `{state, run_id?}`. Requires agreement; the fixture run is fast, so this is not urgent |
| G4 | A run "configuration" (target, spec, accounts, recipe) cannot be set through the API | `/ui/suites`, `/ui/scans` | The fixture target and recipe are fixed in code | A validated config object + guarded runner, only after the safety guard and organizer inputs exist. Do not expose editing before that |
| G5 | No full authorization matrix | `/ui/matrix` | Shows the backend's run-derived cells with an explicit "partial" warning | `GET /api/matrix?endpoint=…` with a full endpoint × actor grid once the matrix is implemented (P1) |
| G6 | No human-in-the-loop path for `NEEDS_MANUAL_INPUT` | `/ui/setup` | Renders the state if it appears; there is nothing to submit | `POST /api/setup/manual-input` with a strict schema, only if the backend supports that flow |
| G7 | No retention/export/delete API | `/ui/reports` | Links only to backend-generated reports | `DELETE /api/scans/{id}` (local DB only) and a bulk export. Out of scope for the demo |
| G8 | No API authentication or user model | all pages | Local single-user UI, stated on every page | Out of scope while the server is local-only; adding auth is a product decision |
| G9 | Evidence is minimized by design (no raw traffic) | `/ui/scans/{id}` | Shows redacted summaries + hashes, explains what is absent | No change proposed — this is a safety property, not a gap to close |
| G10 | No CSRF token for UI form posts | all forms | None needed while the API is unauthenticated and local; adding cookies/sessions later would require CSRF protection | Add CSRF tokens together with any authentication work |

Contract changes to the frozen models or the existing routes were **not** made.

## 7. Tests

`tests/integration/test_ui_pages.py` (13 tests, run with the rest of the suite):

| Test | What it actually proves |
| --- | --- |
| `test_every_page_renders_before_any_run_without_sample_data` | All 8 pages return 200 HTML with no stored run, show the fixture banner, render no verdict badge, reference no external origin, and include a viewport meta |
| `test_ui_scan_action_renders_the_same_run_the_api_returns` | A UI-triggered scan stores exactly one run, the detail page shows the API's own verdict/reason/owner/checklist/hashes/counters |
| `test_ui_never_renders_credentials_or_raw_tokens` | No tokens, bearer headers or private fixture values appear on the run page, evidence page or backend HTML report; `[REDACTED]` does |
| `test_ui_evidence_page_reports_recorded_coverage` | Coverage and every observation hash match `GET /api/scan/{id}/observations` |
| `test_ui_htmx_actions_return_fragments_and_plain_posts_redirect` | HTMX requests get fragments; plain posts get 303 redirects |
| `test_ui_suite_runs_render_backend_verdicts` | Scenario (vulnerable + secure) and authentication runs render the backend's verdict/reason/limitations/check ids |
| `test_ui_rejects_unknown_suite_and_run_ids_with_html_errors` | 404/422 HTML pages, correct statuses, generic messages |
| `test_ui_spec_inspection_is_bounded_and_never_scan_sources` | Inspection echoes endpoints but does not change `/api/endpoints` or create a run; 422/413/415 paths |
| `test_ui_static_assets_are_local_and_served` | CSS/JS/HTMX are served, no `url(http`, licence file present |
| `test_ui_pages_use_the_same_backend_handlers_as_the_json_api` | Counts on `/ui/scans` and `/ui/matrix` equal what the JSON API returns |
| `test_ui_fixture_scan_needs_no_network` | A UI scan completes with `socket.connect` and `getaddrinfo` patched to fail |
| `test_ui_suite_lookup_redirects_to_stored_runs[read-bola/authentication]` | Lookup validation and redirect to a stored run |

Not covered yet: real-browser rendering (no headless browser in this environment),
accessibility audit with a screen reader, JavaScript-disabled manual pass, and
visual regression. Those belong to the design pass.

## 8. Running it

```bash
python -m uvicorn canarygate.api.app:app --host 127.0.0.1 --port 8000
```

Then open `http://127.0.0.1:8000/ui/`. Optional:

```bash
CANARYGATE_DB_PATH=/tmp/canarygate.sqlite3 python -m uvicorn canarygate.api.app:app --port 8000
```

The server stays local-only, unauthenticated and fixture-only. Do not bind it to a
public interface, and do not present fixture verdicts as live-target results.

## 9. Next design pass (not started, by agreement)

1. Visual identity: typography scale, spacing tokens, denser tables, sticky table
   headers, verdict colour legend, dark/light toggle.
2. Drill-downs: endpoint → runs for that endpoint; actor → runs for that actor.
3. Server-side pagination and sorting for large run lists (needs G1/G2).
4. A compare view for "same endpoint, different actors" (works with today's data).
5. Report page: embed the backend HTML report in a framed view with a clear
   "generated by the backend" label, or re-render sections from
   `?view=sections` (no new contracts needed).
6. Accessibility: focus traps for details panels, skip links per section,
   contrast checks, keyboard-only run.
7. Print stylesheet for the report view.
8. Only after the core pipeline is frozen: an async scan with progress (G3).
