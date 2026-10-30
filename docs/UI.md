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
| Styling | Hand-written CSS (`static/css/app.css`) | Dark security-operations theme, design tokens, responsive, print, reduced-motion and forced-colors support |
| Behaviour | ~150 lines of vanilla JS (`static/js/app.js`), optional | Mobile nav, table filter, copy buttons, print button, busy state, inline error fragments |
| Assets | Served by the app itself at `/ui/static/...` | No CDN, no web fonts, no analytics, no external requests |
| Data | `canarygate.api.app` handlers called **in-process** | The UI never re-implements a verdict or a counter |

Pages: dashboard, endpoint inventory, setup & readiness, findings, read-BOLA scan
list, scan detail, evidence/observations, report view, authorization matrix,
reports, test suites, suite run detail, spec inspection, configuration, error
page. The UI is mounted at `/ui/`; `/` redirects there.

Every page renders the same shell: a grouped sidebar (`NAV_GROUPS` in
`routes.py`), a breadcrumb trail, and — on the core review pages — a numbered
**review journey** (Dashboard → Endpoints → Findings/Scan → Ownership proof →
Disclosure proof → Matrix → Report) that links straight to the next artifact. A
judge can walk that strip without being told what to click.

## 2. File map

```
canarygate/ui/
├── __init__.py            # package docstring only
├── app.py                 # FRONTEND ENTRYPOINT: backend app + UI mounted at runtime
├── routes.py              # HTML routes, form actions, view helpers
├── replay.py              # flight recorder adapter: backend evidence -> ordered events
├── templating.py          # Jinja2 environment, filters (verdict/status badges, JSON, tri-state,
│                          #   humanize, pct, short_id)
├── templates/
│   ├── base.html          # shell: banner, navigation, footer, local assets
│   ├── _macros.html       # design-system components: badges, chips, stat, meter, empty/unavailable,
│   │                      #   journey, evidence proof, checklist grid, constraints panel, report links
│   ├── dashboard.html     # health, posture, gates, latest verdict, distribution, recent runs
│   ├── findings.html      # verdict-grouped findings, check-level findings, coverage gaps
│   ├── configure.html     # read-only bundled scope/recipe/spec + disabled config form
│   ├── endpoints.html     # inventory: expected access + provenance + declared auth
│   ├── setup.html         # three readiness gates + account states + BOLA coverage
│   ├── scans.html         # stored fixture runs (Verifiable list from /api/findings)
│   ├── scan_detail.html   # verdict, two-part evidence, 10-key checklist, checks, constraints
│   ├── evidence.html      # minimized observations behind the verdict
│   ├── matrix.html        # run-derived authorization cells
│   ├── reports.html       # links to backend-generated HTML/JSON reports
│   ├── report_view.html   # backend `?view=sections` rendered in-page, print-friendly
│   ├── replay.html        # flight recorder: recorded events, step-through playback
│   ├── suites.html        # read-BOLA + authentication scenario runners
│   ├── suite_run.html     # scenario run / authentication run detail
│   ├── spec.html          # in-memory OpenAPI inspection
│   ├── error.html         # HTML error page (real HTTP status, no JSON body in the page)
│   └── partials/          # HTMX fragments: fixtures scan result, suite result, spec result, error
└── static/
    ├── css/app.css
    ├── css/replay.css      # recorder only (loaded by replay.html)
    ├── js/app.js
    ├── js/replay.js        # playback engine (progressive enhancement)
    └── vendor/htmx.min.js, vendor/htmx.LICENSE
```

**No backend file is modified.** The UI is attached at runtime by
`canarygate/ui/app.py`:

```python
application = create_backend_app(database_path)          # untouched backend factory
application.mount("/ui/static", StaticFiles(...))        # local assets
application.include_router(ui_router)                    # HTML routes
```

`canarygate/api/app.py`, the guard, the runner, the oracles, the models, the
database layer, the existing tests and `pyproject.toml` are byte-identical to the
backend branch. Two servers are therefore possible from the same code:

| Command | Serves |
| --- | --- |
| `uvicorn canarygate.api.app:app` | JSON API only, unchanged |
| `uvicorn canarygate.ui.app:app` | JSON API **and** the UI at `/ui/` |

Mounting in memory (rather than a sub-application) keeps the backend lifespan —
the SQLite table creation — running exactly once, and keeps
`request.app.state.store`, `.scenario_store`, `.auth_store` reachable, because it
is the same application object.

`canarygate/ui/routes.py` imports `canarygate.api.app` lazily (one helper,
`_api()`), so the UI can call the API handlers without a circular import at
module load time.

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
| `GET /ui/scans/{id}/report` | `api.report(..., view="sections")` | full page, 9 backend sections | same |

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
| `/ui/findings` | One place for every conclusion | open-finding count, CONFIRMED findings with reason + remediation + evidence flags, SUSPECTED, check-level findings (AUTHN/INPUT/DISC), SAFE list, coverage gaps | `GET /api/findings` (grouping only) | run fixture scan, drill into run/evidence/report | "No findings yet"; explicit "severity is not in the contract" note |
| `/ui/configure` | What the backend is configured to do | bundled `scope.yaml`, `recipe.json`, `fixture.yaml`, recipe returned by `fixture_recipe()` (canary redacted), disabled config form with reasons | none (reads backend package files + recipe function) | none — read-only by design | empty state if package files are missing |
| `/ui/matrix` | Actor × endpoint access | grid: inventory rows × accounts the backend demonstrated, each cell a verdict or **not assessed**; plus the recorded cell table | `GET /api/matrix` + `GET /api/endpoints` + `GET /api/findings` | open run from a cell | "No grid yet"; assessed/total coverage; explicit partial-coverage warning |
| `/ui/scans/{id}/report` | The backend's own report, re-rendered from `?view=sections` | the 9 sections (`executive_summary` … `constraint_checklist`) with their backend titles and values, plus a link to the backend HTML/JSON originals | `GET /api/reports/{id}?format=json&view=sections` | print (`window.print`), open HTML/JSON | 404 page if the report cannot be generated; a section the backend omits is simply absent, never filled in |
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
8. A matrix combination with no stored run is rendered **not assessed**, never as
   SAFE. The grid shows `assessed / total`, so partial coverage is unmistakable.
9. Severity ranking (CVSS/critical/high/…) does not exist in the backend contract,
   so `/ui/findings` ranks by verdict only and says so on the page (gap R6).
10. Configuration is displayed, not simulated: `/ui/configure` shows the real
    bundled files, disables the inputs it cannot save, and links the gap.

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
| G11 | Severity/risk ranking absent from the contract | `/ui/findings` | Ranks by verdict only, with an on-page explanation | Add `severity: Literal["critical","high","medium","low","info"] \| None` + `severity_source` to `SecurityCheck`/`FixtureRun`. Must stay `None` when the backend has no basis for it — an invented severity is worse than none |
| G13 | Transcript runs expose no per-request capture time (deferred by product decision — not a demo blocker) | `/ui/suites/*/replay` | Renders them as a *sequence* in backend list order and says so | A `captured_at` per transcript entry (or an ordered `steps[]` on the run) would let scenario and authentication runs use the same timeline the fixture run already has |
| G12 | No configuration submission path | `/ui/configure` | Shows bundled config read-only, form disabled with reasons | Same as G3/G4: a validated config object plus a scan-job contract, only after guard + authorization work |

Contract changes to the frozen models or the existing routes were **not** made.

## 7. Tests

`tests/integration/test_ui_pages.py` (24 tests, run with the rest of the suite):

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
| `test_backend_application_is_unmodified_and_ui_is_additive` | The backend factory still produces an app with **no** `/ui` routes (404 alone), its API answers identically, and the UI entrypoint only adds routes |
| `test_findings_page_groups_only_backend_verdicts` | Empty state before data; after a run the reason/remediation/verified owner are the API's own; counts derived from `/api/findings`; no severity badge, value or label is invented |
| `test_configure_page_is_read_only_and_redacts_secrets` | Bundled scope/recipe/spec are shown, the canary value is redacted, `Save`/`Start` are disabled with the reason, and viewing stores nothing |
| `test_matrix_grid_marks_unassessed_cells_instead_of_guessing` | Grid renders inventory rows × demonstrated accounts, unassessed combinations are labelled, and `assessed / total` equals recorded runs vs. the full grid |

| `test_report_view_renders_backend_sections_and_prints` | `/ui/scans/{id}/report` renders the backend's own 9 sections and titles, keeps a single `<h1>`, and offers a print control |
| `test_journey_links_the_review_path_on_core_pages` | The numbered journey appears on every core page, marks the current step, and links onward to endpoints and the run report |
| `test_accessibility_basics_on_every_page` | Every page (including 404 states) has exactly one `<h1>`, a skip link to `#main`, `lang`, a labelled nav with exactly one `aria-current`, no `<img>` without text alternatives and no inline styles |

| `test_replay_orders_fixture_events_by_capture_time_and_marks_evidence` | The recorder's event count equals observations + executed probes, offsets never decrease, evidence parts are annotations rather than extra events, every displayed timestamp is one the API returned |
| `test_replay_refuses_to_invent_a_timeline_for_transcript_runs` | Scenario and authentication runs render as a sequence with no offsets and say "not a measured timeline" |
| `test_replay_is_progressive_enhancement_with_local_assets` | The whole timeline is in the HTML before JavaScript runs, controls start hidden, assets are local and served |
| `test_replay_unavailable_state_is_explicit` | An unknown run is a real 404 page; a stored run always renders a recorder |

Not covered yet: real-browser rendering (no headless browser in this environment),
screen-reader audit, a manual keyboard-only pass, and pixel-level visual
regression. Everything above is asserted on the served HTML/CSS, which is the
limit of what the test environment can prove.

## 8. Running it

```bash
python -m uvicorn canarygate.ui.app:app --host 127.0.0.1 --port 8000
```

Then open `http://127.0.0.1:8000/ui/`. Optional separate database:

```bash
CANARYGATE_DB_PATH=/tmp/canarygate.sqlite3 python -m uvicorn canarygate.ui.app:app --port 8000
```

The backend entrypoint is untouched and still works on its own (JSON only, no
`/ui/`):

```bash
python -m uvicorn canarygate.api.app:app --host 127.0.0.1 --port 8000
```

The server stays local-only, unauthenticated and fixture-only. Do not bind it to a
public interface, and do not present fixture verdicts as live-target results.

## 9. Design system (shipped in this pass)

The visual and usability pass has been **done** (it is what shipped in this
checkpoint). What exists now:

1. **Design tokens.** `app.css` starts with one `:root` block: colour roles
   (`--bg`, `--panel`, `--line`, `--ink`, `--ink-2`, `--ink-3`, verdict tones),
   a type scale, radii, shadows and spacing. Verdict colours are used *only* for
   verdicts and status; the rest of the interface is neutral so the evidence
   stands out.
2. **Components, not one-off markup.** `_macros.html` exposes `verdict_badge`,
   `status_badge`, `tri`, `method_chip`, `stat`, `meter`, `empty`, `unavailable`,
   `kv`, `json_details`, `checklist_grid`, `evidence_proof`, `constraints_panel`,
   `journey`, `crumbs`, `page_head`, `verdict_legend` and the report link sets.
   Pages compose these, so a verdict looks identical on the dashboard, the
   findings list, the run page and the report.
3. **Evidence-first layout.** Every run page shows expected access next to the
   observed outcome, then ownership proof and disclosure proof side by side, each
   with its own anchor (`#proof-ownership`, `#proof-disclosure`). Raw JSON lives
   in collapsed `<details>` blocks, never above the conclusion it supports.
4. **Information density.** Run and endpoint tables are compact with sticky,
   uppercase headers and tabular numerals. Long run ids shorten through the
   `short_id` filter (the link still points at the full id); values that are
   shortened or abbreviated carry a `title` with the full text.
5. **States before decoration.** `empty`, `unavailable`, `alert-*` and the error
   page cover no-data, fixture-only, and backend-refused cases. Nothing animates
   except a short, reduced-motion-aware busy indicator.
6. **Accessibility.** Skip link, one `<h1>` per page, labelled landmarks, visible
   focus rings, `aria-current` for the active nav item, `aria-live` on action
   panels, tri-state values spelled out ("not recorded" rather than a blank cell),
   ≥4.5:1 body contrast, `prefers-reduced-motion` and `forced-colors` support.
7. **No inline styles.** All spacing is tokenised utility classes, so the pages
   stay compatible with a strict CSP and print cleanly.
8. **Print.** Report and run pages drop navigation, flatten cards and keep
   headers with their tables.

Still open, and deliberately not faked:

* Server-side pagination/sorting for very large run lists (needs the list
  endpoints in G1/G2).
* An async scan with progress (needs G3).
* A compare view for "same endpoint, different actors" — possible with today's
  data, but it needs a product decision about which two runs to compare.

## 10. Backend read-only guarantee

The backend is treated as a delivered dependency. The frontend may read, import
and call it; it may not change it.

| Allowed | Forbidden (and not done) |
| --- | --- |
| Read backend source, tests, schemas, `docs/API.md` | Edit any file under `canarygate/` outside `canarygate/ui/` |
| Import `canarygate.api.app` and call its handlers | Change API routes, response models or status codes |
| Use FastAPI objects the backend factory returns | Change `canarygate/models/`, the guard, runner, oracles, accounts/seed/scope logic |
| Read the SQLite schema through the backend's stores | Touch `canarygate/database/`, migrations or stored payloads |
| Add files under `canarygate/ui/`, `docs/UI.md`, `tests/integration/test_ui_pages.py` | Modify existing backend tests or `pyproject.toml` |

### Verification (run these before handing the branch over)

```bash
# 1. No backend file differs from the backend branch
git diff --stat origin/arena/aa67fa1b-hackfusion-30102026 -- \
  canarygate/api canarygate/guard canarygate/runner canarygate/oracles \
  canarygate/accounts canarygate/seed canarygate/scope canarygate/spec \
  canarygate/network canarygate/evidence canarygate/report canarygate/database \
  canarygate/models canarygate/scan canarygate/offline \
  pyproject.toml README.md docs/API.md tests/unit tests/security
# expected: no output

# 2. Every change on this branch is frontend-only
git diff --stat origin/arena/aa67fa1b-hackfusion-30102026
# expected: canarygate/ui/** , docs/UI.md , tests/integration/test_ui_pages.py only

# 3. The whole suite passes, backend tests included and unmodified
python -m pytest -q

# 4. The backend alone still has no UI routes
python -m uvicorn canarygate.api.app:app --port 8001   # GET /ui/ -> 404
```

### Changes I would make outside the frontend, awaiting your approval

These are **not applied**; each is a one-line-to-small change that the frontend
cannot make under the read-only rule.

| # | File | Proposed change | Why the frontend wants it | Risk |
| --- | --- | --- | --- | --- |
| R1 | `README.md` (line ~96) | Add "open `/ui/` for the local frontend; see `docs/UI.md`" next to the uvicorn command | Discoverability: the README currently mentions only the CLI demo | None (docs) |
| R2 | `docs/VS_CODE_DEMO.md` (lines 4–5) | Replace "the frontend/dashboard … not yet implemented" with "a local frontend exists at `/ui/`" | The current sentence is now factually wrong for anyone reading it | None (docs) |
| R3 | `pyproject.toml` `[tool.setuptools.package-data]` | Add `"canarygate.ui" = ["templates/*.html", "templates/partials/*.html", "static/css/*.css", "static/js/*.js", "static/vendor/*"]` | Templates/CSS/JS ship in a built wheel. Editable installs (`pip install -e .`, what CI uses) work without it | Build config only |
| R4 | `canarygate/api/` — **new** route(s) | `GET /api/scenario-scans?limit=` and `GET /api/authentication-scans?limit=` returning `{mode, runs:[{id, created_at, scenario_id, verdict/status}]}` (gap G1/G2) | Without a list endpoint the suites/reports pages can only open a run by pasted id | New read-only route; no change to existing contracts |
| R5 | `canarygate/api/` — **new** route | `POST /api/scan-jobs` + `GET /api/scan-jobs/{id}` (gap G3) | Progress/cancel for long runs. Not needed for the fixture demo, which returns in well under a second | New surface; defer |

Until R1–R5 are approved, the UI shows the workaround (open-by-id) and documents
the gap in place, rather than inventing an endpoint or faking the capability.


## 11. Creating the `fa1b` branch from this work

The current branch is the backend baseline plus two frontend-only commits, so it is
already exactly the content `fa1b` should hold. It was not renamed because this
workspace is bound to one branch name; the separation you asked for is preserved
through *content*, not through the branch label.

Known good refs:

| Ref | Meaning |
| --- | --- |
| `27fd836` | verified backend baseline (`origin/arena/aa67fa1b-hackfusion-30102026`) |
| `3674b40` | basic frontend, pushed and verified (reference/backup) |
| this branch head | backend baseline + frontend-only commits (current frontend) |

Safe transition for the repository owner or the frontend developer (no reset, no
clean, nothing lost):

```bash
git fetch origin

# 1. Preserve the current frontend as its own reference branch (optional but cheap).
git branch frontend-reference arena/a1fe3757-hackfusion-30102026

# 2. Create fa1b from the verified backend baseline.
git switch -c fa1b 27fd836
git push -u origin fa1b

# 3. Either start clean on fa1b …
#    (nothing else to do — fa1b is now the untouched backend)

#    … or bring the reference frontend across as a starting point:
git checkout arena/a1fe3757-hackfusion-30102026 -- \
    canarygate/ui tests/integration/test_ui_pages.py docs/UI.md
git commit -m "chore(ui): import reference frontend onto fa1b"
git push
```

Verification after switching (same commands as section 10):

```bash
git diff --stat 27fd836 -- canarygate/api canarygate/guard canarygate/runner \
  canarygate/oracles canarygate/accounts canarygate/seed canarygate/scope \
  canarygate/spec canarygate/network canarygate/evidence canarygate/report \
  canarygate/database canarygate/models canarygate/scan canarygate/offline \
  pyproject.toml README.md tests/unit tests/security   # expected: no output
python -m pytest -q                                    # expected: 626 passed
```

---

## 12. Flight recorder (replay)

`/ui/scans/{id}/replay` and `/ui/suites/{family}/{id}/replay` step through the
requests that produced a stored result. The page is built by
`canarygate/ui/replay.py` (a read-only adapter), rendered by
`templates/replay.html`, styled by `static/css/replay.css` and driven by
`static/js/replay.js`.

### 12.1 Feasibility audit, run before writing any replay code

The recorder was only built because the backend already exposes the data. What
was checked, against real responses:

| Requirement | Fixture run | Read-BOLA scenario | Authentication scenario |
| --- | --- | --- | --- |
| Per-event capture timestamp | **Yes** — `observations[].timestamp`, `checks[].evidence.timestamp`, both `datetime.now(UTC)` at capture | **No** — both evidence parts share one instant (build time) | **No** — every check equals `run.created_at` exactly |
| Stable event ordering | **Yes** — list order equals execution order, and timestamps are strictly increasing (18/18 unique in every run tested) | Partial — backend list order only | Partial — backend list order only |
| Request detail | **Yes** — method, path, redacted Authorization, status | Method, `path_template`, status | Method, `path_template`, probe kind, status |
| Response detail | **Yes** — minimized, allowlisted fields (`item_count`, `item.id`, `item.owner`, `private_field_present`, truncation flag) | Redacted body only | Redacted body + denial-body flag |
| Actor / role | **Yes** per event | **Yes** per evidence part | **Yes** per check |
| Ownership evidence | **Yes** — `run.evidence.ownership` | **Yes** | n/a (not a BOLA run) |
| Disclosure evidence | **Yes** — `run.evidence.disclosure` | **Yes** | n/a |
| Explicit observation → finding link | **No** — no foreign key; the link is derived (phase, then request identity, then nearest timestamp) | Same (phase name) | Same (check id) |

Consequences, all enforced in code:

1. **A timeline is only claimed where capture timestamps exist.** Fixture runs
   get `mode="timeline"` with real offsets. Transcript runs get
   `mode="sequence"` and the page says, in words, that the order is backend list
   order and no measurement is being claimed.
2. **Evidence parts annotate events, they do not become events.** The ownership
   evidence describes the same request as the `owner_baseline` observation one
   layer of interpretation later; emitting both would make one request look like
   two. Matching is phase-first (see §12.4), and the page states the basis it used.
3. **Skipped checks are absent, not empty.** A SKIPPED check performed no
   request, so it has no event; it stays listed on the run page.
4. **Nothing is invented.** Ordering, relative offsets and labels are the only
   things computed here. Every timestamp, status, assertion, digest and verdict
   is copied from the API response.

If the backend later adds a per-transcript-entry `captured_at` (gap G13), the
same adapter and page can switch transcript runs to `mode="timeline"` without
any template change.

### 12.2 Behaviour

* **No JavaScript:** the page is a complete, scrollable evidence timeline — all
  events, all details, verdict at the end. The transport controls stay hidden.
* **With JavaScript:** the same markup becomes a stepper (`Home`/`End`,
  `←`/`→`, `Space` to play/pause, a speed selector) with an `aria-live`
  announcement per step, `aria-current="step"` on the active card, and the
  verdict panel revealed only after the last event.
* **Playback timing** is derived from the recorded gaps, clamped to
  700–2400 ms so a 1 ms gap stays readable; nothing autoplays.
* **Reduced motion** disables the card transition and switches scrolling to
  instant.

### 12.3 Verification beyond the test suite

The playback engine was executed against the real rendered page in a jsdom DOM
(node + jsdom, outside the repo and outside CI). 25 assertions covered:
controls stay hidden before enhancement, step 1 is active on load, next/prev
clamp at the ends, `←`/`→`/`Home`/`End` move correctly, announcements describe
the current event, play advances on its own, pause freezes, and the verdict is
revealed exactly at the final step. jsdom has no layout engine, so this proves
the behaviour, not the pixels.


### 12.4 Multiple identical requests (audit + fix)

The first matcher used `(actor, method, path, status)` alone and marked the
**last** match. That is wrong when a request is repeated: a retry, or the same
actor reading the same path in two different phases, can steal the annotation
from the request the evidence actually describes.

`tests/integration/test_ui_replay_adapter.py` reproduces that failure with
payloads shaped exactly like backend responses (no database, no backend change).
Three of its cases failed against the first matcher:

| Case | Old behaviour | Current behaviour |
| --- | --- | --- |
| Alice reads Bob's item during `discovery` **and** as `cross_user_read`; disclosure evidence exists | matched the later event by luck | phase filter selects `cross_user_read` first |
| Two `cross_user_read` reads (retry) 6 s apart; evidence timestamp sits 0.5 s after the **first** | marked the retry (wrong request) | nearest capture timestamp wins |
| Two `owner_baseline` reads of the same resource; evidence sits next to the first | marked the second | nearest capture timestamp wins |
| Evidence identity matches no captured request | unmarked, noted | unmarked, noted (unchanged) |

The rule is now, in order: **phase** (`owner_baseline` for ownership,
`cross_user_read` for disclosure) → **request identity** → **nearest capture
timestamp** (within 5 s; otherwise the last match) → and when several requests
still match, the page says how many and which rule chose. Every annotated event
renders its basis:

```
Evidence attached here by: phase cross_user_read · the only captured match
Evidence attached here by: phase owner_baseline · nearest capture timestamp (4 ms …)
```

An unmatched evidence part is never attached to a plausible neighbour: it is
reported in "How this replay is built" instead.

Verified on real runs: the fixture run (5 observations + 13 executed probes)
marks exactly one ownership event and one disclosure event, and the 9 SKIPPED
checks produce no events at all. INCONCLUSIVE and unknown check verdicts render
as recorded — the adapter copies the verdict, it never derives one.

---

## 13. Demonstration script (mapped to the UI)

One confirmed Read-BOLA fixture run, seven clicks. Every step below lands on a
page that already exists on this branch; nothing needs to be typed.

| Step | Where | What the judge sees |
| --- | --- | --- |
| 1. Alice authenticates | `/ui/setup` | Per-account authentication state and the readiness gates — the backend's own values |
| 2. CanaryGate discovers Bob's resource | `/ui/endpoints` | The inventory: method, expected access, provenance of that expectation |
| 3. Alice requests Bob's resource | `/ui/scans/{id}/replay` → Play | Event cards appear in capture order: discovery, owner baseline, cross-user read |
| 4. The server returns private information | same page, the `cross_user_read` card | Status 200, `item.owner = bob`, `private field present = yes`, and the evidence-part tag |
| 5. Ownership and disclosure verified independently | `/ui/scans/{id}/evidence` | Two numbered proof blocks with their own hashes, anchors and checklists |
| 6. Flight Recorder reveals the verdict | `/ui/scans/{id}/replay` → End (or `Space` and wait) | The verdict panel appears only after the final event |
| 7. The matrix reflects the finding | `/ui/matrix` | The actor × endpoint cell for alice × `GET /items/{id}` carries the verdict; unassessed cells stay explicitly "not assessed" |

Two things to say out loud while presenting:

* the recorder never shows a verdict before the last event, and the page states
  that the verdict is derived from the whole run, not from that event;
* the evidence attached to each event is labelled with the matching rule
  (phase, identity, timestamp), so "why is this here?" has an answer on screen.

### 12.5 Ambiguity is shown, never resolved silently

The nearest-timestamp rule is a heuristic, so the page never presents it as
proof. When two candidates are **equally** close (same millisecond distance), or
when no usable timestamp can separate them and more than one request matches,
the association is marked ambiguous:

* the evidence tag reads `ownership evidence · unconfirmed` with a dashed amber
  border instead of the solid colour used for settled associations;
* a `role="note"` warning says *"Ambiguous association … may describe either
  request, so this annotation is not proof on its own"*;
* the basis line prints the competing step numbers
  (`ambiguous: 2 captured requests are 500 ms from the evidence summary (steps 1, 2)`);
* "How this replay is built" repeats that the part is ambiguous;
* the explanatory sentence in the card switches from "This exact request is…"
  to "…more than one captured request fits equally well".

Thresholds: a candidate is usable inside 5000 ms of the evidence summary; ties are
exact millisecond equality. Missing, empty and malformed timestamps are treated
identically (no ordering, no disambiguation) and never raise.

### 12.6 Validation log

| Check requested | Result |
| --- | --- |
| Ambiguous timestamp ties | Marked ambiguous, warning rendered, step numbers listed — `test_equally_plausible_candidates_are_marked_ambiguous_not_silently_chosen` |
| Two identical requests inside the 5 s window | Resolved only when one is clearly nearer (200 ms vs 800 ms); otherwise ambiguous — `test_identical_requests_inside_the_window_still_resolve_when_one_is_clearly_nearer` |
| Missing timestamps | Multi-candidate → ambiguous; single candidate → not ambiguous; events keep list order with `offset = None` — `test_missing_timestamps_make_a_multi_candidate_match_ambiguous`, `test_missing_timestamp_with_a_single_candidate_is_not_called_ambiguous` |
| Malformed timestamps | Treated as missing, no crash — `test_malformed_timestamps_are_treated_as_missing_and_never_crash` |
| Candidates outside the window | Not used for disambiguation; basis says so — `test_candidates_outside_the_matching_window_are_not_used` |
| Scan with no findings | Empty database and a real SAFE transcript run: findings stay at zero, the run is still reachable — `test_a_scan_with_no_findings_is_explained_not_hidden` |
| INCONCLUSIVE verdict | Real backend case (`synthetic-metadata`): suite page, recorder and findings all render it as INCONCLUSIVE, never as a finding — `test_inconclusive_runs_are_rendered_as_inconclusive_everywhere` |
| Structural accessibility (18 pages) | No duplicate ids, no heading jumps, every input inside a label or aria-labelled, every button and link has an accessible name |
| jsdom playback | 25 interaction assertions (controls, keyboard, play/pause, verdict reveal) |
| Real browser (Chromium/Firefox) | **Blocked in this sandbox** — see below |
| Seven-step demo rehearsal | 7/7 routes and artefacts verified over HTTP |

**Why the browser step is still open.** A real Chromium was obtainable
(`@sparticuz/chromium` installs from the npm registry and extracts to `/tmp`),
but it cannot start here: `libnspr4.so`, `libnss3.so` and `libnssutil3.so` are
absent, there is no root, and `apt` has no writable lists directory. Playwright's
browser CDN is outside the allowed network. So the pixel-level pass — layout,
sticky headers, focus rings, print output — remains for a machine with a real
browser. Everything above is the strongest verification this environment allows.
