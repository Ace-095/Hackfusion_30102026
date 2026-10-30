# Checkpoint 44 — a run that stops tells the truth

**Goal:** the loading screen earned the trust of a judge while the engine was
working. This checkpoint fixes what it did when the engine *stopped*.

**Result at this milestone:** every terminal state is rendered by the server, in
the page's own words and with the backend's own sentence; a demonstration that
stored two of three runs is reported as **partial**, never as complete; a
connection failure names the port it tried, the command that starts the lab, and
offers the same configuration again; and a rejected form reads as a rejection
instead of a backend dump.

## 1. What was wrong (measured, not guessed)

CP43 streamed real progress, but the terminal state was drawn only by
`execution.js`. Three consequences, each reproduced against a live server:

| Symptom | How it was reproduced | What a judge saw |
|---|---|---|
| A stopped run explained nothing on the server render | `POST` with a closed port, then `GET` the job page with scripts off | "Assessment in progress", `0` requests, `0 / 3` runs, "The engine has not sent its first request yet." — and no reason anywhere |
| A refreshed or bookmarked finished job lost its summary | load a completed job URL directly | the result banner stayed `hidden` forever, because only the live poller ever revealed it |
| The tab and the page heading lied | open any finished job | `<title>Assessment in progress</title>` and an H1 saying the same, even on a completed or stopped run |
| A partially failed demonstration was called complete | make the third pair fail inside the engine | `status: complete`, "Assessment complete… opening the evidence", while the stats quietly said `2 / 3` |
| A rejected form spoke in developer language | `POST port=80` | "Backend returned HTTP 422 · The UI rendered this page instead of a JSON error body." |

None of these invented data; all of them *withheld* it. That is the failure mode
this checkpoint removes.

## 2. Terminal states are server-rendered

`canarygate/ui/execution.py` now owns one function, `terminal_for(job)`, that turns
the stored job into the page's terminal block — title, tone, sentence, hint, the
failed pairs and the next links. The route passes it to the template, so the HTML
the server sends already contains the answer:

| State | Page title | Body | Next step |
|---|---|---|---|
| `complete` | "Assessment complete" | "N runs stored · M requests sent" | open the stored run (single pair) or the matrix (demonstration) |
| `partial` | "Assessment partially complete" | the backend's own sentence, e.g. "2 of 3 runs stored; 1 pair reported an error." | see what is stored, plus the retry form |
| `failed` | "Assessment stopped" | "No pair completed; nothing was stored." | change the configuration, see what is stored, plus the retry form |

The block carries `role="status"` and `aria-live="polite"`, so the same sentence a
sighted judge reads is announced to a screen reader. `<title>`, the H1 and the
sub-heading all follow the state; a finished page no longer says "in progress".

**The retry form is the existing action.** It posts `kind`, `port`, `actor` and
`asset` — the same fields the workspace form sends, to the same
`POST /ui/actions/run-assessment`. No new endpoint, no automatic retry, no queue.
Steps now carry the owner's `asset_id` (resolved from `/api/lab-catalog`) so the
retry can replay the *same* configuration without the template deriving anything.

## 3. `partial` is a state, not a rounding decision

`start_assessment` used to end with `complete` unless *every* pair failed. A
demonstration whose third pair hit a vanished lab therefore announced completion
while two thirds of the matrix stayed untested. The worker now records each
failure and ends in one of three states:

- **complete** — every planned pair stored a run;
- **partial** — at least one stored and at least one did not, with
  `failure.reason = "partial"`, `pairs_failed`, `runs_stored` and the label of every
  pair that never stored;
- **failed** — nothing stored, with the reason inherited from the first failure.

`failure.reason` is deliberately small and closed: `unreachable`, `ca`, `config`,
`partial`, `internal`. Each maps to one hint that names an action a human can take:

| Reason | HTTP | Hint |
|---|---|---|
| `unreachable` | 502 | "Nothing answered on 127.0.0.1:{port}. Start the lab in another terminal with python -m targetlab --port {port} --tls-cert <pem> --tls-key <key>…" |
| `ca` | 400 | set `CANARYGATE_TARGETLAB_CA`; without it a scan answers 400 and stores nothing |
| `config` | 400 | the port or the pair was rejected before any request was sent |
| `internal` | — | the engine hit an unexpected error; the feed stops at the last real request |
| `partial` | — | the pairs that stored are ordinary runs; the failed pairs' cells stay untested — untested is not SAFE |

The hint never retries, never changes a verdict, and never states a result. The
`partial` hint repeats the rule the matrix already enforces: a missing check is
untested, and untested is not SAFE.

## 4. The client script keeps parity, and stops advertising

`execution.js` now fills the same block the server would have rendered, from the
same snapshot fields: state, tone, title, detail, hint, failed pairs and links.
Two behaviour changes come with it:

- **only a completed run navigates.** A partial or stopped run stays on the page so
  the reason is read instead of skipped;
- the pulse animation stops on `partial` as well as on `complete`/`failed`
  (`.engine[data-status]`), so a finished page is never still "working".

`[hidden] { display: none !important; }` was added to the stylesheet: the retry
form and the hint carry author `display: flex` rules, which beat the user-agent
`[hidden]` rule. Without it the "Try again" button was visible on completed runs.

## 5. A rejected form is still a rejection

`_backend_error` used to title every failure "Backend returned HTTP 422". It now
maps the status to a sentence a judge can act on ("That configuration was
rejected", "The lab could not be reached", …), keeps the HTTP code visible in the
badge, and the error page explains the status in one line. A 422 additionally
offers a button back to the workspace. The backend's own detail sentence is still
printed verbatim — nothing is softened or hidden.

## 6. Verification

```
$ .venv/bin/python -m pytest -q
1109 passed, 1 warning in 122.80s
$ .venv/bin/python tools/p0_audit.py
58 requirements, 1109 collected tests, 66 test files
implemented=47, partial=9, missing=2, unreachable=0
$ .venv/bin/python tools/demo.py
ALL CONSISTENCY CHECKS PASSED (142 invariants over 17 surfaces)
$ .venv/bin/python tools/consistency_audit.py --database <demo db>
ALL STORED RUNS INTACT AND CONSISTENT
$ .venv/bin/python tools/browser_smoke.py --jsdom /tmp/browser-harness
31/31 browser checks passed · 9 known jsdom-only XPath notice(s) suppressed
```

`tests/integration/test_ui_execution_outcomes.py` (11 tests) pins the contract
against the real TLS lab:

- a completed run renders its result **without JavaScript**, with a link to the
  stored run that the API also serves;
- a refused run renders "Assessment did not complete.", the backend's sentence,
  the port it tried, the real `python -m targetlab` command and a retry form
  carrying that exact port;
- `failure` is structured and identical in the page and in `/events`;
- a partial demonstration into the same engine reports `partial`, shows
  "2 of 3 runs stored", names the pair that failed, and leaves the matrix at
  7 tested / 2 untested — exactly the two cells the missing pair would have added;
- the terminal block is a `role="status"` live region;
- an unexpected engine exception is recorded as `internal`, and a clean job reports
  `failure: null`;
- a rejected form reads as a rejection and links back to the workspace.

Two new browser checks drive it end to end in jsdom with the page's own script: a
real run finishes by itself and hands off to evidence (`navigated: true`), and a
real refusal reveals the hint, the retry form and `Assessment did not complete`
with no page error. jsdom implements no `fetch`, so the smoke harness injects the
platform's own `fetch` **only** for the engine page — the polling code under test
is unchanged.

## 7. Limits, stated plainly

- **A job transcript is not persisted.** It lives in a bounded in-memory registry
  (24 jobs). After a server restart the job URL answers 404 "Unknown assessment";
  the *stored runs* are unaffected, and the page says so. Persisting transcripts
  would add a new table and a new contract for a screen that lasts three seconds.
- **`partial` is a job state, not a verdict.** It never reaches the store, the
  matrix or a report; those only ever see the runs that were really stored.
- **Reachability is still not probed.** There is no health request to the lab: a
  probe would be a second outbound path outside the single guarded transport. The
  first real request is the reachability test, and a failure is reported honestly.
- **No real browser was available.** The browser checks are jsdom; they prove
  script execution and DOM state, not paint, focus rings or print output.
- **The 422 page is shared.** The status-specific title is generic to all form
  actions, not only the assessment form.

## 8. Follow-up: the commands a judge actually types

Writing `docs/RUN_LOCALLY.md` meant executing every command on a clean checkout
with a fresh virtual environment. Three defects surfaced, all in the tools rather
than the product, and all fixed here:

| Defect | Reproduced by | Fix |
|---|---|---|
| `tools/demo.py --keep` printed a database path that no longer existed | run it, then `ls` the printed path | with `--keep` the file is created in `mkdtemp()`, which is not cleaned up; the tool also prints the exact audit command to run next |
| `tools/consistency_audit.py --database <file>` died with a raw `sqlite3` traceback | point it at a missing file, then at an empty one | exits `2` with a sentence: "no such database file" / "this database has no CanaryGate tables … this is not a statement that any run is intact" |
| `tools/browser_smoke.py --jsdom <wrong path>` raised `FileNotFoundError` | pass a path that does not exist | treated as a missing prerequisite: prints the `npm install` line and exits `2` |

`tests/integration/test_tool_ergonomics.py` (4 tests) pins all three, including
the rule that an empty database is **never** announced as "all stored runs
intact" — the real clean-store path stays covered by
`test_demo_consistency.py::test_the_consistency_audit_reports_a_clean_store`.

Verified on the fresh environment: `pytest -q` 1113 passed, `p0_audit.py` 58
requirements / 1113 tests / 67 files, `demo.py` 142 invariants over 17 surfaces,
`demo.py --keep` → the printed path exists → `consistency_audit.py` on it exits 0
with "ALL STORED RUNS INTACT AND CONSISTENT", `browser_smoke.py` 31/31 with a
freshly installed jsdom, and both servers serving `/`, `/ui/`,
`/ui/assessment`, `/api/health` with a real assessment completing 3 runs / 54
requests / 9 cells.
