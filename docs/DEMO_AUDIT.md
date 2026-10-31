# CanaryGate — Pre-Demo Architecture & Readiness Audit

**Audited:** 2026-10-31 · **Auditor role:** senior engineer / technical judge
**Repository:** `Ace-095/Hackfusion_30102026` · **Audit branch:** `arena/b79373f3-hackfusion-30102026`

> Every claim in this document was executed in a clean sandbox: fresh venv from
> `requirements.txt`, real loopback TLS TargetLab, real uvicorn server, real HTTP
> requests, real SQLite inspection. Nothing here is inferred from a README.

---

## 1. Executive summary

CanaryGate is a **Python/FastAPI evidence-based API authorization tester** — an
API-security tool, not a web SaaS. It authenticates with two accounts, *proves*
which private asset each account owns, attempts cross-account reads, and only
issues a `CONFIRMED` verdict when a complete chain of evidence exists. It also
detects **Security Control Interaction (SCI)** bugs: two controls that each behave
correctly alone but leak data together.

**The single most important finding of this audit:**

> **`main` does not contain the application.**
> `main` is backend + docs only. It has **no UI, no `run.sh`, no `.env.example`**.
> All of the user-facing product lives in **PR #4**, which is still **OPEN** —
> even though it is `MERGEABLE`, `CLEAN`, with **both CI jobs green** on Ubuntu
> and Windows.

If you demo by cloning the repo and following `main`'s README, you will show a
JSON API and no interface. Fix this before anything else.

Once you are on the PR #4 branch, the project is in **unusually strong shape**:
1133 tests pass, 31/31 browser-level checks pass, the four-stage demo runs clean,
and stored evidence re-verifies at 220 invariants.

| Dimension | Result |
|---|---|
| Build/install from scratch | PASS (12 s, no conflicts) |
| Test suite | **1133 passed** (69 files, 2 m 25 s) |
| One-command launch (`./run.sh`) | PASS |
| Frontend ↔ backend integration | PASS (real HTMX round-trips verified) |
| Main demo workflow (9-cell matrix) | PASS (9 tested / 6 CONFIRMED / 3 SAFE) |
| Safety guards (out-of-scope port) | PASS (rejected, nothing stored) |
| Evidence persistence & re-hash | PASS |

**Readiness: 84 / 100** — see §14. The 16 missing points are entirely
*branch hygiene + doc staleness*, not broken code.

---

## 2. Branch-by-branch analysis

Five remote branches exist. Full history was fetched (`git fetch --unshallow`) so
the ancestry below is real, not an artifact of a shallow clone.

| Branch | Tip | Ahead of `main` | Purpose | Verdict |
|---|---|---|---|---|
| `main` | `c36dda1` | 0 | Merged backend through CP38 | **INCOMPLETE** — no frontend |
| `arena/aa67fa1b` | `5ddeea7` | **0** | README/guide docs | **REDUNDANT** — fully contained in `main` |
| `arena/6ed6ac7f` | `751dc5c` | 0 (behind 82) | Foundation/CI | **OBSOLETE** — behind, no `canarygate/` code |
| `arena/a1fe3757` | `7939d6d` | 18 ahead / 23 behind | UI design exploration | **SUPERSEDED** — divergent |
| **`arena/80050ed6`** | **`f66d179`** | **23 ahead / 0 behind** | **Frontend + CP39–46** | **✅ USE THIS** |

### Detail

**`main` (`c36dda1`)** — the merge of PR #3. Contains the full backend:
`accounts, api, database, evidence, guard, models, network, offline, oracles,
report, scan, scope, seed, spec`, plus `targetlab/`. **No `canarygate/ui/`, no
`run.sh`.** README says to run `uvicorn canarygate.api.app:app` and
`python -m canarygate.demo` — a JSON API and a CLI, no interface.

**`arena/80050ed6` (`f66d179`) — the demonstration baseline.**
Directly on top of `main`, fast-forwardable, 125 files / +22 056 / −455. Adds:
- `canarygate/ui/` — 54 files: FastAPI router, 45 Jinja templates, vendored HTMX
  (no CDN), CSS, JS (landing reel, execution feed, run form, replay).
- `run.sh`, `.env.example`, `docs/RUN_LOCALLY.md`, `docs/UI.md`,
  `docs/FRONTEND_BACKEND_INTEGRATION.md`, checkpoints 39–46.
- `tools/browser_smoke.py` (jsdom harness), hermetic-test fix in `conftest.py`.
- `canarygate/scan/lab_matrix*` (the 9-cell asset matrix).
- **Zero deletions of backend logic.** It is additive, which is why CI is green
  and the merge is clean.

**`arena/a1fe3757` (`7939d6d`) — do not demo.** 18 commits of UI design work
(`intro.html/js/css` cinematic intro, contrast pass, flight-recorder replay). It
is **divergent**: it branched before CP35–38 and therefore **lacks TargetLab
transport, lab-BOLA, lab-SCI and the asset matrix** — i.e. it lacks the entire
flagship demo. `80050ed6` reimplements the landing page (`landing.js`, 11 KB,
Canvas reel) and keeps the product-grade proof pages. Treat `a1fe3757` as design
research; salvage only if you want the `intro.*` assets.

**`arena/6ed6ac7f` (`751dc5c`)** — the original foundation commit. `main` is 82
commits ahead; this branch has no application code. Archive.

**`arena/aa67fa1b` (`5ddeea7`)** — merged as PR #3. `main` == this branch's tree.
Nothing to do.

### Branch comparison matrix

| Branch | Build/Run | Tests | Frontend | Backend | Lab/Matrix | Recommendation |
|---|---|---|---|---|---|---|
| `main` | API only | 61 files | ❌ none | ✅ CP38 | ✅ | Do not demo |
| `80050ed6` | ✅ full | ✅ 1133 pass | ✅ 77 routes | ✅ identical to `main` | ✅ 9-cell | **DEMO THIS** |
| `a1fe3757` | ✅ full | ✅ | ✅ (+intro) | ⚠️ older | ❌ none | Archive |
| `6ed6ac7f` | ⚠️ | — | ❌ | ❌ | ❌ | Archive |
| `aa67fa1b` | = `main` | — | ❌ | ✅ | ✅ | Already merged |

### Conflicts

None. `main` is a direct ancestor of `80050ed6` (`git rev-list --left-right
--count main...80050ed6` → `0 23`). The merge is a **fast-forward-quality**
operation; there is no conflicting implementation to reconcile.

---

## 3. Recommended branch and commit

**`arena/80050ed6-hackfusion-30102026` @ `f66d179`**
("CP46: one command to run it, and the three failing tests root-caused")

Why:
1. **Superset of `main`** — every backend capability plus the entire product UI.
2. **CI proven** — `tests (ubuntu-latest, 3.11)` pass 2 m 09 s,
   `tests (windows-latest, 3.11)` pass 5 m 49 s. Both OSes, on the exact commit.
3. **Reproduced by this audit** — 1133 tests, 31/31 browser checks, 4-stage demo,
   9-cell matrix, `run.sh --doctor` clean.
4. **Self-healing demo** — `run.sh` waits for real readiness, reuses an existing
   lab, cleans up on every exit path, and fails loudly with instructions.
5. **Honest by construction** — the docs and the UI both refuse to present
   untested cells as SAFE.

**Approval needed to merge PR #4** (per your instructions I have not merged).
Recommended command:

```bash
gh pr merge 4 --merge      # MERGEABLE / CLEAN / both checks green
```

After the merge, `main` becomes the demo branch and `RUN_LOCALLY.md`'s promise
("Once pull request #4 is merged, `git switch main` has the same content") is true.
Until then, **every clone instruction must say `git switch
arena/80050ed6-hackfusion-30102026`.**

---

## 4. Complete architecture

```
                        ┌──────────────────────────────────────────┐
  Browser ────HTTP────► │  canarygate/ui/app.py                    │
  (Jinja + HTMX,        │  create_ui_app() = backend app +         │
   no CDN, no CDN JS)   │  StaticFiles + ui router   (:8000)       │
                        └───────────────┬──────────────────────────┘
                                        │ in-process, same app object
                        ┌───────────────▼──────────────────────────┐
                        │  canarygate/api/app.py  (37 routes)      │
                        │  /api/health  /api/scan  /api/lab-*-scans│
                        │  /api/authorization-matrix  /api/reports │
                        └───────┬──────────────────────┬───────────┘
                                │                      │
              ┌─────────────────▼──────┐     ┌─────────▼──────────────┐
              │ scope/authorized.py    │     │ database/*.py          │
              │ AuthorizedScope        │     │ 10 SQLite tables       │
              │ (YAML, safe-load,      │     │ hash + redact +        │
              │  alias rejection)      │     │ re-validate on read    │
              └─────────────────┬──────┘     └────────────────────────┘
                                │
              ┌─────────────────▼──────────────────────────────────┐
              │ guard/run_guard.py + network/targetlab.py          │
              │ THE ONLY EXECUTION BOUNDARY. Every request —       │
              │ auth, discovery, reads — passes here immediately   │
              │ before the socket exists. stdout 0 retries,        │
              │ redirects off, literal-IP pinning, no resolver.    │
              └─────────────────┬──────────────────────────────────┘
                                │  HTTPS + pinned test CA
              ┌─────────────────▼──────────────────────────────────┐
              │ targetlab/ (:8765, loopback, TLS, DELIBERATELY     │
              │ VULNERABLE)  — 3 accounts, 3 assets, /records/{id},│
              │ /records/{id}/secure, /records/{id}/guarded        │
              └─────────────────┬──────────────────────────────────┘
                                │ observations (status, bounded body facts)
              ┌─────────────────▼──────────────────────────────────┐
              │ oracles/read_bola.py · oracles/interaction.py      │
              │ PURE FUNCTIONS: evidence in → verdict + checklist. │
              │ 8 conditions; fail closed; "SAFE" must be earned.  │
              └─────────────────┬──────────────────────────────────┘
                                │
     ┌──────────────────────────┼─────────────────────────────┐
     ▼                          ▼                             ▼
 SQLite store            report projections             authorization matrix
 (lab_bola_runs,        (sections, nine-section        (endpoint × column,
  lab_sci_runs,          P0 report, HTML pages)         asset 3×3 grid)
  lab_sci_resets)                                        untested ≠ SAFE
```

### Component contract table

| Component | Does what | Location | Input | Processing | Output | Depends on |
|---|---|---|---|---|---|---|
| UI app | Serves HTML, mounts API | `canarygate/ui/app.py` | HTTP form/GET | Jinja render, HTMX fragments | HTML | api app |
| UI routes | 77 routes, 10 actions | `canarygate/ui/routes.py` | Form fields | Calls **the same handler functions** the JSON API uses | HTML/303 | api, stores |
| Execution engine | Live job feed | `canarygate/ui/execution.py` | job id | Server-sent polling of stages | JSON events | scan modules |
| JSON API | 37 routes | `canarygate/api/app.py` | JSON | Validates Pydantic models, threads to stores | JSON | all |
| Scope loader | Parses authorization YAML | `canarygate/scope/authorized.py` | YAML | Safe load, **rejects anchors/aliases** | `AuthorizedScope` | — |
| Safety guard | Authorizes each request | `guard/run_guard.py`, `guard/policy.py` | request intent | method/scope/budget check | allow \| refuse | scope |
| Lab transport | Connects without DNS | `network/targetlab.py` | host, port | `ssl`-wrapped socket to literal IP | raw HTTP | guard |
| Oracles | Decide verdicts | `oracles/read_bola.py`, `interaction.py` | observations | Pure function, 8 gates | verdict+checklist | — |
| Stores | Persist + verify | `database/*.py` | run object | hash, redact, re-validate | sqlite rows | — |
| Reports | Project evidence | `report/*.py` + `templates/` | stored run | Deterministic re-render | HTML/JSON | stores |
| Matrix | Coverage grid | `scan/lab_matrix.py` | stored runs | Post-verdict scoring | 9 cells | stores |
| TargetLab | Vulnerable target | `targetlab/` | HTTPS | Deliberate BOLA/SCI bugs | JSON | — |

---

## 5. How the project actually works

**Problem solved.** Sharing a URL like `/records/BRD-2026-018` and getting a 200
is *not* proof of broken authorization — the object may be public, shared, or
your own. Most scanners stop there and produce false positives. CanaryGate
demands a *chain*: verified ownership, owner baselines, a request proven to be the
one answered, and the owner's own private marker in the response.

**Intended user.** An application-security engineer or pentester validating one
API they are authorized to test — not a mass internet scanner.

**What happens when you open it.**
1. `GET /` → cinematic landing page (Canvas reel, `Escape`/`Skip intro`).
2. `Enter CanaryGate` → `/ui/` dashboard. On a fresh DB every tile is `0` and the
   matrix is `0 / 9` — the page says *nothing has been scanned on this database*.
   That is correct behaviour, not a bug.
3. `New run` → `/ui/assessment`: one form, four steps, correct defaults
   (AssetVault/TargetLab, `mallapa → sakshi`, port `8765`).
4. `Run security assessment` → `POST /ui/actions/run-assessment` → 303 →
   `/ui/execution/{id}`: a live feed of every real HTTPS request (method, path,
   the lab's own status, latency), a stage tracker, requester→lab→resource diagram.
5. Three account pairs run (54 requests). Page says *Assessment complete*.
6. Matrix: **9 tested / 0 untested, 6 CONFIRMED, 3 SAFE.** Every cell links to its
   run, check, evidence SHA-256, requester, owner, asset, remediation.

**Frontend ↔ backend.** One process, one FastAPI object. `create_ui_app()` calls
`create_backend_app()` and *attaches* a router + static mount; it does not patch
or fork any backend file. The UI calls the same handler functions the JSON routes
call, so there is no duplicated business logic and no second network path.

**Data.** SQLite, 10 tables. `lab_bola_runs` (3 rows after a full demo),
`lab_sci_runs`, `lab_sci_resets`, plus fixture/scenario/authn/validation/interaction.
Every row stores a SHA-256; reading it back recomputes and refuses mismatch
(`EvidenceIntegrityError` → HTTP 500).

**Algorithms / models.** None. There is **no LLM and no ML** — deliberately
(`JUDGE_DEFENCE.md` §3: "non-deterministic evidence is not evidence"). The
intelligence is *rule-based evidence chaining* (8 gates for BOLA, a control-pair
state machine for SCI) plus SHA-256 tamper-evidence. **Do not claim AI.**

**External services.** None. No cloud, no API keys, no CDN, no telemetry. The lab
CA is a public local fixture. This is a major demo strength — it runs offline.

---

## 6. Technology stack

| Layer | Choice | Why (verified in code) |
|---|---|---|
| Language | Python 3.11 (pins `>=3.11,<3.14`) | 3.14 breaks; tested 3.11.2 |
| Web | FastAPI 0.115.12 | Evidence schema *is* the contract |
| Models | Pydantic 2.10.6, strict | Reject extras, coerce nothing, fail closed |
| Server | Uvicorn 0.34.2 | — |
| Templates | Jinja2 3.1.6, 45 templates | Renders with zero network |
| Frontend | Vendored HTMX + vanilla JS | No CDN ⇒ works air-gapped |
| Storage | SQLite (stdlib) | Single inspectable file, hashable |
| HTTP | HTTPX 0.28.1 + stdlib `ssl` | `trust_env=False`, no redirects |
| YAML | PyYAML 6.0.2 safe_load | Alias/anchor rejected pre-parse |
| Tests | pytest 8.3.5 | 1133 tests, 69 files, 13 946 LOC |
| CI | GitHub Actions | Ubuntu **and** Windows, Python 3.11 |

Scale: 17 905 LOC app / 13 946 LOC tests — a 0.78 test-to-code ratio.

---

## 7. Installation guide (verified)

Requires **Python 3.11–3.13** and Git. Nothing else. No Docker in this repo
(there is no `Dockerfile` or `compose.yaml` — do not tell judges there is one).

```bash
git clone https://github.com/Ace-095/Hackfusion_30102026.git
cd Hackfusion_30102026
git switch arena/80050ed6-hackfusion-30102026   # <-- MANDATORY until PR #4 merges
```

**Why:** on `main` the next steps produce a server with no interface.

```bash
python3.11 -m venv .venv
source .venv/bin/activate            # Windows: .\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

`requirements.txt` is one line — `-e .[test]` — so it installs the package in
editable mode plus pinned runtime deps. **Expected:** no errors, ~12 s.
**Common failure:** `python3.11: command not found` → install 3.11, or use
`py -3.11` on Windows. `externally-managed-environment` → you forgot the venv.

Verify:

```bash
python -c "from canarygate.ui.app import app; print(len(app.routes))"   # 77
python -c "from canarygate.api.app import app; print(len(app.routes))"  # 37
```

> Note: `docs/RUN_LOCALLY.md` says `UI routes: 75`. Actual is **77**. Cosmetic doc
> drift — say 77.

Database: **nothing to do.** SQLite tables are created by the FastAPI lifespan on
first start, at `CANARYGATE_DB_PATH` (default `.canarygate/fixture.sqlite3`).
There are no migrations. To reset: delete the file.

---

## 8. Running guide (verified)

### One command (recommended for judges)

```bash
./run.sh --doctor     # checks only, starts nothing
./run.sh              # lab + website + browser
```

`run.sh` resolves its own directory (works anywhere), prefers `.venv/bin/python`
by **absolute path** (so an activated conda env cannot hijack it), waits on real
`/health` + `/api/health` rather than sleeping, **reuses** a lab already on the
port, and `trap cleanup EXIT` guarantees no orphan process holds the port.

Observed output (this audit):

```
▸ Project      /tmp/cg-front   python: .venv/bin/python (Python 3.11.2)
               ✓ canarygate imports from this checkout
▸ TargetLab    ✓ running on https://127.0.0.1:8765 (pid 3641)
▸ Configuration ✓ pinned test CA; database at .canarygate/canarygate.sqlite3
▸ CanaryGate website  $ uvicorn canarygate.ui.app:app --host 127.0.0.1 --port 8000
```

| Flag | Effect |
|---|---|
| `./run.sh` | start both, open browser |
| `./run.sh --no-browser` | print URL only |
| `./run.sh --doctor` | diagnostics, starts nothing |
| `./run.sh --tests` | full suite with demo env |
| `./run.sh --stop` | stop what it started |

Env overrides: `LAB_PORT`, `UI_PORT`, `CANARYGATE_PYTHON`, `BROWSER=none`.

### Manual (two terminals) — use this if the script misbehaves

**Terminal A — the lab**
```bash
python -m targetlab --port 8765 \
  --tls-cert tests/fixtures/tls/targetlab-cert.pem \
  --tls-key  tests/fixtures/tls/targetlab-key.pem
```
Expected: `targetlab: DELIBERATELY VULNERABLE test API on https://127.0.0.1:8765 (loopback only, do not deploy)`

**Terminal B — the product**
```bash
export CANARYGATE_TARGETLAB_CA=tests/fixtures/tls/targetlab-cert.pem
export CANARYGATE_DB_PATH=.canarygate/judge-demo.sqlite3
python -m uvicorn canarygate.ui.app:app --host 127.0.0.1 --port 8000
```

Then open **http://127.0.0.1:8000** — plain `http`, and `127.0.0.1` **not**
`localhost` (the fixture certificate is issued to the IP literal).

### Verification URLs

| What | URL | Expected |
|---|---|---|
| Lab health | `https://127.0.0.1:8765/health` | `{"status":"ok","deliberately_vulnerable":true,...}` |
| API health | `http://127.0.0.1:8000/api/health` | `{"status":"ok","mode":"fixture","live_scanning":false}` |
| Dashboard | `http://127.0.0.1:8000/ui/` | overview tiles |
| Lab catalog | `http://127.0.0.1:8000/api/lab-catalog` | 3 accounts, 3 assets |
| OpenAPI | `http://127.0.0.1:8000/openapi.json` | 17 path schemas |

`/docs` and `/redoc` are **disabled on purpose** — their default assets come from
a CDN. Do not promise Swagger UI.

### Environment variables

| Variable | Required | Purpose |
|---|---|---|
| `CANARYGATE_TARGETLAB_CA` | **yes**, for any TargetLab run | path to pinned test cert |
| `CANARYGATE_DB_PATH` | no | SQLite file (default `.canarygate/fixture.sqlite3`) |

There is **no `.env` loader** and **no credentials in the repo**. Fixture scan,
offline scenarios, spec upload and all reporting work **without any env var** —
useful as your fallback demo (§11).

---

## 9. Verified functionality

Run on `f66d179`, Python 3.11.2, fresh venv.

| # | Component | Verification method | Expected | Actual | Status |
|---|---|---|---|---|---|
| 1 | Install | `pip install -r requirements.txt` | clean | clean, 12 s | **VERIFIED WORKING** |
| 2 | Import | route counts | 77 / 37 | 77 / 37 | **VERIFIED WORKING** |
| 3 | Test suite | `pytest -q` | all pass | **1133 passed**, 2 m 25 s | **VERIFIED WORKING** |
| 4 | P0 audit | `tools/p0_audit.py` | 0 unreachable | 58 reqs, 47 impl / 9 partial / 2 missing, 0 unreachable | **VERIFIED WORKING** |
| 5 | Lab boot | `python -m targetlab` | listen 8765 | HTTPS up, banner printed | **VERIFIED WORKING** |
| 6 | Lab health | `curl --cacert .../health` | ok | `deliberately_vulnerable:true` | **VERIFIED WORKING** |
| 7 | UI boot | `uvicorn canarygate.ui.app:app` | listen 8000 | up | **VERIFIED WORKING** |
| 8 | API health | `GET /api/health` | ok | `{"mode":"fixture","live_scanning":false}` | **VERIFIED WORKING** |
| 9 | All 16 UI pages | GET each | 200 | **16/16 → 200** | **VERIFIED WORKING** |
| 10 | Static assets | css/js/htmx | 200 | 3/3 → 200 | **VERIFIED WORKING** |
| 11 | Fixture scan | `POST /api/scan` | 201 | 201, run stored | **VERIFIED WORKING** |
| 12 | **read-BOLA scan** | `POST /api/lab-bola-scans {port:8765}` | CONFIRMED | `CONFIRMED`, 2 of 6 cross-account, 18 requests | **VERIFIED WORKING** |
| 13 | BOLA run read | `GET /api/lab-bola-scans/{id}` | 200 | 200 | **VERIFIED WORKING** |
| 14 | BOLA report | `GET .../{id}/report` | 200 | 200 | **VERIFIED WORKING** |
| 15 | BOLA UI pages | `/ui/lab/bola/{id}[/report]` | 200 | 200 / 200 | **VERIFIED WORKING** |
| 16 | SCI scan | `POST /api/lab-sci-scans` | CONFIRMED | `interaction_induced` | **VERIFIED WORKING** |
| 17 | **Judge demo action** | `POST /ui/actions/lab-demo-run` | 9/0 | **9 tested, 6 CONFIRMED, 3 SAFE, 0 untested** | **VERIFIED WORKING** |
| 18 | Assessment action | `POST /ui/actions/run-assessment` | 303 | 303 → execution page, 3 runs stored | **VERIFIED WORKING** |
| 19 | Matrix | `GET /api/lab-matrix` | 9 cells | 9 cells, evidence SHA-256 each | **VERIFIED WORKING** |
| 20 | Authorization matrix | `GET /api/authorization-matrix` | 4 columns | anon/own/other/role | **VERIFIED WORKING** |
| 21 | SQLite persistence | inspect file | rows written | 10 tables, expected rows | **VERIFIED WORKING** |
| 22 | Tamper-evidence | `tools/consistency_audit.py --database ...` | intact | **220 invariants, all intact** | **VERIFIED WORKING** |
| 23 | Four-stage demo | `tools/demo.py` | 142 invariants | **142 invariants / 17 surfaces** | **VERIFIED WORKING** |
| 24 | Browser smoke | `tools/browser_smoke.py --jsdom` | 31/31 | **31/31 passed** | **VERIFIED WORKING** |
| 25 | Safety: port 443 | POST lab scan | reject | 422, `>= 1024` | **VERIFIED WORKING** |
| 26 | Safety: dead port 9999 | POST lab scan | refuse, store nothing | 502 "could not be reached; no evidence was stored" | **VERIFIED WORKING** |
| 27 | `./run.sh --doctor` | run it | clean | clean | **VERIFIED WORKING** |
| 28 | `./run.sh` clean start | run it | both ports | both ports, lab reused/started | **VERIFIED WORKING** |
| 29 | `main` has the app | `git ls-tree main canarygate/` | ui | **no `ui/`, no `run.sh`** | **FAILED** |
| 30 | Real browser pixels | Chromium | visual | no browser binary in sandbox | **NOT TESTED** |
| 31 | VAmPI / crAPI profiles | scan | — | preparation only, organizer approval required | **BLOCKED** (by design) |

---

## 10. Bugs and required fixes

### P0 — must fix before demo

**P0-1 · `main` ships no application.**
*What:* `main` (`c36dda1`) has no `canarygate/ui/`, no `run.sh`, no `.env.example`.
*Why:* work sits unmerged in PR #4.
*File:* repo state / PR #4.
*Fix:* `gh pr merge 4 --merge` (MERGEABLE, CLEAN, both CI green).
*Verify:* on `main`, `ls canarygate/ui run.sh` succeeds and `/ui/` returns 200.
**Until merged: always demo from `arena/80050ed6-hackfusion-30102026`.**

**P0-2 · Wrong branch in your own clone.**
*What:* a fresh clone lands on `main` and shows a JSON API only.
*Fix:* `git switch arena/80050ed6-hackfusion-30102026` — put it on a sticky note.
*Verify:* `./run.sh --doctor` prints `branch  …` and `/ui/` renders.

*(No other P0 issues were found. The application itself starts and runs cleanly.)*

### P1 — fix if time permits

**P1-1 · Doc/route count drift.** `docs/RUN_LOCALLY.md` and `README` say
`UI routes: 75`; actual **77**. `JUDGE_DEFENCE.md` opens with "1055 tests pass";
actual **1133**. Tests quoted as 1113 in `RUN_LOCALLY.md` §7.
*Fix:* update three numbers, or simply *say the measured number* if a judge asks.
*Verify:* `python -c "from canarygate.ui.app import app; print(len(app.routes))"`

**P1-2 · `README.md` on the demo branch still leads with "offline backend
checkpoint".** The first line a judge reads says "this is not a complete
implementation". That is honest but undersells a working product. Keep the
honesty, move it below a two-line "what this is" intro.

### P2

**P2-1 · Swagger/ReDoc disabled.** `/openapi.json` works (17 paths), `/docs`
does not. Do not offer `/docs` to a judge. If you want a visual API proof, use
`/openapi.json` or `curl`.

**P2-2 · `run.sh` advertises a URL that 404s.** Line 289 prints
`API docs  http://127.0.0.1:8000/docs`, but `canarygate/api/app.py:787` sets
`docs_url=None, redoc_url=None` (deliberately — the default Swagger assets come
from a CDN). A judge who clicks that link during the demo gets `{"detail":"Not
Found"}`.
*Why:* the banner text was not updated when the docs routes were disabled.
*Fix (one line in `run.sh`):* replace `/docs` with `/openapi.json`.
*Verify:* `curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/openapi.json` → `200`.
**Do not click "API docs" in the banner until this is patched.**

**P2-3 · `consistency_audit.py` needs `--database`** and exits 2 with a sentence
for an empty/missing DB. Expected, but know it before you run it live.

### P3

**P3-1 · `GET /api/inventory` and `/api/lab/catalog` do not exist.** Correct
paths are `/api/endpoints` and `/api/lab-catalog`. (Non-slash nesting.)
**P3-2 · `run.sh` binds `127.0.0.1` only.** By design (safety), but it means you
cannot show it from another machine / phone. Demo on the laptop itself.

---

## 11. Judge demonstration script

### A. Before the demonstration

| Item | Ready |
|---|---|
| Branch | `arena/80050ed6-hackfusion-30102026` (or `main` post-merge) |
| `.venv` built, `pip install -r requirements.txt` done **that morning** |
| `./run.sh --doctor` run, output clean, ports 8000/8765 free |
| Two terminal tabs at repo root, both `.venv` activated |
| Browser tab 1: `http://127.0.0.1:8000` (landing). Tab 2: `http://127.0.0.1:8000/api/health` |
| Second browser tab pre-warmed at `/ui/lab/matrix` |
| Fresh DB: `rm -f .canarygate/judge-demo.sqlite3` so the `0 / 9` story is honest |
| `./run.sh --tests` run once the night before (1133 passed) |
| Backup A: `python tools/demo.py` — one command, spins its own lab, prints 142 invariants, needs no browser |
| Backup B: `python -m uvicorn canarygate.api.app:app --port 8001` + `curl` — no lab, no UI needed |
| Backup C: 5 screenshots + `tools/demo.py` output in a text file |
| Do **not** rely on: `/docs`, Docker, any internet connection, any API key |

### B. Live demonstration (3 minutes)

| # | You do | On screen | Technically | Say | Proves |
|---|---|---|---|---|---|
| 1 | Open `http://127.0.0.1:8000` | Landing: "Every request has a boundary. Every finding needs proof." | Static Jinja + Canvas reel, zero external requests | "CanaryGate tests API *authorization* — who can read what." | Product exists, offline-capable |
| 2 | `Escape` → `Enter CanaryGate` | Dashboard, all tiles `0`, matrix `0 / 9`, "nothing has been scanned on this database" | GET `/ui/` | "Empty state on purpose: untested is never SAFE." | Honest design, not a demo hack |
| 3 | Note the lab: *"the thing on 8765 is a deliberately vulnerable API I built to be a target"* | — | `targetlab/` | "I need a safe target, so I wrote one — loopback TLS, never deployable." | You built the test fixture |
| 4 | `New run` → `/ui/assessment` → **Run security assessment** | Live feed: `GET /records/BRD-2026-018` → `200` … 54 requests, stages ticking | `POST /ui/actions/run-assessment`; real HTTPS via guard | "Every line is a real request — method, path, the lab's own status, latency." | Real integration, not mocked |
| 5 | Wait ~10 s | *Assessment complete* | job polling | "Three account pairs, six checks each." | Bounded, sequential |
| 6 | Click into matrix | **9 tested / 0 untested · 6 CONFIRMED · 3 SAFE** | `/api/lab-matrix` | "Six confirmed cross-account leaks, three safe." | The finding |
| 7 | Open a CONFIRMED cell | requester `mallapa`, owner `sakshi`, asset `BRD-2026-018`, `LAB-BOLA-03`, `200`, evidence SHA-256 | stored run projection | "This is not 'got a 200'. I proved mallapa's own asset, proved sakshi's baseline, then showed the response carried sakshi's private marker." | **The differentiator** |
| 8 | Open its secure twin | `LAB-BOLA-05`, `403`, SAFE | `oracles/read_bola.py` | "Same object, secure route, denied. So the leak is object-level authorization, not a public object." | Control comparison |
| 9 | Open SCI proof | `403` alone → `401` alone → **`200` combined**; verdict `interaction_induced`; reset `403→401→200→403` | control-pair state machine | "Each control passes alone. Their *interaction* leaks. Almost no scanner reports that." | **Signature result** |
| 10 | Terminal B: `python tools/consistency_audit.py --database .canarygate/judge-demo.sqlite3` | `220 invariants … ALL STORED RUNS INTACT AND CONSISTENT` | re-hash + rebuild every projection | "Every verdict re-derives from stored evidence." | Tamper-evidence |
| 11 | Kill the lab (Ctrl+C in A), run an assessment again | *Assessment did not complete* + reason + the command to start the lab + Try again. Matrix unchanged | fail-closed | "Failure is never a verdict. A connection error is not SAFE." | Honest failure |

### C. Technical proof (if the judge pushes)

```bash
# the finding, as JSON, straight from the API
curl -s -X POST http://127.0.0.1:8000/api/lab-bola-scans \
     -H 'content-type: application/json' -d '{"port": 8765}' | head -c 600

# the stored evidence
sqlite3 .canarygate/judge-demo.sqlite3 \
  "select count(*) from lab_bola_runs;"        # 3 after a full demo
```

Then read one `evidence_sha256` and say: *"that digest is recomputed on read; if a
row is edited, the API returns 500 instead of a report."*

### D. Presentation blocks

**30-second intro.** "CanaryGate is an evidence-based authorization tester for
APIs. Scanners usually stop at 'I got a 200 where I shouldn't'. That's not proof —
the object might be public or shared. CanaryGate only calls something CONFIRMED
when it has proven which asset each account owns, proven each owner's baseline,
and matched the owner's own private marker in a cross-account response. It also
finds control-interaction bugs, where two controls each pass alone but leak
together."

**1-minute technical.** "FastAPI and Pydantic v2 strict models on one process; the
UI is a router attached to the same app object, so there is one code path. SQLite
with SHA-256 per record, re-verified on read. Every outbound request passes one
guard immediately before the socket is created — redirects off, no DNS resolver
(literal-IP pinning), sequential, bounded budget. The oracles do no I/O: evidence
in, verdict plus checklist out, so any verdict re-derives deterministically. 1133
tests, 58 audited requirements, 47 implemented, and the two missing ones are named
in the audit tool."

**3-minute demo.** Use the 11-step table above, cut steps 3 and 11 if tight.

**Architecture in one line.** "UI → same FastAPI app → guard → loopback TLS lab →
observations → pure oracles → SQLite → projections that are checked against each
other."

**Most impressive verified features.** (1) 8-gate evidence chain — no 200-only
findings. (2) SCI attribution with a four-step reset proof. (3) 220 invariants
re-verified over stored evidence. (4) `run.sh`: one command, self-cleaning,
refuses to bind publicly. (5) 31/31 browser checks incl. real HTMX round-trips.

**Practical value.** Cuts false positives in API auth testing, which is OWASP API
#1 (BOLA). Audit teams can hand a regulator a re-verifiable evidence chain instead
of a scanner PDF.

---

## 12. Likely judge questions (with honest answers)

**Q: Is this AI?**
*15 s:* "No, deliberately. Verdicts must be deterministic — an LLM's opinion isn't
evidence. The intelligence is rule-based evidence chaining plus SHA-256
tamper-evidence." *Detail:* `docs/JUDGE_DEFENCE.md` §3. *Follow-up:* "Would you add
AI?" → "Only for triage/prioritisation after the verdict, never to produce it."

**Q: Your target is a lab you wrote. Isn't that circular?**
*15 s:* "Yes — and I say so on every surface. It's a regression target, not a
customer finding. The scanner is what generalises; the lab proves the pipeline end
to end." *Detail:* `targetlab/`, `docs/TARGETLAB.md`. *Follow-up:* "Have you run it
on a real API?" → "Prepared profiles for VAmPI and crAPI exist; running them needs
written organizer approval, so I have not. That is one of the two 'missing' rows in
my own audit."

**Q: Only two accounts, one endpoint class. Is that a real scanner?**
*Honest:* "No. It's one oracle done properly. BFLA role-vs-policy is the missing
piece, and my audit tool names it (D11), rather than hiding it."

**Q: How do you prevent it being used maliciously?**
*15 s:* "Exact authorized scope file, one guard before every socket, DELETE always
blocked, PUT/PATCH blocked by default, no redirects, no DNS, bounded budget, live
external scanning disabled." *Detail:* `guard/`, `scope/authorized.py` §23 of the
spec. *Follow-up:* "Could I point it at example.com?" → "Port must be ≥1024 and the
origin is the loopback lab with a pinned CA; there is no code path to a public host."

**Q: Show me a 200 that is NOT a vulnerability.**
*Strong answer:* the SECURE twin `LAB-BOLA-05` returns 403/Safe while
`LAB-BOLA-04` returns 200/Confirmed on the *same object* — and cells where an owner
reads their own record are SAFE despite a 200.

**Q: What's your weakest point?**
*Honest:* "Branch hygiene. The whole frontend sat in an unmerged PR while `main`
looked finished. And three doc numbers are stale. The engine is solid; the release
process was the risk." (This scores well — it is the actual finding of this audit.)

**Q: Performance?**
No load testing exists. Sequential by design (safety). One full demo = 54 requests
in ~10 s on loopback. Say that; do not invent numbers.

**Q: Security of your own app?**
Unauthenticated, local-only server — stated in the README. No secrets in repo, no
`.env` loader, fixture cert is public. `Identity.token` is excluded from Pydantic
serialization, though the docs honestly say that is not a complete redaction system.

---

## 13. Your technical learning path (in this order)

1. **`docs/JUDGE_DEFENCE.md` (347 lines)** — read twice. It is the whole project in
   prose, with the file behind every claim. This is your single best study asset.
2. **BOLA in plain words** — an API returns record #7 to a user who owns record #12,
   because it checks *logged in* but not *owner*. Then read
   `oracles/read_bola.py` and name its 8 gates out loud.
3. **Why a 200 is not proof** — public object, shared object, own object, cached
   copy. This is the sentence that wins the demo.
4. **The guard** — `guard/run_guard.py`. Follow one request from UI click to socket.
   Then explain "one execution boundary".
5. **Evidence chain + hashing** — `database/store.py`: write hashed, read re-hashed,
   mismatch → 500.
6. **SCI** — `oracles/interaction.py`. Two controls pass alone, fail together.
   Practise the 403→401→200 sequence until it is natural.
7. **Projections** — one evidence set, five views, and a test that they agree.
8. **Self-test:** explain, without notes, (a) why the matrix starts at `0 / 9`,
   (b) what `interaction_induced` means, (c) what happens when the lab is down.

If a concept does not land, say so and I will re-explain it with a different
analogy and quiz you back.

---

## 14. Final readiness checklist

| # | Item | State |
|---|---|---|
| 1 | Correct branch selected | ⚠️ **`main` is wrong** — use `arena/80050ed6…` or merge PR #4 |
| 2 | Dependencies installed | ✅ verified from scratch |
| 3 | Environment configured | ✅ `CANARYGATE_TARGETLAB_CA` is the only must-have |
| 4 | Database initialised | ✅ auto-created by lifespan, 10 tables |
| 5 | Backend starts | ✅ 37 routes |
| 6 | Frontend starts | ✅ 77 routes, 16/16 pages 200 |
| 7 | Frontend ↔ backend | ✅ same process, real HTMX round-trips |
| 8 | Main workflow works | ✅ 9 tested / 6 CONFIRMED / 3 SAFE |
| 9 | Core features verified | ✅ BOLA, SCI, fixture, matrix, reports |
| 10 | No critical runtime errors | ✅ none observed |
| 11 | Demo data prepared | ⚠️ reset the DB and rehearse the `0 / 9` → `9 / 9` arc |
| 12 | Demo sequence rehearsed | ⚠️ rehearse the 11 steps twice |
| 13 | Backup plan | ✅ `tools/demo.py` + curl-only path |
| 14 | Technical questions reviewed | ⚠️ §12 above — drill the "is this AI" and "circular lab" answers |
| 15 | Known limitations documented | ✅ `tools/p0_audit.py`: 47 impl / 9 partial / 2 missing |

### **Readiness: 84 / 100**

Deductions: −8 branch/demo baseline (PR #4 unmerged, wrong default branch),
−4 doc staleness (75 vs 77 routes, 1055/1113 vs 1133 tests),
−2 no real-browser visual verification in this sandbox,
−2 limitations are real and must be spoken honestly (BFLA D11, live target D12).

**Reach 95+ by:** merging PR #4, correcting the three numbers, clearing the DB,
and rehearsing the 11-step script twice.
