# Running CanaryGate on your own machine (VS Code)

Every command on this page was executed on a clean checkout with a fresh virtual
environment before it was written down. If a command fails for you, the
**Troubleshooting** table at the end lists the causes we actually hit.

## The fastest path: `./run.sh`

From the project folder, one command starts everything, waits for it to be healthy,
and opens the browser:

```bash
cd "/home/ace/95/Hackathon/Hackfusion oct302026/Hackfusion_30102026"
source .venv/bin/activate          # optional — the script prefers .venv by itself
./run.sh
```

It prints exactly what it ran, then opens **http://127.0.0.1:8000/ui/**.

| Command | What it does |
|---|---|
| `./run.sh` | start TargetLab + the website, open the browser |
| `./run.sh --no-browser` | same, but just print the URL |
| `./run.sh --doctor` | check Python, dependencies, fixtures, ports and imports — starts nothing |
| `./run.sh --tests` | run the full suite with the demo environment set |
| `./run.sh --stop` | stop a run the script started (Ctrl+C does the same) |

Useful switches (all optional):

```bash
LAB_PORT=8767 ./run.sh        # lab on another port (the script tells you what to type)
UI_PORT=8010 ./run.sh         # website on another port if 8000 is taken
CANARYGATE_PYTHON=/home/ace/95/lrng/cl/python/canarygate/bin/python ./run.sh
BROWSER=none ./run.sh         # same as --no-browser
```

If a TargetLab is **already** running on the chosen port and answers `/health` with the
pinned CA, the script reuses it instead of starting a second one — so it is safe to run
next to the terminal you already have open.

The rest of this page is the manual path, which is what `./run.sh` does for you, plus
what to do when something goes wrong.

---

There are two processes and they are deliberately separate:

| Process | What it is | Where |
|---|---|---|
| **TargetLab** | a deliberately vulnerable API over HTTPS | `127.0.0.1:8765`, loopback only |
| **CanaryGate** | the product: JSON API + the HTML interface | `127.0.0.1:8000` |

CanaryGate never sends your browser to the lab. You submit a *port* to CanaryGate
and CanaryGate makes the guarded requests itself.

---

## 0. Prerequisites

- **Python 3.11** (3.12 and 3.13 also work; 3.14 does not — `pyproject.toml` pins
  `>=3.11,<3.14`).
- **Git**.
- Optional, only for the browser smoke test: **Node.js 18+**.

Check what you have:

```bash
python3 --version        # macOS / Linux
py -3.11 --version       # Windows PowerShell
```

## 1. Get the code

```bash
git clone https://github.com/Ace-095/Hackfusion_30102026.git
cd Hackfusion_30102026
git switch arena/80050ed6-hackfusion-30102026
```

If you already have a clone, just `git fetch origin` and switch to that branch.
Once pull request #4 is merged, `git switch main` has the same content.

## 2. Create the virtual environment

**macOS / Linux**

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

**Windows PowerShell**

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

<details>
<summary>PowerShell says "running scripts is disabled on this system"</summary>

Use the interpreter directly — no activation needed:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pytest -q
```

(To fix it permanently: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.)
</details>

Confirm the install:

```bash
python -c "from canarygate.ui.app import app; print('UI routes:', len(app.routes))"
python -c "from canarygate.api.app import app; print('API routes:', len(app.routes))"
```

Expected: `UI routes: 75` and `API routes: 37`.

## 3. Point VS Code at the environment

1. `Ctrl+Shift+P` (macOS: `Cmd+Shift+P`) → **Python: Select Interpreter** →
   choose `.venv` in the repository folder.
2. Open a terminal with `Ctrl+`` (backtick). VS Code should show `(.venv)` in the
   prompt. If not, run the activation command from step 2 in that terminal.

You need **two terminals** — one per process. Use the split button in the
terminal panel (`Ctrl+Shift+5`).

## 4. Terminal A — start TargetLab

macOS / Linux:

```bash
python -m targetlab --port 8765 \
  --tls-cert tests/fixtures/tls/targetlab-cert.pem \
  --tls-key  tests/fixtures/tls/targetlab-key.pem
```

Windows PowerShell (one line):

```powershell
python -m targetlab --port 8765 --tls-cert tests/fixtures/tls/targetlab-cert.pem --tls-key tests/fixtures/tls/targetlab-key.pem
```

Expected line:

```
targetlab: DELIBERATELY VULNERABLE test API on https://127.0.0.1:8765 (loopback only, do not deploy)
```

Leave it running. Sanity check from a second shell:

```bash
curl --cacert tests/fixtures/tls/targetlab-cert.pem https://127.0.0.1:8765/health
```

```json
{"status":"ok","lab":"targetlab","version":"1.0","deliberately_vulnerable":true, ...}
```

## 5. Terminal B — start CanaryGate

**macOS / Linux**

```bash
export CANARYGATE_TARGETLAB_CA=tests/fixtures/tls/targetlab-cert.pem
export CANARYGATE_DB_PATH=.canarygate/judge-demo.sqlite3
python -m uvicorn canarygate.ui.app:app --host 127.0.0.1 --port 8000 --reload
```

**Windows PowerShell**

```powershell
$env:CANARYGATE_TARGETLAB_CA = "tests/fixtures/tls/targetlab-cert.pem"
$env:CANARYGATE_DB_PATH = ".canarygate/judge-demo.sqlite3"
python -m uvicorn canarygate.ui.app:app --host 127.0.0.1 --port 8000 --reload
```

**Windows cmd.exe**

```bat
set CANARYGATE_TARGETLAB_CA=tests/fixtures/tls/targetlab-cert.pem
set CANARYGATE_DB_PATH=.canarygate\judge-demo.sqlite3
python -m uvicorn canarygate.ui.app:app --host 127.0.0.1 --port 8000 --reload
```

Expected: `Uvicorn running on http://127.0.0.1:8000`. `--reload` restarts on every
file save; drop it for a demo you do not want to interrupt.

Open **<http://127.0.0.1:8000>** in a browser. (Plain `http`, not `https`, and
`127.0.0.1`, not `localhost` — the CA fixture is issued to the IP address.)

## 6. The five-minute judge path

1. **`/`** — the cinematic landing page. `Skip intro` or `Escape` skips it.
   `Enter CanaryGate` → the dashboard.
2. **Dashboard `/ui/`** — on a fresh database every tile reads `0`, the matrix is
   `0 / 9` and the page says *nothing has been scanned on this database*. That is
   correct, not a bug.
3. **`New run` → `/ui/assessment`** — one form in four steps. Defaults are the
   right ones: environment `AssetVault / TargetLab`, pair `mallapa → sakshi`,
   port `8765`.
4. Press **Run security assessment**. The button relabels itself and you land on
   **`/ui/execution/{id}`**: a live feed of every real HTTPS request the engine
   makes (method, path, the lab's own status code, measured milliseconds), a
   stage tracker, and a requester → lab → resource diagram.
5. The demonstration runs three pairs (54 requests). When it finishes the page
   says *Assessment complete* and opens the matrix: **9 tested / 0 untested**,
   6 `CONFIRMED`, 3 `SAFE`.
6. Everything on the dashboard now links into its own page: matrix cells, verdict
   rows, ownership proof, disclosure proof, reports.

Things worth trying deliberately, because they are the honest-failure design:

- **Stop the lab** (Ctrl+C in Terminal A) and run an assessment again. You get
  *Assessment did not complete*, the reason, the port it tried, the command that
  starts the lab, and a **Try again with the same settings** button. Nothing is
  stored and the matrix does not move.
- **Refresh the finished job page**, or open it with JavaScript disabled. The
  outcome is rendered by the server, so it reads the same.
- Clear the database with `rm .canarygate/judge-demo.sqlite3` (Windows:
  `del .canarygate\judge-demo.sqlite3`) and restart CanaryGate for a clean run.

## 7. Tests

All from the repository root, with the virtual environment active.

```bash
python -m pytest -q                      # full suite: 1113 tests, ~2.5 min
```

Faster loops while you read code:

```bash
python -m pytest tests/integration/test_ui_pages.py -q          # dashboard and pages
python -m pytest tests/integration/test_ui_lab_pages.py -q      # TargetLab workflows through the UI
python -m pytest tests/integration/test_ui_execution_outcomes.py -q  # "this stopped" behaviour
python -m pytest tests/lab -q                                   # transport, oracles, adversarial cases
```

The TargetLab tests start their own lab on a free port; **you do not need the lab
or the UI running** for pytest, and the variables from step 2 do not change the result:
`tests/conftest.py` clears every `CANARYGATE_*` variable for each test, so the suite
reports the same verdict in a shell that has exported them and one that has not.

## 8. The audits and the one-command demonstration

```bash
python tools/p0_audit.py
```

```
P0 audit: 58 requirements, 1113 collected tests, 67 test files
status: implemented=47, partial=9, missing=2, unreachable=0
```

The nine partial and two missing rows are the project's real gaps (frozen spec
items D11 and D12 among them). The audit is a gate: it exits non-zero if a test
file is unclassified or a claim has no test.

```bash
python tools/demo.py
```

Starts its own lab and database, runs the four stages, and finishes with:

```
ALL CONSISTENCY CHECKS PASSED (142 invariants over 17 surfaces)
```

To keep the database and re-verify it afterwards:

```bash
python tools/demo.py --keep
# prints: database kept at /tmp/canarygate-demo-xxxx/demo.sqlite3
python tools/consistency_audit.py --database /tmp/canarygate-demo-xxxx/demo.sqlite3
# prints: ALL STORED RUNS INTACT AND CONSISTENT
```

`consistency_audit.py` exits `2` with a sentence (not a traceback) if you point it
at a file that does not exist, or at a database no scan has ever written to.

Optional browser-level smoke test (needs Node.js):

```bash
npm install --prefix /tmp/browser-harness jsdom
python tools/browser_smoke.py --jsdom /tmp/browser-harness
```

```
31/31 browser checks passed · 9 known jsdom-only XPath notice(s) suppressed
```

This drives the real pages against a real uvicorn server and a real TLS lab. It is
jsdom, not a browser: it proves script execution and DOM state, not pixels.

## 9. Talking to the JSON API directly

Use a **second port** so the UI keeps 8000:

```bash
export CANARYGATE_TARGETLAB_CA=tests/fixtures/tls/targetlab-cert.pem
export CANARYGATE_DB_PATH=.canarygate/api-demo.sqlite3
python -m uvicorn canarygate.api.app:app --host 127.0.0.1 --port 8001
```

```bash
curl -s http://127.0.0.1:8001/api/health
curl -s -X POST http://127.0.0.1:8001/api/lab-bola-scans \
     -H 'content-type: application/json' -d '{"port": 8765}'
curl -s http://127.0.0.1:8001/api/lab-matrix
```

The scan returns `"verdict": "CONFIRMED"`, six `checks` and
`"requests_sent": 18`. Interactive docs: <http://127.0.0.1:8001/docs>.

There is also a scripted fixture walkthrough that talks to a **running** server on
port 8000 (fixture data only, no lab needed):

```bash
python canarygate/demo.py
```

## 10. Optional: F5 in VS Code

`.vscode/` is git-ignored, so these files are yours and will not appear in a pull
request. `Ctrl+Shift+P` → **Debug: Open launch.json** is not needed; just create
the two files:

`.vscode/launch.json`

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "CanaryGate UI (:8000)",
      "type": "debugpy",
      "request": "launch",
      "module": "uvicorn",
      "args": ["canarygate.ui.app:app", "--host", "127.0.0.1", "--port", "8000", "--reload"],
      "cwd": "${workspaceFolder}",
      "env": {
        "CANARYGATE_TARGETLAB_CA": "tests/fixtures/tls/targetlab-cert.pem",
        "CANARYGATE_DB_PATH": ".canarygate/judge-demo.sqlite3"
      },
      "console": "integratedTerminal",
      "justMyCode": true
    },
    {
      "name": "TargetLab (:8765)",
      "type": "debugpy",
      "request": "launch",
      "module": "targetlab",
      "args": ["--port", "8765",
               "--tls-cert", "tests/fixtures/tls/targetlab-cert.pem",
               "--tls-key", "tests/fixtures/tls/targetlab-key.pem"],
      "cwd": "${workspaceFolder}",
      "console": "integratedTerminal"
    },
    {
      "name": "Run all tests",
      "type": "debugpy",
      "request": "launch",
      "module": "pytest",
      "args": ["-q"],
      "cwd": "${workspaceFolder}",
      "console": "integratedTerminal",
      "justMyCode": false
    }
  ],
  "compounds": [
    {
      "name": "CanaryGate + TargetLab",
      "configurations": ["TargetLab (:8765)", "CanaryGate UI (:8000)"],
      "stopAll": true
    }
  ]
}
```

Start the pair with **F5 → CanaryGate + TargetLab**, or individually from the Run
and Debug panel. Breakpoints work in the application code.

## 11. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: No module named 'canarygate'` | the virtualenv is not active, or VS Code selected the system interpreter | activate `.venv`, then `Python: Select Interpreter` → `.venv` |
| `SyntaxError` on `match`/`|` type hints, or pip refuses to install | Python too old | install 3.11 and recreate the venv |
| Assessment fails instantly with *"This server has no pinned CA"* | `CANARYGATE_TARGETLAB_CA` was not set in the terminal that runs uvicorn | set it, restart the server |
| Assessment fails with *"Nothing answered on 127.0.0.1:8765"* | TargetLab is not running, or it is on another port | start it (step 4) or change the port field to the one it printed |
| `502` from `/api/lab-bola-scans` with a valid CA | certificate/hostname mismatch, or a different cert pair | use the certificates in `tests/fixtures/tls/`; the cert carries an `IP:127.0.0.1` SAN |
| `[Errno 48] Address already in use` (Windows: `10048`) | something already owns 8000/8765 | `--port 8010` for the UI; stop the other process for the lab |
| Browser shows `https://127.0.0.1:8000` and cannot connect | typed `https` or `localhost` | use `http://127.0.0.1:8000` |
| Pages render but every number is `0` | fresh database, nothing scanned yet | run an assessment (step 6) |
| Old results keep coming back | you are reusing a database | delete `CANARYGATE_DB_PATH` and restart |
| `tools/browser_smoke.py` prints `SKIPPED` | Node or jsdom missing, or a wrong `--jsdom` path | `npm install --prefix /tmp/browser-harness jsdom` |
| Exactly **3** tests fail: the two `test_missing_ca_and_unreachable_lab_store_nothing` and `test_missing_ca_configuration_is_refused_without_contacting_the_lab` | an older checkout that assumed `CANARYGATE_TARGETLAB_CA` was unset in your shell — but step 2 exports it | fixed on this branch by `tests/conftest.py`, which clears `CANARYGATE_*` for every test. `git pull` and the three pass with the variable exported |
| `python` runs the wrong interpreter (conda env shadowing `.venv`) | conda env was activated *after* `.venv`, or `.venv/Scripts` is not first on PATH | use `./run.sh` (it calls `.venv/bin/python` by absolute path) or the full path `.venv/bin/python -m ...` |
| `ValueError: execution halted` | a lab returned two 5xx, a 3xx, 423 or 429 — the guard halts by design | restart the run; this is the safety boundary, not a bug |
| Windows: `ssl` errors inside tests | stale clone or mixed Python versions | recreate the venv with 3.11; CI runs the same suite on Windows |

## 12. What is safe to run

Everything above is loopback-only. TargetLab refuses to bind a non-loopback
address and rejects non-loopback `Host` headers at runtime. CanaryGate has no
route that contacts an arbitrary URL: the only outbound path is the guarded
transport, pinned to `127.0.0.1` with the test CA, with a request budget, no
retries, no redirects and no DNS.

Nothing in this repository needs a credential, and no real target is contacted.
The lab is **deliberately vulnerable** — keep it on loopback.
