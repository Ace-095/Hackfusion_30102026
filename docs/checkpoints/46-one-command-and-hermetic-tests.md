# Checkpoint 46 — one command to run it, and a suite that ignores your shell

**Two problems, both reported from a real machine rather than found in CI.**

## 1. "Three failing tests are still unresolved"

They were not random and they were not the product. They were **test isolation**:

```
$ export CANARYGATE_TARGETLAB_CA=tests/fixtures/tls/targetlab-cert.pem
$ python -m pytest -q
FAILED tests/integration/test_targetlab_bola.py::test_missing_ca_and_unreachable_lab_store_nothing
FAILED tests/integration/test_targetlab_scan.py::test_missing_ca_configuration_is_refused_without_contacting_the_lab
FAILED tests/integration/test_targetlab_sci.py::test_missing_ca_and_unreachable_lab_store_nothing
3 failed, 1119 passed
```

Each of those tests asserts what happens when `CANARYGATE_TARGETLAB_CA` is **not**
configured — the 400 path. They only set the variable *after* that assertion:

```python
with TestClient(create_app(database)) as api:
    assert api.post("/api/lab-scans", json={"port": lab.port}).status_code == 400
```

On a machine following our own instructions (`export CANARYGATE_TARGETLAB_CA=...` in
step 2 of the run guide), the variable was already set, so the request succeeded and
the assertion saw `201` instead of `400`. The tests were measuring the developer's
shell, not the code. CI stayed green because CI never exports it — which is exactly
why this class of bug survives a green pipeline.

**Fix:** `tests/conftest.py` clears every `CANARYGATE_*` / `CANARY_*` variable for every
test. Tests that need one still call `monkeypatch.setenv`, which runs after the fixture,
so their intent is unchanged. `tests/integration/test_suite_is_hermetic.py` pins the
property: no variable leaks in, a test can still opt in, and the missing-CA path returns
400 regardless of the shell.

Verified by running the whole suite twice — once bare, once with both variables exported:
**1133 passed** both times (was 1119 passed / 3 failed with the exports).

## 2. One command that starts everything

`run.sh` at the repository root. It resolves its own directory, so it works wherever the
project is copied, and it never depends on which environment your shell activated:

| Command | What it does |
|---|---|
| `./run.sh` | start TargetLab + the website, open the browser on `/ui/` |
| `./run.sh --no-browser` | same, print the URL instead |
| `./run.sh --doctor` | print interpreter, commit, fixtures, ports, imports, and which `canarygate` is loaded — starts nothing |
| `./run.sh --tests` | run the full suite with the demo environment set |
| `./run.sh --stop` | stop what the script started |

Behaviour that matters for a live demo:

- **It prefers `.venv/bin/python` by absolute path.** A conda environment activated
  after the venv cannot hijack `python`; `--doctor` prints which interpreter and which
  `canarygate` package are actually in use, and flags the case where a previously
  installed wheel is shadowing the checkout.
- **A lab that is already running is reused**, not duplicated: it health-checks
  `https://127.0.0.1:$LAB_PORT/health` with the pinned CA first.
- **It waits for real readiness** (`/health`, `/api/health`) instead of sleeping, and
  prints the log tail when something does not come up.
- **Any exit stops what it started** — `trap cleanup EXIT` plus an idempotent cleanup, so
  a failed start cannot orphan a lab process holding the port.
- **Loopback only.** `--host 127.0.0.1`, never `0.0.0.0`; pinned fixture certificate.
- If the UI port is taken it moves to the next free port and says so.

Tested end to end in this checkpoint: `--doctor`, a clean start on 8055/8766, an
already-running lab being reused, a real assessment through the script's own stack
(18 requests, run stored, matrix updated), `--tests`, `--stop`, and Ctrl+C releasing
both ports with no orphans.

## 3. Verification

```
pytest -q                                            1133 passed (69 files)
pytest -q  (with CANARYGATE_* exported)              1133 passed
tools/p0_audit.py                                    58 requirements / 1133 tests / 47·9·2 / 0 unreachable
./run.sh --doctor                                    clean
./run.sh (clean start, real assessment)              complete, 18 requests, 1 run stored
```

`tests/integration/test_tool_ergonomics.py` grew five launcher tests: it exists and
starts from its own directory, it never binds a public interface and always uses the
pinned certificate, it cleans up on every exit path, it is valid bash, and the run guide
points at it.
