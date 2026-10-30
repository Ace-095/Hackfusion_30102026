# Run the backend checkpoint in VS Code

This is an **offline synthetic fixture demonstration**, not a scan of the
organizer's API. The live-target scanner, complete security checks and full
production safety guard are not implemented, and this walkthrough uses the
backend alone; the local interface is documented separately in
[UI.md](UI.md). The backend server has no user authentication: use it locally
and do not expose it publicly.

## One-time setup (both operating systems)

1. Open this repository folder in VS Code: **File → Open Folder**. Install Python
   **3.11** and VS Code's Python extension. Open **Terminal → New Terminal**.
2. Create a virtual environment and install dependencies. These commands must be
   run in the repository root, where `pyproject.toml` is located.

Windows PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pytest -q
```

If PowerShell blocks activation, use the interpreter directly instead:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pytest -q
```

Linux:

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pytest -q
```

VS Code: use **Python: Select Interpreter** and choose the `.venv` interpreter.
Installing dependencies may require internet access; the fixture execution does
not contact a target or DNS server. Tests must pass before the demo. Tests are
fixture tests, not proof of full v3.2 acceptance.

## Start and demonstrate

1. In the first VS Code terminal (with the virtual environment active):

   ```sh
   python -m uvicorn canarygate.api.app:app --host 127.0.0.1 --port 8000
   ```

   Leave this terminal running. Without activation on Windows, substitute
   `.\.venv\Scripts\python.exe` for `python`.
2. Open a **second** VS Code terminal and activate the same environment. Run:

   ```sh
   python -m canarygate.demo
   ```

   This calls the local backend, prints the fixture endpoint inventory, runs one
   synthetic scan, prints the setup gates, ownership/disclosure evidence, BOLA
   verdict, scoped authentication checks and bounded input/disclosure checks,
   then prints JSON and HTML links. The fixture HTTP
   requests are handled in-process; they do not reach any external service.
3. Copy the printed **HTML fixture report** URL into your local browser. Show
   the fixture label, endpoint inventory, both owner/list checks, two evidence
   summaries, stored discovery/owner/cross-user observations, local reproduction
   instructions, verdict, remediation, authentication results and fixture constraint
   checklist. AUTHN-01/02/03 and INPUT-01/02/03/04 use real fixture responses;
   DISC-01/02/03/04/05 inspect only those bounded responses. DISC-03 checks
   selected sensitive field names; DISC-04 compares top-level fields against an
   explicitly closed fixture response schema. DISC-06 compares the denial for
   Alice’s verified resource with a predeclared absent fixture ID; a difference
   is SUSPECTED, not confirmed. JWT-specific checks say
   SKIPPED for opaque tokens. The report identifies unfinished checks.
4. Optional: in another terminal run the focused safety tests:

   ```sh
   python -m pytest -v tests/security tests/integration/test_offline_scan.py tests/integration/test_auth_checks.py tests/integration/test_input_disclosure.py
   ```

   These test scope, dangerous/unknown operations, DNS isolation, no redirects,
   missing identity, ownership failure, shared/public resources, invalid-token
   probes, opaque-token skips, validation/disclosure responses and secure behavior.
5. Copy the HTML report URL, stop the backend with **Ctrl+C**, and start the same
   backend command again from the same repository folder. Reopen the copied URL:
   the fixture report is retrieved from `.canarygate/fixture.sqlite3`. Stop the
   backend after the demo. The optional `CANARYGATE_DB_PATH` environment variable
   selects a different local database file; use the same path after restart.

The API schema is available locally at `http://127.0.0.1:8000/openapi.json`.
Swagger and ReDoc are intentionally disabled because their default assets are
loaded from external CDNs. If port 8000 is already in use, stop the other local
process first; the demo command deliberately connects only to port 8000.

## Suggested judge narration

- “This is an offline fixture, not testing the organizer's environment.”
- “Both accounts authenticate in the simulated target. Each discovers and reads
  its own resource; each other's list must exclude it.”
- “The finding requires verified ownership, a distinct private owner baseline,
  and that same private data in the attacker's response. HTTP 200 alone is not
  enough.”
- “The guard checks the exact fixture scope, operation classification, identity
  and budget; all HTTP uses a mock transport with no DNS or outbound connection.”
- “Missing, malformed and wrong-scheme credentials are checked only against an
  explicitly authorized fixture operation. A 200 alone is not a confirmed bypass.
  JWT-specific probes are skipped because the fixture tokens are opaque.”
- “Three bounded invalid inputs are compared to a valid control; disclosure
  signatures are inspected in those fixture responses. An ambiguous 200 or 400
  is not automatically SAFE, and unimplemented checks are SKIPPED.”
- “The observation set records what happened during discovery, owner baselines
  and the cross-user read; absent steps are not invented. The reproduction command
  starts a new local mock scan, not a request to a network fixture target.”
- “The redacted fixture report survives a restart. Its hashes detect accidental
  corruption but are not signatures; full live-data redaction is not implemented.”
- “Live DNS pinning, real accounts, remaining security checks and production
  persistence are pending; the report does not claim they passed.”

For the detailed observation and report demonstration, see [checkpoint 5](checkpoints/05-observations.md).

For the separate, non-scanning OpenAPI upload demonstration, see [checkpoint 6](checkpoints/06-spec-inspection.md).

For the sensitive-field and response-schema demonstration, see [checkpoint 7](checkpoints/07-disclosure.md).

For the fixture resource-enumeration comparison, see [checkpoint 8](checkpoints/08-enumeration.md).

For the scoped enum-validation demonstration, see [checkpoint 9](checkpoints/09-enum-validation.md).

For the offline organizer-scope validation demonstration, see [checkpoint 10](checkpoints/10-scope-validation.md).

For the offline preflight policy demonstration, see [checkpoint 11](checkpoints/11-preflight.md).

For the experimental pinned-reader safety tests, see [checkpoint 12](checkpoints/12-pinned-reader.md).

For the guarded HTTPX boundary tests, see [checkpoint 13](checkpoints/13-guarded-httpx.md).

For shared run-guard verification, see [checkpoint 14](checkpoints/14-run-guard.md).

For network-deadline verification, see [checkpoint 15](checkpoints/15-network-deadline.md).

For guarded authentication verification, see [checkpoint 16](checkpoints/16-guarded-login.md).

For the explicit profile observation tests, see [checkpoint 17](checkpoints/17-identity-observation.md).

For the two-account identity observation tests, see [checkpoint 18](checkpoints/18-identity-pair.md).

For bounded read-only resource harvesting, see [checkpoint 19](checkpoints/19-resource-harvest.md).

For owner-baseline observation tests, see [checkpoint 20](checkpoints/20-owner-baselines.md).

For the default-deny live execution tests, see [checkpoint 21](checkpoints/21-live-disabled.md).

For fixture verified ownership, see [checkpoint 22](checkpoints/22-verified-ownership.md).

For the two-part fixture Read-BOLA oracle, see [checkpoint 23](checkpoints/23-read-bola-oracle.md).

For independent validation planning, see [checkpoint 24](checkpoints/24-independent-validation-plan.md).

For the bounded nested fixture detection pipeline, see [checkpoint 25](checkpoints/25-fixture-detection-pipeline.md).

Checkpoint 26 adds the fixture-only nine-section JSON view and the honest P0
audit; see `docs/checkpoints/26-p0-audit.md` and `docs/P0_ACCEPTANCE_MATRIX.md`.
Checkpoint 27 adds the shared fixture/mocked-HTTPX ownership and oracle proof
path, adversarial redaction tests and a JWT metadata helper; see
`docs/checkpoints/27-generic-integration.md`. Checkpoint 28 connects the generic
workflow to the application with a recorded offline transport, SQLite
persistence and consistent JSON/HTML scenario reports; see
`docs/checkpoints/28-generic-scan-integration.md`. Checkpoint 29 adds the
remaining P0 authentication checks (AUTHN-04a/04b/05/06/08) over the same
recorded transport; see `docs/checkpoints/29-authentication-checks.md`.
Checkpoint 30 adds the remaining P0 input-validation and disclosure checks
(INPUT-05/06/07, DISC-01–06) as scope-declared recorded probes; see
`docs/checkpoints/30-input-disclosure.md`. Checkpoint 31 adds the frozen
nine-section P0 report for every offline workflow and an aggregated authorization
matrix that keeps untested cells visible; see
`docs/checkpoints/31-report-and-matrix.md`.
Production networking remains disabled and none of these documents indicates P0
or production acceptance.

### Checkpoint 28 offline scenario demo

With the local API running as above:

```sh
curl -sS -X POST http://127.0.0.1:8000/api/scenario-scans   -H "content-type: application/json" -d '{"scenario_id": "synthetic-vulnerable"}'
curl -sS "http://127.0.0.1:8000/api/scenario-scans/<id>/report?view=sections"
curl -sS "http://127.0.0.1:8000/api/scenario-scans/<id>/report?format=html"
```

Repeat with `synthetic-secure` (checked denial) and `synthetic-metadata`
(inconclusive), plus `synthetic-pagination-limit` and `synthetic-guard-block`
for skipped outcomes. The scenario report is local synthetic evidence, not an
organizer-target or live scan.


### Checkpoint 29 authentication demo

With the local API running as above:

```sh
curl -sS -X POST http://127.0.0.1:8000/api/authentication-scans \
  -H "content-type: application/json" -d '{"scenario_id": "synthetic-jwt-sub-confirmed"}'
curl -sS "http://127.0.0.1:8000/api/authentication-scans/<id>/report?view=sections"
curl -sS "http://127.0.0.1:8000/api/authentication-scans/<id>/report?format=html"
```

Show `synthetic-jwt-secure` (SAFE), `synthetic-jwt-role-confirmed` (CONFIRMED
admin capability), `synthetic-jwt-no-observability` (INCONCLUSIVE/SUSPECTED) and
`synthetic-jwt-opaque` (SKIPPED reasons). The report states that JWT claims are
unverified; no live endpoint or real credential is used.


### Checkpoint 30 input-validation and disclosure demo

With the local API running as above:

```sh
curl -sS -X POST http://127.0.0.1:8000/api/validation-scans \
  -H "content-type: application/json" -d '{"scenario_id": "synthetic-validation-weak"}'
curl -sS "http://127.0.0.1:8000/api/validation-scans/<id>/report?view=sections"
curl -sS "http://127.0.0.1:8000/api/validation-scans/<id>/report?format=html"
```

Show `synthetic-validation-secure` (nine SAFE results), `synthetic-validation-weak`
(three SUSPECTED inputs and six CONFIRMED disclosure findings) and
`synthetic-validation-unobservable` (INCONCLUSIVE plus one SKIPPED schema
comparison). Each check lists `request_probes` and bounded `evidence`, so a
judge can see that the probe executed and what the recorded answer was. The run
contains no request or response body, no credential and no token; the report
states that no live target was contacted.


### Checkpoint 31 nine-section report and matrix demo

With the local API running as above:

```sh
curl -sS -X POST http://127.0.0.1:8000/api/validation-scans \
  -H "content-type: application/json" -d '{"scenario_id": "synthetic-validation-weak"}'
curl -sS "http://127.0.0.1:8000/api/validation-scans/<id>/report?view=p0"
curl -sS "http://127.0.0.1:8000/api/validation-scans/<id>/report?view=p0&format=html"
curl -sS "http://127.0.0.1:8000/api/authorization-matrix"
```

Walk the nine headings in the HTML page, then show the matrix endpoint: hatched
cells are coverage gaps, each row names the stored run that produced it, and two
runs that disagree keep the worse observation with both reasons. Repeat
`view=p0` for a scenario run and an authentication run to show the same contract
over a different workflow.


### Checkpoint 32 acceptance audit demo

```sh
.venv/bin/python tools/p0_audit.py
```

The tool prints 35 requirement rows with status, evidence class, implementation
and cited tests, then fails loudly on any dangling reference or unclassified test
file. `tests/integration/test_p0_audit.py` runs the same audit, so the claim and
the evidence cannot drift apart. The checkpoint document
`docs/checkpoints/32-p0-acceptance-audit.md` states the split verdict: offline
subset accepted with limitations, complete frozen P0 not accepted (BFLA and live
validation missing).

### Checkpoint 33 SCI interaction demo

Run this independently of the three core demos; it uses the same API server.

```sh
.venv/bin/python -m pytest tests/integration/test_sci_scenarios.py tests/security/test_sci_decisions.py -q
```

Then, with the server running (`.venv/bin/python -m canarygate.api`), open the
interactive docs at `/docs` and use `POST /api/interaction-scans`:

```json
{"scenario_id": "synthetic-sci-authz-input-confirmed"}
```

Expected: `201` with `verdict: "CONFIRMED"`, `attribution: "interaction_induced"`,
`interaction_kind: "AUTHZ+INPUT_VALIDATION"`, two `SAFE` baselines
(`AUTHZ-01`, `INPUT-07`) and a combined leg with `impact: "privileged_data"`.
Take the returned `id` and open:

- `GET /api/interaction-scans/{id}/report?view=sections` — both baselines passing
  and the leaking combination side by side, with the plain-language statement.
- `GET /api/interaction-scans/{id}/report?view=p0` — the nine sections, a single
  `SCI-01` finding with `finding_kind: "interaction"`, the `sci_authorization`
  remediation and `why_not_individual`.
- `GET /api/authorization-matrix` — the cell's `source_ref` starts with
  `interaction:`, so an SCI result cannot be confused with an ordinary BOLA cell.

Prove the engine is not credulous:

```json
{"scenario_id": "synthetic-sci-individual-failure"}
{"scenario_id": "synthetic-sci-authz-input-secure"}
{"scenario_id": "synthetic-sci-variation"}
```

Expected verdicts: `INCONCLUSIVE` (`individual_failure`), `SAFE` (`no_failure`) and
`SUSPECTED` (`no_demonstrated_impact`). None of them is `CONFIRMED`; none of them
carries a remediation. Finally run `tools/p0_audit.py` to show the SCI
requirements (C1–C7) with their implementation symbols and tests.

### Checkpoint 34 TargetLab demo

In a second terminal (the first runs the CanaryGate API):

```sh
.venv/bin/python -m targetlab --port 8765
```

Expected first line: `targetlab: DELIBERATELY VULNERABLE test API on
http://127.0.0.1:8765 (loopback only, do not deploy)`.

Open `http://127.0.0.1:8765/docs` to show the generated OpenAPI documentation and
the `bearerAuth` scheme. Then reproduce the ground truth with curl:

```sh
TOKEN=lab-token-mallapa
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8765/records/BRD-2026-018/secure
# {"error":"forbidden"}
curl -s -X POST http://127.0.0.1:8765/login -H 'Content-Type: application/json' \
     -d '{"username":"mallapa","password":"x","admin":true}'
# {"error":"invalid_request"}
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8765/records/BRD-2026-018/guarded
# {"id":"BRD-2026-018","owner":"sakshi","private_note":"targetlab-sakshi-private-marker","compat_state":true}
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8765/records/BRD-2026-018/secure
# {"error":"forbidden"}   (still secure: the flaw is narrow)
```

Show the containment too:

```sh
.venv/bin/python -m targetlab --host 0.0.0.0   # exits 2; refuses to bind publicly
curl -s -H "Host: example.com" http://127.0.0.1:8765/health
# {"error":"non_loopback_host_rejected"}
```

Then `.venv/bin/python -m pytest tests/lab/test_targetlab_api.py -q` → 19 passed.
Say plainly: this is a target we wrote, not live validation, and the scanner
cannot reach it yet.

### Checkpoint 35 TargetLab transport demo

Start the lab with TLS in one terminal:

```sh
.venv/bin/python -m targetlab --port 8765 \
    --tls-cert tests/fixtures/tls/targetlab-cert.pem \
    --tls-key tests/fixtures/tls/targetlab-key.pem
```

Start CanaryGate in another, with the CA configured:

```sh
export CANARYGATE_TARGETLAB_CA=tests/fixtures/tls/targetlab-cert.pem   # Windows: set ...
.venv/bin/python -m uvicorn canarygate.api.app:app --host 127.0.0.1 --port 8000
```

Then:

```sh
curl -sS -X POST http://127.0.0.1:8000/api/lab-scans \
     -H 'content-type: application/json' -d '{"port": 8765}'
```

Expected: `201` with `transport.destination = "127.0.0.1"`,
`transport.tls_verification = "pinned_test_ca_with_hostname_check"`, seven checks
where LAB-01…LAB-04 are `allowed_owner`, LAB-05 is `allowed_other` (the deliberate
BOLA observation) and LAB-06/LAB-07 are `denied`, plus
`constraints.requests_sent = 9`.

Show the report: `GET /api/lab-scans/{id}/report?view=sections` and
`?format=html`. Read the heading aloud: "Controlled validation, not live
validation."

Prove containment quickly: stop the lab and repeat the POST → `502`, and no run is
stored. Then run
`.venv/bin/python -m pytest tests/lab/test_targetlab_transport.py -q` (24 passed).

### Checkpoint 36 TargetLab BOLA demo

With the lab running over TLS (see checkpoint 35) and `CANARYGATE_TARGETLAB_CA`
set:

```sh
curl -sS -X POST http://127.0.0.1:8000/api/lab-bola-scans \
     -H 'content-type: application/json' -d '{"port": 8765}'
```

Expected: `201`, `verdict: "CONFIRMED"`, `summary {confirmed: 2, safe: 4, ...}`,
`constraints.requests_sent = 18`, and six checks where `LAB-BOLA-03`/`04` are
`CONFIRMED` with `checklist.private_disclosure = true`, `LAB-BOLA-05`/`06` are
`SAFE` with `checklist.verified_denial = true`, and `LAB-BOLA-01`/`02` are the
owner baselines.

Then open:

- `GET /api/lab-bola-scans/{id}/report?view=sections` — ownership evidence and the
  ground-truth table showing 6/6 matched, still labelled "evaluated after the
  verdicts".
- `GET /api/lab-bola-scans/{id}/report?view=p0` — nine sections, two `High`
  `Authorization` findings with `bola` remediation.
- `GET /api/authorization-matrix` — `GET /records/{id}` red for
  `other_account_resource`, `GET /records/{id}/secure` green.

The strongest single slide: stop the lab, repeat the POST → `502` and nothing is
stored. Then run `.venv/bin/python -m pytest tests/lab/test_lab_bola_adversarial.py -q`
(11 passed) to show a mutated response, a swapped token and a bad certificate all
fail closed.

### Checkpoint 38 one-command demonstration

```sh
.venv/bin/python tools/demo.py            # add --keep to inspect the database
```

Runs the four stages from a clean start — read-BOLA (`CONFIRMED`), the secure
route (`SAFE`), the control interaction (`CONFIRMED`, `interaction_induced`) with
its separate reset proof (`403, 401, 200, 403`), then the evidence stage — and
exits non-zero if any surface disagrees with any other. After keeping a database:

```sh
.venv/bin/python tools/consistency_audit.py --database /path/to/demo.sqlite3
```

re-hashes every stored run and rebuilds its reports from stored evidence alone.
[`docs/JUDGE_DEFENCE.md`](JUDGE_DEFENCE.md) is the accompanying question-and-answer
document.

### Checkpoint 37 TargetLab interaction demo

With the lab running over TLS and `CANARYGATE_TARGETLAB_CA` set:

```sh
curl -sS -X POST http://127.0.0.1:8000/api/lab-sci-scans \
     -H 'content-type: application/json' -d '{"port": 8765}'
curl -sS -X POST http://127.0.0.1:8000/api/lab-sci-resets \
     -H 'content-type: application/json' -d '{"port": 8765}'
```

Expected: `201` with `verdict: "CONFIRMED"`, `attribution: "interaction_induced"`,
`requests_sent: 11`, `budget_remaining: 5`; `SCI-AUTHZ` `SAFE` on a `403` and
`SCI-AUTHN` `SAFE` on a `401`, then the combined read at `200` with
`impact: "private_data"`. The reset answers `status: "proven"` with four checks
`403/401/200/403` and `requests.total: 8`.

The demo that lands: open
`/api/lab-sci-scans/{id}/report?view=p0` (one `SCI-01` finding, `High`,
`Authorization`, interaction explanation) and
`/api/lab-sci-scans/{id}/report?view=sections&reset={proof_id}` (evidence plus the
reset table in one page). Then run
`.venv/bin/python -m pytest tests/lab/test_lab_sci_adversarial.py -q` to show a
mutated body, a stale response, a swapped token and a redirected connection all
fail closed.
