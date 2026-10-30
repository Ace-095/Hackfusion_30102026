# Run the backend checkpoint in VS Code

This is an **offline synthetic fixture demonstration**, not a scan of the
organizer's API. The frontend/dashboard, live-target scanner, complete security
checks and full production safety guard are not yet implemented. The backend
server has no user authentication: use it locally and do not expose it publicly.

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
