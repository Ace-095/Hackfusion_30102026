# Checkpoint 5: auditable fixture observations and local reports

**Offline synthetic fixture only.** No live target, real credentials, DNS validation,
connection pinning or production redaction is implemented. The local backend is
unauthenticated and must not be exposed to other users or the Internet.

## What works

- An ordered, minimized observation set records each attempted account discovery
  list, owner baseline and cross-user read. A normal run records five observations.
  Each carries a redacted request, status, allowlisted synthetic metadata, nullable
  assertions and a SHA-256 over the minimized record. Private values, raw response
  bodies and Authorization values are not saved. A 20-item limit and truncation
  marker make bounded display explicit; assertions use the full fixture response.
- Skipped or incomplete setup produces only the steps actually observed. For
  example, failed authentication produces a recorded empty set, while cross-list
  leakage records both discovery responses but no baselines or cross-user read.
  A false private-data match means no match was observed; it does not transform a
  401, 404 or ambiguous 200 into proof of security.
- The run and observations are saved atomically. Checkpoint-4 databases are opened
  using an additive table: existing runs report `NOT_RECORDED` rather than having
  fabricated observations. Integrity checks validate both the collection and
  nested records; a corrupt observation response returns a generic 500. Unkeyed
  hashes are **not signatures** and do not stop a database writer from rewriting
  records and recomputing hashes. Deletion of an observation row is also
  indistinguishable from a legacy run without a row.
- A local Jinja2 HTML report displays persisted observations and safe reproduction
  instructions. Its command creates a **new scan** via the local backend; the
  in-process mock target is not an HTTP server. The existing JSON report and run
  responses are unchanged; observations are available through a separate route or
  an opt-in JSON bundle. See [API draft](../API.md).

## VS Code judge demonstration

1. Open the repository in VS Code and set up Python 3.11 as described in
   [VS Code demo guide](../VS_CODE_DEMO.md). Run the focused real tests:

   ```sh
   python -m pytest -v tests/unit/test_observation_storage.py tests/integration/test_observation_reports.py
   ```

   These exercise passing and failed fixture steps, isolated network/DNS, redaction,
   HTML escaping, old databases, corruption, transaction rollback and restart.
2. In terminal 1, start the backend from the repository root:

   ```sh
   python -m uvicorn canarygate.api.app:app --host 127.0.0.1 --port 8000
   ```

3. In a second terminal run `python -m canarygate.demo`. Open the printed HTML
   report URL. Show the explicit fixture label; the two discovery observations,
   two owner baselines, cross-user response, redacted Authorization, assertion
   values and hashes; and the local reproduction section. The reproduction command
   creates a **new** run, not the report you are viewing.
4. Copy the run ID printed by the demo. In a browser open
   `http://127.0.0.1:8000/api/scan/<RUN_ID>/observations` and
   `http://127.0.0.1:8000/api/reports/<RUN_ID>?include_observations=true`,
   substituting the copied ID. The latter has `run` and `observation_set`; the
   existing default `...?format=json` still returns only the run.
5. Stop the server with Ctrl+C. Restart the same command from the same directory
   and reopen those URLs: the same observations and hashes remain. If using
   `CANARYGATE_DB_PATH`, retain the same path across restarts. Stop the server
   after the demonstration.

On Windows PowerShell, if activation is blocked, substitute
`.\.venv\Scripts\python.exe` for `python`. Old checkpoint-4 records show
`NOT_RECORDED`; the absence is not a failed scan or a claim of success. These
fixture-only results do not establish live-target safety or full v3.2 acceptance.
