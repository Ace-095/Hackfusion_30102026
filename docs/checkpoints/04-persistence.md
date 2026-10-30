# Checkpoint 4: SQLite persistence and redacted fixture evidence

This is an **offline fixture-only** checkpoint. It does not enable real target
scanning, live account handling, complete raw HTTP evidence or production-grade
redaction. The backend is unauthenticated and must be run only locally.

## What works

- Fixture runs, verdicts, minimized evidence summaries, scope/spec hashes and an
  endpoint-inventory snapshot are stored in `.canarygate/fixture.sqlite3`.
- Data survives a server restart from the same working directory. To use another
  local database file, set `CANARYGATE_DB_PATH` before starting the server.
- The fixture database and SQLite sidecars are Git-ignored. Keep credentials,
  private target data and generated reports out of Git.
- Evidence hashes are verified before storage; credential-like fields and known
  synthetic values are redacted, and the minimized summaries are rehashed. Report
  and evidence hashes are checked again on read. A corrupted record returns 500,
  not a fabricated verdict. Hashes are unkeyed and **not digital signatures**;
  they do not protect against an attacker able to rewrite data and hashes.
- This redactor is only suitable for the built-in fixture. It is not a guarantee
  that arbitrary secrets or live API response data would be protected.

## Run and show the judge in VS Code

1. Open the repository and follow the environment setup in
   [VS Code demo guide](../VS_CODE_DEMO.md). Run focused tests:

   ```sh
   python -m pytest -v tests/unit/test_fixture_storage.py tests/integration/test_sqlite_persistence.py
   ```

   The tests use temporary databases. They check restart persistence, redaction,
   corrupted records, failed writes, parameterized lookups and concurrent writes.
2. In terminal 1, from the repository root, start the local backend:

   ```sh
   python -m uvicorn canarygate.api.app:app --host 127.0.0.1 --port 8000
   ```

3. In a second terminal run `python -m canarygate.demo`. Open the printed HTML
   report URL and show its fixture label, ownership/disclosure evidence, checks
   and SHA-256 values. Copy the report URL.
4. Stop the server with Ctrl+C. Restart the same command **from the same folder**
   with the same database path; reopen the copied URL. The original fixture report
   should still load, including the inventory captured during that run.
5. The default database file appears under `.canarygate/`. It is local fixture
   output, not a live scan and not something to commit. Stop the server after
   the demo.

On Windows PowerShell, if virtual-environment activation is blocked, replace
`python` with `.\.venv\Scripts\python.exe`. See the main guide for Linux and
Windows setup details.
