# Checkpoint 7: fixture-only disclosure checks

This historical checkpoint used four search responses; checkpoint 9 adds a fifth
scoped response. This checkpoint is **offline and synthetic**. It does not scan a live API or
implement general-purpose secret detection, production redaction or full JSON
Schema validation. The unauthenticated backend must run locally only.

## What works

- **DISC-03:** Inspect the four existing scoped `/search` responses for a short
  allowlist of sensitive JSON field names, including password hashes and tokens.
  A nonempty, unmasked string at one of those names is CONFIRMED; masked, empty
  or null values are not. Uninterpretable content or incomplete traversal cannot
  establish safety. Field paths and values are never stored as evidence.
- **DISC-04:** Compare top-level response keys to the bundled fixture's explicitly
  closed JSON schema for that response status. An undocumented top-level key is
  SUSPECTED, not automatically a confirmed security weakness. Open, missing or
  unsupported schemas, malformed JSON or partial coverage are INCONCLUSIVE.
- Both checks reuse four responses already permitted by the fixture scope; they
  make **no extra requests**. A SAFE verdict means only that the named signal
  was not seen in those four completely inspected fixture responses.
- Evidence is minimized and redacted before return and storage, and hashes are
  verified on reload. Hashes are not signatures. The fixture-only redactor is
  not suitable for arbitrary credentials or live target data.
- Remaining unimplemented checks are explicitly SKIPPED, including DISC-06 and
  the other input checks. The bundled fixture itself returns no sensitive or
  undocumented search fields, so the default report shows SAFE for DISC-03/04.

## VS Code judge demo

1. Open the repository in VS Code and set up Python 3.11 using the
   [main demo guide](../VS_CODE_DEMO.md). From the repository root run:

   ```sh
   python -m pytest -v tests/unit/test_sensitive_disclosure_oracles.py tests/integration/test_sensitive_disclosure.py
   python -m pytest -q
   ```

   The first command runs real synthetic cases: a nested sensitive value, masked
   values, an undocumented field, invalid JSON, partial coverage, redaction and
   persisted reports. The default public demo does not inject a fake finding.
2. In terminal 1, start the local backend:

   ```sh
   python -m uvicorn canarygate.api.app:app --host 127.0.0.1 --port 8000
   ```

3. In terminal 2, run `python -m canarygate.demo` and open the printed HTML report.
   Under **Disclosure checks**, show DISC-03 and DISC-04 and their reasons. Explain
   that SAFE is limited to the four synthetic search responses and that the tests
   also cover positive and inconclusive cases.
4. Copy the report URL, stop the backend with Ctrl+C, restart the same command
   from the same directory and reopen the URL to demonstrate persisted evidence.
   Stop the server after the demo.

If the environment isn't activated, use `.venv/bin/python` on Linux/macOS or
`.\.venv\Scripts\python.exe` on Windows. These fixture results do not establish
live-target safety or complete v3.2 acceptance.
