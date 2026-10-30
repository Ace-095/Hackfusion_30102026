# Checkpoint 9: fixture enum validation

**Offline synthetic fixture only.** No live target or general-purpose fuzzing is
enabled. The unauthenticated backend must run only locally.

## What works

- The bundled search spec defines the integer enum `[1, 2, 3]` within range 1–10.
  The fixture target accepts those values, although the guard permits only the
  separately listed literal queries.
- After the `limit=1` control succeeds, INPUT-03 sends exactly the scoped
  `GET /search?limit=9`: 9 is in the numeric range but outside the declared enum.
  The default fixture rejects it with a field-specific error, yielding SAFE for
  this particular synthetic case. A 2xx is SUSPECTED; ambiguous errors,
  redirects and oversized responses are INCONCLUSIVE.
- Missing or invalid enum metadata, a failed control, a scope or budget block, or
  a previous safety halt prevents the probe and yields SKIPPED. A lockout response
  halts later requests, including the separate enumeration comparison.
- Disclosure checks inspect the enum response as well: normally five bounded
  fixture responses. Incomplete applicable coverage cannot be reported as SAFE.
  Redacted evidence, input-case labels and coverage counts survive persistence.
- The normal run sends 16 requests, below the fixture budget of 20. It does not
  access DNS or a real API. Hashes are unkeyed integrity checks, not signatures.

## VS Code judge demo

1. Open the repository in VS Code; set up Python 3.11 using the
   [main demo guide](../VS_CODE_DEMO.md). Run the test-first cases and full suite:

   ```sh
   python -m pytest -v tests/integration/test_enum_validation.py
   python -m pytest -q
   ```

   The focused cases cover valid/rejected/accepted enum inputs, ambiguous errors,
   guard and budget blocks, malformed metadata, lockout, disclosure coverage,
   network isolation, redaction and stored results.
2. In terminal 1 start the local backend:

   ```sh
   python -m uvicorn canarygate.api.app:app --host 127.0.0.1 --port 8000
   ```

3. In terminal 2 run `python -m canarygate.demo`, then open its printed HTML
   report. Under **Input validation checks**, show INPUT-03 and its redacted
   evidence. Explain that the response is from the synthetic fixture, not a
   real-world scan. Show the five-response disclosure coverage and the request
   count in the fixture constraint checklist.
4. Copy the report URL, stop the server with Ctrl+C, restart it from the same
   folder and reopen the URL. Stop the server after the demo.

If the virtual environment is not activated, use `.venv/bin/python` on Linux or
macOS and `.\.venv\Scripts\python.exe` on Windows. See [API draft](../API.md)
for provisional contracts and limitations.
