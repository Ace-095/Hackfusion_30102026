# Checkpoint 8: fixture resource-enumeration comparison

**Offline synthetic fixture only.** No live API, arbitrary ID guessing or network
target is enabled. The backend is unauthenticated and should only run locally.

## What works

- CanaryGate reuses the missing-auth denial from the verified Alice fixture
  resource, then sends one separately scoped, missing-auth GET to a **known-absent
  synthetic ID**. Every request still passes through the guard and MockTransport.
- It compares only the response status, content type and body bytes in memory.
  A difference is **SUSPECTED**, not automatically a confirmed vulnerability;
  differences may be benign. Matching responses are SAFE only for this one pair
  and those compared aspects. Other headers and timing are not examined.
- A missing identity, unverified ownership, unavailable denial baseline, rejected
  scope or exhausted budget results in SKIPPED without sending the comparison.
  Redirect, server-error or oversized comparison responses are INCONCLUSIVE.
- Evidence contains a minimized request, response status, baseline status, a
  comparison Boolean and a hash; raw error messages and their hashes are not
  persisted. The fixture redactor and unkeyed hashes are not suitable as
  production-grade live-data protection or signatures.
- The fixture runner clears cookies between requests so a missing-auth probe
  cannot inherit a prior login cookie. Cookie- or proxy-authenticated baselines
  are rejected for the comparison.
- At checkpoint 8 the normal fixture used 15 requests; checkpoint 9 adds one
  separately scoped enum probe (16 total, below the budget of 20). All
  results remain fixture-only; real account setup and live scanning are pending.

## VS Code judge demo

1. Open the repository in VS Code and set up Python 3.11 as described in the
   [main demo guide](../VS_CODE_DEMO.md). From the repository root run:

   ```sh
   python -m pytest -v tests/integration/test_resource_enumeration.py
   python -m pytest -q
   ```

   The focused tests use real in-process mock responses for matching/different
   denials, redirects, errors, oversized responses, missing prerequisites, scope
   and budget blocks, network isolation, redaction and persisted evidence.
2. In terminal 1, start the local backend:

   ```sh
   python -m uvicorn canarygate.api.app:app --host 127.0.0.1 --port 8000
   ```

3. In terminal 2, run `python -m canarygate.demo` and open the printed HTML URL.
   Show AUTHN-01 as the baseline and DISC-06 under **Disclosure checks**. The
   default fixture returns matching denials, so DISC-06 shows SAFE for this one
   synthetic pair—not a claim that a live target is safe. The focused tests also
   demonstrate a SUSPECTED difference and inconclusive cases.
4. Copy the report URL. Stop the backend with Ctrl+C, restart it from the same
   folder and reopen the copied URL to show that the result persists. Stop the
   backend after the demo.

If the environment is not activated, use `.venv/bin/python` on Linux/macOS or
`.\.venv\Scripts\python.exe` on Windows. See the [API draft](../API.md) for
provisional response contracts and limitations.
