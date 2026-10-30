# Checkpoint 3: input validation and disclosure (offline fixture)

This checkpoint is **fixture-only**, not a live scan or proof that the full
v3.2 backend is complete. The API, contracts and reports remain provisional.
The fixture guard still cannot connect to live targets or perform DNS pinning.

## What is exercised

- A valid `GET /search?limit=1` control is checked before three invalid cases:
  missing required `limit` (INPUT-01), a non-integer (INPUT-02), and an
  out-of-range number (INPUT-04). The OpenAPI fixture declares the constraint.
- Only the four exact path/query combinations in `scope.yaml` are authorized;
  no arbitrary query, encoded substitute, extra parameter or write is allowed.
- A 400/422 is SAFE only if its body gives a field-specific non-internal error.
  An accepted invalid value is SUSPECTED, not automatically CONFIRMED. An
  unexpected error, ambiguous response or redirect is INCONCLUSIVE.
- DISC-01, DISC-02 and DISC-05 inspect only these fixture responses for narrow
  stack-trace, internal-error and version-header signatures. Evidence records
  a signature name and a hash of the redacted summary, not raw error details.
  Absence is SAFE **only for these sampled responses**, not the whole API.
- The runner stops after two consecutive 5xx responses or a 423/429. Unsent
  probes are SKIPPED; incomplete negative disclosure checks are INCONCLUSIVE.
  No state-changing request is retried.
- Other validation and disclosure checks are listed as SKIPPED, not passed.

## Run it in VS Code

1. Open the repo in VS Code and follow [the setup guide](../VS_CODE_DEMO.md)
   to create and activate the Python 3.11 virtual environment.
2. In a VS Code terminal run the focused tests:

   ```sh
   python -m pytest -v tests/integration/test_input_disclosure.py tests/unit/test_validation_oracles.py tests/security/test_scope_classifications.py
   ```

   They run strict, invalid-input-accepted, ambiguous-400, redirect, traceback,
   verbose-error, version-header, lockout, repeated-5xx and unauthorized-query
   cases. These are real in-process fixture responses, not live-target tests.
3. In terminal 1 start the local backend:

   ```sh
   python -m uvicorn canarygate.api.app:app --host 127.0.0.1 --port 8000
   ```

4. In a second activated terminal run `python -m canarygate.demo`. Open the
   printed HTML report URL; show the **Input validation checks**, **Disclosure
   checks**, skipped entries and fixture constraint checklist. The default fixture
   rejects the invalid inputs and exposes no selected disclosure signatures; its
   separate read-BOLA example remains deliberately vulnerable. Stop the server
   with Ctrl+C after the demonstration.

On Windows PowerShell, if environment activation is blocked, replace `python` in
these commands with `.\.venv\Scripts\python.exe`. The report is local and uses
no external assets. It is not an authentication-protected multi-user service.
