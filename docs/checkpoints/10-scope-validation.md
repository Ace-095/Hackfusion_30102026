# Checkpoint 10: organizer-scope validation (offline only)

This checkpoint adds a **provisional, data-only** validator for a written scope.
It does not provide a live guard, DNS validation, a pinned transport, scope upload,
or live scanning. It cannot prove that a written approval reference is genuine.
The existing fixture API still runs only the built-in in-process target.

## What works

- `load_authorized_scope` validates a bounded YAML string containing mode, exact
  host and port, account identifiers and roles, allowed methods, request budget,
  classified exact operations and a written authorization reference.
- A single organizer-supplied IP is preferred, or an explicitly specified
  `organizer_approved_system` resolver is recorded. **Neither is used to connect
  or resolve** in this checkpoint. Unspecified, multicast, limited broadcast, zone-scoped
  or malformed IPs are rejected; no public DNS resolver is queried.
- Unknown fields, embedded account password/token fields, duplicate keys or
  accounts/operations, YAML aliases, unknown classifications and conflicting
  read/authentication operations fail closed. State-changing POST entries need
  a separate creation-authorization reference; their presence does not execute
  or authorize a request. Destructive operations remain prohibited from execution.
- The model is immutable and uses bounded collection sizes. It deliberately accepts
  only a conservative exact-path subset, not arbitrary query templates. Further
  scope review, a central guard and real connection pinning remain mandatory.

## VS Code judge demo

1. Open the repository in VS Code and set up Python 3.11 using the
   [main demo guide](../VS_CODE_DEMO.md). From the repository root run:

   ```sh
   python -m pytest -v tests/security/test_authorized_scope.py
   python -m pytest -q
   ```

   The focused tests use synthetic documentation-only addresses and check that
   parsing cannot use network/DNS. They exercise malformed scope, classification,
   authorization references, credentials, duplicate entries and non-unicast IPs.
2. Explain: “This validates scope data, but does not enable live traffic. We still
   need a reviewed central guard, approved address resolution and connection
   pinning before any real scan.”
3. To show existing functionality, start the local server in terminal 1:

   ```sh
   python -m uvicorn canarygate.api.app:app --host 127.0.0.1 --port 8000
   ```

   In terminal 2 run `python -m canarygate.demo` and open the printed fixture
   report. Stop the server with Ctrl+C when finished.

If the environment is not activated, use `.venv/bin/python` on Linux/macOS or
`.\.venv\Scripts\python.exe` on Windows. Never put real credentials into a scope
file; a reference to approval is not a substitute for organizer authorization.
