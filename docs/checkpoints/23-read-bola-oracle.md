# Checkpoint 23: fixture Read-BOLA oracle

## VS Code / judge demo

Open this repository in VS Code, activate the Python 3.11 environment, and run:

```sh
python -m pytest -v tests/integration/test_read_bola_oracle.py
python tools/run_ci_tests.py
```

On Linux/macOS use `.venv/bin/python` if needed; on Windows PowerShell use
`.\.venv\Scripts\python.exe`. The tests exercise the real registry and guarded
HTTPX MockTransport with synthetic responses. They do not contact a target or
DNS. For the existing local FastAPI and HTML/JSON demo, see
[VS Code demo](../VS_CODE_DEMO.md). Open the fixture report's Read-BOLA evidence
checklist and separately labeled ownership/disclosure evidence. Stop the local
server after the demo.

## Example outcomes

| Fixture evidence | Verdict | Why |
| --- | --- | --- |
| Both private resources verified, owner read matches, Alice's 200 returns Bob's matching private value, bundled policy says owner-only | CONFIRMED | Ownership and disclosure evidence agree, with a known denying policy. |
| Same ownership, Alice's checked 403 is exactly `{"error":"forbidden"}` and contains no owner marker | SAFE | The bundled fixture's expected denial and its entire body match the narrow denial contract. |
| HTTP 200 with ID/owner metadata but no private data; empty or ambiguous body; 401 or 404; unknown policy | INCONCLUSIVE | Success/status/ID alone, and authentication failure or ambiguous absence, do not prove access or denial. |
| Owner baseline missing/failed, ownership unverified, or actor/target identity mismatched | INCONCLUSIVE in the oracle | Required evidence does not exist or cannot be tied to the guarded fixture request. |
| Shared/public resource, or discovery fails before a cross-user request | SKIPPED by the fixture scanner | The check was not performed; no SAFE or CONFIRMED conclusion. The oracle alone returns INCONCLUSIVE. |
| SUSPECTED | Not currently emitted by this narrow oracle | Ambiguous observations remain INCONCLUSIVE rather than inventing a suspicious finding. |

Every new fixture scan includes a boolean `bola_checklist` and a verdict reason,
even when setup skips the check. False means *not established*, not necessarily
that the opposite was proved. Stored pre-checkpoint scans load with an empty
checklist (not recorded); no historical claims are inferred. Existing redacted,
separately hashed ownership and disclosure summaries remain in use.

## Boundaries and limitations

The pure oracle issues no HTTP requests; the existing scanner uses the existing
fixture runner and central fixture guard. The oracle rechecks registry entries,
owner baselines, synthetic credential/request binding, target, and bounded strict
JSON; it never treats JWT claims as identity evidence. The only accepted policy
source is the bundled synthetic fixture policy, and its only SAFE denial body is
the exact fixture JSON shown above. A 403 that includes extra fields, malformed
JSON, or the private marker is not SAFE. Markers that are masked, empty, the
same as the peer's, or derived from a resource ID do not prove disclosure.

These are trusted in-process fixture inputs, not independently authenticated,
tamper-proof live evidence. The owner/list completeness assumptions described
in [checkpoint 22](22-verified-ownership.md) still apply. Generic policy
provenance, pagination, live identity and ownership, arbitrary response formats,
production evidence redaction and the full evidence/verdict/reporting engine are
not implemented. This checkpoint does not implement BFLA. Production network
execution remains disabled; written organizer authorization is required before
any future external testing.
