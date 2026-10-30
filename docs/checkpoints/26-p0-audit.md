# Checkpoint 26 — P0 audit and fixture reporting (not acceptance)

This checkpoint improves the safe synthetic vertical slice and documents all
known outstanding acceptance gaps; it does **not** complete v3.2 P0. Read
`docs/P0_ACCEPTANCE_MATRIX.md` first. The fixture API is local-only and
unauthenticated; do not expose it as a service. No lab or live target was scanned.

## Test and demo in VS Code

Open the repository folder and an integrated terminal. From the repository root:

```sh
# macOS/Linux (Windows: .venv\Scripts\python instead of .venv/bin/python)
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python tools/run_ci_tests.py
.venv/bin/python -m uvicorn canarygate.api.app:app --host 127.0.0.1 --port 8000
```

In a second terminal:

```sh
.venv/bin/python -m canarygate.demo
```

The demo runs only synthetic in-process HTTP. To see the new JSON section view,
start a fixture scan and substitute the returned `id` in the report request:

```sh
curl -X POST http://127.0.0.1:8000/api/scan
curl 'http://127.0.0.1:8000/api/reports/<id>?view=sections'
curl 'http://127.0.0.1:8000/api/reports/<id>?format=html'
```

In PowerShell use `curl.exe` and replace `<id>` with the actual UUID. The
nine sections match by content; the matrix labels its single fixture cell
`partial_fixture`, and manual/inferred information is `NOT_RECORDED`. Original
JSON and observation interfaces remain available. The report has synthetic,
minimized evidence, not replayable HTTP transcripts; it does not demonstrate
organizer-target authorization.

## Checkpoint changes

- Adversarial tests first exposed false SAFE authentication denials, undetected
  debug headers, missing public-fixture behavior and missing report sections.
- A denial must have the checked empty fixture body; malformed/extra/private
  contents are INCONCLUSIVE. The owner's private baseline is never printed.
- An optional exact scoped, declared fixture public health check reports SAFE
  only with the exact expected body and is SKIPPED by the bundled fixture.
- Debug header signatures are observed without recording values. Stored JSON
  and HTML share nine report sections; old BOLA and authentication SAFE rows lacking a denial checklist
  are not promoted to secured.
- Budget-blocked cases remain skipped and appear in both report formats.
- Production network gate stays disabled. Generic checks, generic runner/oracle
  reconciliation, arbitrary-data redaction, full report, JWT probes, multiple
  input checks and live acceptance remain incomplete. See the detailed matrix.
