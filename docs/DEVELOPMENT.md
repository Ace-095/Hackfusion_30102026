# Development handoff

## Revised ownership

- Backend owner: models, API, spec parsing, accounts, discovery, ownership,
  safety/runner, security checks, evidence, verdicts, persistence and reports.
- Frontend collaborator: `ui/`, Jinja2 templates, locally vendored HTMX and
  local CSS, dashboard, inventory, setup, scan, findings, evidence, matrix and
  reports UI. No frontend is implemented here.
- Both: review the frontend/backend API contracts, integration and acceptance.

The revised requested workflow proposes `develop`, `feature/backend`, and
`feature/frontend`. These branches have **not** been created. Until the owner
sets and agrees an integration branch, `main` is the existing integration branch;
see [CONTRIBUTING.md](../CONTRIBUTING.md). The agent works only on its assigned
Arena branch. Do not assume the collaborator has access or that protections exist.

## 16-hour priorities

1. Review the supplied frozen v3.2 specification and safety addendum; jointly
   review contracts and freeze only after agreement. The API remains provisional.
2. Exercise a fixture-only BOLA vertical slice early, with independent owner and
   attacker observations and report output. Never portray fixtures as live scans.
3. Implement and test the real centrally guarded runner before any live traffic;
   authentication and discovery must go through the same guard.
4. Implement remaining P0 checks, provenance, setup gates, redaction, evidence,
   persisted reports and secured-endpoints section. P1 follows P0.
5. Integrate continuously and run the full spec's adversarial/acceptance suite.

See [decisions and checkpoint](DECISIONS.md) and [API contract](API.md).

## Running it (checkpoint 38)

```sh
python3 -m venv .venv && .venv/bin/pip install -e ".[test]"

.venv/bin/python -m pytest tests -q          # full regression
.venv/bin/python tools/p0_audit.py           # requirement audit; fails on drift
.venv/bin/python tools/demo.py               # four-stage demonstration, clean start
.venv/bin/python tools/consistency_audit.py --database <file.sqlite3>
```

`tools/demo.py` and `tools/consistency_audit.py` import one shared library,
`tools/demo_kit.py`, so the demonstration and the audit cannot drift apart. The
demo starts its own loopback TargetLab over TLS, uses a fresh database, and exits
non-zero if any reporting surface disagrees with any other. The audit re-hashes
every stored run and rebuilds its report projections from stored evidence alone.

Every new test file must be registered in `tools/p0_audit.py` with an evidence
class, or the audit fails; that is intentional, so no test can silently claim an
environment it does not use.
