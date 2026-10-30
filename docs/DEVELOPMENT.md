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
