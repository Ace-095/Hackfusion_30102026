# Development handoff

## Ownership

- Developer A: OpenAPI/spec inventory, expected access and provenance, accounts,
  authentication, setup recipes, discovery, ownership and readiness.
- Developer B: scope, centralized guard, runner, test execution/oracles, evidence,
  verdicts, remediation, reports, secured-endpoint section, matrix and UI.
- Both: shared contract review, fixtures, integration and adversarial tests.

The owners are proposed until both developers agree. All authentication and
resource-discovery requests must use the same central guard as test requests.

## Collaboration

Agree on an integration branch and a feature branch per developer with the
repository owner. Review small PRs, require passing Linux and Windows tests, and
avoid concurrent changes to frozen contracts without mutual agreement. Do not
put passwords or tokens in commits, issues, fixtures, reports or logs. Repository
settings and branch creation require the owner's explicit action and permissions.

## 16-hour deadline: priorities

1. Jointly review/freeze contracts and prepare offline fixtures.
2. Implement a guard before a mocked runner, plus parser/inventory and accounts.
3. Verify fixture ownership for two accounts; run read-BOLA through the guard.
4. Produce a report with separate ownership and disclosure evidence. A 200 alone
   or an unverified ID is never enough for CONFIRMED.
5. Add required P0 checks, secured endpoints, safety/adversarial tests, and honest
   skipped/partial setup. Add P1 matrix/BFLA only if P0 is complete.
6. Integrate continuously; reserve time for an offline acceptance run and demo.

The acceptance suite must cover no disclosure, unverified ownership, shared
resources, unknown permissions, missing second identity, secure behavior and
blocked destructive operations, in addition to a confirmed fixture case. Do not
claim the system passes until the actual pipeline and adversarial tests exist.
