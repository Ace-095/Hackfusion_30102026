# Independent API validation plan (preparation only)

**Status: no approval recorded; no independent target executed.** VAmPI and
OWASP crAPI are independent applications, not CanaryGate dependencies. Their
profiles are planning artifacts, not executable recipes, scope files, approval,
or a way to enable traffic. Offline fixtures remain the default. Do not send
scanner traffic to either application, including self-hosted instances, until
organizers explicitly authorize that exact target in writing. The same written
scope requirement applies to the competition API.

- [VAmPI profile and scenarios](VAmPI.md) and [candidate mapping](profiles/vampi.yaml)
- [crAPI profile and scenarios](crAPI.md) and [candidate mapping](profiles/crapi.yaml)
- [VS Code checkpoint demo](../checkpoints/24-independent-validation-plan.md)

## Revised milestones

| Milestone | Scope | Current status |
| --- | --- | --- |
| M2 | Read-BOLA oracle and evidence engine | Fixture-only oracle exists; general evidence/verdict engine remains outstanding. |
| M3 | Generic pagination and remaining P0 checks | Outstanding. |
| M4 | HTML and JSON reports | Fixture reports exist; production reporting remains outstanding. |
| M5 | Complete offline end-to-end validation | Existing synthetic vertical slice is partial; full acceptance remains outstanding. |
| M6 | Independent VAmPI validation | Preparation only; approval and readiness required. |
| M7 | Independent crAPI validation | Preparation only; approval and readiness required. |
| M8 | Competition API verification | Await exact supplied target, accounts and written scope, plus readiness. |

The eventual goal is one generic architecture usable against all four contexts;
the current fixture-only implementation has **not** demonstrated that goal.
The 16-hour deadline remains the priority; the eight-hour buffer is contingency,
not permission to expand scope.

## Gate before any future execution

1. Obtain explicit written organizer approval **for each** target, instance and
   permitted activity, including even locally hosted labs. Keep VAmPI, crAPI and
   competition authorization separate. Obtain safe supplied accounts/resources,
   approved expected-access policy and its source, time window, request budget,
   permitted operations and any remaining constraints. Mere self-hosting, source
   documentation, a populated planning profile or a claimed reference is not approval.
2. Check readiness and independently review the single guarded live HTTPX
   boundary, exact scope and classification, DNS validation/connection pinning,
   account identity, discovery and pagination, policy provenance, ownership,
   evidence redaction, reporting and end-to-end safety tests. **Production network
   execution is currently disabled in code; approval alone does not enable it.**
3. Only after those prerequisites are satisfied and enabling is separately
   approved and reviewed, construct a separate organizer-authorized scope for
   each exact scheme, host, port, actor and operation, plus budget. Scope is the
   sole target authority: never take a destination from a recipe, OpenAPI
   `servers`, redirect, profile or unchecked DNS result. Prefer organizer-supplied
   IP, otherwise use only an explicitly approved resolver; never query public
   resolvers. Never follow redirects or remote `$ref`.
4. Classify every exact operation from reviewed deployed behavior, not the HTTP
   verb or OpenAPI alone. Default to read-only and the exact explicitly
   authorized authentication operation. Unknown, DELETE and destructive
   operations are blocked. PUT/PATCH are blocked by default. Creation POST needs
   separate written authorization for that exact operation; no self-registration,
   state-changing retries, cleanup or deletion. Obtain seeded accounts/resources
   out of band. Never execute VAmPI's destructive `GET /createdb`.
5. Pre-register ground truth by resource, identity, policy source and mode before
   any probe. Perform only the authorized tests, sequentially under the one
   central guard and budget. Stop on guard, lockout, rate-limit or repeated-error
   conditions. Never use JWT claims alone to establish identity or access.
6. Record the target and exact authorized scope, approval reference (not secret
   material), version, case, expected and observed verdict with reason, checklist,
   coverage/skips, guard counters and minimized/redacted evidence. Keep fixture,
   VAmPI, crAPI and competition results separate. Compare expected vs observed;
   count TP/FP/TN/FN only for cases with independently established ground truth;
   report indeterminate and skipped cases separately. No claims until actually run.

## What works now versus later

The current scanner, registry and Read-BOLA oracle are fixture-specific; the
oracle recognizes the bundled synthetic policy and denial body only. It does
not accept these plans or operate generically against either application. Generic
recipe binding, per-target policy and response interpretation, live ownership,
pagination and production evidence storage/redaction remain incomplete. Planning
profiles contain no host, port, credentials, scope grant or execution entry
point. No additional HTTP mechanism, lab dependency or frontend is introduced.
The OpenAPI parser accepts a bounded subset; a successful static parse does not
imply runtime support or authorization to contact any host.
