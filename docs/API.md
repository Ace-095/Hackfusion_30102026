# Provisional fixture API — frontend handoff

These routes and schemas are **draft**, not approved or frozen. The v3.2
specification and user safety addendum are available in this repository but the
API has not completed full conformance or team review. The current schemas are
at `/openapi.json`. Swagger/ReDoc are disabled because their default assets use
external CDNs. The API is unauthenticated and in-memory: run only locally, never
expose it as a multi-user service.

All successful responses identify `mode: "fixture"`; they are not live results.
`POST /api/scan` takes no configuration or target, executes the bundled synthetic
fixture synchronously, and returns the completed result (201). A restart clears
all runs. The fixture target is not exposed as a network service. The local CLI
`python -m canarygate.demo` exercises these routes; see `VS_CODE_DEMO.md`.

| Route | Current response / behavior |
| --- | --- |
| `GET /api/health` | `{"status":"ok","mode":"fixture","live_scanning":false}` |
| `POST /api/spec/upload` | 501: not implemented; no uploaded spec is processed |
| `GET /api/endpoints` | Fixture inventory, parameters, OpenAPI auth requirements/provenance |
| `GET /api/setup/status` | Most recent fixture setup, or null before the first run |
| `POST /api/scan` | Synchronously run bundled fixture, return `FixtureRun` |
| `GET /api/scan/{id}` | `FixtureRun`, or 404 |
| `GET /api/findings` | `{mode, findings: [FixtureRun, ...]}` |
| `GET /api/matrix` | `{mode, cells: [...]}` for runs; not a full authorization matrix |
| `GET /api/reports/{id}?format=json` | `FixtureRun`, or 404; `json` is the default |
| `GET /api/reports/{id}?format=html` | Preliminary HTML fixture report; unknown formats return 400 |

`FixtureRun` includes ID, time, status, actor/role, endpoint, target resource,
verified owner, expected access and provenance, setup/readiness states, verdict,
reason, remediation, scope hash and fixture-only counters. Evidence has separately
named `ownership` and `disclosure` entries. Each is nullable and includes a
redacted request/response summary, account, role, time, status, verification
checklist and SHA-256 of the redacted summary. These are minimized summaries, not
complete captured HTTP traffic; there are no raw bodies or credentials. Use the
schema endpoint for exact fields and enum values. Missing evidence does not mean
that a check passed.

There is no real upload, authentication setup, asynchronous progress, live scan,
SQLite persistence, general evidence viewer, or complete report yet. Handle 501,
404 and null states rather than presenting placeholder data as completed scans.
