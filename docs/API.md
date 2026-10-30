# Provisional fixture API — frontend handoff

These routes and schemas are **draft**, not approved or frozen. The v3.2
specification and user safety addendum are available in this repository but the
API has not completed full conformance or team review. The current schemas are
at `/openapi.json`. Swagger/ReDoc are disabled because their default assets use
external CDNs. The API is unauthenticated and uses a local fixture-only SQLite
database: run only locally, never expose it as a multi-user service.

All successful responses identify `mode: "fixture"`; they are not live results.
`POST /api/scan` takes no configuration or target, executes the bundled synthetic
fixture synchronously, and returns the completed result (201). Runs persist
across restarts in `.canarygate/fixture.sqlite3` by default, or the file specified
by `CANARYGATE_DB_PATH`. The fixture target is not exposed as a network service. The local CLI
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
reason, remediation, scope/spec hashes, a captured endpoint inventory and
fixture-only counters. `checks` contains
per-test authentication, validation and disclosure verdicts, evidence and skip
reasons; AUTHN-01/02/03 run only after their prerequisites and when the fixture
scope explicitly permits them. JWT-specific checks are skipped for opaque tokens.
INPUT-01/02/04 and DISC-01/02/05 cover only four fixed fixture responses, not all
possible inputs or disclosures. The remaining checks are explicitly SKIPPED. Evidence has separately
named `ownership` and `disclosure` entries. Each is nullable and includes a
redacted request/response summary, account, role, time, status, verification
checklist and SHA-256 of the redacted summary. These are minimized summaries, not
complete captured HTTP traffic; there are no raw bodies or credentials. Use the
schema endpoint for exact fields and enum values. Missing evidence does not mean
that a check passed.

Report and evidence checksums are verified when a stored run is retrieved. A
corrupt record yields a generic 500 instead of a finding; these unkeyed hashes
are not signatures or protection against a database writer who can recompute
them. Stored evidence is a minimized fixture summary, not full raw traffic.

There is no real upload, authentication setup, asynchronous progress, live scan,
general evidence viewer, migration system or complete report yet. Handle 501,
404, 500 and null states rather than presenting placeholder data as completed
scans. The fixture redactor is not approved for live credentials or real data.
