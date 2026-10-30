# Provisional fixture API — frontend handoff

These routes and schemas are **draft**, not approved or frozen. The v3.2
specification and user safety addendum are available in this repository but the
API has not completed full conformance or team review. The current schemas are
at `/openapi.json`. Swagger/ReDoc are disabled because their default assets use
external CDNs. The API is unauthenticated and uses a local fixture-only SQLite
database: run only locally, never expose it as a multi-user service.

Fixture scan responses identify `mode: "fixture"`; they are not live results.
The separate specification-inspection response uses `mode: "inventory_only"` and
never runs a scan.
`POST /api/scan` takes no configuration or target, executes the bundled synthetic
fixture synchronously, and returns the completed result (201). Runs persist
across restarts in `.canarygate/fixture.sqlite3` by default, or the file specified
by `CANARYGATE_DB_PATH`. The fixture target is not exposed as a network service. The local CLI
`python -m canarygate.demo` exercises these routes; see `VS_CODE_DEMO.md`.

| Route | Current response / behavior |
| --- | --- |
| `GET /api/health` | `{"status":"ok","mode":"fixture","live_scanning":false}` |
| `POST /api/spec/upload` | Inspect raw UTF-8 YAML/JSON locally; returns `SpecInspection`, does not select a target or start a scan |
| `GET /api/endpoints` | Fixture inventory, parameters, OpenAPI auth requirements/provenance |
| `GET /api/setup/status` | Most recent fixture setup, or null before the first run |
| `POST /api/scan` | Synchronously run bundled fixture, return `FixtureRun` |
| `GET /api/scan/{id}` | `FixtureRun`, or 404 |
| `GET /api/scan/{id}/observations` | Minimized ownership observation set, or 404 |
| `GET /api/findings` | `{mode, findings: [FixtureRun, ...]}` |
| `GET /api/matrix` | `{mode, cells: [...]}` for runs; not a full authorization matrix |
| `GET /api/reports/{id}?format=json` | `FixtureRun`, or 404; `json` is the default |
| `GET /api/reports/{id}?include_observations=true` | Opt-in JSON bundle `{run, observation_set}`; default response stays `FixtureRun` |
| `GET /api/reports/{id}?format=html` | Local Jinja2 HTML fixture report with observations; unknown formats return 400 |

## Specification inspection (provisional)

Send the file as the **raw HTTP body**, not multipart form data. Accepted content
types are `application/yaml`, `application/x-yaml`, `text/yaml`, `text/plain`,
`application/json` and `application/octet-stream`; only UTF-8 is supported.
Compressed bodies are rejected. Example from the repository root (local API on
port 8000):

```sh
curl -sS -H 'Content-Type: application/yaml' --data-binary @canarygate/offline/fixture.yaml http://127.0.0.1:8000/api/spec/upload
```

The response contains `mode: "inventory_only"`, `live_scanning: false`, the
SHA-256 of the original bytes, `endpoint_count`, `endpoints` and a limitation
message. Status 415 means unsupported content type or encoding, 413 means the
128 KiB input limit was exceeded, and 422 means malformed or unsupported input.
Error responses are generic and do not echo the document.

This is a **bounded OpenAPI 3.0/3.1 subset**, not full OpenAPI validation: it
requires a `paths` mapping, uses safe YAML, rejects duplicate keys, YAML merge
keys, unsupported scalar types, cyclic aliases, remote/file references and
unresolved references. Local JSON-pointer references and operation-level
parameter/security overrides are supported. Expansion, parameter, endpoint and
serialized-inventory sizes are bounded. YAML response status keys such as `200`
are accepted. Authentication requirements are not ownership or role policy;
none of this grants permission to contact a host. The spec's `servers` values
are ignored as target authority.

Uploads are processed in memory and are not persisted, selected for `/api/scan`,
or used by `/api/endpoints`. That route and the scanner remain tied to the
bundled offline fixture. Only send synthetic or authorized specifications; the
response can include parameter details supplied in the document, and this is not
a production secret-redaction system. API contracts remain provisional.

## Fixture scan contracts

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

The observation-set response is `{mode, run_id, coverage, observations}`. `coverage`
is `RECORDED` when the set was saved (including an empty set if setup stopped
before discovery), or `NOT_RECORDED` when no observation row exists (normally runs saved before this checkpoint).
The absence of a row cannot distinguish a legacy run from a deleted observation set. The
ordered, individually hashed records cover the attempted discovery lists, owner
baselines and cross-user read. Nullable assertions indicate checks not performed;
false match means the expected match was not observed, not that an ambiguous
response proves security. Only synthetic actor names, methods/paths and IDs,
status codes, bounded allowlisted list/item metadata and Boolean comparisons are
stored. Authorization is redacted; response headers, arbitrary strings and private
values are not stored. Lists are limited to 20 displayed items and carry the total
count and a truncation flag. The assertion is calculated on the full fixture
response, so a truncated minimized observation is not independently exhaustive.

The JSON report's opt-in bundle is additive; existing run, findings, matrix and
default report contracts have not changed. The HTML report renders the stored
observations and provides a command to start **a new** local scan, plus a command
to retrieve the stored report. The mock target is in-process, not a curl endpoint.

Report, observation-set and per-observation checksums are verified when the
corresponding stored data is retrieved. A corrupt record yields a generic 500 instead of a finding; these unkeyed hashes
are not signatures or protection against a database writer who can recompute
them. Stored evidence is a minimized fixture summary, not full raw traffic.

The observation table is an additive, narrowly scoped migration, not a general
database migration system. There is no scan configured from an uploaded spec, real authentication setup,
asynchronous progress, live scan, general evidence viewer or complete report yet.
Handle 501, 404, 500 and null states rather than presenting placeholder data as completed
scans. The fixture redactor is not approved for live credentials or real data.
