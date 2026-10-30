# Backend decisions and checkpoint log

## 2026-10-30 — initial offline vertical slice (historical; superseded below)

**Ownership:** backend is ours; frontend belongs to the collaborator. The
complete v3.2 specification and collaborator approval have not been provided.
Neither the existing shared models nor the new API schemas are frozen or claimed
to conform to the full spec. See CONTRACTS.md. There is no sign-off yet.

**Execution boundary:** only the bundled synthetic target is callable. HTTPX is
constructed with `MockTransport` inside the fixture runner. No live transport or
user-supplied target exists. The fixture guard validates exact host/port, actor,
method, exact permitted operations and budget; the runner serializes calls and
does not follow redirects. This is **not** the real network guard: DNS resolution
and pinning, real request/streaming response size limits, authorized account
management, and live-target execution are not implemented. No claim of production
safety or full compliance is made.

**Ownership and evidence:** the synthetic recipe supplies ground truth for Bob's
private resource and its canary. Bob must log in and read that canary before Alice
is tested. Alice must independently receive that canary for CONFIRMED, and the
fixture policy must say owner-only. Otherwise the verdict is SKIPPED, SAFE or
INCONCLUSIVE as appropriate. This is fixture evidence, not live ownership proof.
Evidence stores only allowlisted summary metadata; SHA-256 is computed over the
canonical redacted summary, not the original HTTP exchange, and is not a signature
or proof that a request occurred. Tokens and private canary values are omitted.

**Parser:** uses `yaml.safe_load`, rejects all `$ref` (including local refs),
handles security inheritance and empty security alternatives. This is a deliberately
limited inventory parser, not complete OpenAPI 3.0/3.1 support.

**API:** synchronous, local-only, in-memory fixture demo. Runs are lost on restart;
there is no authentication, SQLite, upload, real account handling, live execution,
background queue, cancellation, or safe multi-user deployment. Route and JSON
shapes are documented in API.md and available as FastAPI OpenAPI schemas, but
must not be considered frozen until reviewed against the full spec and approved.
A single fixture scan runs on POST; no arbitrary host or scenario is accepted.
The JSON and HTML reports are preliminary, not the full spec-compliant report;
secured-endpoint reporting and the full constraint checklist remain unimplemented.

**Verification:** `python -m pytest -q` runs real in-process HTTP behavior. Tests
block `socket.connect` during the API flow, exercise parsing/security inheritance,
login, owner verification, disclosure, reports, missing identity, shared/public
resources, unknown access, denial, metadata-only responses, redirects, guard
rejections and budgets. These are fixture tests, not full spec adversarial
acceptance or evidence of live-target safety. This checkpoint ran 35 tests on
Linux/Python 3.11 (one third-party Starlette/AnyIO deprecation warning) and
built a wheel whose bundled fixture files were verified. Windows CI must run
after these changes are pushed; it has not been claimed as passing for this
checkpoint.

## 2026-10-30 — specification and safety corrections checkpoint (historical)

The supplied v3.2 Markdown is stored unchanged in `docs/spec/`. It still contains
`base_url` and lacks the two promised new numbered tests, so the user's explicit
corrections are recorded in `SAFETY_ADDENDUM.md` and take precedence. The recipe
validator rejects `base_url` and embedded passwords. A separate synthetic scope
is the sole origin authority. The fixture runner uses a central operation-aware
guard: exact classified operation and account, destination, budget, and method
are checked; unknown classification fails closed; dangerous GET, all DELETE,
and unauthorized writes are blocked. Fixture transport never performs DNS or
scanner network I/O. Approved DNS resolution, IP pinning, and live transport
remain unimplemented and must not be claimed.

The fixture now logs in both actors, discovers each actor's own resource, verifies
that each resource is excluded from the other actor's list, obtains both owner
baselines, then runs Alice's read of Bob's resource. CONFIRMED requires a private
owner baseline, observed disclosure, and known owner-only policy. Reflected IDs,
metadata-only responses, unknown policy, cross-list leakage and missing accounts
cannot produce CONFIRMED. Reports include setup gates, minimized/redacted
ownership and disclosure summaries, remediation, scope hash and fixture-only
constraint counters. They are still preliminary; full raw redacted evidence,
secured endpoint coverage, other P0 categories and SQLite remain outstanding.

The subset parser now resolves bounded local JSON-pointer references, rejects
remote/file references and traversal, rejects cycles, and retains OpenAPI security
inheritance and parameter overrides. It is not a full OpenAPI validator.
The default Swagger/ReDoc endpoints are disabled because they load CDN assets;
the local schema remains available at `/openapi.json`. See `VS_CODE_DEMO.md`
for runnable judge-demo instructions. The API schemas remain provisional until
team approval and full spec conformance review.

**Tests:** 50 passed on Linux/Python 3.11, including the two correction tests,
network/DNS-blocked end-to-end fixture execution, dangerous GETs, shared/public
resources, missing identity, cross-list isolation, local/remote refs, and redaction.
One third-party Starlette/AnyIO deprecation warning remains. The VS Code demo
CLI was also exercised against a running local Uvicorn process and its HTML
report was checked for fixture labeling and redaction; the process was stopped.
A built wheel contained all bundled fixture files. Windows CI for the current
changes has not run. These tests do not constitute the full section 15
acceptance suite or demonstrate live-target safety.

## 2026-10-30 — fixture authentication checkpoint (historical)

AUTHN-01 (missing token), AUTHN-02 (malformed token) and AUTHN-03 (wrong
scheme) run against the synthetic protected resource only after a valid owner
baseline and both-account readiness are available. Each specific probe must be
explicitly authorized for that exact read-only operation by the fixture scope;
the central guard validates it immediately before the in-process request. The
fixture accepts only fixed synthetic probe values, not arbitrary token overrides.
No live credentials or live network transport are enabled.

A 401/403 yields SAFE. A 200 is CONFIRMED only if it contains the same private
field established by the authenticated owner baseline; an empty/ambiguous 200,
redirect or response too large is INCONCLUSIVE. A probe rejected by scope or
budget is SKIPPED, never SAFE. Request/response summaries omit token values and
hash the redacted summary. The fixture's tokens are opaque: AUTHN-04a/04b/05 are
explicitly SKIPPED. JWT detection parses base64url JSON and the `alg` header only
to determine applicability, not to verify identity or privileges. JWT tampering,
logout, public endpoint and API-key checks remain unimplemented and SKIPPED.
If setup gates fail, these three fixture probes are also skipped; they are not
yet independently scheduled for partial setups.

Automated tests exercise actual mock responses for denial, bypass with private
disclosure, empty 200 and redirects; scoped and blocked probes; opaque versus JWT
classification; no network/DNS; redaction and evidence hashing; and the
executed-but-oversized distinction. 61 tests passed locally on Linux/Python 3.11
with one third-party Starlette/AnyIO deprecation warning. These are fixture
checks, not evidence of live-target safety or full section 15 acceptance. The
CLI and HTML report were also exercised against a running local backend.

The first Windows CI run failed because Windows asyncio creates an internal
loopback socketpair when the test client starts; the blanket socket block was
installed too early. The integration test now starts the client first and then
blocks DNS and socket connections for all API calls. Separate fixture-only tests
still block sockets before scanner execution. The failure was not suppressed:
GitHub Actions subsequently passed on both Windows and Linux for commit `dff0db5`
(run 41023826401). CI now publishes pytest failures as annotations and preserves
pytest's actual exit code.

## 2026-10-30 — input validation and disclosure checkpoint (historical)

The fixture scope now lists four **exact** read-only path/query combinations;
other values, encodings and extra parameters are rejected before transport.
A successful valid `limit=1` control precedes three fixed, bounded invalid
inputs (INPUT-01/02/04). A field-specific 400/422 is SAFE; an accepted invalid
input is SUSPECTED, while generic errors and redirects remain INCONCLUSIVE.
This is a fixture-specific subset, not generic OpenAPI-driven fuzzing.

DISC-01/02/05 examine these bounded responses for narrowly defined stack-trace,
internal-error and version-header signatures. Evidence contains the signal and
a hash of the redacted summary, not raw stack traces or version strings. A
negative result is limited to the sampled responses and requires all four to be
inspected; incomplete coverage is INCONCLUSIVE. Other validation/disclosure
checks are explicitly SKIPPED. Execution stops after two consecutive 5xx or a
423/429; unsent requests remain SKIPPED. Live DNS, pinning, live execution,
SQLite and other P0 checks remain unimplemented.

`docs/checkpoints/03-input-disclosure.md` gives the VS Code demo procedure and
expected fixture behavior. 78 tests passed locally on Linux/Python 3.11 with one
third-party deprecation warning; tests cover different observed fixture outcomes,
exact scope enforcement, network/DNS isolation, stop behavior and redaction.
The local CLI and HTML report were also exercised against a running local
backend, and a wheel was checked for the new modules and scope fixture. These
results are not the full v3.2 acceptance suite or evidence of live-target safety.
GitHub Actions also passed on Linux and Windows for checkpoint commit `937b33f`
(run 41024758853).

## 2026-10-30 — fixture persistence and evidence checkpoint

Fixture scan results and minimized redacted evidence are stored in a local
SQLite file (`.canarygate/fixture.sqlite3` by default, configurable with
`CANARYGATE_DB_PATH`). The API is still local-only and unauthenticated. Each
operation opens its own SQLite connection, writes use transactions and
parameterized SQL, duplicate run IDs cannot overwrite a record, and the JSON
report is size-limited. The fixture database and sidecars are Git-ignored.

Before writing, incoming evidence hashes are verified, credential-like fields,
patterns and known synthetic secrets are redacted, request/response fields are
minimized, and evidence hashes are recomputed over the stored summaries. On read,
both the report hash and each evidence hash are checked; corrupted records yield
a generic error instead of being served. SHA-256 hashes are **not signatures**:
a database writer who recomputes them can modify records. Redaction is designed
for the built-in fixture and is **not approved for arbitrary live credentials or
real API traffic**. Full redacted raw HTTP evidence, signing and database schema
migration are not implemented. No live target execution has been enabled.

Each run now retains its parsed fixture inventory and specification hash, so a
later spec change cannot silently alter a historical HTML report. The JSON API
response adds `inventory` and `spec_hash`; the contract remains provisional. The
VS Code procedure for demonstrating restart persistence is in
`docs/checkpoints/04-persistence.md`. Automated tests cover SQLite restart,
concurrent writes, credential redaction, evidence minimization, SQL parameters,
failed writes and corrupted report/evidence records. 90 tests passed locally on
Linux/Python 3.11 with one third-party deprecation warning. The local server was
also stopped and restarted and the original redacted report retrieved. These
results do not establish full v3.2 acceptance or live-target safety. GitHub
Actions passed on Linux and Windows for checkpoint commit `f5a004e`
(run 41027248092).

## Checkpoint 5 — fixture ownership observations and report auditability

Record the actual in-process fixture discovery, owner baseline and cross-user
responses as a separately stored, ordered minimized observation set, with truthful
nullable assertions. The allowlist retains only synthetic actor/role, fixed request
method/path, status, bounded safe IDs/owners, presence flags and Boolean checks;
private values, Authorization and arbitrary response fields are excluded. Truncated
lists are explicitly marked; assertions evaluate the full fixture response.

Use an additive `fixture_observation_sets` table keyed by run ID to preserve the
strict checkpoint-4 `FixtureRun` contract. New run and observation rows are written
in one transaction. Legacy runs with no row are `NOT_RECORDED`; a recorded empty
set means no qualifying steps occurred. Check the set and each observation hash on
read. These hashes are unkeyed integrity checks, not proof against a database writer
who can recompute them. The default JSON report remains unchanged; observation
access and the bundle are opt-in. Render the HTML with a local autoescaped Jinja2
template. Its reproduction command invokes a new local scan, never the in-process
mock target as a network endpoint.

Tests cover successful, failed, partial, secure and ambiguous fixture behavior;
legacy migration; redaction and SQLite bytes; corruption including a recomputed set
hash; injected write failure and transaction rollback; HTML escaping; persistence
and network/DNS isolation. This is not full v3.2 report or live-target capability;
the fixture redactor remains unsuitable for arbitrary credentials or live data.
106 tests passed locally on Linux/Python 3.11 (one third-party deprecation warning).
The CLI, stored JSON bundle and Jinja2 report were exercised against Uvicorn, then
retrieved after a real restart; the packaged wheel contains the report template.
GitHub Actions passed on Linux and Windows for code commit `f5bffbc`
(run 41029679747).

## Checkpoint 6 — bounded in-memory OpenAPI inspection

Add a raw-body UTF-8 YAML/JSON inspection endpoint with a 128 KiB streamed input
limit and generic errors. The uploaded document is never saved or used to select
the fixture or any live target. The existing `/api/endpoints` and `/api/scan`
remain fixture-only, with unchanged response contracts. `servers` cannot override
the scope file. Multipart and compressed uploads are not supported in this
checkpoint; the provisional client contract must be reviewed with the frontend
collaborator.

Continue supporting the bounded OpenAPI 3.0/3.1 subset, local JSON-pointer refs,
security inheritance and parameter overrides. Reject duplicate YAML/JSON keys,
merge keys, unsafe/non-JSON scalars, remote/file refs, cycles, invalid security
requirements and malformed or duplicate parameters. Limit expanded nodes,
operations, parameters and serialized inventory size. Authentication declarations
are not ownership policy or scope authorization. This is not full OpenAPI
validation or production redaction; parameter metadata can echo user input.

Tests cover YAML and JSON, stream and declared size limits, malicious refs, alias
expansion, bad encodings and malformed declarations; they verify that inspection
and the unchanged fixture run do not use network or DNS and that uploaded data is
not written to SQLite. 129 tests passed locally on Linux/Python 3.11 with one
third-party Starlette/AnyIO deprecation warning. A real Uvicorn upload and the
existing demo were exercised, and the wheel was checked for parser and template.
GitHub Actions passed on Linux and Windows for code commit `90f2e80`
(run 41037800312). Live scanning remains disabled.

## Checkpoint 7 — fixture sensitive-field and response-schema disclosure checks

Follow a test-first sequence: integration cases for normal, sensitive, masked,
undocumented, invalid-JSON, partial and persisted fixture responses were written
and run before implementation; the seven new scenarios initially failed because
DISC-03/04 were SKIPPED. Oracle tests also initially failed because the functions
were absent. A masking edge-case test was added, observed failing, then fixed.
Deeply nested JSON tests subsequently exposed uncaught decoder recursion in fixture response
handling; those tests failed first, then passed after bounded failure handling.
An existing full-suite assertion that still expected DISC-03/04 to be skipped was
updated after confirming the changed behavior. No result was fabricated.

DISC-03 scans only bounded JSON fixture responses for a small explicit allowlist
of sensitive field names containing unmasked nonempty strings; it returns flags,
not names, paths or values. Masked, redacted, empty and null values do not trigger
confirmation. Uninterpretable values and incomplete traversal do not prove safety.
DISC-04 compares only top-level keys against the bundled fixture's explicit,
closed JSON response schemas for the actual status. An undocumented field is
SUSPECTED rather than equated to sensitive disclosure; missing, open or complex
schemas are INCONCLUSIVE. Both checks reuse the four already-scoped responses,
with no extra requests. SAFE means only that the named signature was not seen in
the four fully inspected synthetic responses. Redaction occurs before evidence is
returned or stored; hashes cover minimized evidence, not raw traffic.

The local full test suite passed: 142 tests, with one third-party Starlette/AnyIO
deprecation warning. Real Uvicorn checks verified both the prior-checkpoint run
and a new run, and reloaded the new report after restart; the wheel contains the
fixture response schema and new oracle. GitHub Actions passed on Linux and Windows
for code commit `6057db9` (run 41039218117). Live scanning, general secret
detection, full JSON Schema validation and pattern-based detection remain unimplemented. API contracts remain
provisional and the fixture redactor is not appropriate for arbitrary live data.

## Checkpoint 8 — scoped fixture enumeration comparison

Test-first integration cases for uniform responses, status/body differences,
redirect, server error, oversized response, missing prerequisites, scope block
and persistence were run before implementation: eight failed for the missing
feature and one existing skip case passed. A subsequent test exposed an overly
broad SAFE explanation; its assertion failed first and the explanation was made
specific to the actual status, content type and body comparison. New pre-fix
tests also revealed that HTTPX cookies could carry authentication into the
missing-auth probe; the fixture runner now clears its cookie jar between requests,
and comparisons reject baselines carrying cookies or proxy authorization. Existing request
count and skipped-check assertions were updated only after verifying that one new
exactly scoped request is actually sent.

DISC-06 uses the already-executed missing-auth denial response for Alice's
independently verified synthetic resource, then makes one guard-authorized,
missing-auth GET to the known-absent fixture ID. It compares only status, content
type and response body bytes in memory. A difference is SUSPECTED, not confirmed;
matching values are SAFE only for those compared aspects and this synthetic pair.
Other headers and timing are not measured, and a difference may be benign. A
missing denial baseline, failed identity, scope rejection or exhausted budget
prevents the request. Redirects, server errors and oversized responses are
INCONCLUSIVE. Raw responses, values and hashes of the raw responses are not
persisted. The normal fixture now sends 15 requests within its budget of 20.

This is not a generic ID enumeration mechanism, not a live-target check and not
proof of system-wide safety. The full local test suite passed: 159 tests with one
third-party Starlette/AnyIO deprecation warning. Tests cover DNS/network isolation,
missing prerequisites, authorization and budget blocks, actual fixture response
variants, redaction, persistence and evidence hashes. A real Uvicorn demo was run,
old and new reports were retrieved, and the new result survived a server restart;
the wheel contains the enumeration module and its exact scope. GitHub Actions
passed on Linux and Windows for code commit `8ee800e` (run 41040353076). Live
scanning stays disabled.

## Checkpoint 9 — bounded fixture enum validation

The 159-test baseline passed before work. Nine test-first integration cases were
added and run before implementation: eight failed because enum probing and its
coverage were absent, while a missing-prerequisite case passed. A later test found
that the fixture did not accept all values declared by its new enum; it failed
first, and the fixture handler was corrected. Another test found that a Boolean
minimum could be mistaken for integer `1`; strict integer-type checks now fail
closed. Existing tests were updated after observing the additional guarded request
and five-response disclosure coverage. No tests were made to pass artificially.

The fixture declares integer enum `[1, 2, 3]` within range 1–10. INPUT-03 runs
only after the existing `limit=1` control and an applicable enum; it sends exactly
`GET /search?limit=9`, which is in numeric range but outside the enum. The scope
contains that exact query and continues to block unspecified variants. A 400/422
is SAFE only with a field-specific, non-internal error, acceptance is SUSPECTED,
and ambiguous, oversized, redirect or lockout responses are INCONCLUSIVE. Missing
schema/control, guard rejection, exhaustion or halt is SKIPPED. Lockout stops the
later enumeration probe. No user-provided target or arbitrary fuzzer is enabled.

Disclosure checks inspect all five applicable bounded fixture responses, including
the enum response. If the enum is not applicable, they inspect the original four;
if an applicable probe is blocked or oversized, absence cannot be reported as SAFE.
The redacted enum case and sample count survive persistence. The normal fixture
sends 16 requests within its budget of 20. The local full test suite passed: 176
tests with one third-party Starlette/AnyIO deprecation warning. The real Uvicorn
demo was run; old and new reports were retrieved, and the new result survived a
restart. The wheel includes the fixture schema and exact scope. Live scanning
and full generic OpenAPI/validation execution remain unimplemented.

## Outstanding checkpoints

- [ ] Both developers review shared and API contracts against the supplied specification and addendum.
- [ ] Complete OpenAPI parsing and validation beyond the current local-reference subset.
- [ ] Implement real account/authentication and verified resource discovery.
- [ ] Implement reviewed live-network guard with DNS pinning and all safety limits.
- [ ] Implement full readiness gates and honest setup statuses.
- [ ] Implement remaining P0 security checks, evidence storage/redaction and reports.
- [x] Add fixture-only SQLite persistence for minimized evidence and reports.
- [ ] Complete secured endpoints, constraint checklist and reviewed live-data persistence.
- [ ] Implement P1 BFLA/matrix per spec after P0.
- [ ] Run full offline integration and section 15 adversarial acceptance suite.
- [ ] Integrate collaborator's frontend after contract agreement.
