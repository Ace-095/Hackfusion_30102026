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
restart. The wheel includes the fixture schema and exact scope. GitHub Actions
passed on Linux and Windows for code commit `a3db65f` (run 41041165887). Live
scanning and full generic OpenAPI/validation execution remain unimplemented.

## Checkpoint 10 — organizer scope data validation, still offline

After a 176-test baseline, test-first cases for exact host/IP, written reference,
account/role and operation classifications, DNS isolation, bounds, unsafe YAML,
credentials and scope ambiguity were added; they initially failed because the
module did not exist. A later set of tests exposed that non-unicast addresses
were accepted and were fixed before the full test run. The validator accepts only
bounded, unique-key YAML without aliases, exact unencoded paths and literal IPs
or an explicitly named organizer-approved system resolver. It does not resolve a
hostname, open a socket, persist the scope or configure the fixture scanner.

The immutable provisional scope model records written authorization references,
accounts/roles, method allowlists, budgets and classified operations. State-changing
POST entries require a separate written creation-authorization reference; this is
metadata only and does not enable any write. Destructive classifications are also
metadata, not executable permission. A reference cannot prove actual authorization.
This is not the central live guard, DNS validation or a pinned transport; all live
execution remains disabled. Limits and exact-literal-path restrictions are a
conservative subset pending real organizer scope and team review.

The full local suite passed: 214 tests, with one third-party Starlette/AnyIO
warning. No credentials, private organizer scope or generated reports were added
by this checkpoint. Scope contracts remain provisional.

CI verification: GitHub Actions run `41041772272` passed Ubuntu and Windows
for checkpoint 10 commit `c7bf78e`. The wheel and in-process fixture demo also
passed locally.

## Checkpoint 11 — offline preflight policy

Test-first exact actor/method/URL/classification and budget checks initially
failed because the preflight module was absent. Follow-up tests exposed that
Pydantic `model_copy(update=...)` bypasses validation; construction now validates
a serialized copy of the scope. The offline decision budget is protected by a
lock and a concurrent test cannot overspend it. Full local suite: 232 passed,
one third-party warning. GitHub Actions run `41042037520` passed Ubuntu and
Windows for commit `6eb1078`. See [judge demo](checkpoints/11-preflight.md).

This policy model is not connected to any runner or transport and is not a live
guard. Its per-instance decision counter is not a live request budget; it does
not enforce sequential requests, inspect authentication bodies, validate DNS or
pin connections. It does not allow resource creation, including when an approval
reference is present. No live target feature has been enabled.

## Checkpoint 12 — narrow pinned HTTPS read transport

At this historical checkpoint, a test-first, unintegrated component in
`canarygate.network.pinned_reader` could
perform only GET operations classified READ_ONLY in an organizer scope with a
literal organizer IP, HTTPS and in-memory per-account bearer tokens. The exact
actor/path decision occurs immediately before creating a socket; the IP is used
without DNS, and TLS verifies the scoped hostname. It is not exposed through the
API or used by the scanner. At that historical checkpoint direct invocation
could create traffic; checkpoint 21 subsequently disabled production execution.
Do not use it without written organizer authorization and independent review.

At checkpoint 12 the experimental reader used `http.client` directly, a mismatch
with the specified HTTPX runner. It was removed at checkpoint 13.

No proxies, automatic redirects, cookies, retries, login, writes, arbitrary
headers or query strings are supported. The reader uses one sequential lock and
per-instance budget; it stops on network failures, oversized bodies, rate limits,
lockout or repeated server errors. Raw response bytes are ephemeral and are not
safe to persist. It has a per-socket timeout but no overall wall-clock deadline;
the budget is not global across instances. DNS-only scopes, authentication,
discovery, real data redaction, full central guard integration, response policy
and end-to-end safety review remain outstanding. These limitations are blockers
for live scanning, not evidence that it is complete.

Initial 14 tests failed because the component did not exist. A subsequent TLS
failure test exposed exception details leaking and lack of halt; both were fixed.
Tests use mocked network sockets plus real TLS over an in-process socket pair,
including certificate hostname rejection. A follow-up test also caught inherited
TLS session-key logging, which is now disabled before the handshake. No external
target was contacted.
Full local suite: 257 passed, one third-party warning. GitHub Actions run
`41043336104` passed Ubuntu and Windows for `f9ee1cb`. After the session-key
logging fix, 258 local tests passed and GitHub Actions run `41043526099` passed
Ubuntu and Windows for `3e71a2d`. Judge demonstration:
[checkpoint 12](checkpoints/12-pinned-reader.md).

## Checkpoint 13 — a single guarded HTTPX execution boundary

Test-first boundary cases showed that the old standalone reader was still
importable and no guarded HTTPX transport existed. The old reader implementation was removed; an import-error-only tombstone
prevents stale build directories from repackaging it. Its existing socket, real-TLS socketpair, redirect, size, budget, halt, TLS
key-log and concurrency tests were retained against the HTTPX transport. The
HTTPX runner now sends through a single custom transport that performs the
scope/classification decision immediately before opening a pinned socket. The
transport itself rejects foreign hosts/ports, requests without authorized actor,
body-bearing GETs and non-GET methods; it replaces all incoming headers with
fixed scoped headers and never forwards cookies. It suppresses response headers
and stops after redirects, including when wrapped by an HTTPX client configured
to follow them. Real sockets and TLS are used only if this experimental Python
component is explicitly invoked; tests use mocks or a local socketpair only.

The HTTPX transport uses `http.client` only as its low-level HTTP/1.1 wire
implementation over the pinned, certificate-verified socket; the application
request/response interface and runner are HTTPX. No functional standalone reader remains. A wheel built over a stale build
directory was inspected to verify that only the inert tombstone is packaged. This is still not an integrated or approved live scanner:
only bearer-authenticated GETs to a supplied literal IP are supported, token
identity is not verified, response headers are not yet available to disclosure
checks, and login, DNS-only scopes, shared run budgets, absolute deadlines,
production evidence and full live safety review are missing. The fixture scanner
continues to use its separate in-process mock transport, not the live boundary.

The full local suite passed 263 tests with one third-party warning. GitHub Actions
run `41044921428` passed Ubuntu and Windows for `c78a3f7`. See
[judge demo](checkpoints/13-guarded-httpx.md). This is a conservative subset,
not completion of P0 or authorization to scan a real target.

## Checkpoint 14 — shared run guard state

A test-first checkpoint introduced `RunSafetyGuard`, a validated-scope-bound,
shared budget, sequential execution lock, halt state and server-error streak.
Multiple guarded HTTPX runners can be explicitly given the same guard, so a
request, rate limit, redirect or failure in one runner affects the entire shared
run. Tests initially failed because the guard did not exist. Full local suite:
270 passed, one third-party warning. GitHub Actions run `41045516009` passed
Ubuntu and Windows for `9b91345`. See [judge demo](checkpoints/14-run-guard.md).

This does not yet integrate a real scanner. A caller must explicitly share the
same guard; creating a new guard creates a new independent run. An eventual scan
orchestrator must create exactly one guard per scan and pass it through all
outbound paths, including login and discovery. At checkpoint 14 the HTTPX boundary was GET-only. Checkpoint 15 subsequently
adds a bounded network deadline and checkpoint 16 adds a narrow guarded login.
Resolver-only scopes and scanner/API integration remain unsupported. No external target or
DNS service was contacted in testing. The independently validated live-target
safety requirements remain outstanding.

## Checkpoint 15 — total network deadline

Test-first TLS socketpair tests exposed that a peer could delay the handshake,
headers or body beyond an intended total timeout while each individual socket
operation remained within its timeout. The HTTPX boundary now uses a 10-second
monotonic deadline and a watchdog that interrupts the active socket; it performs
TLS handshake only after the watchdog can track the wrapped socket. Network
failure or deadline expiry halts the shared run. Tests cover stalled handshake,
stalled headers/body and a slow-drip response without real target traffic. The
local full suite passed 274 tests with one third-party warning. GitHub Actions
run `41045822373` passed Ubuntu and Windows for `0b3a326`.

The timer addresses network waits, not an independently verified hard execution
time bound for arbitrary Python computation, thread starvation or local system
calls. Live safety review and real-target validation remain outstanding. The
component was GET-only at this checkpoint; checkpoint 16 later adds a narrow
guarded login. It is not connected to the scanner or API. See the
[checkpoint 15 demo](checkpoints/15-network-deadline.md).

## Checkpoint 16 — scope-classified JSON login boundary

A test-first implementation adds a narrowly configured JSON POST login through
the same guarded HTTPX transport and shared run guard used for reads. Its
configuration names the exact scope-classified authentication path, two JSON
field names, one top-level token field and account-to-environment references;
embedded passwords and target URLs are forbidden. Environment names must begin
`CANARY_`. Passwords are read at request time, are bounded and never stored in
scope, recipe, logs or returned response. The account must be in the scope;
the transport constructs the JSON body and ignores caller-supplied headers and
bodies. POST login is attempted at most once per account in a shared run, and
a blocked retry does not consume an additional request budget. No other write
is enabled. Returned login bodies are replaced by `token_obtained` and
`identity_verified: false`; 200 or a token is not proof of account identity.

Initial login tests failed because the capability was absent; further tests
caught a rejected retry consuming budget and a password echo being accepted as a
token. Both were fixed. Tests cover direct HTTPX bypass attempts, malformed or
duplicate-key token responses, scope mismatch, missing credentials, redirects,
redaction and real TLS/HTTP framing via an in-process socketpair. No external
target was contacted. Full local suite: 293 passed, one third-party warning.
GitHub Actions run `41046397842` passed Ubuntu and Windows for `5de7aa7`.
See [judge demo](checkpoints/16-guarded-login.md).

This is not a full recipe/account workflow, identity verification, cookie/API
key support, discovery or a complete live scanner. It is not integrated into
the fixture scan or API. The `LoginConfig` and response are provisional internal
contracts; the v3.2 recipe and readiness gates still need integration and review.
At checkpoint 16 direct Python calls could send POST login and GET requests;
checkpoint 21 subsequently disabled production network execution pending review.

## Checkpoint 17 — explicit profile identity observation

Test-first cases introduced a bounded, ephemeral identity observation using a
specified scoped read-only profile path and top-level field through the guarded
HTTPX runner. A 200 response with a matching field is only `MATCHED`, never
identity verification or authorization proof. Missing/ambiguous data is
`INCONCLUSIVE`, unscoped setup is `SKIPPED`, and a clear mismatch halts the
shared run. Returned records contain no raw profile data or credentials. Tests
cover malformed and duplicate-key JSON, mismatches, unscoped inputs, shared
halts and a guarded login followed by a profile observation. They use mock
sockets only; no external target was contacted. Local full suite: 308 passed,
one third-party warning. GitHub Actions run `41046712345` passed Ubuntu and
Windows for `f3588a7`. See [judge demo](checkpoints/17-identity-observation.md).

This is not the two-account identity readiness gate or ownership verification.
Independent cross-account controls, resource discovery, generic recipes and the
live scan orchestrator remain missing. It is not exposed through the API and is
not authorization to run against a target.

## Checkpoint 18 — two-account identity observations

Test-first cases added `observe_identity_pair`: it requires two distinct scoped
accounts and two distinct in-memory bearer credentials before any request, then
observes the explicitly scoped profile operation as each account. Two matching
profiles yield `MATCHED_PAIR`, not a BOLA or ownership verdict; ambiguous data
is inconclusive, missing/duplicate identities are skipped and clear mismatches
halt the shared run. Responses and token values are not returned. Seven cases
initially failed because the pair helper did not exist. The full local suite
passed 315 tests with one third-party warning. GitHub Actions run `41046973754`
passed Ubuntu and Windows for `6cd6aa8`. See [judge demo](checkpoints/18-identity-pair.md).

These are observed profile controls, not proof of role, policy, resource
privacy or ownership. The scanner/API remain disconnected. Resource discovery,
verified ownership, live-data evidence, end-to-end safety review and the
remaining backend requirements are still outstanding. Tests contact no
external target or DNS service.

## Checkpoint 19 — bounded read-only resource harvest

Test-first cases added an in-memory, non-reporting private-list harvest through
the guarded HTTPX runner. It first observes two distinct account profiles, then
reads one explicitly scoped list as each account. A list must be bounded,
nonempty, unambiguous JSON with safe unique IDs and owner fields matching the
respective account. Overlap, mixed owners, missing data, budget exhaustion and
malformed responses are inconclusive; shared/public/unknown models and unscoped
setup are skipped before requests. Raw identifiers are excluded from repr and
must never be persisted by this component.

`HARVESTED` means only that two disjoint lists were observed. It is **not** a
verified ownership registry, proof of privacy, evidence or a BOLA verdict. Owner
detail baselines, independently reviewed expected policy, cross-user private
disclosure, redaction and report integration remain necessary. The helper is not
connected to the scanner or API. Tests use mocks only, with no external traffic.
The full local suite passed 334 tests, one third-party warning. GitHub Actions
run `41047263116` passed Ubuntu and Windows for `eab894d`. See
[judge demo](checkpoints/19-resource-harvest.md).

## Checkpoint 20 — conservative owner-baseline observations

Test-first cases added an in-memory helper that first performs the existing
account-profile and disjoint-list controls, then reads both owners' exact scoped
detail paths. It requires matching ID/owner fields and distinct, unmasked,
non-identifier private-field strings. Invalid templates, unscoped detail paths,
missing/masked/duplicate/ambiguous data and budget failures do not produce a
baseline. Follow-up tests caught masked values, public identifier fields and a
value derived from an ID being accepted; those now fail closed. The result
cannot be constructed with `ownership_verified=True` and never returns a BOLA
verdict. Identifiers and private values remain in memory, are omitted from repr,
and are **not approved for serialization or storage**.

These are observations only, not verified ownership, policy or separate
cross-user disclosure evidence. No live scan or API integration is enabled.
Tests used synthetic responses and mock sockets; no external target was contacted.
Full local suite: 360 passed, one third-party warning. GitHub Actions run
`41047675475` passed Ubuntu and Windows for `ddd9730`. See
[judge demo](checkpoints/20-owner-baselines.md).

## Checkpoint 21 — disable production live execution pending review

The user directed that the experimental boundary must not be connected to live
scanning before safety is reconciled and tested. Test-first cases showed that a
valid direct GET or login could still create a socket. The transport now has an
internal, default-deny gate with no environment or API override. Production
calls fail before DNS, socket creation, budget consumption or credential use.
The existing transport tests explicitly replace the gate only while using mocked
sockets or in-process socketpairs; separate tests exercise the unchanged disabled
production path. The fixture scanner remains in-process and operational.

This is a code-level safety hold, not a completed live scanner or production
security boundary against code changes or monkeypatching. Enabling live traffic
requires finishing and reviewing the outstanding guard, identity, ownership,
evidence and integration work, plus written organizer authorization. Full local
suite: 363 passed, one third-party warning. GitHub Actions run `41048031705`
passed Ubuntu and Windows for `c1586d7`. See [judge demo](checkpoints/21-live-disabled.md).

## Checkpoint 22 — fixture verified ownership

Test-first work added a fixture-only registry using the existing `OwnedResource`
contract. Two distinct synthetic accounts must discover bounded, unambiguous
lists, each peer list must exclude the other's selected resource, and both
owners must read a matching ID and explicit owner. Duplicate/unsafe IDs,
malformed JSON, pagination indicators, failed detail reads, missing credentials
and guard rejection cannot yield verified entries. Shared/public entries remain
unverified. Private disclosure markers are separate from ownership. All requests
use the existing guarded mock runner; only the existing synthetic BOLA pipeline
was wired to require the registry, with no new BOLA oracle. Baseline bodies are
transient and omitted from repr. Fixture list completeness is an assumption of
its synthetic array contract, not a guarantee for arbitrary live APIs. Production
network execution remains disabled. Local suite: 389 passed, one third-party
warning. See [judge demo](checkpoints/22-verified-ownership.md).

## Checkpoint 23 — fixture Read-BOLA oracle

The scanner's inline BOLA verdict logic is replaced by one pure fixture oracle
using the existing `Result` and verified `OwnedResource` registry. It checks
both owner baselines and fixture request identities, distinct unmasked private
marker, matching cross-account private response, and the bundled owner-only
policy. HTTP 200/ID alone, unverified ownership, unknown policy, non-private
resources, ambiguous bodies and identity mismatch are inconclusive; the scanner
skips if prerequisites prevent a probe. SAFE requires the exact checked fixture
403 denial body without the marker; 403 status alone is insufficient. A
regression test caught a denial body matching the private marker and prevents a
false SAFE. It emits no SUSPECTED verdict at this narrow stage.

New fixture reports store a boolean oracle checklist and reason. Old stored runs
remain readable with an empty checklist instead of fabricated evidence; the
unkeyed stored checksum is not an authenticity guarantee. This is a provisional
API addition for the frontend collaborator. The existing redacted fixture
summaries and guard remain in use. No BFLA, general evidence engine, live network
execution, or live target testing was added. Full local suite: 427 passed, one
third-party warning. See [judge demo](checkpoints/23-read-bola-oracle.md).

## Checkpoint 24 — independent validation planning only

The user added separate VAmPI and crAPI validation milestones, explicitly gated
on written organizer approval even for local instances. Added inert, target-free
candidate mapping profiles and scenario/ground-truth plans; neither profile is
a runtime recipe or scope and neither application is a dependency. Static review
of pinned GitHub sources found VAmPI's global book list prevents the frozen
peer-list-exclusion proof; its destructive GET `/createdb` is never allowed.
crAPI's candidate owner and location fields are nested and its detail response
does not directly match the registry's owner contract. These are readiness
blockers, not permission to weaken ownership. Full pinned upstream OpenAPI specs
were parsed locally for inventory only; no lab was launched or contacted. No
independent live validation has been performed, and network execution is still
disabled. See [validation plan](validation/README.md) and
[judge demo](checkpoints/24-independent-validation-plan.md).

## Checkpoint 25 — fixture detection pipeline and bounded extraction

Test-first work added bounded dotted object-key selectors to the existing
fixture recipe, registry, oracle and minimized observations, and optional body
continuation-token pagination with exact scoped queries, a four-page-per-account
cap, 256 IDs/account, existing response and request budgets, explicit null
termination, cycle detection and fail-closed ambiguity. Follow-up tests found a
model-copy validation bypass and contradictory `has_more` metadata; both now
fail before a false ownership result. Wrapped lists require explicit termination.
This is not generic live pagination, and list/detail fields still must match.

The fixture oracle now returns SUSPECTED only for a matching private marker with
incomplete but noncontradictory identity, after verified ownership/baselines and
a known denying fixture policy. Confirmed, safe, inconclusive and skipped cases
remain independently tested. An end-to-end nested fixture exercises the same
registry, guard, oracle, storage and JSON/HTML report. Credential/cookie/private
sentinels were absent from tested fixture outputs, logs and SQLite; no claim is
made about arbitrary live data. No independent lab was run, no live execution
was enabled, and VAmPI/crAPI blockers remain. Full local suite: 471 passed,
one third-party warning. See [judge demo](checkpoints/25-fixture-detection-pipeline.md).

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
