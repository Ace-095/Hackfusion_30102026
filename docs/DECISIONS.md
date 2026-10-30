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

## 2026-10-30 — specification and safety corrections checkpoint

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

## 2026-10-30 — fixture authentication checkpoint

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

## 2026-10-30 — input validation and disclosure checkpoint

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

## Outstanding checkpoints

- [ ] Both developers review shared and API contracts against the supplied specification and addendum.
- [ ] Complete OpenAPI parsing and validation beyond the current local-reference subset.
- [ ] Implement real account/authentication and verified resource discovery.
- [ ] Implement reviewed live-network guard with DNS pinning and all safety limits.
- [ ] Implement full readiness gates and honest setup statuses.
- [ ] Implement remaining P0 security checks, evidence storage/redaction and reports.
- [ ] Implement SQLite, secured endpoints and constraint checklist.
- [ ] Implement P1 BFLA/matrix per spec after P0.
- [ ] Run full offline integration and section 15 adversarial acceptance suite.
- [ ] Integrate collaborator's frontend after contract agreement.
