# Checkpoint 35 — isolated TargetLab HTTPS transport

**Goal:** let CanaryGate collect evidence from the running TargetLab itself,
without touching `competition` or `approved_lab`, without enabling production
networking, and without weakening a single existing safety rule.

**Result:** `POST /api/lab-scans` now performs real HTTPS requests to
`https://127.0.0.1:<port>` and stores verified, bounded evidence. It is
controlled validation against our own lab — **not** live-organizer validation, and
this checkpoint deliberately emits no BOLA or SCI verdict.

## Separate mode, separate transport

| Property | Competition / approved lab | TargetLab (`local_lab`) |
|---|---|---|
| Target | Organizer-approved host | Exact literal `127.0.0.1` |
| Transport | `GuardedHTTPXTransport` (disabled) | `TargetLabTransport` (new) |
| Certificate | Organizer-approved | Test-only CA, SAN `IP:127.0.0.1` |
| Scope | Organizer allow-list | Fixed `TARGETLAB_OPERATIONS` constant |
| Budget | Existing limits | Same guard, default 12 |
| Redirects | Blocked | Refused (a 3xx raises and halts) |
| Retries | Blocked | None: exactly one attempt |
| Production networking | Approval-dependent | Never enabled |

`approved_lab` and `competition` were not modified. Two *tightenings* were added,
both of which only ever reject:

1. A scope in `competition` or `approved_lab` mode may no longer use a loopback
   hostname or loopback `organizer_ip`. Before this checkpoint that combination
   validated; now it fails with *"loopback destinations require local_lab mode"*.
2. `local_lab` accepts only `https`, only the literal `127.0.0.1`, no
   `approved_resolver`, and only the exact routes in `TARGETLAB_OPERATIONS`
   (method + classification must match). `/lab/ground-truth` is deliberately
   **not** in that list, so the scanner can never read the answers it is scored
   against.

## Containment, enforced in code

| Requirement | Where it is enforced |
|---|---|
| Exact destination | `TargetLabTransport` requires `mode == "local_lab"` and `hostname == "127.0.0.1"`; the socket connects to the numeric literal. |
| No DNS | The transport calls `socket.connect((127.0.0.1, port))` directly. A test patches `socket.getaddrinfo`/`gethostbyname` to raise and the full evidence run still succeeds. |
| TLS verification | `ssl.create_default_context(cafile=<test CA>)`, `check_hostname=True`, `CERT_REQUIRED`, TLS ≥ 1.2. There is no `verify=False` anywhere in the module. |
| SAN enforcement | Proven two ways: a wrong CA fails closed, and a direct handshake with `server_hostname="api.organizer.example"` raises `SSLCertVerificationError`. |
| One authorization point | Every request calls `RunSafetyGuard.authorize`/`authorize_authentication` inside `execution()` immediately before the socket is created. |
| Budget | Same guard counter; a budget of 7 blocks the last two reads and the run reports `blocked_by_guard`. |
| No retries | One attempt per call; a 500 is returned once and the server sees exactly one hit. |
| No redirects | A 302 raises `TargetLabRefused`, the guard halts, and the server records exactly one request. |
| Size limit | `MAX_RESPONSE_BYTES` cap on every read. |
| Deadline | Per-request timeout (default 5 s, max 30 s). |
| Refusal before connect | A refused path opens no socket at all: a spy on `socket.socket.connect` records zero connections. |

## Evidence workflow (`POST /api/lab-scans`)

Requires `CANARYGATE_TARGETLAB_CA` to point at the test certificate; without it the
API returns `400` and stores nothing. The request body is `{"port", "request_budget"}` —
nothing else can be configured.

Seven checks are executed in a fixed order against the live lab:

| Check | Request | Ground truth |
|---|---|---|
| LAB-01 | `GET /profile` as alice | alice's identity |
| LAB-02 | `GET /profile` as bob | bob's identity |
| LAB-03 | `GET /records/ra` as alice | own record |
| LAB-04 | `GET /records/rb` as bob | own record |
| LAB-05 | `GET /records/rb` as alice | **bob's record — the deliberate BOLA** |
| LAB-06 | `GET /records/rb/secure` as alice | denied |
| LAB-07 | `GET /admin/users` as alice | denied |

Each response must be the object the transport recorded for that actor and path
(`verifies_recorded_read`); otherwise the check is `unverified`. Evidence is
bounded to status codes and booleans (`owner_matches_actor`,
`private_marker_present`, `body_sha256`, …). Tokens, passwords and response
bodies are never stored: a test asserts the strings
`lab-token-alice`, `alice-lab-password` and both private markers are absent from
the run JSON, the sections report, the HTML page and the raw SQLite file.

A live run against the lab produces `allowed 5 · denied 2 · authenticated 2` with
`requests_sent = 9` and `budget_remaining = 3` on the default budget of 12.

## Tests added (36)

`tests/lab/test_targetlab_transport.py` (24):

- admission: non-loopback literal rejected for seven host forms; `competition`/
  `approved_lab` cannot point at loopback; transport refuses a non-lab scope; CA
  file required; undeclared paths refused with zero connections; credentials must
  belong to scoped accounts;
- live: ground truth collected and verified; payload free of credentials/markers;
  budget exhaustion reported as `blocked_by_guard`; duplicate login refused; a 302
  refused and not followed; a 500 returned once (no retry); no hostname resolution;
  wrong CA fails closed; hostname/SAN mismatch rejected; unreachable port halts.

`tests/integration/test_targetlab_scan.py` (12):

- scan through `TestClient(create_app(tmp sqlite))` against a real uvicorn+TLS lab;
  storage/restart; tamper → 500; missing CA → 400 with nothing stored; unreachable
  lab → 502 with nothing stored; invalid payloads → 422; competition scope refused
  by the transport; refused request opens no socket.

## Results

- Full suite: **815 passed** (779 before this checkpoint + 36).
- Audit: 42 requirements, **49 test files**, 0 failures; `real_networking` files 0;
  the two new files are classified `loopback_tls` (loopback-only sockets).
- Wheel build: `canarygate-0.1.0-py3-none-any.whl`, 192,927 bytes, 116 files —
  contains the scanner's lab transport but **no** certificates, keys, tests or
  `targetlab` package.
- Local CI parity: Linux run of the full suite above; Windows CI result recorded
  separately after push.

## What this does and does not prove

**Does:** CanaryGate independently authenticates two accounts, performs real
HTTPS requests, verifies response provenance, and collects the ground truth
including the BOLA observation and the two secure denials — over a transport that
cannot reach anything except `127.0.0.1`.

**Does not:** emit a BOLA or SCI verdict (checkpoint 36/37), prove detection
quality (the lab is ours), or demonstrate live-organizer readiness. The report
says "controlled validation, not live validation" on every page.

## Next: checkpoint 36

Map these seven observations onto the existing read-BOLA oracle so the lab scan
produces a real `CONFIRMED` for `/records/rb` and a `SAFE` for
`/records/rb/secure`, through the same nine-section report and matrix — with the
lab's ground truth used only to score the result afterwards, never as an input to
the decision.
