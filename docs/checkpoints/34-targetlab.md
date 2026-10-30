# Checkpoint 34 — TargetLab

**Goal:** stop validating SCI only against scenarios we wrote for ourselves.
Build a real, independently running API with known ground truth, so the next
checkpoints can prove CanaryGate's behaviour against a server that is not a
transcript inside the scanner.

TargetLab is a separate FastAPI service in `targetlab/`. It is deliberately
vulnerable, runs on loopback only, and never talks to the network.

## Why a lab, and why this lab

The frozen P0 rules do not allow scanning anything without written organizer
authorization, and the production transport requires a pinned organizer IP over
TLS. That is the right default. It also means the scanner's own recorded
transcripts are, so far, the only executable evidence.

TargetLab closes that gap in the only way that is honest today: a target we own,
on one machine, whose answers are declared ahead of time. It is a *controlled
validation* environment — not a live target, not VAmPI, not crAPI, and not an
organizer system.

## What the lab contains

| Property | Implementation |
|---|---|
| Two independent accounts | `alice`, `bob` with distinct tokens and roles |
| Private resources | `ra` (alice), `rb` (bob), each with a unique private marker |
| Vulnerable endpoint | `GET /records/{id}` ignores ownership (BOLA) |
| Secure endpoint | `GET /records/{id}/secure` enforces ownership; `/admin/users` denies non-admins |
| Interaction-vulnerable endpoint | `GET /records/{id}/guarded` skips ownership for one account **after** that account's login attempt is rejected as malformed |
| OpenAPI documentation | `/openapi.json` and `/docs`, with the `bearerAuth` scheme |
| Predictable credentials | documented in `targetlab.state.LAB_ACCOUNTS` and `docs/TARGETLAB.md` |
| Harmless variation | `/diagnostics/banner` changes without granting anything |
| Disclosure endpoint | `/errors/trace` returns a synthetic stack trace and marker |

`/lab/ground-truth` exposes the flaw map, accounts and markers, so a scan can be
scored mechanically later instead of by eye.

## The interaction flaw, proven over a real socket

The lab was started with `.venv/bin/python -m targetlab --port 8765` and exercised
with curl (transcript abbreviated):

```
1) GET /records/rb/guarded            → 403 {"error":"forbidden"}
2) POST /login {username,password,admin:true} → 422 {"error":"invalid_request"}
3) GET /records/rb/guarded            → 200 {"id":"rb","owner":"bob",
                                             "private_note":"targetlab-bob-private-marker",
                                             "compat_state":true}
4) GET /records/rb/secure             → 403
```

That is the exact sequence the user asked to be proven: denied, then rejected,
then leaking — with the secure route unaffected. It is currently proven against
the **lab directly**; CanaryGate's own transport is checkpoint 35.

## Safety design

- The bind host must be loopback: `--host 0.0.0.0` exits with status 2 and a
  message. `assert_loopback_host` is reused by the launcher.
- A middleware rejects any request whose `Host` header is not loopback, so an
  accidental reverse proxy cannot expose it.
- The package has no outbound HTTP client; a test fails if a connection is
  attempted during the whole interaction sequence.
- Errors are bounded JSON; only `/errors/trace` returns a trace, by design.
- Credentials are obviously fake (`alice-lab-password`) and public. They must
  never be reused anywhere else.
- `canarygate` does not import `targetlab`; a test asserts the scanner package
  contains no reference to the lab.

## Tests (19, all green)

`tests/lab/test_targetlab_api.py`:

| Test | What it pins |
|---|---|
| `test_the_lab_documents_two_independent_accounts_with_private_markers` | Ground truth exists and is distinct per account. |
| `test_login_returns_identity_and_rejects_bad_credentials` | Login contract; no password echo. |
| `test_anonymous_access_is_rejected_everywhere_except_health_and_errors` | 401 with a bounded body on every protected route. |
| `test_admin_endpoint_denies_both_accounts` | No accidental admin in the lab. |
| `test_vulnerable_endpoint_leaks_another_accounts_private_marker` | The BOLA endpoint really leaks. |
| `test_secure_endpoint_enforces_ownership_in_both_directions` | The secure endpoint really denies, and allows the owner. |
| `test_the_full_interaction_sequence_denies_rejects_then_leaks` | The whole deny → reject → leak sequence, including the bounded 422. |
| `test_the_interaction_flaw_is_scoped_to_the_failing_account` | The flag is per account, never global. |
| `test_a_successful_login_clears_the_compatibility_state` | The flaw is resettable and deterministic. |
| `test_the_interaction_flaw_never_spreads_to_the_secure_endpoint` | The flawed route stays narrow. |
| `test_harmless_response_variation_has_no_security_impact` | Case H has a real counterpart in the lab. |
| `test_verbose_error_endpoint_leaks_a_synthetic_trace` | The disclosure target exists. |
| `test_openapi_documents_every_route_and_the_bearer_scheme` | The documentation requirement is real, not asserted. |
| `test_host_header_must_be_loopback` | Host-based exposure defence. |
| `test_the_runner_refuses_to_bind_a_public_interface` | Bind-time safety. |
| `test_the_lab_makes_no_outbound_connection` | Egress safety during a full sequence. |
| `test_the_scanner_package_never_references_the_lab` | Lab and scanner stay separate. |
| `test_the_lab_has_no_outbound_http_client` | No hidden client in the lab. |
| `test_reports_and_errors_never_echo_the_credentials` | No credential echo in responses. |

## Results

- Full suite: **779 passed** (760 before this checkpoint + 19 lab tests).
- Audit: 42 requirements, 47 classified test files, 0 failures. The lab test file
  is classified `in_process_api`; it is not a P0 capability.
- The lab also ran as a real uvicorn process on `127.0.0.1:8765` for the curl
  transcript above, then was stopped.

**Remote verification:** delivered in commit `ece5e0f`; CI run **41073125720**
passed on `ubuntu-latest` and `windows-latest` (19 lab tests included).

## What this does and does not prove

**Does:** the interaction scenario CanaryGate must detect is real, externally
observable, and deterministic; the "secure" negative control genuinely denies; and
the ground truth needed to score a scan exists.

**Does not:** prove CanaryGate can reach a live server (no live transport is
enabled), does not count as live validation, and does not change the P0 gate.
The lab is authored by the same team as the scanner, so it cannot be used as
evidence of real-world detection quality.

## Next: checkpoint 35

The production guard requires a pinned organizer IP over TLS and must not be
weakened. Checkpoint 35 will therefore add a **separate, stricter loopback mode**:
TLS with a test-only certificate for `127.0.0.1`, `hostname` restricted to
`127.0.0.1`/`localhost`, the same `RunSafetyGuard`, the same budget and the same
one-execution boundary, plus a test proving the mode cannot be pointed at a
non-loopback host. Until that exists, nothing in this repository can scan the lab
from inside CanaryGate.

**Gate:** unchanged. Offline P0 subset accepted with limitations; complete frozen
P0 not accepted; live validation not claimed.
