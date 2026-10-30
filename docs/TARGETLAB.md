# TargetLab — the controlled test API

TargetLab is a small, deliberately vulnerable FastAPI service that runs on
**loopback only**. It exists so CanaryGate can eventually be validated against a
server whose ground truth is written down, instead of only against its own
synthetic transcripts.

> **It is intentionally insecure. Never deploy it, never bind it to a public
> interface, never point it at real data.** The process refuses any bind host
> that is not loopback, and every request whose `Host` header is not loopback is
> rejected with `403 {"error": "non_loopback_host_rejected"}`.

TargetLab is not part of the scanner package. `canarygate` never imports it, and
a test enforces that.

## Run it

```bash
# plain HTTP: manual poking only
.venv/bin/python -m targetlab --port 8765

# TLS: required for CanaryGate scans (checkpoint 35)
.venv/bin/python -m targetlab --port 8765 \
    --tls-cert tests/fixtures/tls/targetlab-cert.pem \
    --tls-key tests/fixtures/tls/targetlab-key.pem
# targetlab: DELIBERATELY VULNERABLE test API on https://127.0.0.1:8765 (loopback only, do not deploy)
```

The test certificate has `subjectAltName = IP:127.0.0.1` and is signed only by
itself; it is a public fixture, never a credential for a real service. Point
CanaryGate at it with `CANARYGATE_TARGETLAB_CA=tests/fixtures/tls/targetlab-cert.pem`
before calling `POST /api/lab-scans`.

| Route | Behaviour |
|---|---|
| `GET /health` | Public status plus a live state snapshot. |
| `POST /login` | `{"username","password"}` → `{"token","identity","role"}`; 401 for bad credentials; 422 for a malformed body. |
| `GET /profile` | Bearer token required; returns the caller's identity and role. |
| `GET /admin/users` | Bearer token required; denies all three demo accounts (403) — no admin exists. |
| `GET /records` | Correct: each account sees only its own records (discovery for ownership verification). |
| `GET /records/{id}` | **Deliberately vulnerable (BOLA)**: any authenticated account reads any record. |
| `GET /records/{id}/secure` | Correct: owner-only, 403 for anyone else. |
| `GET /records/{id}/guarded` | **Deliberately vulnerable (interaction)**: owner-only *unless* that account's last login attempt was rejected as malformed. |
| `GET /errors/trace` | **Deliberately vulnerable (disclosure)**: synthetic stack trace with an internal marker. |
| `GET /diagnostics/banner` | Harmless variation: the banner flips to `compatibility` after a rejected login; nothing is granted. |
| `GET /lab/ground-truth` | Machine-readable flaw map, accounts and markers. |
| `GET /openapi.json`, `GET /docs` | OpenAPI 3 documentation, including the `bearerAuth` scheme. |

## Ground truth (synthetic, public, deterministic)

| Item | Value |
|---|---|
| Accounts | `mallapa`, `sakshi`, `harsha` (passwords `<name>-lab-password`) |
| Titles | Marketing Manager, Brand Designer, Campaign Analyst |
| Tokens | `lab-token-mallapa`, `lab-token-sakshi`, `lab-token-harsha` |
| Assets | `MKT-2026-041` (mallapa), `BRD-2026-018` (sakshi), `ADS-2026-027` (harsha) |
| Private markers | `targetlab-<account>-private-marker` |
| Trace marker | `targetlab-trace-marker` |

The three accounts model one fictional Digital Asset Management tenant: colleagues
who differ only in which private asset they own. Roles are descriptive metadata;
no route in the lab authorises on a role, so this is an authorization story, not a
role-permission story. Every ordered pair of distinct accounts is a valid
cross-account read.

> The **frozen offline fixture** in `scope.yaml` (`alice`/`bob`, `/items/alice-item`,
> `synthetic-bob-private-canary`) is a *different, untouched dataset*. The interface
> labels the two datasets separately so they are never confused.

`targetlab.state.FLAWS` is the single source of truth for the intentional flaws;
the tests and this document read the same data.

## The interaction flaw, exactly

Take any ordered pair, for example requester `mallapa` and owner `sakshi`
(asset `BRD-2026-018`):

1. `GET /records/BRD-2026-018/guarded` as mallapa → `403 {"error":"forbidden"}` (the
   control works alone).
2. `POST /login` as mallapa with an unexpected property → `422 {"error":"invalid_request"}`
   (input validation works alone, and the error is bounded).
3. `GET /records/BRD-2026-018/guarded` as mallapa → `200` with sakshi's private
   marker, because the rejected login left a legacy compatibility flag for that
   account.
4. `GET /records/BRD-2026-018/secure` as mallapa → still `403`; the flaw is narrow.
5. A successful login clears the flag; the flag is per account, never global.

The same sequence reproduces for every other ordered pair, with that owner's asset.

This is the sequence checkpoint 35–37 must reproduce through CanaryGate's own
guarded transport.

## Safety properties (tested)

- Binds loopback only; `python -m targetlab --host 0.0.0.0` exits with an error.
- Rejects non-loopback `Host` headers.
- Contains no outbound HTTP client and no internet access; a test fails if a
  connection is attempted.
- Bounded JSON errors only (no framework tracebacks except the deliberate
  `/errors/trace` endpoint).
- Passwords and tokens are obviously fake and documented; they are not secrets.

## What TargetLab does **not** prove

Running CanaryGate against TargetLab will be **controlled validation**, not
"live scanning of a real target". The lab is written by the same team, its flaws
are declared, and it runs on the same machine. Reports must say so.

## What it enables (checkpoints 35–37)

| Checkpoint | Goal |
|---|---|
| 35 | **Done.** Dedicated `local_lab` transport: literal `127.0.0.1`, pinned test CA with hostname checking, no DNS, no redirects, no retries, same `RunSafetyGuard`. See [checkpoint 35](checkpoints/35-targetlab-transport.md). |
| 36 | **Done.** Real requests through the `local_lab` transport reach the shared read-BOLA oracle: `/records/{id}` is CONFIRMED in both directions and `/records/{id}/secure` is SAFE, matching the declared ground truth 6/6. See [checkpoint 36](checkpoints/36-targetlab-bola.md). |
| 37 | **Done.** Real requests reproduce deny → rejected login → leak: `SCI-AUTHZ` and `SCI-AUTHN` pass alone, the combined read returns the owner's private marker and the SCI engine returns `CONFIRMED`/`interaction_induced`. A separate two-run scenario proves a successful login clears the condition. See [checkpoint 37](checkpoints/37-targetlab-sci.md). |
| Playground | **In progress.** `GET /api/lab-catalog` publishes the demo tenant (accounts, assets, the nine combinations and the ordered pair to run for each). A BOLA run covers one pair and answers that combination's row; `actor`/`owner` on `/api/lab-bola-scans` and `/api/lab-sci-scans` select the pair. |

The production guard stays as it is. A loopback mode is a separate, stricter
path: it must accept **only** `127.0.0.1`/`localhost`, require TLS, keep every
existing check, and be impossible to point at a remote host.
