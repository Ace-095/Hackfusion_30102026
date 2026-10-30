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
.venv/bin/python -m targetlab --port 8765
# targetlab: DELIBERATELY VULNERABLE test API on http://127.0.0.1:8765 (loopback only, do not deploy)
```

| Route | Behaviour |
|---|---|
| `GET /health` | Public status plus a live state snapshot. |
| `POST /login` | `{"username","password"}` → `{"token","identity","role"}`; 401 for bad credentials; 422 for a malformed body. |
| `GET /profile` | Bearer token required; returns the caller's identity and role. |
| `GET /admin/users` | Bearer token required; denies both lab accounts (403) — no admin exists. |
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
| Accounts | `alice` / `alice-lab-password`, `bob` / `bob-lab-password` |
| Tokens | `lab-token-alice`, `lab-token-bob` |
| Records | `ra` owned by alice, `rb` owned by bob |
| Private markers | `targetlab-alice-private-marker`, `targetlab-bob-private-marker` |
| Trace marker | `targetlab-trace-marker` |

`targetlab.state.FLAWS` is the single source of truth for the intentional flaws;
the tests and this document read the same data.

## The interaction flaw, exactly

1. `GET /records/rb/guarded` as alice → `403 {"error":"forbidden"}` (the control
   works alone).
2. `POST /login` as alice with an unexpected property → `422 {"error":"invalid_request"}`
   (input validation works alone, and the error is bounded).
3. `GET /records/rb/guarded` as alice → `200` with bob's private marker, because
   the rejected login left a legacy compatibility flag for that account.
4. `GET /records/rb/secure` as alice → still `403`; the flaw is narrow.
5. A successful login clears the flag; the flag is per account, never global.

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
| 35 | A guarded transport that can reach the lab over TLS without weakening the production guard: a loopback-only scope mode, pinned certificate, no redirects, same budget and one-execution boundary. |
| 36 | Live BOLA validation: detect `/records/{id}` (CONFIRMED with verified ownership and disclosure) and reject `/records/{id}/secure` (SAFE). |
| 37 | Live SCI validation: reproduce deny → reject → leak, verify the disclosure independently, and report CONFIRMED with an interaction explanation. |

The production guard stays as it is. A loopback mode is a separate, stricter
path: it must accept **only** `127.0.0.1`/`localhost`, require TLS, keep every
existing check, and be impossible to point at a remote host.
