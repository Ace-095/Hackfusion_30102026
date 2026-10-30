# Checkpoint 38 — stabilization, evidence consistency and the demonstration

**Goal:** stop adding features and make the existing product reliable to
demonstrate and to defend. A verdict that reads correctly but is *rendered*
optimistically is still wrong, so this checkpoint treats every reporting surface
as part of the evidence.

**Result:** one command runs the whole demonstration from a clean start and
refuses to print a result if any surface disagrees: 4 stages, 16 surfaces,
73 invariants, 916 tests, 0 audit failures (measured at CP38; head after CP39 is
142 invariants over 17 surfaces and 1055 tests).

Scope was frozen for this checkpoint: no new scan mode, no new interaction type,
no BFLA (D11 stays missing), no live-target testing (D12 stays missing), no LLM
classification.

## What was added

| Artifact | Purpose |
|---|---|
| `tools/demo_kit.py` | Shared library: run the stages, collect every surface, compare them, re-hash storage, static safety sweep |
| `tools/demo.py` | The judge demonstration, one command, clean start, non-zero exit on any disagreement |
| `tools/consistency_audit.py` | Re-check an existing database: re-hash every payload and rebuild every report from stored evidence |
| `tests/integration/test_demo_consistency.py` | 12 tests, including negative tests that prove the checker detects tampering |
| `docs/JUDGE_DEFENCE.md` | Architecture, technology choices, internals, false-positive prevention, limits, comparison and likely questions |

No API route, scope rule, verdict rule or oracle changed. The only product-code
edit is a report label that had been worded `no verify=False path exists`; it now
reads `no unverified-TLS code path exists`, so the static sweep can treat that
literal as forbidden everywhere without an exception.

## The four stages (exact numbers)

| Stage | What it shows | Result |
|---|---|---|
| 1 | read-BOLA, both directions, on `/records/{id}` | `CONFIRMED` ×2, owner baselines `SAFE`, 18/20 requests |
| 2 | the same cross-account read on `/records/{id}/secure` | `SAFE` ×2, `403` with the checked denial body |
| 3 | deny → rejected login → leak on `/records/{id}/guarded` | `CONFIRMED`, `interaction_induced`, 11/16 requests |
| 3b | reset proof, separate two-run scenario | `proven`: `403 → 401 → 200 → 403`, 8 requests |
| 4 | stored run, sections, nine sections, HTML, matrix | 73 invariants over 16 surfaces, all agree |

Stage 2 is deliberately a *projection* of stage 1's stored run, and the checker
says so: it is verified against its parent run and against the secure matrix cell
rather than being counted as new evidence.

## What "consistent" means here

For every stage the checker compares:

- **Identity** — one run id, one scenario id, on the run, the sections report and
  the nine-section report.
- **Verdicts** — every check's verdict in the stored run equals the verdict in
  the sections report and in the report findings; the report's verdict counts
  equal a recount of the stored checks (or, for SCI, the single interaction
  finding).
- **Evidence** — every control has exactly one digest; no two controls share one;
  every digest cited by a report exists in the stored evidence.
- **Accounting** — `requests_sent`, `blocked_by_guard` and `budget_remaining`
  agree across surfaces, and no run exceeds its budget.
- **Matrix** — the endpoint's `other_account_resource` cell matches the run's
  verdict and carries a `lab_` source label; stage 2's secure cell is green/`SAFE`.
- **Storage** — each payload re-hashes to its stored checksum, its `id` matches the
  row key, no id appears twice, and no lab secret appears in any payload.
- **Honesty** — every transport block says `127.0.0.1`, pinned test CA, redirects
  refused, no retries, no DNS, `live_target_contacted: false`; every HTML page
  states "Controlled validation, not live validation"; no surface leaks a token,
  password or private marker.

## The checker is itself tested

A checker that never fires proves nothing. The negative tests tamper with one
surface at a time and require the corresponding failure:

| Tampering | Expected code | Result |
|---|---|---|
| A finding's verdict changed in the nine-section report | `p0-verdict-mismatch` | detected |
| `requests_sent` changed in the sections report | `accounting-mismatch` | detected |
| A finding deleted from the report | `p0-finding-missing` | detected |
| Two controls given the same evidence digest | `duplicate-evidence-digest` | detected |
| The matrix cell's verdict flipped | `matrix-verdict-mismatch` | detected |
| A stored payload edited in SQLite | `database-hash-mismatch` | detected |
| `verify=False` planted in a source file | `forbidden-verify-disabled` | detected |

The first run of the checker also found three real modelling mistakes in itself —
it had expected a SCI report to carry one finding per baseline, it counted stage 2
as duplicate evidence, and it reported the same problem twice. They were fixed in
the checker, not by weakening it.

## Static safety sweep

`demo_kit.safety_sweep()` re-checks, on every demo run:

- forbidden: `verify=False`, `_create_unverified_context`, `CERT_NONE`,
  `check_hostname = False`, `follow_redirects=True`, `import requests`,
  `urllib.request`, `socket.create_connection`, `getaddrinfo`;
- required: `follow_redirects=False` in the guarded HTTPX client and the offline
  runner, `CERT_REQUIRED` and `check_hostname = True` in the lab transport.

## Results

- Full suite: **916 passed** (903 before + 13).
- Audit: **58 requirements**, 56 classified test files, 0 failures,
  `implemented=47 / partial=9 / missing=2 / unreachable=0`, `real_networking=0`,
  `loopback_tls=7`, 17 API routes checked.
- Demo: `ALL CONSISTENCY CHECKS PASSED (73 invariants over 16 surfaces)` (head
  after CP39: `142 invariants over 17 surfaces`).
- Delivered in commit `fc5f361` on `arena/aa67fa1b-hackfusion-30102026`.
- CI: workflow run `fc5f361` checks — `ubuntu-latest` success and
  `windows-latest` success, including the subprocess demo run and the real
  loopback TLS servers.

## Remaining gaps (unchanged)

`{D11 BFLA, D12 live validation}` plus the nine partial rows. 916 tests are
regression evidence, not 916 validated vulnerabilities. The lab is ours, so this
is not a measurement of real-world detection quality.
