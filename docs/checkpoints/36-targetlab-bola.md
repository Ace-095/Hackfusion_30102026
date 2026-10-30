# Checkpoint 36 — real TargetLab read-BOLA validation

**Goal:** prove CanaryGate can *detect* a real read-BOLA flaw against an
independently running API — not replay a transcript, and not read the answer key.

**Result:** `POST /api/lab-bola-scans` sends real HTTPS requests to the loopback
TargetLab, collects ownership through the shared registry, decides through the
single read-BOLA oracle, and stores a run whose six checks match the lab's
declared ground truth 6/6.

This is **controlled validation**, not live-organizer validation: the target is
`127.0.0.1` with a test CA, and the lab was written by the same team.

## What was integrated (and what was deliberately not built)

| Concern | Reused artifact |
|---|---|
| Ownership discovery, cross-list isolation, owner baselines | `canarygate.seed.registry.collect_guarded_ownership` |
| Identity observation before any ownership claim | `canarygate.accounts.identity_check.observe_identity_pair` |
| The verdict itself | `canarygate.oracles.read_bola.evaluate_read_bola` |
| Provenance | `TargetLabRunner.verifies_recorded_read` (same boundary as every other runner) |
| Guard, budget, one-shot login | `RunSafetyGuard` |
| Report | `report/p0.py` (nine sections) + `report/matrix.py` |
| Storage | `LabBolaStore` — same re-validate/redact/hash/tamper pattern |

**No second oracle and no second registry exist.** `canarygate/scan/lab_bola.py`
imports the shared ones, and a test asserts the file contains no local copy of the
decision logic (`test_the_workflow_reuses_the_single_bola_oracle`).

Exactly one change was made to the shared oracle: `evaluate_read_bola` previously
trusted `"offline scenario policy"` for every guarded runner. It now resolves the
trusted source per transport (`trusted_policy_source`): fixture →
`synthetic fixture policy`, generic guarded → `offline scenario policy`,
TargetLab → **`targetlab declared record policy`**. Nothing else in the oracle
changed; every pre-existing test still passes unchanged.

## The six checks

Requests per run: 2 logins + 2×(2 profile + 2 discovery + 2 baselines) + 4 cross
reads = **18** on a budget of 20.

| Check | Direction | Route | Expected | Observed |
|---|---|---|---|---|
| LAB-BOLA-01 | alice → alice | `GET /records/{id}` | SAFE | `200`, own record, marker distinct |
| LAB-BOLA-02 | bob → bob | `GET /records/{id}` | SAFE | `200`, own record, marker distinct |
| LAB-BOLA-03 | alice → bob | `GET /records/{id}` | **CONFIRMED** | `200`, bob's private marker |
| LAB-BOLA-04 | bob → alice | `GET /records/{id}` | **CONFIRMED** | `200`, alice's private marker |
| LAB-BOLA-05 | alice → bob | `GET /records/{id}/secure` | SAFE | `403 {"error":"forbidden"}` |
| LAB-BOLA-06 | bob → alice | `GET /records/{id}/secure` | SAFE | `403 {"error":"forbidden"}` |

A `CONFIRMED` requires the oracle's full chain: private resource, distinct
accounts, verified ownership for both owners, both owner baselines matching
id+owner with distinct private markers, the cross-account request matched to the
recorded response for that actor, and the response carrying the *owner's* marker
with the owner's id and owner field. `SAFE` on the secure route requires the
checked denial body, not just a 403.

Overall run verdict is `CONFIRMED` with `summary = {confirmed: 2, safe: 4}`.

## Ground truth is evaluated last, never consulted

`/lab/ground-truth` is **not** in the scanner's allow-list
(`TARGETLAB_OPERATIONS`), and the transport refuses any undeclared path before a
socket exists. Two tests prove the independence:

- `test_the_scanner_never_requests_the_lab_ground_truth` serves the lab behind a
  path recorder and asserts no `/lab/*` path was requested during a full scan;
  the observed paths are exactly the declared ones.
- `test_ground_truth_is_scored_after_the_verdicts_and_cannot_change_them`
  monkeypatches the declared table to all-`SKIPPED`: the stored comparison becomes
  0/6 while every check verdict stays byte-identical.

`GroundTruthComparison` records `evaluated_after_verdicts: true` and
`used_as_decision_input: false` so the stored run cannot be misread.

## Reporting

`?view=p0` returns the frozen nine sections with six findings
(`LAB-BOLA-01…06`, category `Authorization`), severity `High` for the two
confirmed ones, remediation key `bola`, per-finding `curl` with `$TOKEN_A`
placeholders, and expected/observed/expectation-source text. `secured_endpoints`
lists only the secure-route checks. The matrix gains two rows:

| Endpoint | Column | State |
|---|---|---|
| `GET /records/{id}` | `other_account_resource` | **red** (`CONFIRMED`, source `lab_bola:targetlab-bola:vulnerable`) |
| `GET /records/{id}/secure` | `other_account_resource` | **green** (`SAFE`, source `lab_bola:targetlab-bola:secure`) |

The other 13 declared lab routes stay `hatched`/untested, so the coverage gap is
visible rather than hidden. `executive_summary.network_transport_enabled` is
`true` and `live_target_contacted` is `false` — the run really opened sockets, but
not to any organizer or internet target.

## Adversarial results (11 tests, all pass)

| Case | Result |
|---|---|
| Mutated response body after receipt | provenance fails → `INCONCLUSIVE` |
| Response recorded for a different actor | rejected → `INCONCLUSIVE` |
| Ownership proof from the other endpoint | proof mismatch → `INCONCLUSIVE` |
| `shared` / `public` ownership model | registry refuses private ownership → `INCONCLUSIVE` |
| Untrusted policy source (fixture / offline / self-declared) | `policy_denies_access=false` → `INCONCLUSIVE` |
| Wrong account identity (token swapped between accounts) | identity mismatch halts the run; no `CONFIRMED`, no `SAFE` |
| Attempted `/lab/ground-truth` or `/openapi.json` read | refused before any socket |
| Reusing a closed runner | no re-authentication, verdict drops |
| Duplicate login in one run | guard blocks the second attempt, one request sent |
| Budget exhausted at 16 | last checks `SKIPPED`, `blocked_by_guard ≥ 1`, no invented verdict |
| Invalid CA / unreachable lab | API answers `502` and stores nothing |
| Non-loopback destination in the scope | rejected by the model |

## Results

- Full suite: **851 passed** (815 before this checkpoint + 36).
- Audit: **48 requirements**, 52 classified test files, 0 failures,
  `implemented=37 / partial=9 / missing=2`, `real_networking=0`,
  `loopback_tls=4`.
- Wheel: 122 files, no certificates, keys, tests or `targetlab` package.
- Delivered in commit `16b50cd` on `arena/aa67fa1b-hackfusion-30102026`.
- CI: workflow run **41081121279** — `ubuntu-latest` success and
  `windows-latest` success, including the real loopback TLS servers (uvicorn in a
  thread plus TLS handshakes) on Windows.

## Remaining gaps (unchanged, stated honestly)

1. Not live validation: no organizer, VAmPI, crAPI or internet target was
   contacted, and none may be without written approval.
2. The lab is ours, so detection quality against real-world APIs is unmeasured.
3. Only two record routes are exercised; BFLA (D11) and full frozen P0 remain
   open, and the nine partial requirements are unchanged.
4. Interaction (SCI) validation against the lab is **not** included here. The
   lab's state-dependent flaw (a rejected login enabling one guarded read) is
   checkpoint 37 work, and the combined leg must preserve that exact sequence.
