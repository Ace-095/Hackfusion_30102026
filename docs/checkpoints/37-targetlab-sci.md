# Checkpoint 37 — real HTTPS control-interaction (SCI) validation

**Goal:** prove CanaryGate can detect a weakness created by the *interaction* of
two individually correct controls, using real HTTPS requests, and prove the
lab's state-dependent condition resets — without letting the answer key decide
anything.

**Result:** `POST /api/lab-sci-scans` performs deny → rejected login → leak
against the loopback TargetLab. The existing SCI decision engine returns
`CONFIRMED` with `interaction_induced`. `POST /api/lab-sci-resets` proves, in a
separate scenario, that a successful login clears the condition.

This is **controlled validation**, not live-organizer validation, and it is not a
claim of general-purpose SCI coverage.

## The flaw being detected

TargetLab skips the ownership check on `GET /records/{id}/guarded` for an account
whose last login attempt was **rejected**. A rejected credential is normally a
*correct* control, and so is the ownership check; only their sequence leaks data.

## What ran (exact sequence, one runner, one budget)

| # | Leg | Request | Result |
|---|---|---|---|
| — | authenticate | `POST /login` as alice, then as bob | `200`, distinct tokens |
| — | identity | `GET /profile` ×2 | identity matched each account |
| — | discovery | `GET /records` ×2 | each account saw only its own record |
| — | owner baselines | `GET /records/{id}/guarded` ×2 | `200`, own record, distinct private markers |
| **1** | authorization baseline | alice → bob's guarded record | **`403`** `{"error":"forbidden"}` |
| **2** | authentication baseline | alice `POST /login` with a wrong password | **`401`** `{"error":"invalid_credentials"}` |
| **3** | combined read | alice → bob's guarded record again | **`200` + bob's private marker** |

**11 requests** on a budget of 16 (`budget_remaining 5`, `blocked_by_guard 0`).
Every leg was verified by the transport that produced it; a response recorded for
another actor, a mutated body, or a response from another run is not evidence.

## The verdict, and why it is not a route-name guess

```
SCI-AUTHZ  Authorization  GET /records/{id}/guarded   SAFE  (checked denial body)
SCI-AUTHN  Authentication POST /login                 SAFE  (checked rejection body)
combined   GET /records/{id}/guarded -> 200, private_data, verified
verdict    CONFIRMED   attribution interaction_induced   remediation sci_authentication
checklist  all eight keys true
```

The disclosure is not "a 200 happened". `disclosure_impact()` requires the
combined body to carry **the marker bob returned on his own baseline**, with
`id` and `owner` still identifying bob's record. A matched marker with an
incoherent identity is `ambiguous`; a different account's marker, an empty value
or a redacted placeholder is `none`. `private_data` is therefore only reachable
through a real cross-account disclosure.

## Reuse, and the one arithmetic change

Ownership comes from `collect_guarded_ownership`, identity from
`observe_identity_pair`, the credential rule from `credential_rejection_decision`,
and the verdict from `decide()` — the same engine the offline SCI scenarios use.
`canarygate/scan/lab_sci.py` contains no `def decide`, and a test asserts it.

One change was made to the shared oracle, and it is a hardening: `decide()` used
to accept an interaction with a *single* baseline, so a plan that silently dropped
one control could still be confirmed. It now requires one baseline per declared
control. Every pre-existing caller already passed two or more, so its behaviour is
unchanged and its tests pass untouched.

The run model is the existing `InteractionRun`, widened by exactly one mode
(`targetlab_sci`) with three optional evidence blocks (`transport`, `ownership`,
`disclosure`). An offline run is now *rejected* if it claims networking or carries
lab evidence, and a lab run is rejected unless it declares `127.0.0.1` and
`live_target_contacted: false`.

## One vocabulary addition, and why it was unavoidable

The rejected-login probe is declared as `wrong_password`, a new name in the
scope's probe vocabulary. A syntactically broken JSON body cannot be used here:
TargetLab only sets its legacy condition when the body parses and carries a string
`username`. A broken body returns `422` without touching the account state machine,
so the interaction would never reproduce. `wrong_password` is a well-formed login
body with a wrong password, it is permitted only where a scope declares it on the
exact authentication `POST`, and it is one-shot per run.

## Reset proof — a separate scenario, separate storage

`POST /api/lab-sci-resets` runs four checks with **two** guarded runs:

| Check | What it establishes | Result |
|---|---|---|
| RESET-01 | before any rejected login the guarded read is denied | `403` |
| RESET-02 | the rejected login is refused with the declared body | `401` |
| RESET-03 | the same read immediately after returns bob's record and marker | `200` |
| RESET-04 | after a **successful** login the same read is denied again | `403` |

Why two runs: a run may authenticate an account only once by design, and the
clearing event *is* a successful login. The second run performs only that login;
the reads stay on the first run. Totals: `runner_a 7`, `runner_b 1`, 8 requests.

The proof is stored in its own table (`lab_sci_resets`) and never rewrites the
interaction run. It can be attached to a report **explicitly** with
`?reset=<proof_id>` (rejected if the proof belongs to another port), and the
primary run's stored bytes are unchanged by running it — both are tested.

Ordering matters in the lab, so it is asserted behaviourally: the identical
request by the identical actor returns `403` at sequence 1 and `200` at sequence 3,
and only the intervening rejected login explains the difference.

## Ground truth stays out of the decision

The run is sealed and stored **without** any ground-truth data. The declared table
is read at report time by `lab_sci_ground_truth.evaluate_sci()`, which the scanner
does not import. Consequences, both tested:

- corrupting the declared table changes the report's score (1/1 → 0/1) and leaves
  the stored run **byte-identical**;
- a path recorder proves a full scan never requests `/lab/ground-truth` (which is
  not in the allow-list either).

## Reporting

- `?view=sections` — executive summary, scope and transport, baselines, combined,
  decision, disclosure, ownership, evaluation, limitations (+ `reset_verification`
  when a proof is attached).
- `?view=p0` — the frozen nine sections. `SCI-01`, category `Authorization`,
  `CONFIRMED`/`High`, remediation key `sci_authentication`, the interaction block
  (kind, controls, attribution, both baselines, combined exchange) and
  expected/observed/expectation-source text.
- Matrix — `GET /records/{id}/guarded` as a red `other_account_resource` cell with
  `source_ref` `lab_sci:targetlab-sci`; the aggregate matrix keeps
  `scope: partial_offline` because 13 other lab routes and the whole frozen P0
  surface remain untested.
- Manual interventions record the sequence, the baselines, the after-the-fact
  ground-truth comparison and the separately recorded reset.

## Adversarial results (all pass)

Missing baseline (rejected at the decision boundary) · unobserved baseline ·
already-failing control · undened read · denied secure read (`SAFE`) ·
data-free success (`SUSPECTED`) · ambiguous rejection body · accepted wrong
password · wrong marker · another account's marker · marker with incoherent
identity · mutated response after receipt · stale response from another run ·
reordered legs (proved behaviourally) · duplicated probe (guard blocks) ·
second login in one run (guard blocks) · swapped token · shared/public ownership ·
probe aimed at another path · `/lab/ground-truth` and `/openapi.json` refused ·
non-loopback scope · redirect not followed (one hit, `502`) · invalid CA · budget
exhausted · offline run claiming networking.

## Results

- Full suite: **903 passed** (851 before this checkpoint + 52).
- Audit: **54 requirements**, 55 classified test files, 0 failures,
  `implemented=43 / partial=9 / missing=2 / unreachable=0`, `real_networking=0`,
  `loopback_tls=6`, 17 API routes checked.
- Wheel: 130 files, 231,320 bytes, no certificates, keys, tests or `targetlab`
  package.
- Delivered in commit `fc965fb` on `arena/aa67fa1b-hackfusion-30102026`.
- CI: workflow run **41087011678** — `ubuntu-latest` success and
  `windows-latest` success, including the two-run reset scenario and the real
  TLS servers.
- Also fixed here: the redactor now knows the TargetLab fixture secrets, so a
  regression that leaked one would be scrubbed as well as asserted against.

## Remaining gaps (unchanged, stated honestly)

1. Not live validation: no organizer, VAmPI, crAPI or internet target was
   contacted, and none may be without written approval.
2. Only one interaction kind (`AUTHN+AUTHZ`) is exercised against one lab route.
   That is not evidence of general SCI coverage.
3. The lab is ours, so detection quality on real-world APIs is unmeasured.
4. BFLA (D11) and full frozen P0 (D12 and the nine partial rows) remain open; the
   missing set is still `{D11, D12}`.
