# Judge defence — architecture, evidence and honest limits

This is the document to read before presenting CanaryGate. It answers the
questions a technical judge is most likely to ask, with the reasoning and the
file that backs each answer. Where the answer is "we do not do that yet", it says
so.

Everything below is verifiable in this repository at the checkpoint 38 commit:
**916 tests pass, 58 audited requirements (47 implemented, 9 partial, 2 missing),
0 audit failures.**

---

## 1. What the tool is, in one paragraph

CanaryGate is an evidence-based authorization tester for APIs. It authenticates
with two distinct accounts, proves which private resource each account really
owns, then attempts cross-account reads and records exactly what came back. A
finding is only `CONFIRMED` when a *complete chain* of evidence exists: verified
ownership, verified owner baselines, a cross-account request proven to be the
request that was answered, and a response carrying the owner's own private
marker. It also detects a second class of weakness that ordinary checkers miss: a
**security control interaction (SCI)**, where two controls each behave correctly
in isolation but their combination leaks data. Every verdict is reproducible from
stored evidence, and the same evidence is projected into a stored run, a sections
report, the frozen nine-section report, an HTML page and an authorization matrix
that are continuously checked against each other.

**What makes it different:** most scanners report "two checks failed". CanaryGate
proves "these two controls passed alone, and their interaction is what leaked
data" — and it refuses to claim either without the evidence chain.

---

## 2. The architecture

```
scope file (YAML)  ──> AuthorizedScope  ──> RunSafetyGuard ──> transport
                                              │  (the only place that
                                              │   authorizes a request)
                                              ▼
                            observations (status, bounded body facts)
                                              │
      ownership registry ──────────────┐      │      ┌────────────── oracles
      (collect_guarded_ownership)      ▼      ▼      ▼
                                   read-BOLA oracle   SCI oracle   authn/input/disclosure oracles
                                              │
                                              ▼
                                   verdict + checklist + evidence digest
                                              │
                     ┌────────────────────────┼─────────────────────────┐
                     ▼                        ▼                         ▼
               SQLite store            report projections        authorization matrix
             (hash, redact,          (sections, nine sections,     (endpoint × column)
              re-validate)                    HTML)
```

Five properties are structural, not conventions:

1. **One execution boundary.** Every request — including authentication and
   discovery — calls `RunSafetyGuard` immediately before the socket is created
   (`canarygate/network/targetlab.py`). There is no second code path that can
   reach a network.
2. **One oracle per question.** There is exactly one read-BOLA oracle
   (`canarygate/oracles/read_bola.py`) and one SCI engine
   (`canarygate/oracles/interaction.py`). The TargetLab workflows add
   orchestration and evidence adapters, never a second decision engine; a test
   asserts the lab modules contain no local copy of the decision logic.
3. **Verdicts are pure functions of evidence.** The oracles perform no I/O. They
   receive observations and return a verdict plus a checklist, so the same
   evidence can be re-evaluated deterministically.
4. **Storage is not a trust boundary.** A run is re-validated, redacted and hashed
   before it is written; reading it back recomputes the hash and refuses a
   mismatch (`EvidenceIntegrityError` → HTTP 500).
5. **Fail closed.** Unknown methods, unknown routes, unverified responses,
   ambiguous bodies, missing baselines and exhausted budgets all reduce or refuse
   the claim. Nothing defaults to "safe".

---

## 3. Why these technologies

| Choice | Reason | Where |
|---|---|---|
| **FastAPI + Pydantic v2 (strict models)** | The evidence schema *is* the contract. Strict models reject extra fields, coerce nothing, and fail closed on shape drift, so a malformed run cannot reach storage or a report. | `canarygate/scan/*_models.py`, `canarygate/api/schemas.py` |
| **SQLite** | A single-file, inspectable evidence store: no server, no ORM, tamper checks and tests can read it directly. | `canarygate/database/*` |
| **HTTPX** | The mandated client for guarded reads: explicit transport, `trust_env=False`, `follow_redirects=False`. | `canarygate/network/guarded_httpx.py`, `canarygate/offline/runner.py` |
| **stdlib `socket` + `ssl` for the lab transport** | `http.client.HTTPSConnection` resolves a hostname. We connect to the numeric literal `127.0.0.1` and attach a TLS-wrapped socket, so **no resolver is ever consulted** and DNS rebinding is structurally impossible. | `canarygate/network/targetlab.py` |
| **Jinja2 with local CSS, vendored HTMX** | Reports must render with no network access; no CDN, no remote assets, no remote `$ref`. | `canarygate/report/templates/` |
| **PyYAML safe loading with alias/anchor rejection** | Scope files are attacker-supplied input. Anchors/aliases are refused before parsing, so a scope cannot be made exponential or self-referential. | `canarygate/scope/authorized.py` |
| **pytest, 916 tests** | The claims are regression-protected: every safety property has an adversarial test, and the audit fails if a test file is unclassified. | `tests/`, `tools/p0_audit.py` |

Deliberately **not** used: an LLM classifier (non-deterministic evidence is not
evidence), a vulnerability database or CVSS engine (frozen spec excludes it),
Playwright/browser automation (the target is an API), a general-purpose scanner
library (it would hide the safety boundary).

---

## 4. How read-BOLA works internally

BOLA ("broken object level authorization") is: *the endpoint returns a record you
do not own*. Almost every scanner stops at "Alice got a 200 for Bob's id". That
is not proof. A 200 can be a public object, a shared object, a decoy, or a cached
copy of Alice's own data.

The oracle requires **eight** conditions, in order
(`canarygate/oracles/read_bola.py`):

1. **The resource is declared private.** `ownership_model == "private"`; shared
   and public resources can never be confirmed.
2. **Two distinct accounts** with distinct credentials, confirmed by an identity
   control (`/profile` must report the account the token belongs to).
3. **A trusted policy source.** The expected rule (`owner-only`) must come from a
   source bound to the transport that produced the evidence — fixture, offline
   scenario, or the lab's declared policy. A lab run cannot borrow fixture trust.
4. **Verified ownership for both accounts.** Each account's discovery list must
   contain its own record and must *not* contain the other's (cross-list
   isolation), and the two ids must differ.
5. **Owner baselines.** Each owner reads their own record; the response must carry
   the owner's id, the owner's identity, and a private field that is distinct
   between the two accounts and not a placeholder (`[redacted]`, `null`, `***`).
6. **The cross-account request is the one that was answered.** The response object
   must verify against the recorded request for *that actor, that method, that
   exact path* — not another run's response, not a mutated body.
7. **The response discloses the owner's marker** — compared with the value the
   owner returned on their own baseline — *and* still identifies itself as the
   owner's record. A matching marker with an incoherent identity is `SUSPECTED`,
   never `CONFIRMED`.
8. **A denial is only `SAFE` with a checked denial body.** A bare 403 is not
   enough; the exact declared denial contract must match.

Anything less produces `INCONCLUSIVE` or `SKIPPED` with the missing condition
named in the reason. The checklist stored with every finding is the eight booleans,
so a reader can see exactly which conditions were met.

**In the lab:** `GET /records/{id}` ignores ownership (vulnerable) and
`GET /records/{id}/secure` enforces it. Both directions are tested, and the
secure route produces `SAFE` with the same rigor.

---

## 5. How SCI works internally

A security control interaction is a weakness that neither control has alone. The
canonical shape in this repo:

```
oracle_1: EC(INPUT) = "input validation"   -> rejects a malformed request
oracle_2: EC(AUTHZ) = "authorization"      -> denies a cross-tenant read
interaction: the rejected request leaves state that makes the read succeed
```

The engine (`canarygate/oracles/interaction.py`) is a decision procedure over
five facts:

- both controls were **executed** and **observable**,
- both **passed on their own** (a control that already fails is *its own* finding;
  it can never be attributed to an interaction),
- the combined exchange was **executed, permitted and verified**,
- the impact was **demonstrated** (`private_data`, `privileged_data`,
  `internal_detail`),
- the outcome is **not explained by either control alone**.

Only then is the verdict `CONFIRMED` with attribution `interaction_induced`. If a
baseline is missing or unobservable → `INCONCLUSIVE`/`incomplete_baseline`. If a
control already fails → `INCONCLUSIVE`/`individual_failure`. If the combined read
was denied → `SAFE`. If it returned 200 with no private data →
`SUSPECTED`/`no_demonstrated_impact`. There are five global verdicts and no sixth.

**The TargetLab demonstration (real HTTPS):**

| # | Request | Result | Meaning |
|---|---|---|---|
| 1 | alice → bob's `GET /records/{id}/guarded` | `403 {"error":"forbidden"}` | authorization control works |
| 2 | alice `POST /login` with a wrong password | `401 {"error":"invalid_credentials"}` | authentication control works |
| 3 | alice → **the same** guarded read | `200` + **bob's private marker** | their interaction leaks |

The identical request by the identical actor changes outcome only because of the
intervening rejected login. The disclosure proof compares the returned marker with
the marker bob's own baseline returned, so a stale or unrelated value cannot
confirm it.

A separate two-run scenario (`POST /api/lab-sci-resets`) proves the state is
really state: `403 → 401 → 200 → 403`, where the last step follows a *successful*
login that clears the condition. It is deliberately separate — a run may
authenticate an account only once, and weakening that invariant to fit the proof
into one run would have been the wrong trade.

---

## 6. False-positive prevention

The question "how do you know it is real?" has one answer: **the tool cannot say
`CONFIRMED` without a chain, and each link is independently falsifiable.**

| Failure mode | Prevention | Test |
|---|---|---|
| Public or shared object | `ownership_model` must be `private`; discovery must show cross-list isolation | `test_shared_or_public_ownership_is_never_confirmed` |
| The id belonged to the caller | Owner baselines must carry distinct markers | `test_owner_baselines_are_distinct_and_marker_bearing` |
| Wrong account identity | `/profile` must match the token's account, or the run halts | `test_a_wrong_identity_halts_ownership_and_never_confirms` |
| Stale or replayed response | Responses verify against the actor+method+path that produced them, per runner | `test_a_stale_response_from_another_runner_is_not_evidence` |
| Edited evidence | Body digest checked after receipt; stored payload re-hashed on read | `test_a_mutated_combined_response_is_not_evidence`, `test_runs_survive_restart_and_tampering_is_rejected` |
| 403 treated as safe without proof | Checked denial body required | `test_a_checked_denial_is_the_only_clean_authorization_baseline` |
| 200 treated as vulnerable | Marker + identity required; a 200 without the owner's marker is `none`/`SUSPECTED`, never `CONFIRMED` | `test_a_denied_final_read_is_safe_and_a_data_free_success_is_not`, `test_disclosure_requires_the_owner_baseline_marker_and_the_owner_identity` |
| A control that is simply broken | `individual_failure` attribution, never an interaction | `test_an_already_failing_control_is_not_an_interaction` |
| Answer-key contamination | Ground truth is not in the allow-list and is scored after the run | `test_the_scanner_never_requests_the_lab_ground_truth`, `test_ground_truth_evaluation_cannot_change_the_stored_run` |
| Report drifting from evidence | Every surface is compared with every other, and the comparison is itself tested | `tests/integration/test_demo_consistency.py` |

The last row matters: a scanner that reports accurately but *renders*
optimistically is still wrong. Checkpoint 38 added a checker that compares the
stored run, the sections report, the nine-section report, the HTML page and the
matrix — and negative tests that prove the checker detects a tampered surface.

---

## 7. Limitations — the honest list

Stated in the product, the reports and the audit:

1. **No live-organizer validation (D12 missing).** The production transport is
   disabled by design. Every real request in this repository goes to
   `127.0.0.1`. This is deliberate: without written organizer approval, scanning
   someone else's API is out of scope, and the tool encodes that refusal.
2. **The lab is ours.** TargetLab was written by the same team as the scanner.
   Detecting its flaws proves the evidence pipeline and the reasoning, not
   real-world detection quality.
3. **Two accounts, one resource type.** The ownership model handles one private
   resource per run; roles, API keys and cookie sessions are not onboarded (D3
   partial).
4. **BFLA is not implemented (D11 missing).** Role coverage is a single
   escalation probe, not a role-versus-policy matrix.
5. **Nine requirements are partial** — notably: parser is a subset not full
   OpenAPI (D1), expected access is not generally ingested (D2), authentication
   checks use fixed fixtures (D6/D7), input validation uses recorded bodies
   (D8), disclosure detection is signature-based over recorded bodies (D9).
6. **One interaction kind** is exercised against the lab (`AUTHN+AUTHZ`). Three
   kinds exist in the engine; quantity is not coverage.
7. **916 tests are regression evidence, not 916 validated vulnerabilities.** They
   prove the implementation and its safety properties behave as specified.
8. **Not a replacement for manual review.** It answers "is this specific
   cross-account read provably broken" — not "is this API secure".

---

## 8. Comparison with conventional API security scanners

| Dimension | Conventional scanner | CanaryGate |
|---|---|---|
| Basis of a finding | Status code / signature match | Evidence chain: ownership + baselines + provenance + disclosure |
| False positives | Tuned by heuristics | Structurally reduced: a missing link downgrades the verdict, never a threshold |
| Denial handling | "403 = protected" | 403 counts only with the checked denial contract |
| Controls in combination | Rarely modelled | First-class: `interaction_induced` vs `individual_failure` |
| Evidence | Often "response body" in a log | Bounded facts, digests, re-hashable storage, no secrets or bodies |
| Reproducibility | Re-scan and hope | Deterministic re-projection; one command re-runs the demo |
| Safety | Scan anything, anywhere | Exact scope, one guard, loopback-only lab mode, refusals encoded in code |
| Reporting | One dashboard | Nine frozen sections + sections report + matrix, all cross-checked |
| Answer key | n/a | Ground truth exists, is scored after the fact, and is proven not to influence verdicts |

The trade-off is real and worth stating: CanaryGate is **narrower** than a
commercial scanner by design. It handles fewer vulnerability classes because each
class it does handle carries a proof obligation that a breadth-first scanner
cannot afford.

---

## 9. Likely judge questions, with answers

**"How do you know Alice didn't just read Alice's record?"**
Three independent facts: the ids are discovered from each account's own list and
must differ; each owner's baseline carries an id, an identity and a distinct
private marker; and the cross-account response is checked against the *owner's*
marker and the *owner's* record identity. Test:
`test_real_bola_is_confirmed_both_directions_and_the_secure_route_is_safe`.

**"Your target is a lab you wrote. Isn't that circular?"**
Yes, and we say so everywhere. The lab proves the evidence pipeline and the
decision logic against real HTTP and TLS. It cannot prove real-world detection
quality; that needs an approved external target (D12), which we do not claim.

**"What stops the tool from scanning a random host?"**
Three layers: the scope model only admits declared operations; `local_lab` requires
the literal `127.0.0.1` and refuses any other destination (a test tries
`127.0.0.2`, `192.168.x.x`, `::1`, and a hostname); and the lab transport refuses
any path outside a fixed allow-list before a socket exists. `competition` and
`approved_lab` modes cannot be pointed at loopback, so the lab path cannot be
reached by accident.

**"How is the answer key kept out of the verdict?"**
`/lab/ground-truth` is not in the allow-list, and a recorder test shows a full
scan never requests it. The declared table is read at *report* time by a module
the scanner does not import; corrupting it changes the report's score and leaves
the stored run byte-identical.

**"Why is `wrong_password` a probe? Isn't that just a failed login?"**
Because the flaw is state-dependent and the lab only sets its condition when the
login body parses and carries a string username. A syntactically broken body is
rejected before the account state machine is touched, so it would exercise
nothing. The probe is well-formed JSON with a wrong password, declared on the
exact authentication operation, one-shot per run.

**"What happens if the target is down or the certificate is wrong?"**
The API answers `502` and stores nothing. A refused or unverified connection is a
transport failure, not evidence; storing six `SKIPPED` checks would pollute the
evidence base. Tests: `test_missing_ca_and_unreachable_lab_store_nothing`,
`test_an_untrusted_certificate_is_refused`, `test_a_redirect_is_refused_rather_than_followed`.

**"Can the tool be tricked by a malicious target?"**
Partly. It is hardened against the obvious: duplicate JSON keys, non-standard
constants, oversized bodies, ambiguous bodies, replayed or mutated responses,
redirects, and identity mismatch. It is not hardened against a target that
deliberately fabricates a *consistent* private marker — that is an inherent limit
of black-box testing, and the report says findings are only as good as the
evidence chain.

**"Why not use an LLM to classify findings?"**
Because a verdict has to be reproducible from stored evidence and testable in CI.
A probabilistic classifier cannot be audited, cannot be re-derived from the
stored run, and would make the checklist meaningless.

**"What is the single most compelling thing to show?"**
Stage 3: 403 → 401 → 200 with the owner's private marker, then the reset proof
403 → 401 → 200 → 403. It shows the tool understands that the *sequence* is the
vulnerability, and that it can prove the state is real and reversible.

**"What would you do with another 8 hours?"**
In order: an organizer-approved live target for D12; BFLA for D11; then role and
API-key onboarding. Not more vulnerability classes — the evidence chain is the
differentiator, not breadth.

---

## 10. Reproducing every claim

```sh
python3 -m venv .venv && .venv/bin/pip install -e ".[test]"

.venv/bin/python -m pytest tests -q            # 916 passed
.venv/bin/python tools/p0_audit.py             # 58 requirements, 0 failures
.venv/bin/python tools/demo.py                 # the four-stage demonstration
.venv/bin/python tools/consistency_audit.py --database <demo.sqlite3>
```

`tools/demo.py` starts its own TargetLab over TLS on a free loopback port, uses a
fresh database, runs the four stages, and exits non-zero if any surface disagrees
with any other. It prints the exact request counts, statuses and verdicts quoted
in this document.
