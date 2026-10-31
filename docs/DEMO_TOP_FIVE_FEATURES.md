# CanaryGate — The Top Five

**How to use this:** each feature has a **pitch** (say it verbatim, ~10 seconds), an
**example** (the "for instance" that makes it concrete), a **where to click** (exact
demo location), and **cross-questions** with 15-second answers plus the trap
follow-up.

Every number here was measured against the running application. Nothing is invented.

---

## The 60-second pitch that covers all five

Use this to open, then expand whichever feature the judges lean into.

> "Five things make this different from a scanner you've seen before.
>
> **One** — I don't report a finding because I got a 200. I report it because I have
> a ten-link chain of proof. **Two** — I catch bugs where two security controls each
> pass their own test but fail together, and I prove which one caused it. **Three** —
> every finding is sealed with a hash, so you can re-verify it live instead of
> trusting my screenshot. **Four** — every request passes one guard that enforces
> scope, method and budget, with no DNS lookup and redirects off. **Five** — when I
> haven't tested something, I say so: an untested cell is never painted green.
>
> Let me show you the first two on the live system."

---

## The mapping table (pin this next to your screen)

| # | Feature | Demo step | Where exactly | Number to cite |
|---|---|---|---|---|
| 1 | Evidence-gated BOLA | 6, 7 | Matrix → click a **red** cell | 10 checklist flags, 9 true |
| 2 | SCI + reset proof | 9 | `/ui/lab` → SCI proof page | `403 → 401 → 200 → 403` |
| 3 | Tamper-evident evidence | 10 | Terminal: `consistency_audit.py` | 220 invariants |
| 4 | Fail-closed safety guard | 3 or 11 | Kill the lab, re-run / point at port 443 | 422 refused, nothing stored |
| 5 | Honest coverage model | 2, 6 | Dashboard before the run; matrix after | `0 / 9` → `9 / 9`, 0 untested |

**If you only get 90 seconds:** show 1, 2 and 5. They are the story.

---

# FEATURE 1 — Evidence-gated BOLA

### The pitch (say this)
> "Any scanner can tell you it got a 200 where it wanted a 403. That's a guess — the
> object might be public, shared, or the user's own. I only report a finding when ten
> conditions hold, and the deciding one is that I find the *owner's own private
> marker* inside the other account's response."

### The example (say this next)
> "For instance: mallapa reads sakshi's brand asset. Before I believe that's a bug, I
> first have sakshi read her own record — that's how I *learn* her private marker
> without ever being told it. Then I check mallapa's response contains that exact
> marker. Nine of my ten checklist flags go true. The tenth says 'was there a proper
> denial?' — it's false, and that's precisely why it's a finding."

### Where to show it
1. Matrix → click the **red** cell for `mallapa × Brand Designer`.
2. The panel shows: requester `mallapa`, owner `sakshi`, asset `BRD-2026-018`,
   check `LAB-BOLA-03`, **HTTP 200**, verdict `CONFIRMED`, the **10-flag checklist**,
   the evidence SHA-256, and the remediation text.
3. Then the **green** cell (mallapa × his own asset) — `SAFE`, `own_record_returned`.
   "Look, it *can* say safe."

### Cross-questions

| Question | Your 15-second answer | The trap follow-up |
|---|---|---|
| "What exactly are the ten conditions?" | "Private resource, two genuinely distinct accounts, policy from a trusted source, ownership verified in both directions, each owner's own baseline captured, distinct private markers, the attacker's request proven to be the one answered, a bounded checked response, the owner's marker found, and no verified denial." | *"Who decides what 'private' means?"* → "The target's own declared policy — for the lab, its declaration; for offline scenarios, the scenario file. I never infer privacy from a missing field." |
| "Isn't that just checking the response body for a string?" | "The string is the last link, not the only one. Without the owner's baseline I have no idea what the marker is; without verified ownership I can't prove the accounts are distinct; without the checked denial I can't rule out a public object." | *"What if two owners have the same marker?"* → "Then it's rejected — the markers must be distinct, or the finding is INCONCLUSIVE." |
| "What if the API returns 403 but leaks the data anyway?" | "Handled. A denial isn't trusted on its status code — `verified_denial` requires the exact declared denial body *and* the absence of the owner's marker. Otherwise it's INCONCLUSIVE, not SAFE." | *"Show me that in the code."* → `canarygate/oracles/read_bola.py`, and the test `test_targetlab_bola.py`." |
| "Give me three reasons a 200 isn't a vulnerability." | "Public object, shared object, or my own object because I mistyped the ID. Also a decoy with an empty body, or a cached copy of my own data." | *"Which of those do you actually detect?"* → "Shared and public, via the declared policy; my-own, via the distinct-marker and distinct-ID checks. A decoy shows up as INCONCLUSIVE because the marker is missing." |
| "How do you know which record belongs to whom?" | "I ask the API. Each account lists its records; the list must contain its own and *not* the other's — that's cross-list isolation. Then each owner reads their own record and the owner field must match." | *"What if the list endpoint is broken?"* → "Then ownership can't be established, and the verdict is INCONCLUSIVE with that reason. It fails closed — it never falls back to guessing from the ID." |
| "What does the SHA-256 on the panel prove?" | "That this finding is byte-identical to what was stored. It's computed over the canonical evidence, so even changing a verdict changes the hash." | *"Could I forge it?"* → "You'd have to rewrite the row *and* recompute a consistent hash. The audit recomputes independently, and on a real deployment the store wouldn't be writable by the person being audited." |

---

# FEATURE 2 — Security Control Interaction (SCI) + the reset proof

**This is your unique feature. No other team in the room will have it.**

### The pitch (say this)
> "Every scanner tests one control at a time. This finds bugs that only exist in the
> *combination* of two controls — where each one passes its own test, but together
> they leak data."

### The example (say this next)
> "For instance: ask for another user's guarded record and you get a clean 403 — the
> authorization control works. Submit a wrong password and you get a clean 401 — the
> authentication control works. Do those two in that order, and the *identical* read
> returns 200 with the owner's private data. Neither control alone explains that. Then
> a successful login closes the door again: 403. So I'm not saying 'something broke' —
> I'm proving which two things had to combine."

### Where to show it
`/ui/lab` → the SCI proof page. On screen:

| Step | Check | Result |
|---|---|---|
| authorization alone | `SCI-AUTHZ` | `403` → **SAFE** |
| authentication alone | `SCI-AUTHN` (wrong password) | `401` → **SAFE** |
| **combined** | the identical guarded read | **`200`, `impact: private_data`** |

Verdict `CONFIRMED`, attribution **`interaction_induced`**. Then the reset:
`RESET-01 403 → RESET-02 401 → RESET-03 200 → RESET-04 403`, status **`proven`**.

Quote the tool's own sentence, verbatim — it is the best line in the project:
> *"The authentication and authorization controls each passed alone, but their
> interaction demonstrated private data; neither control alone explains this outcome."*

### Cross-questions

| Question | Your 15-second answer | The trap follow-up |
|---|---|---|
| "Isn't that just two separate bugs?" | "No. Authorization returns 403 correctly on its own, and authentication rejects the wrong password correctly on its own. The leak exists only in the sequence — that's why the attribution is `interaction_induced` and not 'authorization broken'." | *"Then which control do I fix?"* → "That's the value: the tool names the remediation key `sci_authentication` — the state left behind by the rejected login. Fixing authorization wouldn't have helped." |
| "How do you know it's the interaction and not a coincidence?" | "The reset test. Same guarded read, four times: 403 with a clear condition, 401 sets the condition, the identical read returns 200, a successful login clears it and it's 403 again. Same request, same accounts — only the condition changed." | *"Could the 200 be a cached response?"* → "Redirects and caching are off in the transport, and each request carries a fresh verified identity; the sequence proves the state change." |
| "What kinds of interaction do you model?" | "Authentication combined with authorization — the rejected-login-then-guarded-read case. It's one interaction modelled properly, not a catalogue." | *"What about rate limiting plus caching? Race conditions?"* → "Not covered. That's a genuine gap and I'd rather name it than pretend." |
| "Isn't SCI speculative? Where's it from?" | "It's a real class — the pattern is 'control-state leakage'. A rejected login shouldn't change authorization state on the next request. The lab has that flaw deliberately, and every step is a real HTTPS request." | *"Have you seen it in the wild?"* → "I can't claim that. I claim the detector works on a target known to have the flaw." |
| "What if one of the two controls already fails?" | "Then it isn't SCI — the attribution logic requires both baselines to be observed *passing*. A leak when a control already fails is an ordinary finding, not an interaction." | *"Show me."* → "`canarygate/oracles/interaction.py` — one baseline per declared control, `ValueError` otherwise. There was a bug exactly here in checkpoint 37 and it's now regression-tested." |
| "How many requests does that cost?" | "Eleven. Budget-bounded, sequential, and the budget remaining is printed in the report." | *"Can it loop forever?"* → "No — the guard refuses once the budget is exhausted; the run ends, it doesn't retry." |

---

# FEATURE 3 — Tamper-evident evidence you can re-verify live

### The pitch (say this)
> "A screenshot of a finding is worth nothing. Every run I store is sealed with a
> SHA-256, and reading it back recomputes the seal. If anyone edits the database, the
> tool refuses to show the report instead of showing a lie."

### The example (say this next)
> "For instance, this is the seal on the finding I just showed you —
> `40eb58b7…`. It's computed over the canonical evidence, so changing *the verdict*
> changes the hash even if you rewrite the row. Watch me re-verify the whole database
> right now, on stage."

### Where to show it
Terminal, with the app running:

```bash
python tools/consistency_audit.py --database .canarygate/judge-demo.sqlite3
```

Expected (verified): `runs checked: 3 · projections rebuilt: 7 · invariants: 220` then
**`ALL STORED RUNS INTACT AND CONSISTENT`**

Optional stronger version, if you want to show the *engine* rather than the UI:
`python tools/demo.py` → ends with
`ALL CONSISTENCY CHECKS PASSED (142 invariants over 17 surfaces)`.

### Cross-questions

| Question | Your 15-second answer | The trap follow-up |
|---|---|---|
| "What exactly is hashed?" | "A canonical, minimised evidence dict — status, verdict, checklist, counts. No bodies, no tokens, no headers, no markers, no IDs. The hash is computed over that dict, not over the raw HTTP response." | *"So you can't prove the actual response existed?"* → "Correct, and deliberately — storing raw responses would store the victim's private data. I store enough to re-derive the verdict, never the payload." |
| "What happens if I edit the database?" | "The hash won't match and the API returns an error instead of a report — `EvidenceIntegrityError`, HTTP 500. Refusing to report is the safe failure." | *"Can't I just recompute the hash too?"* → "You can, which is why the audit is independent and, in a real deployment, the store wouldn't be writable by the party being audited. I'm not claiming a blockchain." |
| "Isn't this just a checksum? That's not tamper-proof." | "Agreed — it's tamper-*evident*, not tamper-proof. A local SQLite file can be rewritten. The value is that silence is impossible: a change either breaks the seal or requires recomputing consistency across every projection." | *"Then what's the real security benefit?"* → "Evidence discipline. The finding isn't a rendered opinion, it's a stored, re-derivable object — which is what an auditor actually needs." |
| "Why store evidence at all instead of a report?" | "One evidence set, many views: a stored run, a sections report, the nine-section report, the HTML page, and the matrix. They're all projections, and a test asserts they agree with each other." | *"Nine sections — name them."* → "Executive summary, scope and rules, endpoint inventory, findings, secured endpoints, skipped and inconclusive, authorization matrix, manual interventions, constraint checklist." |
| "How do I know your report isn't cherry-picked?" | "Run the audit yourself — one command, no arguments beyond the database. It rebuilds every projection from the stored rows and compares." | *"How many invariants?"* → "220 on a completed demo; 142 across 17 surfaces in the four-stage demo." |

---

# FEATURE 4 — Fail-closed safety guard

### The pitch (say this)
> "A security tool is a dual-use weapon, so safety can't be a setting — it has to be
> structural. Every outbound request, including login and discovery, passes one guard
> immediately before the socket is created. There is no second code path that can
> reach a network."

### The example (say this next)
> "For instance: I can't point it at a public website. It requires the literal address
> `127.0.0.1`, a pinned test certificate, and a port of at least 1024 — try 443 and it
> refuses with a validation error. DELETE is in a prohibited set with PUT, PATCH, TRACE
> and CONNECT. And there's a hard request budget, so it can't loop."

### Where to show it (three cheap options, pick one)

| Show | Command | What appears |
|---|---|---|
| The health flag | `curl -s http://127.0.0.1:8000/api/health` | `{"status":"ok","mode":"fixture","live_scanning":false}` |
| A refused port | `POST /api/lab-bola-scans {"port":443}` | `422` — "Input should be greater than or equal to 1024" |
| A dead lab | `POST /api/lab-bola-scans {"port":9999}` | `502` — "TargetLab could not be reached; **no evidence was stored**"; matrix unchanged |

The dead-lab one is the best demo: it proves failure is never a verdict.

### Cross-questions

| Question | Your 15-second answer | The trap follow-up |
|---|---|---|
| "Could I use this to attack a website?" | "Not this build. Loopback literal only, pinned certificate, port ≥ 1024, live external scanning disabled, `live_scanning: false` in the health response, and destructive methods refused." | *"But the code's on GitHub — can't I just edit it?"* → "Anyone can fork anything; that's true of every scanner. What I control is that the shipped build fails closed and says so on every surface." |
| "Why no DNS lookup?" | "It connects to the numeric literal `127.0.0.1` with an `ssl`-wrapped socket, so no resolver is ever consulted. That makes DNS rebinding structurally impossible rather than merely discouraged." | *"What about redirects to another host?"* → "Redirects are off in the transport. A redirect can't take you anywhere." |
| "What's in the prohibited method list?" | "DELETE, PUT, PATCH, TRACE and CONNECT. Only explicitly authorized login and creation operations are allowed alongside reads." | *"Why is TRACE prohibited?"* → "It reflects the request — it's an information-disclosure primitive, not a debugging aid you need here." |
| "What if the target is malicious and returns a 10 GB response?" | "Bounded reads. There's a size limit and a request-body limit in the transport, and a network deadline, so a hostile target can't exhaust the scanner." | *"Show me."* → "`canarygate/network/targetlab.py` — 'request body exceeds limit', plus the deadline in checkpoint 15." |
| "How do you know the guard is the *only* path?" | "A test asserts no other module can reach a socket, and the lab transport refuses 'path is not a declared TargetLab route' or 'outside the validated TargetLab scope' before connecting." | *"What if someone adds a feature and bypasses it?"* → "That's exactly what the audit tool and that test are for — they fail the build." |
| "Isn't the whole thing unauthenticated?" | "Yes — it's a local tool, and the README says it must not be exposed to other users or the internet. It binds `127.0.0.1` only, by design." | *"Isn't that a vulnerability?"* → "It's a deployment constraint I state up front rather than hide. Adding auth is the obvious next step, not a claim I'm making today." |

---

# FEATURE 5 — Honest coverage: untested is never "safe"

### The pitch (say this)
> "The most dangerous thing a scanner can do is turn silence into a green tick. So
> there are exactly five verdicts, 'not tested' is one of them, and an untested cell
> can't carry a verdict at all."

### The example (say this next)
> "For instance, watch the dashboard before I run anything: it reads zero out of nine,
> every cell hatched, and the page says 'untested is not SAFE'. Then watch it after:
> nine tested, zero untested. And it can never compute 'safe' as 'total minus
> findings' — safe is only ever an *observed* control working."

### Where to show it
1. **Step 2** — the fresh dashboard, `0 / 9`.
2. **Step 6** — after the run, `9 tested / 0 untested · 6 CONFIRMED · 3 SAFE`, plus
   the words *"Untested is not SAFE"* still on the page.
3. **Bonus, if pushed** — the ground truth block in the run JSON:
   `"used_as_decision_input": false`, `"evaluated_after_verdicts": true`.

The five verdicts: **`CONFIRMED` · `SUSPECTED` · `SAFE` · `INCONCLUSIVE` · `SKIPPED`**.

### Cross-questions

| Question | Your 15-second answer | The trap follow-up |
|---|---|---|
| "Name all five verdicts." | "CONFIRMED — full chain, it's a finding. SUSPECTED — a lead, chain incomplete. SAFE — the check ran and I observed the control working. INCONCLUSIVE — the check ran but can't support either conclusion. SKIPPED — it never ran." | *"Which is the dangerous one?"* → "INCONCLUSIVE, if you let it drift into SAFE. That's why it's hatched and excluded from the safe count." |
| "What's the difference between SKIPPED and INCONCLUSIVE?" | "SKIPPED means I never performed the check — budget or guard or a missing precondition. INCONCLUSIVE means I performed it and the evidence doesn't settle the question." | *"Give an example of each."* → "Skipped: budget exhausted before that check. Inconclusive: I got a 200 but couldn't find the owner's marker in it, so I can't prove disclosure." |
| "What's this 'ground truth' you keep mentioning?" | "The lab declares which of its six routes are supposed to be broken. That table is scored against my verdicts *after* they're computed — the run records `used_as_decision_input: false`, so the answer key never decides the answer." | *"So the ref said 6 out of 6 — isn't that circular?"* → "It's a self-consistency check on a lab I wrote, and the field makes that checkable by a machine. It's not a detection-rate claim." |
| "How do I know the matrix isn't just showing me the good cells?" | "It shows all nine, including the ones with no evidence — hatched, no verdict. And the run records how many runs it considered, so duplicates and re-runs are visible." | *"What if I run it twice?"* → "Tested — nine duplicated cells, zero stale, and every cell cites the newest run while listing the superseded ones." |
| "Can you ever say an endpoint is secure?" | "I can say a *specific check* on a specific route was observed working. I never say 'the endpoint is secure' or 'nothing else is wrong' — those are unprovable claims." | *"That's weaselly."* → "It's the only honest claim. A 403 on one read doesn't prove the POST on the same route is authorized." |
| "What are your real gaps?" | "Two, and my own audit names them: no broken function-level authorization — role versus policy — and no scanning of a third-party API. Nine more requirements are partial, each with the gap text written down." | *"Why not just finish them?"* → "Because a named gap is worth more than a fake complete. The audit tool exits non-zero if a claim has no test behind it." |

---

# The knocks you should expect on the whole project

These are about all five features together. Rehearse the first one twice.

| The knock | Your answer |
|---|---|
| **"Your target is a lab you wrote. Isn't this all circular?"** ⚠️ | "Yes, and the tool says so on every page. It proves the machinery — real sockets, real TLS, real denial bodies, real cross-account reads. It does not prove a detection rate on an API I've never seen. That's gap D12 in my own audit, and testing a third party needs written approval." |
| "Why only two bug classes?" | "Because one oracle done properly beats thirty done badly. The architecture is general — a new check is a new oracle plus its gates, not a rewrite." |
| "What's a scanner that does this better?" | "Commercial tools cover far more. What they mostly don't give you is the per-finding evidence chain and the control-interaction attribution, and that's the wedge I chose." |
| "What would you do with another month?" | "BFLA, then a real authorized target, then evidence export signed for the customer's auditor. And merge my own pull request before a demo — which is the lesson from this week." |
| "Is this AI?" | "No, deliberately. A verdict has to be reproducible; an LLM's opinion isn't evidence." |

---

# Delivery notes

**Ordering.** Always lead with Feature 1, then Feature 2. They are the two that make
judges lean forward. Features 3–5 are what make them *believe* you.

**Length.** Each pitch is ~10 seconds. Do not expand a pitch until you have delivered
it — the value is the brevity.

**The one habit that wins marks:** every time you claim something, point at the screen
where it is visible. Claim without pointing sounds rehearsed; claim with pointing
sounds like engineering.

**Never claim:** AI · Docker · cloud · production-ready · live scanning · "finds all
vulnerabilities" · `alice`/`bob` · 916 tests.
