# CanaryGate — Demo Masterclass

**For:** you, a beginner, presenting in a hackathon.
**What this is:** everything you need to *understand*, *say*, *click*, and *survive* — in one document, in the order you need it.
**Baseline:** branch `arena/80050ed6-hackfusion-30102026`, commit `f66d179`. Do not merge anything.

> Everything marked **REAL** was executed against the live app while writing this
> document. Everything marked **DO NOT SAY** is something a judge would catch you on.

---

## ⚠️ READ THIS FIRST: the old guide is wrong in four places

You attached `CANARYGATE_COMPLETE_TECHNICAL_GUIDE.md` (3 173 lines). It is an
excellent document, but it was written against an **older checkpoint** — before the
frontend existed. Four things in it will make you say the wrong thing on stage:

| The guide says | The truth on your demo branch | Why it matters |
|---|---|---|
| Lab accounts are **`alice` and `bob`** | **`mallapa`, `sakshi`, `harsha`** | A judge reading your screen sees "mallapa". Wrong names = looks memorised |
| **916 tests** pass (§19.3) | **1133 tests**, 69 files | You will be asked "how many tests?" |
| Bare `GET …/report` returns **HTTP 500** (§13.6, C1) | **Fixed — all 200** (I re-tested all four forms) | You'd warn the judge about a bug that isn't there |
| Demo = **10 API `curl` steps** (§20) | Demo = **the web UI**, 11 clicks | The guide predates the interface |

**Use the guide for concepts and depth (it is genuinely superb there). Use *this*
document for the demo, the numbers, and the words.**

---

# PART 1 — What you are actually showing

## 1.1 The one sentence

Say this exactly. It is honest, it is specific, and it survives every follow-up:

> **"CanaryGate is an API authorization scanner that only reports a finding when it
> has proven it with cross-account evidence — and it also catches a class of bug
> that ordinary scanners miss, where two security controls each pass their own test
> but fail together."**

## 1.2 What it is NOT (say this before they ask)

Being upfront about limits is the single highest-scoring move available to you.

> "Three things I want to be clear about up front. It is not an AI tool — the
> verdicts are deterministic, because an LLM's opinion isn't evidence. It has never
> scanned a third-party API — it validates against a deliberately vulnerable lab
> that my team wrote. And it covers two bug classes properly rather than claiming
> thirty. I'd rather be narrow and provable."

That paragraph, delivered early, removes the three traps a technical judge would
otherwise spend five minutes trying to spring.

## 1.3 The cast (memorise these three names)

Your demo target, **TargetLab**, is a deliberately vulnerable invoice/asset API.
It has exactly three users, each owning exactly one private asset:

| Account | Job title | Owns asset | Asset |
|---|---|---|---|
| **mallapa** | Marketing Manager | `MKT-2026-041` | Unreleased campaign artwork |
| **sakshi** | Brand Designer | `BRD-2026-018` | Premium brand identity kit |
| **harsha** | Campaign Analyst | `ADS-2026-027` | Confidential performance report |

Each record also carries a **private marker** string, e.g.
`targetlab-sakshi-private-marker`. That marker is the whole trick: the scanner only
believes a leak happened if it sees *sakshi's exact marker* inside *mallapa's*
response.

**The bug we planted:** `GET /records/{id}` checks that you are logged in — it never
checks that the record is yours. So mallapa can read `BRD-2026-018`.

**The control that works:** `GET /records/{id}/secure` does check ownership, and
returns `403 {"error": "forbidden"}`.

**The subtle bug (SCI):** `GET /records/{id}/guarded` is correct on its own — it
returns 403. But if a **failed login** happens first, the next guarded read returns
200 with the owner's data. Two controls, each individually correct, combining into
a leak.

---

# PART 2 — The six ideas. Learn these, not the codebase.

For each: the **analogy** you say out loud, the **technical truth** you fall back on
if pushed, and **how to prove it yourself**.

---

## Idea 1 — Authentication vs. Authorization

**Analogy.** Authentication is the **ID check at the door** — *who are you?*
Authorization is **which rooms your badge opens** — *what may you touch?*

**Technical truth.** Authentication answers "is this token valid and whose is it?"
Authorization answers "does this identity satisfy the policy for *this* object?"
Almost every serious API breach is the second one, because the first is easy and
every framework gives it to you free.

**How it maps here.** `canarygate/oracles/authentication.py` handles the door.
`canarygate/oracles/read_bola.py` handles the rooms.

**Say:** *"My lab happily authenticates mallapa. The bug is that it never
authorizes. That distinction is the entire project."*

---

## Idea 2 — BOLA: the hotel key that opens the wrong door

**BOLA** = **B**roken **O**bject **L**evel **A**uthorization. It is **OWASP API
Security Top 10 #1** — the most common serious API vulnerability in the world.

**Analogy.** You check into room 210. Your key card works. You walk to room 412,
tap, and **the door opens**. The hotel verified you are a paying guest. It never
verified that room 412 is yours.

**Technical truth.** The endpoint takes an object identifier (`/records/BRD-2026-018`)
and returns the object without comparing `object.owner` to `token.subject`.

**How it maps here.** `LAB-BOLA-03` = mallapa reads sakshi's record → HTTP `200`
→ `CONFIRMED`.

**Say:** *"The API confirmed who I am. It never confirmed that the record belongs
to me."*

---

## Idea 3 — Why "I got a 200" is NOT a vulnerability ⭐

**This is the single most important idea in your demo.** If you learn one thing,
learn this. It is what separates you from every other team in the room.

A `200 OK` on someone else's ID can be entirely harmless, for at least five reasons:

| # | Harmless explanation | What a naive scanner says |
|---|---|---|
| 1 | The object is **public** (a marketing page) | "VULNERABLE!" |
| 2 | The object is **shared** (a team document) | "VULNERABLE!" |
| 3 | It's actually **your own** object — you mistyped the ID | "VULNERABLE!" |
| 4 | It's a **decoy**: the ID resolves but the body is empty/generic | "VULNERABLE!" |
| 5 | It's a **cached copy** of your own data | "VULNERABLE!" |

Judges know this. It is the exact reason they distrust student scanners.

**CanaryGate's answer: ten checklist flags, all but one required.** Here is the
*real* checklist from the stored run (REAL, copied from `LAB-BOLA-03`):

```json
{
  "attacker_request": true,     "distinct_accounts": true,
  "owner_baseline": true,       "ownership_verified": true,
  "policy_denies_access": true, "private_baseline": true,
  "private_disclosure": true,   "private_resource": true,
  "response_checked": true,     "verified_denial": false
}
```

Nine `true`, and the tenth (`verified_denial`) is correctly `false` — because a
denial *didn't* happen; that's why it's a finding. For the **SAFE** twin
(`LAB-BOLA-05`), the pattern inverts: `verified_denial` is `true` and
`private_disclosure` is `false`.

In plain English, the chain is:

1. **Is the asset actually private?** (not shared, not public)
2. **Are there two genuinely different accounts** with different credentials?
3. **Did the policy come from a trusted source?** (the lab's own declaration — not a guess)
4. **Is ownership verified?** Each account's list contains its own record and
   *not* the other's. The two IDs must differ.
5. **Did each owner read their own record first?** (a "baseline" — this is how the
   scanner *learns* sakshi's private marker without ever being told it)
6. **Is the attacker's request the request that was answered?** (identity and path
   consistent — no redirect, no cache)
7. **Does the response contain the owner's exact private marker,** plus the owner's
   id and owner field?

**Say:** *"A 200 is a hint. I only call it CONFIRMED when I've proven the asset is
private, proven who really owns it, captured the owner's own baseline, and found
the owner's own private marker inside the other account's response. If any link in
that chain is missing, my verdict is INCONCLUSIVE or SAFE. It fails closed. Every
checklist flag you see here is one of those links."*

**Prove it yourself:** click a CONFIRMED cell → the panel shows the checklist and
a SHA-256. Then click the `secure` twin → `403`, `SAFE`.

---

## Idea 4 — SCI: two locks that are each fine ⭐⭐

**SCI** = **S**ecurity **C**ontrol **I**nteraction. This is your unique feature and
the most impressive thing you will show.

**Analogy.** A door has two locks: a badge reader and a PIN pad.

- Badge reader alone → refuses you. ✅
- PIN pad alone → refuses you. ✅
- Use **both, in the wrong order** → the door opens. ❌

Each lock is correct. The **combination** is broken. No standard scanner tests
combinations, because scanners test one control at a time.

**The real numbers (REAL, from the stored run):**

| Step | Check | What happened | Verdict |
|---|---|---|---|
| 1 | `SCI-AUTHZ` — authorization alone: mallapa reads sakshi's **guarded** record | `403` with the checked denial body | `SAFE` |
| 2 | `SCI-AUTHN` — authentication alone: mallapa submits a **wrong password** | `401`, refused | `SAFE` |
| 3 | **Combined** — the identical guarded read, after that rejected login | **`200`, `impact: "private_data"`, owner's marker returned** | — |

**Overall verdict:** `CONFIRMED`, **attribution:** `interaction_induced`.

The reason string is the money quote:

> *"The authentication and authorization controls each passed alone, but their
> interaction demonstrated private data; neither control alone explains this
> outcome."*

**And it proves causation with a reset test** — four checks that show the door
closes again:

| Check | Action | Expected → Observed |
|---|---|---|
| `RESET-01` | guarded read, condition clear | `403` → `403` |
| `RESET-02` | rejected login (sets the condition) | `401` → `401` |
| `RESET-03` | **the same** guarded read | `200` → `200` ← the leak |
| `RESET-04` | successful login (clears the condition) | `403` → `403` ← the proof |

Status: `proven`. Reason: *"A successful login cleared the lab condition: the same
guarded read that leaked the owner's record after a rejected login was denied
again afterwards."*

That `403 → 401 → 200 → 403` sequence is your strongest 20 seconds. It is not just
"it broke" — it is "it broke **because of this**, and here is it breaking and then
fixing itself."

**Say:** *"Any scanner can tell you a check failed. This tells you which two
controls, and proves it was their interaction — because after a successful login
the door closes again. 403, 401, then 200 with the private data, then 403."*

---

## Idea 5 — Evidence you can re-verify (the trust idea)

**Analogy.** A court does not accept "the police say he did it." It needs **chain of
custody**: every item sealed, labelled, re-checkable.

**Technical truth.** Every stored run is hashed with **SHA-256** — a wax seal.

- **Write:** canonicalise the evidence → compute the seal → store both.
- **Read:** recompute the seal → compare → match? render. Mismatch? **refuse (HTTP 500).**
- The seal is computed over the *canonical evidence dict*, so even changing a
  verdict changes the hash.

REAL seal from your `LAB-BOLA-03`:
`40eb58b78691e0473768990d61e227d6869b6d84c903d5257daedcd464c6bf3d`

**Why this matters for the demo:** it lets you run the audit *live*, on stage,
which very few teams can do.

**Say:** *"Every finding is sealed. If anyone edits the database, the seal breaks
and the tool refuses to report it. That's why I can run this check in front of you
instead of showing you a screenshot."*

**Prove it yourself:**
```bash
python tools/consistency_audit.py --database .canarygate/judge-demo.sqlite3
```
Expect: `220 invariants … ALL STORED RUNS INTACT AND CONSISTENT`

---

## Idea 6 — Five verdicts, and "untested is not safe"

**Analogy.** A school report card with five grades, and one of them means "not
examined" — which must never be quietly rounded up to "pass".

| Verdict | Plain meaning |
|---|---|
| `CONFIRMED` | The full evidence chain exists, so this is a real finding |
| `SUSPECTED` | Something looked wrong but part of the chain is missing — a lead, not a finding |
| `SAFE` | The check ran, and the control was *observed working* (e.g. a checked 403) |
| `INCONCLUSIVE` | The check ran but can't support either conclusion — an honest gap |
| `SKIPPED` | The check never ran (budget, guard, missing precondition) |

The matrix colours map to these: `CONFIRMED`→red, `SAFE`→green, `SUSPECTED`→orange,
`INCONCLUSIVE`/`SKIPPED`→hatched grey. **Hatched means "not tested" and the page
says so in words.**

The rule in the codebase: `SAFE` is never computed as `total − findings`. A check
that did not run is `SKIPPED`, never `SAFE`.

**Say:** *"That's why the dashboard starts at zero. An untested cell is not a pass —
it's hatched, and the page says 'untested is not SAFE'. I'd rather show you nine
grey cells than nine green ones I didn't earn."*

---

# PART 3 — THE SCRIPT

## 3.0 Before you open your mouth

- Branch: `arena/80050ed6-hackfusion-30102026` — `ls run.sh` must succeed
- `rm -f .canarygate/judge-demo.sqlite3` (so the `0 → 9` story is true)
- `./run.sh` running, browser at `http://127.0.0.1:8000`
- Browser zoom ~110–125% so the back row can read
- **Do not click the "API docs" link** in the run banner — it 404s
- Do not open `/docs` or `/redoc` — deliberately disabled

---

## 3.1 The 30-second introduction

> "Every API that serves users has to answer two questions: *who are you*, and *what
> are you allowed to touch*. The first one is solved — every framework gives it to
> you. The second one is where breaches happen, and it's OWASP's number one API
> risk: a user reads someone else's data by changing an ID in a URL.
>
> The problem is that almost every tool checks this badly. It sees a 200 where it
> expected a 403 and declares a vulnerability — but that object might be public, or
> shared, or the user's own. **CanaryGate only reports a finding when it has
> actually proven it, with cross-account evidence.** And it catches a second class
> of bug most tools miss: two controls that each pass alone but fail together."

*Timing: ~28 seconds. Practise until it's smooth. Do not add to it.*

---

## 3.2 The 1-minute technical overview

> "It's Python and FastAPI, one process. The frontend is a router attached to the
> same application object as the JSON API, so there's one code path and no
> duplicated logic.
>
> Three design decisions matter.
>
> **One — a single execution boundary.** Every outbound request, including login
> and discovery, passes through one guard immediately before the socket is created.
> It enforces an exact host and port, an allow-list of methods, and a hard request
> budget. Redirects are off. There is no DNS lookup — it connects to the literal
> `127.0.0.1` with a pinned test certificate. Deleting is always refused.
>
> **Two — the decision layer does no I/O.** The oracles are pure functions: evidence
> goes in, a verdict and a checklist come out. So every verdict is reproducible from
> stored evidence, and unit-testable.
>
> **Three — storage isn't trusted.** Every run is redacted, hashed with SHA-256 and
> re-validated on read. If the row changed, the API returns an error instead of a
> report.
>
> Behind it: 1133 tests, and an audit tool that tracks 58 requirements — 47
> implemented, 9 partial, and 2 that I've deliberately left open and named."

*Timing: ~55 seconds.*

---

## 3.3 The 3-minute live demonstration (11 steps)

**Golden rules:** never type a URL you haven't rehearsed; never open `/docs`; if a
page is slow, talk over it.

| # | You click / do | What appears | What you say | What it proves |
|---|---|---|---|---|
| 1 | Open `http://127.0.0.1:8000` | Cinematic landing page, headline *"Every request has a boundary. Every finding needs proof."* | "Everything you're about to see runs on this laptop. No cloud, no internet, no API keys." | It's real and self-contained |
| 2 | `Escape` → **Enter CanaryGate** | Dashboard. Every tile `0`, matrix `0 / 9`, text: *nothing has been scanned on this database* | "Fresh database, so everything is zero — and that's the first design decision. An untested cell is not a pass. It's hatched, and the page says 'untested is not SAFE'." | Honest-by-construction, not a demo hack |
| 3 | Point at the other terminal | `targetlab: DELIBERATELY VULNERABLE test API on https://127.0.0.1:8765` | "That's my target: an API I wrote to be deliberately broken. Three users, three private assets. It only listens on loopback and can never be deployed." | You built the test fixture |
| 4 | **New run** → **Run security assessment** | Live feed of requests scrolling: `GET /records/…` with status and milliseconds, stage tracker | "Every line here is a real HTTPS request — method, path, the lab's own status code, measured latency. Nothing is mocked." | Real integration, real sockets |
| 5 | *wait ~10 s* | *Assessment complete.* | "Three account pairs, six checks each, fifty-four requests." | Bounded and sequential |
| 6 | Open the matrix | **9 tested / 0 untested · 6 CONFIRMED · 3 SAFE** | "Six confirmed cross-account leaks. Three safe. And notice the zeros on untested — I'm not hiding a cell I didn't check." | The finding + coverage honesty |
| 7 | Click a **red** cell (mallapa × Brand Designer) | Panel: requester `mallapa`, owner `sakshi`, asset `BRD-2026-018`, `LAB-BOLA-03`, **HTTP 200**, verdict `CONFIRMED`, a 10-flag checklist, a SHA-256, and remediation text | "This is the part I care about. A normal scanner stops at 'I got a 200'. I can show you nine verified links: the asset is declared private, the two accounts are genuinely different, ownership was verified in both directions, each owner read their own record first — that's how the tool *learns* the private marker — and then the owner's exact marker appeared inside the other account's response." | **The differentiator** |
| 8 | Click a **green** cell (mallapa × his *own* asset) → then open the run detail (`/ui/lab/bola/{run}/`) and find `LAB-BOLA-05` | Green cell: `SAFE`, `own_record_returned`. Run detail: `LAB-BOLA-05`, HTTP **403**, `SAFE`, `verified_denial: true` | "Two negatives. The green cell is mallapa reading his *own* record — correct, and the tool says SAFE rather than inventing a finding. And here's the same cross-account read against the **secure** route: 403, `verified_denial` true. Same object, same two accounts, control works. That's what tells me this is object-level authorization and not a public object. And note SAFE here is a *positive* result — I observed the control working, it isn't just 'I found nothing'." | Negative control — this is what kills false positives |
| 9 | Open the **SCI** proof page | `403` alone → `401` alone → **`200`** combined, with `interaction_induced`, then the reset `403 → 401 → 200 → 403` | "This is the part most scanners don't have. The authorization control refuses — 403. The authentication control refuses — 401. Each one is correct. Run them in that order and the identical read returns 200 with the owner's private data. Then a successful login closes the door again — 403. So I'm not just saying it broke, I'm proving *what* broke it." | **Your signature result** |
| 10 | Terminal: `python tools/consistency_audit.py --database .canarygate/judge-demo.sqlite3` | `runs checked: 3 · invariants: 220` then `ALL STORED RUNS INTACT AND CONSISTENT` | "Every number on those pages is a projection of the stored evidence. This re-hashes all of it and rebuilds every view, live. If someone edited the database, this fails." | Tamper-evidence, proven live |
| 11 | *(optional, if time)* `Ctrl+C` the lab, run again | *Assessment did not complete*, the reason, the port it tried, the command to fix it, and a **Try again** button. Matrix unchanged | "And failure is never a verdict. A connection refused is not 'safe' — nothing is stored and nothing moves." | Fail-closed design |

**If you're running long, do 1, 2, 4, 6, 7, 9.** That's the whole story.
**If you're running very long, do 1, 4, 6, 7, 9.**

---

## 3.4 The technical-proof moment (when a judge says "prove it's not hardcoded")

Have this typed but **not** run, in a spare terminal:

```bash
# the finding, straight out of the JSON API — no UI involved
curl -s -X POST http://127.0.0.1:8000/api/lab-bola-scans \
     -H 'content-type: application/json' -d '{"port": 8765}' | head -c 700
```

Expected shape (REAL): `"verdict": "CONFIRMED"`, `"reason": "2 of 6 checks confirmed
cross-account private disclosure on the vulnerable route, while the secure route
denied the same reads"`.

Then:

```bash
sqlite3 .canarygate/judge-demo.sqlite3 "select count(*) from lab_bola_runs;"
```

> "That's the same run, from the database. The UI is a view of this — it doesn't
> contain the answer."

**If `sqlite3` isn't installed**, use this instead (Python is definitely installed):

```bash
python -c "import sqlite3;print([r[0] for r in sqlite3.connect('.canarygate/judge-demo.sqlite3').execute(\"select name from sqlite_master where type='table'\")])"
```

---

# PART 4 — Questions, with answers you can say

Format: **the question** → **say this (15–30 s)** → *(fallback depth if pushed)*.

### A. Overview

**"Explain the project in one line."**
> "An API authorization scanner that only reports findings it has proven with
> cross-account evidence, and that also detects failures caused by two security
> controls interacting."

**"What problem does it solve?"**
> "API authorization bugs are the number one API risk, and they're easy to fake. A
> tool that says 'no 403, therefore vulnerable' produces so many false positives
> that teams ignore it. CanaryGate solves the credibility problem, not the detection
> problem."

**"Who is the user?"**
> "An application-security engineer testing one API they're authorized to test.
> Narrow by design — it is not a mass internet scanner."

### B. The hard ones (rehearse these twice)

**"Your vulnerable target is a lab you wrote. Isn't that circular?"** ⭐ most likely trap
> "Yes — and the tool says so on every page. It's a regression target, not a customer
> finding. The lab proves the *machinery* is real: real sockets, real TLS, real
> HTTP, real denial bodies. What it does **not** prove is the detection rate on an
> API I've never seen. That's one of the two gaps my own audit tool lists as
> missing, and I'd need written approval to test a third-party API."

*Do not get defensive here. This answer scores higher than a dodge.*

**"Is this AI?"**
> "No, deliberately. A verdict has to be reproducible — an LLM's opinion isn't
> evidence. The intelligence is rule-based: ten evidence gates and SHA-256 sealing.
> I'd only ever use a model to prioritise results *after* the verdict, never to
> produce it."

**"So it's just a wrapper around a few HTTP requests?"**
> "The requests are trivial. The hard part is deciding when a response is *evidence*.
> A 200 might be a public object, a shared object, a decoy, or the attacker's own
> data. Most of this codebase is the machinery that refuses to make a claim without
> a complete chain."

**"Have you scanned a real API?"**
> "No. I have profiles prepared for VAmPI and crAPI, two known-vulnerable public
> projects, but running them needs written organizer approval, so I haven't. It's
> gap D12 in my audit."

**"What's your weakest point?"** ⭐ answer honestly
> "Release process, not the engine. The whole frontend sat in an unmerged pull
> request while the main branch looked finished — so anyone cloning it got an API
> with no interface. We also had stale numbers in the docs. The code is solid; our
> branching discipline was the risk, and we found it by auditing our own repo, not
> by it blowing up on stage."

**"How many tests do you have?"**
> "1133 tests across 69 files, about two and a half minutes, and CI runs them on
> Ubuntu and Windows."

### C. Architecture

**"Walk me through what happens when I click Run."**
> "The UI posts to an action endpoint on the same FastAPI app. The backend builds a
> scoped plan, logs both accounts in, verifies identity against `/profile`, harvests
> each account's record list to prove isolation, reads each owner's own record to
> capture the private marker, then performs the cross-account reads on the
> vulnerable and secure routes. Each request passes the guard immediately before the
> socket. Observations go to a pure oracle, which emits a verdict plus a checklist.
> The run is redacted, hashed, stored, and then projected into the report and the
> matrix. The UI polls a job endpoint and streams the request feed."

**"Why one guard instead of validation everywhere?"**
> "Because two code paths means one of them eventually forgets. The guard is the
> only thing that can approve a request, and a test asserts no other module can
> reach a socket."

**"Why no DNS?"**
> "It connects to the numeric literal `127.0.0.1` with an `ssl`-wrapped socket, so no
> resolver is ever consulted. That makes DNS rebinding structurally impossible
> rather than merely discouraged."

### D. Detection

**"Name three reasons a 200 isn't a vulnerability."**
> "The object might be public; it might be shared; it might be the caller's own
> object — I mistyped the ID. Also a decoy with an empty body, or a cached copy of
> my own data."

**"What if the server returns 403 but leaks the data in the body?"**
> "That's handled. A denial isn't trusted just because of its status code —
> `verified_denial` requires the exact declared denial body *and* the absence of the
> owner's marker. Otherwise it's INCONCLUSIVE, not SAFE."

**"How do you avoid false positives?"**
> "Every finding needs the full chain, and the two strongest guards are the negative
> controls: the secure route must deny the same read, and each owner must
> successfully read their own record. Both are in the run you just saw."

**"What do you miss?"**
> "Genuine BOLA when the object has no private field to compare, when the list
> endpoint doesn't isolate owners, when the API returns HTML instead of JSON, or
> when IDs aren't discoverable. Each of those produces INCONCLUSIVE with a reason —
> which is the correct outcome. A missed finding that says 'I couldn't establish
> this' is honest."

### E. SCI (if you showed it — expect this)

**"Isn't that just two bugs?"**
> "No. Each control passes its own test. Authorization returns 403 correctly.
> Authentication rejects the wrong password correctly. The bug exists only in their
> combination — that's why the attribution is `interaction_induced` and not
> 'authorization broken'."

**"How do you know the interaction caused it, rather than coincidence?"**
> "The reset test. Same guarded read, four times: 403 with a clear condition, 401
> sets the condition, the identical read returns 200, a successful login clears the
> condition and it's 403 again. Same request, same accounts — only the condition
> changed."

### F. Safety

**"Could I use this to attack a website?"**
> "Not with this build. The port must be at least 1024, the origin is the loopback
> lab with a pinned certificate, live external scanning is disabled and the health
> endpoint reports `live_scanning: false`. DELETE is always refused, PUT and PATCH
> are refused by default, and there's a hard request budget."

**"Are credentials stored?"**
> "No. Evidence is minimised — no bodies, no tokens, no headers, no markers. There's
> no `.env` loader and no secrets in the repo; the only certificate is a public test
> fixture."

### G. Practical value

**"Why would anyone pay for this?"**
> "Because audit findings have to survive scrutiny. A false positive costs a team a
> day of investigation and damages the security team's credibility. An evidence
> chain with a hash per finding can be handed to a regulator or a customer. And
> control-interaction bugs are almost never covered by automated scanning."

---

# PART 5 — Numbers card (memorise this box)

```
Accounts:     mallapa (MKT-2026-041) · sakshi (BRD-2026-018) · harsha (ADS-2026-027)
BOLA run:     6 checks · 2 CONFIRMED · 4 SAFE · 18 requests · 20 budget
Full demo:    3 account pairs · 54 requests · 9-cell matrix
Matrix:       9 tested · 6 CONFIRMED · 3 SAFE · 0 untested
SCI run:      11 requests · 403 alone / 401 alone / 200 combined
Attribution:  interaction_induced
Reset:        4 checks · RESET-01..04 · 403 -> 401 -> 200 -> 403 · status "proven"
Checklist:    10 flags (9 true for CONFIRMED; verified_denial false)
Verdicts:     5 (CONFIRMED / SUSPECTED / SAFE / INCONCLUSIVE / SKIPPED)
Report:       9 sections
Tests:        1133 across 69 files · CI on Ubuntu + Windows
Audit:        58 requirements = 47 implemented, 9 partial, 2 missing (D11, D12)
Routes:       77 UI · 37 API
Invariants:   220 (consistency audit) · 142 over 17 surfaces (tools/demo.py)
Stack:        Python 3.11 · FastAPI 0.115 · Pydantic 2.10 · SQLite · HTMX (vendored)
```

### The nine report sections (in order)
1. Executive summary · 2. Scope and rules · 3. Endpoint inventory · 4. Findings ·
5. Secured endpoints · 6. Skipped and inconclusive · 7. Authorization matrix ·
8. Manual interventions · 9. Constraint checklist

### DO NOT SAY ❌

| Never | Say instead |
|---|---|
| "AI-powered" / "machine learning" | "rule-based, deterministic evidence chaining" |
| "It finds all API vulnerabilities" | "two bug classes, done properly" |
| "Docker" / "deployed" / "cloud" | "runs locally, fully offline, no external services" |
| "alice and bob" | "mallapa, sakshi and harsha" |
| "916 tests" | "1133 tests" |
| "works on any API" | "on an authorized API with two accounts and verified ownership" |
| "no 403, so vulnerable" | "only with the full evidence chain" |
| "we're production-ready" | "controlled validation of our own lab" |

---

# PART 6 — Failure playbook

| Symptom | Do this | Say this |
|---|---|---|
| Page won't load | `./run.sh --doctor`, then `./run.sh` again | "Give me ten seconds — the environment needs a restart." |
| Dashboard shows numbers, not zeros | You didn't clear the DB. Either clear it or embrace it | "This database already has runs from rehearsal — let me clear it so you see the honest starting state." |
| Lab dead / assessment fails | Expected behaviour. Show it | "That's the fail-closed design — a connection failure is never a verdict. Nothing stored, matrix unmoved." |
| UI completely broken | `python tools/demo.py` | "Let me show you the engine directly instead of the interface." |
| Even Python broken | Talk the 11-step narrative over the architecture diagram, cite the proof commands | "I'll show you the design and give you the commands to verify it yourself." |

**`python tools/demo.py` is your parachute.** It spins up its own lab and database,
runs four stages, and ends with `ALL CONSISTENCY CHECKS PASSED (142 invariants over
17 surfaces)`. No browser needed. Run it once before you present so you know the
output.

---

# PART 7 — Rehearsal plan (your next 4 hours)

| Time | Do | Pass condition |
|---|---|---|
| 0:00–0:45 | Get it running. `./run.sh --doctor` → `./run.sh` → click through every page | You can recover from a dead lab unaided |
| 0:45–1:30 | Read Part 2. Say each analogy out loud. Answer the 6 self-test questions below | All six without notes |
| 1:30–2:30 | Rehearse the 11 steps **twice**, timed, on a cleared DB. Second run: no notes | Under 4 minutes, no hesitation |
| 2:30–3:15 | Part 4 questions. Focus on the two ⭐ traps. Have someone interrupt you | Neither trap makes you defensive |
| 3:15–3:45 | 30-second and 1-minute intros, timed with a phone | 28–32 s and 55–65 s |
| 3:45–4:00 | Failure playbook: kill the lab on purpose, recover. Run `tools/demo.py` | Both recoveries work |

## Self-test — cover the answers

1. Authentication vs authorization?
2. What is BOLA, with an example?
3. **Three** reasons a 200 might not be a vulnerability.
4. What must be true before `CONFIRMED`?
5. What does `interaction_induced` mean, and how do you prove causation?
6. What happens if someone edits a stored run?
7. Why does the dashboard start at zero?
8. Is this AI? Does it use Docker? Has it scanned a real API?

<details><summary>Answers</summary>

1. Who you are vs. what you may touch.
2. An API returns an object the caller doesn't own — my key opens room 412.
3. Public, shared, my own (also decoy/empty body, cached copy).
4. Private asset + two distinct accounts + trusted policy + verified ownership +
   owner baselines + consistent attacker request + the owner's exact private marker
   in the response (10-flag checklist).
5. Two controls each behaved correctly alone; only their combination leaked. Proven
   by the reset: 403 → 401 → 200 → 403.
6. The SHA-256 seal fails, the API returns an error instead of a report.
7. Untested is not SAFE — an unexamined cell must not look like a pass.
8. No AI (deterministic); no Docker (local Python); never scanned a third-party API.
</details>

---

# PART 8 — If you remember nothing else

**Three sentences:**

1. **"A 200 is a hint, not a finding — I only report what I can prove with
   cross-account evidence."**
2. **"Two controls each passed their own test; only their interaction leaked — and
   the reset proves it."**
3. **"Our only real target is a laboratory we wrote; it proves the machinery, not
   the detection rate."**

Say those three, show the red cell and the SCI page, and you have a better
demonstration than most teams will manage.

---

## Where to read more in the guide you attached

The guide is written against an older checkpoint, so read it for *depth*, not for
the demo. Best chapters for you, in order:

| Guide section | Why read it |
|---|---|
| §11.1–11.4 (five verdicts, gates, false-positive table) | The best explanation anywhere of why 200 ≠ bug |
| §4 (SCI in depth) | Your signature feature; §4.8 covers the reset |
| §5.5 (request pipeline inside the guard) | For "walk me through the architecture" |
| §7.3 (the oracle algorithm in real code) | The ten-flag checklist in code |
| §18 (limitations, verbatim audit gaps) | So you can state limits precisely |
| Appendix F (what to understand before defending) | A study checklist |
| §21 (fifty-two judge questions) | Extra practice; **skip the numbers in it** — use Part 5 here |
