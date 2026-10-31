# Your 4-hour beginner's plan to demo CanaryGate

**For:** a beginner presenting in 1–4 hours.
**Baseline (do not merge anything):** branch `arena/80050ed6-hackfusion-30102026`.
**Rule for these 4 hours:** *do not read the source deeply.* You do not have time
to become a Python expert. You have time to (a) make it run, (b) understand five
ideas, (c) rehearse eleven clicks, (d) memorise seven answers.

| Hour | Goal | You will be able to… |
|---|---|---|
| 0:00–0:45 | It runs on your machine | launch it and recover from any failure |
| 0:45–1:45 | Five ideas, in plain English | explain what the tool *is* without notes |
| 1:45–2:45 | Rehearse the demo twice | click through it calmly |
| 2:45–3:30 | Judge Q&A drill | answer the seven hard questions honestly |
| 3:30–4:00 | Pre-flight + backup | not panic if something breaks |

---

# HOUR 1 (0:00–0:45) — Make it run

## Step 1 — open the right branch

A "branch" is a parallel copy of the project. Yours has five. **Only one has the
website.**

```bash
git clone https://github.com/Ace-095/Hackfusion_30102026.git
cd Hackfusion_30102026
git switch arena/80050ed6-hackfusion-30102026
```

**How to check you are on the right one** — you should see a file called `run.sh`:

```bash
ls run.sh
```

- File found → correct branch. ✅
- `No such file` → you are on `main`, which has **no website**. Run the
  `git switch` again.

> This is the single most common way people fail this demo. `main` looks finished
> (`README`, `docs/`, a whole backend) but it is the API only. Everything you
> will show a judge lives on the branch above.

## Step 2 — install (once)

```bash
python3.11 -m venv .venv
source .venv/bin/activate          # Windows: .\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Takes ~12 seconds. Your prompt should now start with `(.venv)`.

| Error | What it means | Fix |
|---|---|---|
| `python3.11: command not found` | no Python 3.11 | install 3.11–3.13. On Windows: `py -3.11 -m venv .venv` |
| `externally-managed-environment` | you skipped the venv | do Step 2 from the top |
| `running scripts is disabled` (Windows) | PowerShell policy | use `.\.venv\Scripts\python.exe -m pip …` directly |

## Step 3 — check before you start

```bash
./run.sh --doctor
```

This starts **nothing**; it just tells you if things are healthy. You want to see
`✓ test CA present`, `✓ runtime dependencies import`, and which commit you are on.

## Step 4 — start it

```bash
./run.sh
```

Wait ~5 seconds. You should see a box:

```
  CanaryGate is running
  Landing page   http://127.0.0.1:8000/
  Dashboard      http://127.0.0.1:8000/ui/
```

Open **http://127.0.0.1:8000** in your browser.

> ⚠️ Type `127.0.0.1`, **not** `localhost`, and **`http`**, not `https`. The test
> certificate is issued to the number `127.0.0.1`, so `localhost` will fail.
> ⚠️ The banner also prints `API docs → /docs`. **That link 404s** (a known bug —
> P2-2 in the audit). Do not click it in front of a judge.

If the page loads with a headline "Every request has a boundary. Every finding
needs proof." — **you are done with Hour 1.** Press `Escape`, click
`Enter CanaryGate`, and you should be on a dashboard where every number is `0`.

**That `0` is not a bug.** It means "nothing has been scanned on this database
yet." We come back to this in the demo.

To stop: `Ctrl+C` in that terminal (it cleans up both servers).

---

# HOUR 2 (0:45–1:45) — Five ideas, in plain English

You do not need to know Python to explain this project. You need **five ideas**.
Each one comes with the analogy you will actually say out loud, and the one file
that backs it up.

## Idea 1 — Authentication vs. Authorization

**Analogy.** Authentication is the **ID check at the door**: *who are you?*
Authorization is **which rooms your key opens**: *what are you allowed to touch?*

Most security bugs are not at the door. They are at the rooms.

**In this repo:** `canarygate/oracles/authentication.py` checks the door
(does the token belong to the account it claims?). `canarygate/oracles/read_bola.py`
checks the rooms (can this account read something it does not own?).

## Idea 2 — BOLA: the hotel key that opens the wrong room

**BOLA** = **B**roken **O**bject **L**evel **A**uthorization. It is OWASP **API #1**,
the most common serious API bug in the world.

**Analogy.** You check into room 210 and get a key card. You walk to room 412,
tap, and **the door opens**. The hotel checked that you are a paying guest — it
never checked that room 412 is yours.

**In this repo:** the vulnerable lab accepts `GET /records/BRD-2026-018` from an
account that owns a *different* record, and returns the data with `200 OK`.

**Say it like this:** *"The API confirmed who I am, but never confirmed that the
record belongs to me."*

## Idea 3 — Why "I got a 200" is *not* proof

This is the idea that makes your project better than a normal scanner. Learn this
one properly.

A `200 OK` on someone else's ID can mean **five harmless things**:

1. the object is **public** (a marketing page),
2. the object is **shared** (a team document),
3. it is actually **your own** object and you mistyped the IDs,
4. it is a **decoy / empty shell** (the ID exists, the body is blank),
5. it is a **cached** copy of your own data.

A naive scanner screams "VULNERABLE!" at all five. Judges know this — and it is
exactly the question that separates a real project from a toy.

**What CanaryGate does instead:** it demands a *chain of evidence* before it is
allowed to say `CONFIRMED`. Eight gates. In order:

1. the resource is declared **private**,
2. there are **two different accounts** with different credentials,
3. the expected rule comes from a **trusted policy source** (not guessed),
4. **ownership is verified** for both accounts — each list contains its own
   record and *not* the other's,
5. **owner baselines** — each owner reads their own record first,
6. the cross-account request is **proven to be the request that was answered**,
7. the response contains the **owner's own private marker**,
8. nothing was ambiguous, and the **budget/host** were within scope.

**Say it like this:** *"A 200 is a hint. I only call it CONFIRMED when I have
proven the asset is private, proven who really owns it, captured the owner's own
baseline, and found the owner's private marker inside the other account's
response. If any link is missing, my verdict is INCONCLUSIVE or SAFE — it fails
closed."*

**File:** `canarygate/oracles/read_bola.py`.

## Idea 4 — SCI: two locks that are each fine

**SCI** = **S**ecurity **C**ontrol **I**nteraction. This is your *unique* feature.

**Analogy.** A building has two locks on a door: a badge reader and a PIN pad.
Test the badge reader alone → it refuses you. ✅ Test the PIN pad alone → it
refuses you. ✅ But use **both in the wrong order** and the door opens. Each lock
is correct. The *combination* is broken. No standard scanner tests combinations.

**In this repo, and you will show these exact numbers:**

| Step | What happens alone | Result |
|---|---|---|
| authorization check alone | mallapa asks for sakshi's guarded record | `403` refused ✅ |
| authentication check alone | mallapa posts a wrong password | `401` refused ✅ |
| **both, in sequence** | the identical guarded read | **`200` with private data** ❌ |

The verdict is `interaction_induced` — meaning: *the leak was caused by the
interaction, not by either control on its own.*

And it proves the *cause* with a reset test: `403 → 401 → 200 → 403`. It shows the
door closes again after a reset, so the `200` really was caused by the sequence.

**Say it like this:** *"This is the thing ordinary scanners miss. Two controls each
pass their own test. Their interaction is what leaks data. I report the
attribution, not just the failure."*

**File:** `canarygate/oracles/interaction.py`.

## Idea 5 — Evidence you can re-verify (the trust idea)

**Analogy.** A court does not accept "the police say he did it." It needs **chain
of custody**: every item sealed, labelled, and re-checkable.

Every stored run is **hashed with SHA-256** — like a **wax seal on an envelope**.

- Write the run → compute the seal, store it.
- Read the run → recompute the seal, compare.
- Seal differs → the file was edited → **the API refuses (HTTP 500)** instead of
  showing you a report.

**Say it like this:** *"A stored finding is sealed. If anyone edits the database,
the seal breaks and the tool refuses to report it. That is why I can let you
re-run the audit live."*

**Files:** `canarygate/database/*.py`, `tools/consistency_audit.py`.

## Bonus: four words you might be asked, 10 seconds each

| Word | Plain meaning | Here |
|---|---|---|
| **FastAPI** | a Python web framework: turns functions into URLs | `canarygate/api/app.py` |
| **Pydantic** | a strict shape-checker for data | `canarygate/scan/*_models.py` |
| **SQLite** | a database that is just one file | `.canarygate/*.sqlite3` |
| **HTMX** | JavaScript that swaps a piece of the page without reloading | `ui/static/vendor/htmx.min.js` |

And one thing you must **not** claim: **there is no AI and no machine learning.**
The project deliberately avoids it (`docs/JUDGE_DEFENCE.md` §3: *"non-deterministic
evidence is not evidence"*). If you say "AI", a judge will ask you to show the
model, and you will have nothing. Say **"rule-based evidence chaining"** instead.

## Self-test (do this before Hour 3)

Cover the answers and say these out loud:

1. What is the difference between authentication and authorization?
2. What is BOLA, in one sentence with an example?
3. Name three reasons a `200` might not be a vulnerability.
4. What must be true before CanaryGate says `CONFIRMED`?
5. What does `interaction_induced` mean?
6. What happens if someone edits a stored run?
7. Does this project use AI?

<details>
<summary>Answers</summary>

1. Authentication = who you are. Authorization = what you may access.
2. An API returns an object the caller does not own — e.g. my key opens room 412.
3. Public object, shared object, my own object (or cached copy / decoy).
4. Private asset + two distinct accounts + verified ownership + owner baselines +
   matched request + the owner's private marker in the response + no ambiguity.
5. Two controls each behaved correctly alone; their *combination* leaked the data.
6. The SHA-256 seal breaks and the API returns an error instead of a report.
7. No — deliberately. It is deterministic rule-based evidence chaining.
</details>

---

# HOUR 3 (1:45–2:45) — Rehearse the demo twice

## Reset first (so the `0 → 9` story is true)

```bash
rm -f .canarygate/judge-demo.sqlite3
./run.sh
```

## The eleven steps

Do this **twice**, out loud, with a timer. Target: 3 minutes.

| # | You do | What appears | What you say |
|---|---|---|---|
| 1 | Open `http://127.0.0.1:8000` | Landing page with a headline | "CanaryGate tests API **authorization** — who can read what." |
| 2 | Press `Escape`, then **Enter CanaryGate** | Dashboard, all tiles `0`, matrix `0 / 9` | "Fresh database. Untested is never SAFE — that zero is a promise, not a bug." |
| 3 | — (point at the other terminal) | TargetLab log line | "That's a deliberately vulnerable API I built as a safe target. Loopback only, never deployable." |
| 4 | **New run** → **Run security assessment** | Live feed of requests: `GET /records/... → 200`, ticking stages | "Every line is a real HTTPS request — method, path, the lab's own status, latency." |
| 5 | wait ~10 s | "Assessment complete" | "Three account pairs, six checks each, 54 requests." |
| 6 | Open the matrix | **9 tested / 0 untested · 6 CONFIRMED · 3 SAFE** | "Six confirmed cross-account leaks. Three safe." |
| 7 | Click one **CONFIRMED** cell | requester, owner, asset, `LAB-BOLA-03`, `200`, a SHA-256 | "Not just a 200. I proved mallapa's own asset, proved sakshi's baseline, and matched sakshi's private marker in the response." |
| 8 | Open the secure twin | `LAB-BOLA-05`, `403`, SAFE | "Same object, secure route, refused. So this is object-level authorization, not a public object." |
| 9 | Open the SCI proof | `403` → `401` → **`200`**, verdict `interaction_induced`, reset `403→401→200→403` | "Each control passes alone. Their interaction leaks. That's the part most scanners miss." |
| 10 | In terminal: `python tools/consistency_audit.py --database .canarygate/judge-demo.sqlite3` | `220 invariants … ALL STORED RUNS INTACT AND CONSISTENT` | "Every verdict re-derives from sealed evidence." |
| 11 | (optional) `Ctrl+C` the lab, run an assessment again | "Assessment did not complete", the reason, the command to fix it; matrix unchanged | "A connection failure is never reported as SAFE." |

**If you are running out of time in front of judges:** do steps 1, 2, 4, 6, 7, 9.
Those are the story. Skip 3, 8, 10, 11.

## Rehearsal rules

- **Never improvise an endpoint.** Click the screen, don't type URLs. If you must
  type, only `/ui/`, `/api/health`, `/api/lab-matrix` are safe.
- **Never open `/docs`** — it 404s.
- **Never say "AI", "machine learning", "cloud", "Docker" or "real customers".**
  None of those exist here.
- If a click is slow, **talk over it**: "the engine is sequential by design — one
  request at a time, so nothing races."

---

# HOUR 4 (2:45–3:30) — The seven questions you will actually get

Answers written for a beginner: short, honest, and impossible to be caught out on.

**1. "Is this AI?"**
> "No, and that's deliberate. A verdict has to be reproducible — an LLM's opinion
> isn't evidence. The intelligence here is rule-based: eight evidence gates plus
> SHA-256 sealing."

*If pushed:* "I'd only ever use AI for prioritising results *after* the verdict,
never to produce it."

**2. "Your vulnerable target is a lab you wrote. Isn't that circular?"**
> "Yes — and I say so on every page. It's a regression target, not a customer
> finding. The lab proves the pipeline works end to end; the scanner is the part
> that generalises."

*This is the most likely trap. The honest answer scores well; a defensive one
does not.*

**3. "Have you run it against a real third-party API?"**
> "No. I have profiles prepared for VAmPI and crAPI, but running them needs
> written organizer approval, so I haven't. It's one of the two gaps my own audit
> tool lists as 'missing'."

**4. "Why should I trust a CONFIRMED verdict?"**
> "Because it needs the full chain — private asset, two accounts, verified
> ownership, owner baselines, the matched request, and the owner's private marker
> in the response. If any link is missing it can't say CONFIRMED. And the stored
> evidence is sealed, so you can re-run the audit live."

**5. "How do you stop someone abusing this to attack a site?"**
> "Every request goes through one guard immediately before the connection: exact
> scope, method allow-list, no redirects, no DNS lookup, a hard request budget,
> and DELETE blocked. Live external scanning is disabled — it can only reach the
> loopback lab with a pinned certificate."

**6. "What's your weakest point?"** *(answer this one honestly — it's a trap for
people who claim perfection)*
> "Release process, not the engine. The whole frontend sat in an unmerged pull
> request while the main branch looked finished — so anyone cloning it got an API
> with no interface. We also had three stale numbers in the docs. The code is
> solid; our branching discipline was the risk."

**7. "What would you build next?"**
> "Broken function-level authorization — role versus policy, not just object
> ownership. My audit tool already names it as the missing requirement D11."

## Things you must never say

| ❌ Never | ✅ Say instead |
|---|---|
| "It's an AI-powered scanner" | "An evidence-based, rule-driven authorization tester" |
| "It finds all API vulnerabilities" | "It proves two classes: read-BOLA and control-interaction" |
| "It works on any API" | "On an authorized API with two accounts and verified ownership" |
| "It's a full scanner" | "One oracle implemented properly, end to end" |
| "Docker/deployed/cloud" | "Runs locally, fully offline, no external services" |

---

# FINAL 30 MINUTES (3:30–4:00) — Pre-flight

## Backup plans, in order

1. **The UI misbehaves?** → `python tools/demo.py`
   One command. It starts its own lab, runs four stages, and prints
   `ALL CONSISTENCY CHECKS PASSED (142 invariants over 17 surfaces)`. No browser
   needed. This is your strongest safety net — **try it once now.**
2. **The lab won't start?** → in a second terminal start it manually, then start
   the website manually (commands in `docs/DEMO_AUDIT.md` §8).
3. **Everything Python fails?** → screenshots of steps 6, 7, 9 + the saved output
   of `tools/demo.py`, and talk through the architecture diagram.

## Pre-flight checklist

- [ ] `git switch arena/80050ed6-hackfusion-30102026` and `ls run.sh` exists
- [ ] `./run.sh --doctor` is clean
- [ ] `.canarygate/judge-demo.sqlite3` deleted (fresh `0 / 9`)
- [ ] `./run.sh` running; browser open at `http://127.0.0.1:8000`
- [ ] One rehearsal of the 11 steps completed in under 4 minutes
- [ ] `python tools/demo.py` verified working once (backup ready)
- [ ] The seven answers said out loud at least once
- [ ] Phone/notifications off; browser zoom at 110% for the back row
- [ ] You can say "I don't know, but here's how I'd find out" comfortably

## The one sentence to open with

> "CanaryGate proves API authorization bugs instead of guessing at them — and it
> finds a class of bug, control interaction, that ordinary scanners miss."

## If everything goes wrong

Say this, calmly: *"The environment is fighting me, so let me show you the
evidence instead of the click-path."* Then run `python tools/demo.py` and narrate
its output. You will still have demonstrated: real requests, real verdicts, real
evidence, real consistency checks. That is a complete demo.
