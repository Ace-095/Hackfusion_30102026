# Checkpoint 42 — the product experience

**Goal:** let a first-time judge open CanaryGate, understand what it tests, configure
a run, execute it, inspect the evidence and reach a report without anyone explaining
the steps — without inventing a single verdict, event or number.

**Result at this milestone:** a standalone cinematic landing page, a configuration
workspace built entirely from backend data, and a recorded execution + disclosure
proof view on every BOLA run. The architecture report that precedes the code is
`docs/frontend/EXPERIENCE_ARCHITECTURE.md`.

## What shipped

| Surface | What it does | Where the data comes from |
|---|---|---|
| `/` | Cinematic entry: network formation → request paths → authorization boundary → evidence assembly → brand, on a single 15-second CSS timeline. Headline, both calls to action and **Skip intro** are usable from the first frame; `prefers-reduced-motion` and the skip control pin every layer to its finished state; Escape also skips | none — the page holds no data and makes no claim |
| `/ui/assessment` | Four-section workspace: **A** specification (operations and methods, labelled "inventory only — no security scan performed"), **B** the two environments with capabilities and limits, **C** the three demo accounts with their owned assets, **D** three real run forms plus **RUN SECURITY ASSESSMENT** | `GET /api/lab-catalog`, `GET /api/lab-matrix`, `GET /api/endpoints`, readiness from the CA environment |
| `/ui/lab/bola/{id}` — *Execution timeline* | Authentication → owner baselines → cross-account request → disclosure verification → secure-route comparison, each naming the stored check ids, statuses and verdicts, with a banner saying the backend streams no live events and a stage with no stored check saying so | the stored run only |
| `/ui/lab/bola/{id}` — *Disclosure proof* | Requester → owner baseline → ownership verified → cross-account request → private disclosure → verdict, plus the secure route's own status and check id; every step anchors to the check it came from, and the oracle's reason and remediation are quoted | the stored check's evidence block |
| Navigation | Overview · New security assessment · API inspector · Authorization matrix · Evidence explorer · Scan history · Reports · TargetLab · Offline suites · Configuration | `NAV_GROUPS`; every link is fetched by a test |

## The decisions behind it

**The landing page sells, it does not claim.** It is standalone (no shell, no data,
no forms) and every sentence in it is either a product description or an explicit
boundary statement ("not a live scan of your API"). The motion is one CSS timeline
with SVG; there is no canvas, no dependency, no audio and no forced wait.

**No fake telemetry.** The backend runs a scan synchronously and stores it at the
end. Rather than animate requests that never happened, the run page renders the
recorded stages and states the limitation on the page itself. The architecture
report specifies the observer-hook + SSE design that would make real progress
possible, and why it is not in this milestone.

**The workspace cannot start anything by accident.** Every section is rendered from
a backend payload, and only the three explicit forms post to existing action routes.
Opening `/ui/assessment` performs no scan, and a test asserts the run count stays 0.

**The proof flow is the product.** The disclosure chain is read field-by-field from
one stored check (`owner_baseline`, `ownership_verified`, `status`,
`private_disclosure`) and ends with the secure route's own 403 — the sequence a
judge should remember.

## Verification

```
$ .venv/bin/python -m pytest -q
1088 passed, 1 warning in 110.11s
$ .venv/bin/python tools/p0_audit.py
P0 audit: 58 requirements, 1088 collected tests, 64 test files
$ .venv/bin/python tools/demo.py
ALL CONSISTENCY CHECKS PASSED (142 invariants over 17 surfaces)
$ .venv/bin/python tools/browser_smoke.py --jsdom /tmp/browser-harness
19/19 browser checks passed
$ .venv/bin/python tools/consistency_audit.py --database <3 BOLA runs>
runs checked: 3  projections rebuilt: 7  invariants: 220
```

Plus a focused jsdom run against the live landing page: skip control present and
effective (`is-static` applied, label becomes "Intro skipped"), Escape handled, zero
external assets, one `<h1>`, four sections.

## What is not built (and is not claimed)

- **Live progress.** No SSE, no job endpoint, no per-stage timestamps. The run page
  says so. The observer design is documented in the architecture report.
- **Per-endpoint findings analytics, historical comparison charts and Gantt
  durations.** The backend exposes no aggregation for them, and inventing a metric
  in a template would break the data-integrity rule. The pages that exist show
  per-endpoint evidence for the offline dataset only, where it is stored.
- **A dedicated demo-accounts page.** Accounts live in the workspace section C with
  ownership links into the matrix; adding a second surface for the same catalog
  would duplicate the data, not the value.
- **Real-browser verification of the motion.** jsdom executes the scripts but has no
  layout engine; the visual sequence is verified structurally and by the live
  preview, and that limitation is stated in `EXPERIENCE_ARCHITECTURE.md` §6.

## Remaining blockers

- `D11` (BFLA) and `D12` (live validation) are still missing; P0 stays *incomplete*.
- Nothing here tests a real organizer API; the lab remains loopback-only.
