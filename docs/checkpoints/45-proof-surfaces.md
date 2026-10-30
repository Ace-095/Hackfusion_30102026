# Checkpoint 45 — ownership and disclosure proof as real destinations

**What prompted it:** a reviewer followed the numbered journey the dashboard shows and
clicked "5 · Ownership proof". It went to `/ui/findings` — the *fixture* findings page —
which is empty when the database holds only TargetLab runs. The same for
"6 · Disclosure proof", "7 · Matrix" and "8 · Report". The proofs existed on the run
page and in the dashboard cards, but as journey destinations they did not exist.

That is a fair complaint, and it was reproducible in three places:

| What was wrong | Reproduced by | Why it happened |
|---|---|---|
| Five of the eight journey steps pointed at fixture surfaces | open `/ui/` on a lab-only database and read the nav hrefs | the journey macro predates TargetLab; every step was hardcoded to `/ui/scans`, `/ui/findings`, `/ui/matrix`, `/ui/reports` |
| Ownership and disclosure proof had no page of their own | click steps 5 and 6 | their only homes were a dashboard section and a section on one run page |
| The run page contradicted its own verdict | open a CONFIRMED run and read "Evidence the run kept" | the card printed `run.evidence.disclosure.checklist`, which ANDs `private_disclosure` across the *secure* checks too, where `false` is the correct answer |

## 1. The journey now follows the dataset

`journey(current, run_id=None, lab=None)` takes the hrefs from
`canarygate.ui.proofs.proof_anchors(runs)`. With lab runs stored, steps 3–8 walk the
TargetLab surfaces (run history → a stored run → ownership proof → disclosure proof →
asset matrix → that run's report); with none, the original fixture path is used
unchanged. The nav also prints which dataset it is walking (`TargetLab runs` /
`offline fixtures`), because the two must never be confused.

Lab pages now carry the journey too — the index, the matrix and the run page previously
had breadcrumbs but no numbered path.

## 2. Two new pages, built only from stored runs

`canarygate/ui/proofs.py` is a pure projection over run payloads plus the published
catalog. It cannot create a check, a status, a verdict or a hash.

**`/ui/lab/proof/ownership`** — one row per catalog account: the stored owner-baseline
check that verified it, that check's run, HTTP status and evidence SHA-256, with the
reason the oracle recorded. An account with no stored owner read is marked *not verified*
and shows "no stored owner read in any run". The page also states what the proof does
and does not establish.

**`/ui/lab/proof/disclosure`** — one chain per stored cross-account request, five steps,
each a stored field: owner baseline → requester's own record → cross-account request →
private disclosure → the same request against the secure route. Every step carries its
check id (an anchor into the run page), HTTP status and evidence hash. A `403` is drawn
as `denied`; a `false` on that step is explained as the expected answer rather than
hidden.

Both pages have real empty states, and both say the run is loopback-lab validation, not
live-target validation.

## 3. The run page no longer contradicts itself

"Evidence the run kept" used to print an aggregate. It now prints three labelled groups —
Owner baselines, Cross-account requests, Secure-route denials — each with its own checks
and flags, plus one sentence per group saying what a `false` means there. The
contradictory "Vulnerable route disclosure / private disclosure: no" line, printed beside
a CONFIRMED verdict, is gone; the run page also gained `#proof-ownership` and
`#proof-disclosure` anchors so the journey and the dashboard can link straight to a proof.

The stored `evidence` payload is untouched. The defect was in how the UI *read* it, so
the fix is in the UI — no hash, no stored field and no audit changed.

## 4. Verification

```
pytest -q                                  1122 passed (68 files)
tools/p0_audit.py                          58 requirements / 1122 tests / 47·9·2 / 0 unreachable
tools/demo.py                              142 invariants over 17 surfaces
tools/consistency_audit.py <demo db>       ALL STORED RUNS INTACT AND CONSISTENT
tools/browser_smoke.py --jsdom             31/31
```

`tests/integration/test_ui_lab_proofs.py` (9 tests, real TLS lab) pins:

- the journey walks the lab surfaces when lab evidence exists, every step resolving to a
  200, and keeps the fixture path when only fixtures exist;
- the ownership page reports every verified baseline with the check id and hash the API
  returned, is empty-and-honest on a fresh database, and leaves owners unverified after a
  single-pair run;
- the disclosure page chains all six stored checks of a pair run, labels denials as
  denials, and prints the confirmed count the API reports;
- the run page shows the three groups and none of the old aggregate wording.

## 5. Limits, stated plainly

- **A check's evidence digest binds content, not identity.** `evidence_sha256` is the
  digest of the check's id, verdict, flags and bounded evidence within its run, so the
  same check position in two different runs produces the same digest for different
  actors. Rows are therefore identified by run id **and** check id, both printed on the
  page; the digest is not presented as an identity. Changing the recipe would give old
  and new runs two hash vintages without re-hashing what is already stored, which is a
  worse trade than stating the limitation.
- **Proof pages read the newest stored run per account.** A later run supersedes an
  earlier one; nothing is merged across runs, so a proof never combines evidence from two
  scans.
- **Still loopback only.** These pages prove what the lab recorded. They are not evidence
  about a live or organizer-supplied API, and every page says so.
