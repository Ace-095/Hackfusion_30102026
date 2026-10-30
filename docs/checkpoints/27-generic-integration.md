# Checkpoint 27 — generic proof-path integration and trustworthy verdicts

**P0 remains NOT ACCEPTED.** This checkpoint closes part of the largest
architectural gap — fixture-only ownership and BOLA evidence — but it does not
turn CanaryGate into a generic live scanner. All new HTTPX-path tests use fake
HTTP/TLS/socket objects. Production network execution is still hard-disabled,
and VAmPI, crAPI and organizer targets were not contacted. See
[`docs/P0_ACCEPTANCE_MATRIX.md`](../P0_ACCEPTANCE_MATRIX.md) for the
requirement-by-requirement status.

## What changed

### One ownership algorithm, two evidence sources

`canarygate/seed/registry.py` now has one shared `_collect_ownership` routine.
It performs the same checks for both sources:

1. two distinct scoped accounts (for guarded HTTPX: distinct credentials and
   two successful profile-identity controls);
2. bounded private-list discovery with explicit pagination termination;
3. cross-account list exclusion in both directions;
4. one owner-detail read per account, with matching ID and owner and a distinct
   private baseline;
5. verified private ownership only if every preceding step succeeds.

`collect_fixture_ownership` keeps the existing fixture contract.
`collect_guarded_ownership` is the mocked-HTTPX entry point. Neither function
performs a cross-account probe; that remains an explicit caller step.

### One two-part oracle

`canarygate/oracles/read_bola.py` still owns the only BOLA verdict logic. Fixture
responses are checked against synthetic bearer headers and fixture origin;
guarded-HTTPX responses are checked through ephemeral request metadata and an
in-process response record. The oracle still requires verified private
ownership, two owner baselines, a distinct private marker, a guarded
cross-account request and separate disclosure evidence. A 200/D status by itself
never confirms, and a 403 is SAFE only for the exact checked fixture denial body.

The generic path is bound to the exact `Resource` used for collection and to a
collector-issued provenance snapshot. A caller cannot construct a matching
`FixtureOwnershipResult`, mutate its entries, reuse a baseline from another
collection or change the recipe and still obtain CONFIRMED. Guarded response
records detect a response whose body or status was changed after receipt. This
is an in-process invariant, not cryptographic attestation.

### Fail-closed discovery details

- Hidden pagination headers (`Link`, `X-Next-Page`, `Content-Range`,
  `X-Total-Count`) can no longer be silently dropped by the guarded transport
  and mistaken for a complete list. Header values are not released; only a
  boolean "pagination metadata present" extension is retained and checked.
- A configured page limit that ends while a continuation token remains is
  incomplete and cannot verify ownership. No unscoped second-page URL is sent.
- Duplicate JSON keys, non-finite JSON constants, identity mismatches, unknown
  owner fields, ambiguous lists and guard-blocked discovery fail closed.
- `FixtureOwnershipResult` no longer exposes entries/IDs/baselines in `repr`.

### Evidence redaction

`canarygate/evidence/redaction.py` now also normalizes camelCase and additional
secret names (access/refresh/ID tokens, API keys, password hashes, passphrases,
session IDs/tokens) and redacts bounded cookie-header and secret-assignment
patterns in error/debug strings. Tests cover nested objects, arrays, alternate
field names, headers, cookies, error text and debug text through JSON, HTML,
observation output, Python logging capture and SQLite bytes.

This is known-shape redaction, not a universal redactor. Stored reports remain
minimized to a fixed evidence schema; arbitrary live bodies, encodings, stack
traces and third-party log sinks are not claimed safe.

### JWT metadata helper

`canarygate/oracles/authentication.py::inspect_jwt_metadata` decodes bounded,
well-formed JWT metadata (`alg`, `sub`, `role`, `exp`) and explicitly marks it
`claims_unverified=True`. It rejects duplicate keys, non-finite numbers,
excessive nesting, invalid claim types and oversized input. It never returns the
token or claim values in `repr`, never verifies a signature and never authorizes
a request or verdict. Crafted-token checks AUTHN-04a/04b/05 remain missing.

## Generic proof path

```
guarded HTTPX runner (production gate disabled; fake sockets in tests)
  -> two profile identity controls + distinct credentials
  -> shared bounded discovery / cross-exclusion / owner baselines
  -> ephemeral provenance-bound ownership result
  -> caller's guarded cross-account GET
  -> same evaluate_read_bola() two-part oracle
  -> CONFIRMED / SUSPECTED / SAFE / INCONCLUSIVE / SKIPPED
```

**Missing after the oracle:** generic run orchestration, persistence, report
rendering, API exposure and any live-target execution. Only fixture runs reach
SQLite and the JSON/HTML reports today.

## Tests

New regression files (29 new test cases):

- `tests/security/test_generic_guarded_bola.py` — generic guarded runner feeding
  the same oracle in vulnerable, denied, missing and malformed-denial modes;
  missing/unverified/shared/public evidence; profile mismatch; ambiguous lists;
  unknown owner baselines; forged and mutated responses; caller-constructed
  registry/recipe mismatch; guard-blocked discovery; hidden pagination headers;
  pagination limit; halted runner; fixture/generic shared entry point.
- `tests/unit/test_redaction_adversarial.py` — nested alternate secret keys,
  arrays, headers, cookies and error/debug strings while preserving status,
  method and ownership metadata.
- `tests/integration/test_checkpoint27_redaction.py` — synthetic nested secrets
  absent from API JSON, section JSON, HTML, observations, logs and SQLite bytes,
  while the CONFIRMED checklist and disclosure evidence survive.
- `tests/unit/test_jwt_metadata.py` — unverified metadata, hostile JSON, invalid
  claim types and unchanged SKIPPED status for crafted-token checks.
- `tests/integration/test_checkpoint27_acceptance.py` — seven offline outcomes
  through persistence and both report formats: CONFIRMED, SAFE,
  INCONCLUSIVE (metadata-only read), INCONCLUSIVE (403 with leaky body),
  SKIPPED (malformed owner baseline), SKIPPED (authentication setup failure)
  and SKIPPED (pagination limit).

These tests first exposed: forged response objects accepted by the oracle,
caller-constructed ownership results accepted, recipe substitution accepted,
hidden pagination headers lost at the guarded transport, non-finite identity
JSON accepted, and limited redaction coverage. Each was fixed before the final
suite run.

## Three outcomes for the judge demo

Run from the repository root in VS Code (Windows: `.venv\Scripts\python`):

```sh
.venv/bin/python - <<'PY'
from canarygate.offline.scan import run_fixture
from canarygate.offline.target import FixtureTarget

confirmed = run_fixture()
safe = run_fixture(FixtureTarget(attacker_access='deny'))
inconclusive = run_fixture(FixtureTarget(attacker_access='metadata'))
for label, run in [('CONFIRMED', confirmed), ('SAFE', safe), ('INCONCLUSIVE', inconclusive)]:
    print(label, '->', run['verdict'], '|', run['reason'])
    print('   checklist:', {k: v for k, v in run['bola_checklist'].items() if v})
PY
```

Expected: `CONFIRMED` shows ownership, owner baseline, private baseline,
attacker request, response and disclosure checks; `SAFE` shows ownership and a
checked denial; `INCONCLUSIVE` shows ownership but no private disclosure or
verified denial. The fixture API emits the same evidence in HTML and JSON:

```sh
.venv/bin/python -m uvicorn canarygate.api.app:app --host 127.0.0.1 --port 8000
# second terminal
curl -sS -X POST http://127.0.0.1:8000/api/scan
curl -sS 'http://127.0.0.1:8000/api/reports/<id>?view=sections'
curl -sS 'http://127.0.0.1:8000/api/reports/<id>?format=html'
```

Run the generic mocked proof path and all regressions with:

```sh
.venv/bin/python -m pytest -q tests/security/test_generic_guarded_bola.py -vv
.venv/bin/python tools/run_ci_tests.py
```

## Local and CI results

- Local full suite: **516 passed**, one third-party Starlette/AnyIO
  `DeprecationWarning`.
- `git diff --check`: clean.
- Isolated wheel build succeeded (`canarygate-0.1.0-py3-none-any.whl`, 65 files);
  the retired `pinned_reader.py` remains an inert `ImportError` tombstone.
- Ubuntu/Windows CI: see the Actions run for this checkpoint's pushed commit in
  the hand-off message. A green workflow is not P0 acceptance.

## Remaining gaps (honest list)

- Generic scan orchestration and API exposure; generic verdicts are not stored
  or reported.
- Production network execution, approved resolver/DNS flow and one unified
  reviewed guard boundary. Production remains disabled.
- Crafted-token AUTHN-04a/04b/05 behavior; AUTHN-06/08; generic AUTHN-01–03/07.
- INPUT-05–07 and generic input validation; full DISC-01–06 coverage.
- Generic/spec-derived policy ingestion, multi-role matrix and general
  remediation/catalog.
- Universal evidence redaction and any claim about arbitrary live secrets.
- BFLA/P1 features, independent lab validation and any live target.
