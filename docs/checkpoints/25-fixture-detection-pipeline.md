# Checkpoint 25: fixture detection pipeline and bounded extraction

## VS Code / judge demo

From the repository root in a Python 3.11 environment:

```sh
python -m pytest -v tests/integration/test_generic_fixture_pipeline.py
python -m pytest -v tests/integration/test_read_bola_oracle.py tests/integration/test_verified_ownership.py
python tools/run_ci_tests.py
```

Use `.venv/bin/python` on Linux/macOS or `.\.venv\Scripts\python.exe` on
Windows. The focused tests run two synthetic in-process target behaviors through
the **existing** registry, guard, oracle, API, SQLite store and HTML/JSON report.
They forbid DNS and socket connections in the end-to-end test. The nested and
paginated scenario is a synthetic Python fixture, not VAmPI or crAPI. For a
visible local API/report demo, follow [VS Code demo](../VS_CODE_DEMO.md).

## Checkpoint status

| Question | Status |
| --- | --- |
| BOLA oracle implemented? | Yes, for the existing **fixture-only** registry, fixture identities and synthetic policy. Complete ownership, owner baseline, cross-account private disclosure and denying policy are required for CONFIRMED. It is not a generic live oracle. |
| All five verdicts adversarially tested? | Yes, for fixture cases: CONFIRMED, SUSPECTED, SAFE, INCONCLUSIVE and SKIPPED. Missing ownership/baseline cannot confirm or suspect; unknown policy remains inconclusive; public/shared cannot auto-confirm. |
| Nested field extraction generic? | Bounded dotted dictionary-key selectors now drive list, ID, owner and private-field extraction in the fixture registry/oracle. No target-specific field names are in scanner logic. This is a narrow object-only subset, not a general JSONPath engine; list and detail still share the same ID/owner selectors. |
| Pagination bounded? | Yes, **fixture-only explicit body continuation-token mode**: at most four pages/account and 256 total IDs/account, response and shared guard budgets apply, each next query must be individually exact-scope authorized, cycles/unsafe tokens/missing termination/known conflicting pagination indicators fail closed. URLs, redirects and unscoped pages are never followed. Not universal pagination support. |
| Credentials redacted everywhere? | Supported fixture API, evidence, observation, HTML/JSON, findings, matrix, status, log and SQLite paths were tested with synthetic credential/cookie/private sentinels. Arbitrary live credentials, all possible payloads and production storage have **not** been proven safe. |
| Complete offline workflow? | A meaningful synthetic vertical slice works: recipe → guarded discovery and owner baselines → cross-account read → verdict/checklist → minimized evidence → persisted JSON/HTML report, including nested paginated cases. The full frozen-spec offline acceptance suite, all P0 checks, and general multi-target pipeline are still incomplete. |
| Existing tests? | Full local suite: 471 passed, including the original 437, with one third-party warning. |

## Verdict examples in the synthetic fixture

- **CONFIRMED:** both lists complete and mutually exclude, both owner reads
  match, Alice's 200 response contains Bob's matching private string and
  identity, and the bundled owner-only policy denies Alice.
- **SUSPECTED:** those prerequisites hold and Alice's 200 contains the matching
  private string, but the response omits ID or owner, with no conflicting ID or
  owner; attribution is incomplete. A contradictory identity, unknown policy,
  invalid owner baseline or missing ownership cannot reach this verdict.
- **SAFE:** independently verified owner access and expected denial, plus the
  fixture's exact checked `403 {"error":"forbidden"}` body without the owner
  marker. Status alone never proves safety.
- **INCONCLUSIVE:** metadata-only or empty 200, incorrect identity, uncertain
  policy or ambiguous 404. A response code or ID alone is not disclosure.
- **SKIPPED:** the scanner did not run the cross-account check because setup,
  identity, complete lists, ownership or the private baseline failed.

## Extraction and safety boundaries

Selectors are at most eight dot-separated object keys; no array indexing,
wildcards, expression execution or implicit owner conversion. A wrapped list
must use explicit token pagination with an explicit null termination marker.
One exact synthetic continuation query is allow-listed in fixture scope; a
server-provided token cannot widen it. Other known paging headers/metadata,
missing termination, duplicate/unsafe IDs or a page/budget/size limit prevent
verification. A target claiming null termination could still lie or use an
unknown pagination convention: completeness depends on a reviewed fixture/API
contract, not inference from an arbitrary JSON response. The ownership rule
still requires actual peer-list exclusion across **all** accepted pages and
successful matching owner detail reads.

Existing fixture authentication probes are skipped for nested private fields
because that separate oracle only understands flat fields. The HTML/JSON summaries
are minimized and hash redacted fixture evidence, not full transcripts or signed
proof. Production network execution remains disabled; written organizer
approval is still required before any VAmPI/crAPI or competition API execution.
VAmPI's global list cannot prove exclusion, and crAPI's differing detail/list
fields and nested object baseline still prevent support. Neither was run.
