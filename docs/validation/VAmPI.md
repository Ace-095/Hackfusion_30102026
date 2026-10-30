# VAmPI validation profile — planning only

**No scanner traffic without explicit written organizer approval**, even for a
local instance. Profile: [vampi.yaml](profiles/vampi.yaml). It is inert planning
metadata, not an accepted scanner recipe/scope and not authorization. Values are
candidates to be checked against the exact approved deployed revision and written
scope; do not treat them as a host allow-list or an instruction to execute.

## Source-reviewed candidates

Static review used [VAmPI README](https://github.com/erev0s/VAmPI/blob/f16052dce83f05847133ec98f01c5193a41de7d8/README.md),
[OpenAPI](https://github.com/erev0s/VAmPI/blob/f16052dce83f05847133ec98f01c5193a41de7d8/openapi_specs/openapi3.yml),
[book handlers](https://github.com/erev0s/VAmPI/blob/f16052dce83f05847133ec98f01c5193a41de7d8/api_views/books.py),
[book model](https://github.com/erev0s/VAmPI/blob/f16052dce83f05847133ec98f01c5193a41de7d8/models/books_model.py),
and [DB initializer](https://github.com/erev0s/VAmPI/blob/f16052dce83f05847133ec98f01c5193a41de7d8/api_views/main.py).
The reviewed OpenAPI file SHA-256 is
`35200f354f9c9968182fc19458295ed45bb4c368150348c46d5146a7e40a61c9`.
A one-time **static local parse**, not a target test, returned 14 inventory
operations. The upstream spec advertises a local server, but CanaryGate must
ignore it as target authority. It declares a private book secret and the README
describes vulnerable/secure modes; treat these as proposed expectations until
independently confirmed by authorized policy and instance-specific ground truth.

The source-reviewed book list returns a global wrapped `Books` collection with
`book_title` and `user`. Detail returns `book_title`, `owner`, `secret` (the
upstream OpenAPI response schema describes an array; the source handler returns
an object). **The global list cannot establish mutual peer-list exclusion.**
Therefore the current ownership contract does not verify these books and no
cross-user BOLA probe is ready under this plan. Do not filter the global list
locally and misrepresent that as a peer-list exclusion. Require a genuinely
account-scoped, complete list or other evidence path explicitly consistent with
the frozen ownership rule, subject to review and written authorization; if
unavailable, record BOLA coverage SKIPPED. The current fixture registry/oracle
also cannot process these response shapes or compare this policy.

The exact documented `GET /createdb` drops/recreates the database; it is
**DESTRUCTIVE and always blocked**, despite being GET. Registration, book
creation, PUT and DELETE are not part of this plan. Seed resources/accounts out
of band under the organizer's rules. Never auto-cleanup.

## Scenario matrix

Before approval, all independent execution rows are **NOT RUN**; use only the
existing synthetic test suite. Record target/version/policy source and expected
results before any future approved test.

| Case | Prepared expectation / acceptance criterion |
|---|---|
| Offline OpenAPI inventory | Parse a locally supplied pinned spec and list operations; parsing is not permission to request any operation. Reject unsupported remote refs and oversized inputs. |
| Authentication | With an exact approved login operation and supplied accounts, observe distinct account identities separately; JWT claims alone are insufficient. No automatic login retry. |
| Public list and ownership | Detect global peer visibility; no verified private ownership and no BOLA cross-read. Mark coverage SKIPPED, never SAFE or CONFIRMED. |
| Conditional vulnerable mode | Only if the frozen ownership rule is independently satisfied and policy denies A: A reading B's matching private secret with A credentials yields CONFIRMED. Otherwise do not probe/confirm. |
| Conditional secure mode | Only if ownership, authenticated A, expected denial and inspected response body independently establish a correct denial, SAFE; ambiguous 404 remains INCONCLUSIVE. |
| Metadata-only 200, empty body, unknown policy | INCONCLUSIVE; ID/owner, 200, or unverified ownership cannot establish a leak. |
| Shared/public resource | No automatic private BOLA confirmation; report coverage/uncertainty honestly. |
| Reset/write operation | Not executed; guard blocks destructive GET and unapproved writes before transport. |

No upstream deployment was started or scanned for these plans. A static source
review is not validation of deployed behavior, nor a live result.
