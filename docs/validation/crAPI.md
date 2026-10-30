# OWASP crAPI validation profile — planning only

**No scanner traffic without explicit written organizer approval**, even for a
local instance. Profile: [crapi.yaml](profiles/crapi.yaml). It is inert planning
metadata, not an accepted scanner recipe/scope and not authorization. Confirm
each candidate against the precise approved deployment and policy before any
future action.

## Source-reviewed candidates

Static review used the pinned [README](https://github.com/OWASP/crAPI/blob/b5fc307f3e5f875809b095b771108ef342a33724/README.md)
and [OpenAPI document](https://github.com/OWASP/crAPI/blob/b5fc307f3e5f875809b095b771108ef342a33724/openapi-spec/crapi-openapi-spec.json).
The reviewed OpenAPI SHA-256 is
`9d57e0e76348a9a6bdff2c841ce791bb9de604a316b724074a998e3c484a4ace`.
A one-time **static local parse**, not a target test, returned 44 inventory
operations. OpenAPI's bearer security means authentication is described, not
that owner-only policy is proven. The profile identifies a candidate login,
identity dashboard, vehicle list and location detail for later review. No
concrete IDs, hosts, credentials or approved ownership/access policy are supplied.

The reviewed vehicle-list schema describes a UUID, an `owner` object with
`email`, and nested `vehicleLocation`; location detail describes `carId`,
`fullName`, and nested `vehicleLocation`, not a directly comparable owner field.
The fixture registry now supports bounded dotted object keys, but requires the
same ID and owner selectors to match both list and owner-detail responses. The
fixture oracle still requires a string marker and bundled fixture policy; the
candidate location is a nested object and detail has different identity fields.
These contracts **cannot currently verify or test this candidate**.
The spec alone does not prove an identity mapping, list completeness, valid ID
mapping, privacy policy, vulnerable behavior or a secure-mode counterpart.
If those cannot be independently established from authorized sources and
observations, mark coverage SKIPPED/INCONCLUSIVE, never infer them from JWTs or
IDs. Generic bounded pagination and response-field/policy support are future
work; do not relax the frozen verified-ownership rule.

No signup, add-vehicle, mutation, destructive endpoint, multi-step workflow or
cleanup is part of this plan. Obtain two pre-provisioned accounts and owned
resources out of band under the organizer's rules. Source-level details are not
an authorization to call the candidates.

## Scenario matrix

Before approval, every independent execution row is **NOT RUN**. Actual
expectations are established per approved version, instance and policy, not
assumed from this table.

| Case | Prepared expectation / acceptance criterion |
|---|---|
| Two-account authentication | Exact approved login only; distinct observed account identities, no token/secret persistence and no JWT-claim-only proof. |
| Discovery | Both accounts' complete bounded lists, ID mapping, explicit owner mapping and mutual exclusion must be established; pagination or response ambiguity blocks verification. |
| Owner baseline | Both guarded owner reads must establish resource identity and ownership under the frozen rule; mismatch or missing evidence blocks the probe. |
| Conditional cross-account disclosure | Only with verified private ownership and an independently reliable denying policy may a successful A read matching B's actual private baseline be CONFIRMED. |
| Metadata-only/empty 200, ambiguous 404, incorrect identity or unknown policy | INCONCLUSIVE, or SKIPPED if prerequisites prevent a probe; never a false confirmation. |
| Shared/public and unverified resources | No automatic private BOLA confirmation; no unsupported ownership inference. |
| Conditional verified denial | SAFE only if policy, identity, baseline, actual denial and full relevant body are checked; status alone is not sufficient. |
| Guard failure / unapproved operation | No request to target; record SKIPPED/blocked and reason. |

No crAPI deployment was started or scanned. Secure-mode behavior and ground
truth must be independently established, not invented from fixture results.
