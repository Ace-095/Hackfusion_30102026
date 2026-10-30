# Contract review — DRAFT, not frozen

The models in `canarygate/models/` transcribe the proposed interfaces in the
provided plan, with basic validation of explicitly listed values. They are not an
implementation of the security pipeline or proof of conformity to the full v3.2
specification. The attached document is now in `docs/spec/`; see also the
user-directed corrections in `docs/SAFETY_ADDENDUM.md`.

Before freezing, both developers must review the original section 23 and sign
off on field names, types, defaults and serialization behavior. In particular:

- The plan lists five setup outcomes but does not define where an overall outcome
  belongs in `SetupStatus`, nor schemas for its dictionaries or three readiness
  gates. `SetupOutcome` is provided without inventing an extra model field.
- `OwnedResource.ownership_verified` is only a claim in this draft, not evidence
  that ownership was verified. Define the provenance and evidence linking needed
  to demonstrate ownership separately from disclosure.
- `Result` and `ScanRun` do not specify associations to tests, endpoints or
  evidence; agree on traceability without guessing at the frozen spec.
- The evidence `redacted` flag and `sha256` string are not verified or computed.
  The fixture pipeline separately hashes redacted summaries; future general-purpose
  storage code must perform redaction and hashing, not trust these model fields.
- `Identity.token` is excluded from normal dumps and representations as a
  precaution; all other data still requires explicit redaction. Check whether
  this serialization choice is compatible with the full specification.
- Recipe, security, claims, request and response dictionaries remain intentionally
  underspecified; validate against the actual spec before use.

Approval record: **pending review and agreement by the backend owner and frontend collaborator**.
No one should independently change shared interfaces after the team freezes them.
