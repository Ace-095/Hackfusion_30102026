# User-directed safety corrections to the supplied v3.2 document

The attached v3.2 Markdown is preserved unchanged in `docs/spec/`. Despite the
message describing an updated document, the attached copy still contains a
`base_url` in the section 23 example and does not contain numbered tests 20–21
or the four classification labels. The user's later explicit corrections take
precedence for implementation:

1. **Scope is the sole target authority.** Recipe `base_url` and embedded
   passwords are rejected. The current fixture runner derives its origin from
   its separate synthetic scope. A provisional organizer-scope data validator
   exists, but no live scope upload or execution is enabled.
2. **Every operation requires an explicit classification:** `READ_ONLY`,
   `AUTHENTICATION`, `STATE_CHANGING` or `DESTRUCTIVE`. Unknown classifications
   and unlisted operations fail closed. A `GET` classified state-changing or
   destructive is blocked before transport. DELETE is always blocked. Only
   the exact fixture login is allowed; all other state changes are blocked.
3. **DNS isolation:** an organizer-supplied IP should be preferred for a future
   live implementation. Otherwise only explicitly organizer-approved resolution
   mechanisms may be used; never query public resolvers. An experimental,
   unintegrated guarded HTTPX GET transport can connect directly to an
   organizer-supplied IP if called from Python; it makes no DNS query. It is not
   exposed through the API and is not a complete live guard or scanner. Resolver-based scanning
   and the remaining live safeguards are not implemented. Fixture mode makes
   no DNS queries and cannot make scanner network connections.

The two added automated checks are in
`tests/security/test_scope_classifications.py`: classification of dangerous or
unknown GETs before transport, and DNS/network isolation of the fixture run.
They do not replace the full section 15 acceptance suite.
