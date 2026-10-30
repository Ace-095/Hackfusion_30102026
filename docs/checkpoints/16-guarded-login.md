# Checkpoint 16: experimental guarded login

> Update: checkpoint 21 disables production network execution pending safety review. Any earlier statement about direct network execution describes historical behavior.

An exact scope-classified JSON login now runs through the same guarded HTTPX
transport as reads, with a shared run budget and no retry. This is not a live
scanner: no API route invokes it, identity is not verified, and discovery,
complete readiness and live-data evidence handling remain outstanding. Direct
use can send HTTPS POST login requests; written authorization and independent
safety review are mandatory before using it against a real target.

## VS Code judge demo — tests only

Activate the project environment and run, from the repository root:

```sh
python -m pytest -v tests/security/test_pinned_reader.py -k "login or password_echo"
python -m pytest -q
```

Alternatively use `.venv/bin/python` (Linux/macOS) or
`.\.venv\Scripts\python.exe` (Windows). Tests use synthetic passwords,
mock sockets and an in-process TLS socketpair; no external target or DNS is
contacted. They demonstrate exact scope-classified login, environment-only
password references, rejection of unapproved accounts/paths and supplied bodies,
one attempt per account in a shared run, safe handling of malformed token
responses and redirects, and exclusion of passwords/tokens from returned results.

The provisional internal config permits only `CANARY_`-prefixed password
variable names, explicit JSON field names and a top-level token field. It does
not store credential values or accept a target URL. A response indicating
`token_obtained` is **not** proof of the account's identity or authorization;
`identity_verified` is always false here. It does not implement cookies, API-key
login, full recipe integration or the ownership-verification gates. See the
[main VS Code guide](../VS_CODE_DEMO.md) for the explicitly synthetic fixture demo.
