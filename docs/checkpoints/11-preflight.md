# Checkpoint 11: offline policy preflight

This checkpoint demonstrates conservative decisions against the provisional
organizer scope. **It is not a live guard and cannot authorize a connection.**
The fixture runner is unchanged and no live scan is enabled.

## VS Code judge demo

From the repository root in an activated Python environment run:

```sh
python -m pytest -v tests/security/test_authorized_policy.py
python -m pytest -q
```

If needed use `.venv/bin/python` on Linux/macOS or
`.\.venv\Scripts\python.exe` on Windows. The synthetic tests demonstrate exact
actor, method and full literal URL matching, rejection of query/encoding/path
changes, rejection of destructive operations even when GET, blocking DELETE,
PUT, PATCH and creation, and a shared, thread-safe per-instance decision counter.
They also check that neither DNS nor a socket is used and an unvalidated Pydantic
copy cannot bypass scope validation.

The preflight returns a classification for exact read-only operations or the
single exact login operation; it does not validate credentials or request bodies.
Its counter counts **decisions**, not network requests. Passing a preflight check
must never be used as permission to connect. Central enforcement immediately
before every actual connection, sequential execution, approved DNS resolution,
connection pinning, authentication constraints and response limits still need
implementation and end-to-end review. State-changing requests remain disabled.

The existing fixture demonstration is in [the main guide](../VS_CODE_DEMO.md);
its synthetic findings are not live results.
