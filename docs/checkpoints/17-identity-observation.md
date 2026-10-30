# Checkpoint 17: explicit identity observation

> Update: checkpoint 21 disables production network execution pending safety review. Any earlier statement about direct network execution describes historical behavior.

A provisional helper observes one top-level account field from an explicitly
scoped, classified profile GET through the guarded HTTPX runner. **A matching
field alone is not verified identity or ownership and cannot confirm BOLA.**
The live scanner and API integration remain disabled.

## VS Code judge demo

In an activated Python environment from the repository root:

```sh
python -m pytest -v tests/security/test_pinned_reader.py -k "identity_check or observed_identity or profile_observation or identity_mismatch"
python -m pytest -q
```

Use `.venv/bin/python` on Linux/macOS or `.\.venv\Scripts\python.exe` on
Windows if needed. Tests use synthetic identities and mocked sockets; no external
target or resolver is contacted. They demonstrate that a matching profile is
reported only as `MATCHED`, missing or malformed profiles are inconclusive,
unscoped paths are skipped, and a clear mismatch halts all runners sharing the
run guard. A guarded login followed by the profile check shares the request budget.
No raw profile body or token is returned by the observation object.

A real two-account readiness gate, independent cross-account controls, verified
resource ownership and live-data evidence are still needed. The component can
send real requests if directly invoked, so it must not be used without written
organizer authorization and independent safety review. The existing
[fixture demo](../VS_CODE_DEMO.md) remains synthetic.
