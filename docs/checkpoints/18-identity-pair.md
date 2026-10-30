# Checkpoint 18: two-account identity observations

> Update: checkpoint 21 disables production network execution pending safety review. Any earlier statement about direct network execution describes historical behavior.

This adds an in-memory control that requires two distinct scoped account names
and bearer credentials, then checks an explicitly scoped profile GET separately
as each account. `MATCHED_PAIR` is **not** evidence of resource ownership,
privacy, role policy or a BOLA finding. It does not enable live scanning.

## VS Code judge demo

From the repository root in an activated Python environment:

```sh
python -m pytest -v tests/security/test_pinned_reader.py -k identity_pair
python -m pytest -q
```

If needed, use `.venv/bin/python` on Linux/macOS or
`.\.venv\Scripts\python.exe` on Windows. Tests use synthetic data and mocked
sockets; no external target or DNS resolver is contacted. They cover distinct
accounts and token requirements, two profile matches, ambiguous responses,
identity mismatch and run halt. Results do not return tokens or response bodies.

No resource discovery, ownership verification or live report is implemented by
this helper. The experimental transport is not wired to the scanner/API; direct
use can contact a target and requires written authorization and independent
review. The [main VS Code guide](../VS_CODE_DEMO.md) demonstrates the explicitly
synthetic fixture pipeline.
