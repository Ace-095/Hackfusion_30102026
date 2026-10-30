# Checkpoint 19: bounded resource-list harvest

This provisional in-memory helper observes two scoped account profiles and then
one exact read-only list operation as each account. It is **not an ownership
registry or BOLA test** and is not connected to the scanner/API.

## VS Code judge demo

From the repository root with the Python environment activated:

```sh
python -m pytest -v tests/security/test_pinned_reader.py -k discovery
python -m pytest -q
```

Use `.venv/bin/python` on Linux/macOS or `.\.venv\Scripts\python.exe` on
Windows if needed. Tests use synthetic accounts and mocked sockets; no external
target or resolver is contacted. They cover distinct account controls, bounded
lists, exact scope, safe IDs and owner fields, overlapping lists, unsupported
ownership models and exhausted budget. Uncertain cases do not produce a harvest.

`HARVESTED` means two disjoint lists were observed, not that ownership or a
vulnerability has been verified. IDs remain in memory and are omitted from
`repr`, but this object is **not approved for storage**. Owner detail baselines,
private-disclosure comparison, policy provenance, reviewed evidence redaction,
scanner integration and live safety review remain outstanding. Direct invocation
of the experimental transport can contact a target and requires written organizer
authorization. The [main demo](../VS_CODE_DEMO.md) is synthetic fixture-only.
