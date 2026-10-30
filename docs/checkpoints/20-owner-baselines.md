# Checkpoint 20: conservative owner-baseline observations

The experimental helper observes two account profiles, two disjoint scoped lists
and two exact scoped owner-detail reads. It requires matching account/ID fields
and distinct unmasked, non-identifier private-field values. It **does not verify
ownership, confirm BOLA, or enable the scanner/API**.

## VS Code judge demo

In an activated Python environment from the repository root:

```sh
python -m pytest -v tests/security/test_pinned_reader.py -k "owner_baselines or owner_baseline or owner_observation"
python -m pytest -q
```

Use `.venv/bin/python` on Linux/macOS or `.\.venv\Scripts\python.exe` on
Windows if needed. The tests use synthetic data and mock sockets, not an external
target or DNS. They cover exact scope, account/profile prerequisites, owner
baselines, masked values, public IDs, invalid templates and missing scope.

A `BASELINES_OBSERVED` result **always has `ownership_verified: false`**. It
contains raw identifiers and private values in memory, hidden from `repr` but not
safe to serialize or persist. A reviewed ownership model, expected permission,
separate cross-user private-disclosure evidence, redaction, reports and full
scanner integration remain outstanding. Direct invocation can contact a target;
written organizer authorization and independent safety review are required.
The existing [fixture demo](../VS_CODE_DEMO.md) is synthetic only.
