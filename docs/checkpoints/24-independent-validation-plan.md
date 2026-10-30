# Checkpoint 24: independent validation planning

Historical note: checkpoint 25 later added limited nested fixture selectors and
bounded token pagination, but did not resolve crAPI compatibility or enable labs.

This checkpoint prepares VAmPI and crAPI profiles and scenarios without running
or contacting either lab application. Written organizer approval for each exact
instance is required even if self-hosted. Production network execution remains
disabled. The profiles are inert planning documents, **not** approved scope or
runtime recipes. See the [plan and gate](../validation/README.md),
[VAmPI](../validation/VAmPI.md), and [crAPI](../validation/crAPI.md).

## VS Code judge demo

From the repository root in the Python 3.11 environment:

```sh
python -m pytest -v tests/integration/test_independent_validation_profiles.py
python tools/run_ci_tests.py
```

On Linux/macOS use `.venv/bin/python`, or on Windows PowerShell use
`.\.venv\Scripts\python.exe`. Tests read the planning files, exercise the
existing OpenAPI parser on reduced synthetic specs, prove that destructive
`GET /createdb` is stopped by the in-process fixture guard, and show that
unsupported global/nested list shapes do not verify ownership. Fixture network
and DNS calls are forbidden in the test. These are **not** executions of VAmPI
or crAPI, or proof of generic live compatibility.

Static GitHub source/spec review found the VAmPI global book list cannot satisfy
the current peer-list-exclusion ownership rule, and the crAPI candidate uses
nested data unsupported by the fixture registry/oracle. Both are explicit
blockers, not shortcuts around verified ownership. Source review locally parsed
pinned upstream OpenAPI documents; that is parser-only inspection, separate
from target validation. No lab container or service was launched.
