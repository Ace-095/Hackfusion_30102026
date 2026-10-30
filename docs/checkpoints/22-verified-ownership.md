# Checkpoint 22: fixture verified ownership

## VS Code / judge demo

Open the repository root in VS Code and use the existing Python 3.11 virtual
environment. From a terminal, run:

```sh
python -m pytest -v tests/integration/test_verified_ownership.py
python tools/run_ci_tests.py
```

On Linux/macOS, `python` can be replaced with `.venv/bin/python`; on Windows
PowerShell use `.\.venv\Scripts\python.exe`. The first command demonstrates the
fixture registry, including denied owner reads, cross-list inclusion, incomplete
lists, shared/public resources, absent credentials and guard rejection. The
second runs the complete test suite. The test target is an HTTPX in-process mock;
no outside target or DNS is contacted.

For the existing **synthetic** API/report demonstration, follow
[VS Code demo](../VS_CODE_DEMO.md). Its BOLA check predates this checkpoint and
now requires the registry result; no new BOLA oracle or live functionality was
implemented here. In the default fixture, both ownership checks succeed. The
fixture's separate private disclosure marker is still required for its existing
BOLA finding, but is not necessary to establish ownership itself.

## What is verified and what is not

`collect_fixture_ownership` accepts only the fixture runner and its fixed
synthetic credentials. It uses the existing `OwnedResource` contract. It requires
two distinct accounts; bounded, valid JSON array lists without observed
pagination indicators, unsafe or duplicate IDs; an explicit owner field separate
from the ID; mutual peer-list exclusion; and successful, matching owner detail
reads for both resources. All four GETs pass through the fixture safety guard.
Only when all conditions succeed are both private entries marked verified.
Shared/public candidates are explicitly unverified and never treated as private.
A missing prerequisite, guard rejection or ambiguous response fails closed.

The fixture's array contract is assumed complete when no pagination indicator is
observed; this is not a universal proof that arbitrary live lists are complete.
Raw responses and IDs exist transiently in memory only; the registry does not
write them to storage and omits baseline responses from repr. Existing fixture
observation reporting remains minimized. Production/live ownership integration,
real identity readiness, generic pagination semantics and live-data redaction
are still outstanding. The experimental live transport remains disabled, and
written organizer authorization is required before any future external testing.
