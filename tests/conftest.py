"""Suite-wide isolation from the developer's shell.

Why this exists
---------------
Three integration tests assert what happens when ``CANARYGATE_TARGETLAB_CA`` is
*not* configured. They passed in CI and failed on a developer machine that had
exported the variable — which is exactly what docs/RUN_LOCALLY.md and the demo
instructions tell you to do before starting the interface:

    export CANARYGATE_TARGETLAB_CA=tests/fixtures/tls/targetlab-cert.pem

Those three tests were therefore not testing the code; they were testing the
shell they were launched from. A suite that changes its verdict depending on
ambient environment variables cannot be trusted to say a build is validated.

The fixture below removes every CanaryGate variable a developer might have
exported, for every test. Tests that need a variable set it themselves with
``monkeypatch.setenv`` — which runs after this fixture, so their intent is
preserved and the isolation is invisible to them.
"""
from __future__ import annotations

import os

import pytest

#: Variables the application reads from the process environment. A developer
#: running the demo exports several of these; the suite must ignore them.
_ISOLATED_PREFIXES = ("CANARYGATE_", "CANARY_")


@pytest.fixture(autouse=True)
def isolated_canarygate_environment(monkeypatch):
    """Run every test as if no CanaryGate variable had ever been exported."""
    for name in list(os.environ):
        if name.startswith(_ISOLATED_PREFIXES):
            monkeypatch.delenv(name, raising=False)
    yield
