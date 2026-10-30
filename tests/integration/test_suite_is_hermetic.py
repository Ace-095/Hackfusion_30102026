"""The suite must give the same verdict whatever the developer's shell says.

A real failure this catches
---------------------------
`export CANARYGATE_TARGETLAB_CA=...` is step 2 of running the product. With it
exported, three "no CA configured" tests used to fail, because they asserted the
behaviour of an unset variable while inheriting an exported one. The suite said
"3 failed" for a build that CI called green — and both were right, about different
environments.

`tests/conftest.py` clears the CanaryGate variables for every test. These tests
prove the isolation exists and that a test can still opt back in.
"""
from __future__ import annotations

import os

import pytest


def test_no_canarygate_variable_leaks_into_a_test():
    leaked = [name for name in os.environ
              if name.startswith(("CANARYGATE_", "CANARY_"))]
    assert leaked == [], f"the suite inherited exported variables: {leaked}"


def test_a_test_can_still_configure_a_variable(monkeypatch):
    """Isolation must not prevent a test from setting what it needs."""
    monkeypatch.setenv("CANARYGATE_TARGETLAB_CA", "tests/fixtures/tls/targetlab-cert.pem")
    assert os.environ["CANARYGATE_TARGETLAB_CA"].endswith("targetlab-cert.pem")


def test_the_missing_ca_behaviour_is_independent_of_the_shell():
    """The exact assertion that used to depend on the developer's environment."""
    from fastapi.testclient import TestClient

    from canarygate.api.app import create_app

    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as holder:
        with TestClient(create_app(Path(holder) / "no-ca.sqlite3")) as api:
            response = api.post("/api/lab-scans", json={"port": 65500})
        assert response.status_code == 400
        assert "CANARYGATE_TARGETLAB_CA" in response.json()["detail"]


@pytest.mark.parametrize("name", ["CANARYGATE_TARGETLAB_CA", "CANARYGATE_DB_PATH",
                                  "CANARYGATE_LIVE_ENABLED"])
def test_each_known_switch_is_isolated(name):
    assert name not in os.environ
