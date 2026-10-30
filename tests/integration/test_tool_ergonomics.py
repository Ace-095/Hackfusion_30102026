"""The two command-line tools a judge runs by hand.

These are usability cases, not security ones, and both were found by following the
documented sequence literally on a clean checkout:

* ``tools/demo.py --keep`` printed the path of a database that was already gone,
  because the file lived inside a ``TemporaryDirectory`` that deletes itself when
  the interpreter exits;
* ``tools/consistency_audit.py --database <new-or-empty file>`` died with a raw
  ``sqlite3.OperationalError`` traceback instead of saying what was wrong.

Both now either produce a path that exists or explain the problem and exit 2.
"""
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import consistency_audit  # noqa: E402  (the tool, imported as a module)


def test_the_audit_explains_a_missing_database(tmp_path, capsys):
    missing = tmp_path / "never-created.sqlite3"
    status = consistency_audit.main(["--database", str(missing)])
    out = capsys.readouterr().out
    assert status == 2
    assert "no such database file" in out
    assert "Traceback" not in out
    # A tool must not create the file it was asked to inspect.
    assert not missing.exists()


def test_the_audit_explains_a_database_without_tables(tmp_path, capsys):
    empty = tmp_path / "empty.sqlite3"
    sqlite3.connect(empty).close()
    status = consistency_audit.main(["--database", str(empty)])
    out = capsys.readouterr().out
    assert status == 2
    assert "no CanaryGate tables" in out
    assert "Traceback" not in out


def test_an_empty_database_is_not_reported_as_intact(tmp_path, capsys):
    """No stored runs must never be announced as "everything checks out".

    The real clean-store path (three stored runs, exit 0) is covered by
    tests/integration/test_demo_consistency.py::test_the_consistency_audit_reports_a_clean_store.
    """
    from canarygate.ui.app import create_ui_app

    database = tmp_path / "ui.sqlite3"
    create_ui_app(database)          # a real CanaryGate database, no scans yet
    status = consistency_audit.main(["--database", str(database)])
    out = capsys.readouterr().out
    assert status == 2
    assert "nothing to audit" in out
    assert "ALL STORED RUNS INTACT" not in out
    assert "Traceback" not in out


def test_the_browser_smoke_skips_instead_of_crashing_on_a_bad_jsdom_path(tmp_path):
    """A wrong --jsdom path is a missing prerequisite, not a traceback."""
    import browser_smoke

    assert browser_smoke.node_available(str(tmp_path / "missing")) is None
    empty = tmp_path / "no-node-modules"
    empty.mkdir()
    assert browser_smoke.node_available(str(empty)) is None
