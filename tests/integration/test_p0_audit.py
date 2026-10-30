"""The P0 acceptance audit is itself a tested artifact.

It must resolve every implementation and test reference against the real
repository, classify every test file's evidence, and keep the gap list honest.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import p0_audit  # noqa: E402


def audit():
    report = p0_audit.run_audit()
    assert report["failures"] == [], "\n".join(report["failures"])
    return report


def test_audit_is_clean_and_covers_every_test_file():
    report = audit()
    assert report["requirements"] >= 30
    assert report["requirements"] == len(p0_audit.REQUIREMENTS)
    assert report["test_files"] == len(p0_audit.TEST_EVIDENCE)
    assert report["collected_tests"] >= 690
    assert report["real_networking_tests"] == []
    # Missing work is declared, not hidden.
    missing = {row["id"] for row in report["rows"] if row["status"] == "missing"}
    assert missing == {"D11", "D12"}
    assert all(row["gap"] for row in report["rows"]
               if row["status"] in {"partial", "missing", "unreachable"})


def test_every_requirement_row_is_well_formed():
    report = audit()
    ids = [row["id"] for row in report["rows"]]
    assert len(ids) == len(set(ids))
    for row in report["rows"]:
        assert row["frozen"].startswith("§"), row["id"]
        assert row["statement"], row["id"]
        assert row["evidence"] in p0_audit.EVIDENCE_LABELS, row["id"]
        if row["status"] in {"implemented", "partial"}:
            assert row["implementation"] and row["tests"], row["id"]
        for route in row["api_routes"]:
            assert route.startswith(("GET ", "POST ")), row["id"]
    # Every frozen section that the report claims is represented in the audit.
    for requirement in ("R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9"):
        assert requirement in ids


def test_windows_style_test_paths_are_normalised():
    # CI runs on Windows; the audit must classify a backslash path identically.
    p0_audit.check_test_file("tests\\integration\\test_auth_checks.py::test_example")
    assert all("\\" not in key for key in p0_audit.TEST_EVIDENCE)
