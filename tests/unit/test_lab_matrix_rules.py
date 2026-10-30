"""Rules the matrix aggregation must obey, tested without any scan.

The inputs below are minimal *stored-run projections*: dictionaries shaped like a
persisted read-BOLA run so the aggregator can be exercised on cases a real lab
cannot easily produce (all five verdicts, a missing cell, a duplicate, a stale
instance). They are fixtures for the rules — not scan results, never stored, and
never presented as evidence anywhere in the product.
"""
import copy
import hashlib

import pytest

from canarygate.scan.lab_matrix import build_lab_matrix
from canarygate.scan.lab_matrix_models import LabMatrixCell

ASSETS = {"mallapa": "MKT-2026-041", "sakshi": "BRD-2026-018", "harsha": "ADS-2026-027"}
def _sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def _check(check_id, direction, actor, owner, verdict, *, status=200, **flags):
    checklist = {"private_disclosure": False, "verified_denial": False,
                 "ownership_verified": True, "owner_baseline": direction == "owner_baseline"}
    checklist.update(flags)
    return {"id": check_id, "direction": direction, "actor": actor, "owner": owner,
            "verdict": verdict, "status": status,
            "endpoint": ("GET /records/{id}" if direction != "cross_account_secure"
                         else "GET /records/{id}/secure"),
            "evidence_sha256": _sha(f"{check_id}{actor}{owner}{verdict}"),
            "reason": f"stored reason for {check_id}", "checklist": checklist,
            "evidence": {"bounded": True}}


def _stored_run(run_id, actor, owner, *, created_at, port=8765, cross="CONFIRMED",
                secure="SAFE", baseline="SAFE"):
    """A stored-run projection for one ordered pair (unit fixture, not a scan)."""
    checks = [
        _check("LAB-BOLA-01", "owner_baseline", actor, actor, baseline),
        _check("LAB-BOLA-02", "owner_baseline", owner, owner, baseline),
        _check("LAB-BOLA-03", "cross_account", actor, owner, cross,
               private_disclosure=cross == "CONFIRMED",
               **({"status": 403, "verified_denial": True} if cross == "SAFE" else {})),
        _check("LAB-BOLA-05", "cross_account_secure", actor, owner, secure,
               status=403, verified_denial=secure == "SAFE"),
    ]
    return {"id": run_id, "created_at": created_at, "mode": "targetlab_bola",
            "scope": {"port": port}, "checks": checks,
            "constraints": {"requests_sent": 18}}


RUN_A = "11111111-1111-4111-8111-111111111111"
RUN_B = "22222222-2222-4222-8222-222222222222"


def test_no_stored_runs_means_nine_untested_cells():
    matrix = build_lab_matrix([])
    assert matrix["summary"]["tested"] == 0 and matrix["summary"]["untested"] == 9
    for cell in matrix["cells"]:
        assert cell["state"] == "untested"
        assert cell["verdict"] is None and cell["evidence"] is None and cell["secure"] is None
        assert cell["actual_access"] == "no_evidence"
        assert cell["sources"] == 0


def test_a_tested_cell_carries_the_stored_run_and_check():
    matrix = build_lab_matrix([_stored_run(RUN_A, "mallapa", "sakshi",
                                           created_at="2026-10-30T10:00:00Z")])
    cell = next(item for item in matrix["cells"]
                if item["requester"] == "mallapa" and item["asset_id"] == "BRD-2026-018")
    assert cell["state"] == "tested" and cell["verdict"] == "CONFIRMED"
    assert cell["evidence"]["run_id"] == RUN_A and cell["evidence"]["check_id"] == "LAB-BOLA-03"
    assert cell["secure"]["status"] == 403 and cell["secure"]["verdict"] == "SAFE"
    assert cell["actual_access"] == "private_record_returned"
    assert cell["sources"] == 1


def test_the_five_verdicts_stay_distinct_and_are_never_coerced():
    for verdict in ("CONFIRMED", "SUSPECTED", "SAFE", "INCONCLUSIVE", "SKIPPED"):
        matrix = build_lab_matrix([_stored_run(RUN_A, "mallapa", "sakshi",
                                               created_at="2026-10-30T10:00:00Z",
                                               cross=verdict, secure=verdict)])
        cell = next(item for item in matrix["cells"]
                    if item["requester"] == "mallapa" and item["asset_id"] == "BRD-2026-018")
        assert cell["verdict"] == verdict
        if verdict not in {"SAFE", "CONFIRMED"}:
            assert cell["verdict"] != "SAFE", "a non-deciding verdict must never become SAFE"


def test_an_inconclusive_check_is_not_safe_and_shows_unverified_access():
    matrix = build_lab_matrix([_stored_run(RUN_A, "mallapa", "sakshi",
                                           created_at="2026-10-30T10:00:00Z",
                                           cross="INCONCLUSIVE")])
    cell = next(item for item in matrix["cells"]
                if item["requester"] == "mallapa" and item["asset_id"] == "BRD-2026-018")
    assert cell["verdict"] == "INCONCLUSIVE"
    assert cell["actual_access"] == "unverified_response"


def test_a_missing_cell_stays_untested_while_others_are_tested():
    matrix = build_lab_matrix([_stored_run(RUN_A, "mallapa", "sakshi",
                                           created_at="2026-10-30T10:00:00Z")])
    tested = [cell for cell in matrix["cells"] if cell["state"] == "tested"]
    untested = [cell for cell in matrix["cells"] if cell["state"] == "untested"]
    # This projection records one owner baseline per account plus one cross direction,
    # so three cells are tested. Everything else stays untested and is never SAFE.
    assert len(tested) == 3 and len(untested) == 6
    assert {(cell["requester"], cell["asset_id"]) for cell in untested} == {
        ("mallapa", "ADS-2026-027"), ("sakshi", "MKT-2026-041"),
        ("sakshi", "ADS-2026-027"), ("harsha", "MKT-2026-041"),
        ("harsha", "BRD-2026-018"), ("harsha", "ADS-2026-027")}
    assert all(cell["verdict"] is None for cell in untested)


def test_duplicate_evidence_uses_the_newest_run_and_lists_the_old_one():
    older = _stored_run(RUN_A, "mallapa", "sakshi", created_at="2026-10-30T10:00:00Z",
                        cross="SAFE")
    newer = _stored_run(RUN_B, "mallapa", "sakshi", created_at="2026-10-30T11:00:00Z",
                        cross="CONFIRMED")
    matrix = build_lab_matrix([older, newer])
    cell = next(item for item in matrix["cells"]
                if item["requester"] == "mallapa" and item["asset_id"] == "BRD-2026-018")
    assert cell["evidence"]["run_id"] == RUN_B and cell["verdict"] == "CONFIRMED"
    assert cell["sources"] == 2 and cell["superseded_runs"] == [RUN_A]
    assert matrix["summary"]["duplicated_cells"] >= 1


def test_evidence_from_an_older_lab_instance_is_flagged_not_hidden():
    old_instance = _stored_run(RUN_A, "mallapa", "sakshi",
                               created_at="2026-10-30T10:00:00Z", port=8765)
    new_instance = _stored_run(RUN_B, "sakshi", "harsha",
                               created_at="2026-10-30T11:00:00Z", port=9001)
    matrix = build_lab_matrix([old_instance, new_instance])
    old_cell = next(item for item in matrix["cells"]
                    if item["requester"] == "mallapa" and item["asset_id"] == "BRD-2026-018")
    new_cell = next(item for item in matrix["cells"]
                    if item["requester"] == "sakshi" and item["asset_id"] == "ADS-2026-027")
    assert old_cell["stale"] is True and old_cell["evidence"]["port"] == 8765
    assert new_cell["stale"] is False and new_cell["evidence"]["port"] == 9001
    assert matrix["summary"]["ports"] == [8765, 9001]
    assert matrix["summary"]["stale_cells"] == len(
        [cell for cell in matrix["cells"] if cell["stale"]]) > 0


def test_an_owner_cell_never_borrows_a_secure_counterpart():
    matrix = build_lab_matrix([_stored_run(RUN_A, "mallapa", "sakshi",
                                           created_at="2026-10-30T10:00:00Z")])
    diagonal = next(item for item in matrix["cells"]
                    if item["requester"] == "mallapa" and item["asset_id"] == "MKT-2026-041")
    assert diagonal["state"] == "tested" and diagonal["secure"] is None


def test_an_untested_cell_cannot_carry_a_verdict():
    base = {"requester": "mallapa", "asset_id": "MKT-2026-041", "owner": "mallapa",
            "kind": "legitimate_owner_request", "state": "untested",
            "expected_access": "owner-only", "actual_access": "no_evidence",
            "stale": False, "sources": 0}
    LabMatrixCell(**base)  # the honest shape is accepted
    for bad in ({"verdict": "SAFE"}, {"reason": "looks fine"},
                {"sources": 1}, {"actual_access": "denied"}):
        with pytest.raises(ValueError):
            LabMatrixCell(**{**base, **bad})


def test_a_tested_cell_must_match_its_evidence_verdict():
    matrix = build_lab_matrix([_stored_run(RUN_A, "mallapa", "sakshi",
                                           created_at="2026-10-30T10:00:00Z")])
    cell = next(item for item in matrix["cells"]
                if item["requester"] == "mallapa" and item["asset_id"] == "BRD-2026-018")
    payload = copy.deepcopy(dict(cell))
    payload["verdict"] = "SAFE"
    with pytest.raises(ValueError):
        LabMatrixCell(**payload)
