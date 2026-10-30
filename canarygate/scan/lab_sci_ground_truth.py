"""Report-time comparison of a finished lab run with the declared ground truth.

This module is deliberately *outside* the decision path: it is called when a
report is built, after the run has been sealed and stored. The scanner never
imports it, so corrupting or deleting the declared table cannot change a verdict
or a single byte of stored evidence.
"""
from canarygate.scan import lab_sci_scenarios as scenarios

SCI_CHECK = "SCI-01"
RESET_CHECK_IDS = ("RESET-01", "RESET-02", "RESET-03", "RESET-04")
SOURCE = "declared_targetlab_ground_truth"
STATEMENT = ("Ground truth is a declared table scored against the finished run. The scanner never "
             "requests /lab/ground-truth and never consults this table before deciding, so a "
             "wrong or missing expectation can only change this comparison, never the verdict.")


def _table():
    table = getattr(scenarios, "EXPECTED", None)
    return dict(table) if isinstance(table, dict) else {}


def _rows(pairs):
    rows = []
    for check_id, observed in pairs:
        expected = _table().get(check_id, "NOT_DECLARED")
        rows.append({"check_id": check_id, "expected": expected, "observed": observed,
                     "matched": expected == observed})
    matched = sum(row["matched"] for row in rows)
    return {"source": SOURCE, "evaluated_after_verdicts": True,
            "used_as_decision_input": False, "rows": rows,
            "total": len(rows), "matched": matched, "mismatched": len(rows) - matched,
            "statement": STATEMENT}


def evaluate_sci(run):
    """Score the finished interaction verdict against the declared outcome."""
    return _rows([(SCI_CHECK, run["verdict"])])


def evaluate_reset(proof):
    """Score each reset check's recorded status against the declared status."""
    return _rows([(check["id"], str(check["status"])) for check in proof["checks"]])
