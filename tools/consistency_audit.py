"""Re-check every stored run in a database against its own report projections.

This is the offline half of the checkpoint 38 demonstration: it does not scan
anything. For each stored TargetLab run it recomputes the payload hash, rebuilds
the sections and nine-section reports from the stored evidence, and compares them
with each other and with the authorization matrix.

Exit status is 0 only when every stored run is intact and self-consistent.
Exit status is 2 when there is nothing to audit at all (no such file, or a file
CanaryGate never wrote to), with a sentence saying which of the two it is.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import demo_kit  # noqa: E402


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True, help="the SQLite database to audit")
    parser.add_argument("--json", default=None, help="write the report here")
    args = parser.parse_args(argv)

    print(f"CanaryGate stored-evidence audit: {args.database}")
    # Two ways a judge reaches this tool with nothing to audit. Say so and stop,
    # rather than letting a sqlite3 traceback stand in for the explanation.
    if not Path(args.database).exists():
        print("no such database file — nothing to audit.")
        print("  run .venv/bin/python tools/demo.py --keep, or point --database at a file "
              "CanaryGate created")
        return 2
    try:
        report = demo_kit.audit_database(args.database)
    except sqlite3.OperationalError as exc:
        print(f"this database has no CanaryGate tables ({exc}).")
        print("  nothing was ever scanned into it, so there is nothing to audit — this is "
              "not a statement that any run is intact.")
        print("  run .venv/bin/python tools/demo.py --keep to create an auditable database")
        return 2
    print(f"runs checked: {report['runs_checked']}  "
          f"projections rebuilt: {report['surfaces']}  "
          f"invariants: {report['invariants_checked']}")
    for run_id, verdict in sorted(report["summary"].items()):
        print(f"  {run_id}  {verdict}")
    if report.get("asset_matrix"):
        summary = report["asset_matrix"]["summary"]
        print(f"asset matrix rebuilt offline: {summary['tested']} tested, "
              f"{summary['untested']} untested, {summary['confirmed']} CONFIRMED, "
              f"{summary['safe']} SAFE")
    print()
    if report["problems"]:
        print(f"PROBLEMS ({len(report['problems'])}):")
        for problem in report["problems"]:
            print(f"  - {problem}")
        status = 1
    else:
        print("ALL STORED RUNS INTACT AND CONSISTENT")
        status = 0
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
        print(f"report written to {args.json}")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
