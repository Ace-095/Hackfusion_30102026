"""One-command judge demonstration, repeated from a clean start.

Runs four stages against a fresh TargetLab and a fresh database, and refuses to
print a result if any surface disagrees with any other:

1. read-BOLA on the vulnerable route            -> CONFIRMED (both directions)
2. the same cross-account read on the secure route -> SAFE (checked denial)
3. control interaction (deny, rejected login, leak) -> CONFIRMED, interaction_induced
   plus the separate reset proof                 -> proven (403, 401, 200, 403)
4. evidence and reporting: stored run, sections, nine sections, HTML and matrix
   all describe the same evidence

Exit status is 0 only when every consistency check passes.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import demo_kit  # noqa: E402


def _print_stage(index, title, lines):
    print(f"\nSTAGE {index} — {title}")
    for line in lines:
        print(f"  {line}")


def _stage_1_lines(stage):
    lines = []
    for check_id in ("LAB-BOLA-01", "LAB-BOLA-02", "LAB-BOLA-03", "LAB-BOLA-04"):
        lines.append(f"{check_id}  mallapa/sakshi  GET /records/{{id}}  "
                     f"status {stage['statuses'][check_id]}  {stage['checks'][check_id]}")
    lines.append("owner baselines verified against each account's own record; "
                 "the leaked marker matched the owner's baseline")
    return lines


def _stage_2_lines(stage):
    return [f"{check_id}  GET /records/{{id}}/secure  status {stage['statuses'][check_id]}  "
            f"{stage['checks'][check_id]} (checked denial body)"
            for check_id in ("LAB-BOLA-05", "LAB-BOLA-06")]


def _stage_3_lines(stage, reset):
    run = stage["run"]
    return [
        f"SCI-AUTHZ  mallapa -> sakshi's guarded record   status {stage['statuses']['SCI-AUTHZ']}  "
        f"{stage['baselines']['SCI-AUTHZ']}",
        f"SCI-AUTHN  mallapa posts a wrong password    status {stage['statuses']['SCI-AUTHN']}  "
        f"{stage['baselines']['SCI-AUTHN']}",
        f"combined   the identical guarded read      status {stage['combined_status']}  "
        f"{run['combined']['impact']}",
        f"verdict    {run['verdict']} ({run['attribution']})  remediation "
        f"{run['remediation_key']}",
        f"reset      {' -> '.join(str(value) for value in reset['statuses'])}  "
        f"{reset['verdict']} (separate two-run scenario)",
    ]


def _stage_4_lines(bundle):
    stages = {stage["id"]: stage for stage in bundle["stages"]}
    bola = stages["bola"]
    sci = stages["sci"]
    asset = bundle["summary"].get("asset_matrix") or {}
    return [
        f"stage 1 stored run, sections, nine sections, HTML and matrix agree "
        f"({bola['requests_sent']}/{bola['request_budget']} requests)",
        f"stage 3 stored run, sections, nine sections, HTML and matrix agree "
        f"({sci['requests_sent']}/{sci['request_budget']} requests)",
        "matrix: GET /records/{id} red for another account's resource; "
        "GET /records/{id}/secure green; GET /records/{id}/guarded red",
        f"asset matrix from the stored runs: {asset.get('tested')} cells tested "
        f"({asset.get('confirmed')} CONFIRMED, {asset.get('safe')} SAFE), "
        f"{asset.get('untested')} untested — untested is not SAFE",
        "ground truth is scored when the report is built, never before the verdict",
        "every surface states: controlled validation of the loopback lab, not live validation",
    ]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", default=None,
                        help="database file to use (default: a fresh temporary file)")
    parser.add_argument("--json", default=None, help="write the machine-readable summary here")
    parser.add_argument("--keep", action="store_true",
                        help="keep the database and print its path for inspection")
    args = parser.parse_args(argv)

    from fastapi.testclient import TestClient

    import targetlab.testing as lab_server
    from canarygate.api.app import create_app

    if args.database:
        holder = None
        database = Path(args.database)
        if database.exists():
            parser.error("the demonstration needs a database that does not exist yet")
    elif args.keep:
        # A TemporaryDirectory deletes itself when the interpreter exits, so --keep
        # used to print a path that was already gone. mkdtemp stays where it is.
        holder = None
        database = Path(tempfile.mkdtemp(prefix="canarygate-demo-")) / "demo.sqlite3"
    else:
        holder = tempfile.TemporaryDirectory(prefix="canarygate-demo-")
        database = Path(holder.name) / "demo.sqlite3"
    os.environ["CANARYGATE_TARGETLAB_CA"] = str(lab_server.TARGETLAB_CERT)

    print("CanaryGate — demonstration (checkpoint 38)")
    print(f"database: {database}")
    with lab_server.LabTlsServer() as lab:
        print(f"TargetLab: https://127.0.0.1:{lab.port} (pinned test CA, loopback only)")
        with TestClient(create_app(database)) as client:
            bundle = demo_kit.run_demo(client, port=lab.port, database=database)
            other_problems = (demo_kit.check_evidence_integrity(bundle)
                              + demo_kit.check_honesty_and_redaction(bundle)
                              + demo_kit.safety_sweep(ROOT))
    stages = {stage["id"]: stage for stage in bundle["stages"]}

    _print_stage(1, "read-BOLA on the vulnerable route — CONFIRMED", _stage_1_lines(stages["bola"]))
    _print_stage(2, "the secure route — SAFE", _stage_2_lines(stages["bola_secure"]))
    _print_stage(3, "security control interaction — CONFIRMED (interaction_induced)",
                 _stage_3_lines(stages["sci"], stages["reset"]))
    _print_stage(4, "evidence and reporting", _stage_4_lines(bundle))

    problems = [str(item) for item in bundle["problems"]] + [str(item) for item in other_problems]
    summary = {
        "ok": not problems,
        "stages": bundle["summary"]["stages"],
        "surfaces_checked": bundle["surfaces_checked"],
        "invariants_checked": bundle["invariants_checked"],
        "problems": problems,
    }
    print()
    if problems:
        print(f"CONSISTENCY FAILURES ({len(problems)}):")
        for problem in problems:
            print(f"  - {problem}")
        print("\nDEMONSTRATION FAILED")
        status = 1
    else:
        print(f"ALL CONSISTENCY CHECKS PASSED "
              f"({summary['invariants_checked']} invariants over "
              f"{summary['surfaces_checked']} surfaces)")
        status = 0
    if args.json:
        Path(args.json).write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
        print(f"summary written to {args.json}")
    if args.keep:
        print(f"database kept at {database}")
        print(f"  audit it with: python tools/consistency_audit.py --database {database}")
    elif holder is not None:
        holder.cleanup()
    return status


if __name__ == "__main__":
    raise SystemExit(main())
