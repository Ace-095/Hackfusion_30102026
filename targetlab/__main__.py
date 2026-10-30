"""Start TargetLab on loopback. Refuses any non-loopback bind address."""
from __future__ import annotations

import argparse
import sys

from targetlab.app import create_lab_app
from targetlab.safety import assert_loopback_host


def run(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="targetlab", description=__doc__)
    parser.add_argument("--host", default="127.0.0.1", help="loopback host only (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    try:
        assert_loopback_host(args.host)
    except ValueError as exc:
        print(f"targetlab: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    if not 1 <= args.port <= 65535:
        print("targetlab: port must be between 1 and 65535", file=sys.stderr)
        raise SystemExit(2)
    import uvicorn  # imported here so importing the package never starts a server

    print(f"targetlab: DELIBERATELY VULNERABLE test API on http://{args.host}:{args.port} "
          "(loopback only, do not deploy)", file=sys.stderr)
    uvicorn.run(create_lab_app(), host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
