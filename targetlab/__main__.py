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
    parser.add_argument("--tls-cert", default=None, help="PEM certificate with an IP:127.0.0.1 SAN")
    parser.add_argument("--tls-key", default=None, help="PEM private key for --tls-cert")
    args = parser.parse_args(argv)
    try:
        assert_loopback_host(args.host)
    except ValueError as exc:
        print(f"targetlab: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    if bool(args.tls_cert) != bool(args.tls_key):
        print("targetlab: --tls-cert and --tls-key must be provided together", file=sys.stderr)
        raise SystemExit(2)
    if args.tls_cert:
        from pathlib import Path
        for item in (args.tls_cert, args.tls_key):
            if not Path(item).is_file():
                print(f"targetlab: TLS file not found: {item}", file=sys.stderr)
                raise SystemExit(2)
    if not 1 <= args.port <= 65535:
        print("targetlab: port must be between 1 and 65535", file=sys.stderr)
        raise SystemExit(2)
    import uvicorn  # imported here so importing the package never starts a server

    scheme = "https" if args.tls_cert else "http"
    print(f"targetlab: DELIBERATELY VULNERABLE test API on {scheme}://{args.host}:{args.port} "
          "(loopback only, do not deploy)", file=sys.stderr)
    uvicorn.run(create_lab_app(), host=args.host, port=args.port, log_level="warning",
                ssl_certfile=args.tls_cert, ssl_keyfile=args.tls_key)
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
