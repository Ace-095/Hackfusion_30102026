"""CLI for demonstrating the fixture API from a local VS Code terminal."""
import json
import sys

import httpx


def main() -> int:
    # Local application only, not a scanner target or a browser-facing endpoint.
    try:
        with httpx.Client(base_url="http://127.0.0.1:8000", trust_env=False, timeout=10.0) as client:
            health_response = client.get("/api/health")
            health_response.raise_for_status()
            health = health_response.json()
            if health != {"status": "ok", "mode": "fixture", "live_scanning": False}:
                print("Unexpected server; refusing to start a scan.", file=sys.stderr)
                return 1
            endpoints = client.get("/api/endpoints")
            endpoints.raise_for_status()
            print("=== Fixture endpoint inventory ===")
            print(json.dumps(endpoints.json(), indent=2))
            scan = client.post("/api/scan")
            scan.raise_for_status()
            result = scan.json()
            print("\n=== Fixture scan (not live-target testing) ===")
            print(json.dumps(result, indent=2))
            print(f"\nOpen the HTML fixture report: http://127.0.0.1:8000/api/reports/{result['id']}?format=html")
            print(f"JSON report: http://127.0.0.1:8000/api/reports/{result['id']}")
            return 0
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        print(f"Cannot run fixture demo: {exc}. Start the backend first; see docs/VS_CODE_DEMO.md.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
