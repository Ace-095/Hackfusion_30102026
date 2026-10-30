# Checkpoint 15: total network deadline

The experimental guarded HTTPX transport now uses a 10-second monotonic network
deadline and an interrupting watchdog in addition to per-socket timeouts. An
expired or failed request halts its shared run. This is **not** an enabled live
scanner or a guarantee that all local computation and system calls complete
within ten seconds.

## VS Code judge demo

From the repository root in an activated Python environment:

```sh
python -m pytest -v tests/security/test_pinned_reader.py -k absolute_network_deadline
python -m pytest -q
```

Use `.venv/bin/python` on Linux/macOS or `.\.venv\Scripts\python.exe` on
Windows if needed. Tests use a real TLS connection over an in-process socketpair,
not an external target or DNS. They stall the TLS handshake, response headers,
response body and a slow-drip response; each must time out and halt the run.
The full suite includes the other scope, pinning, redirect and shared-budget
regressions. The test certificate is synthetic and must not be used in production.

The component remains GET-only and unconnected to the scanner/API. The scanner
still needs authentication, discovery, approved resolver-only support, live-data
redaction and independent end-to-end safety review. A direct call to the
experimental transport can make real requests; never use it without written
authorization. The [main demo](../VS_CODE_DEMO.md) is fixture-only.
