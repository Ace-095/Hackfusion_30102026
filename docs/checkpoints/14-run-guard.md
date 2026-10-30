# Checkpoint 14: shared run safety state

This checkpoint adds a `RunSafetyGuard` that can be explicitly shared among
experimental HTTPX runners for one run. It shares a budget, sequential lock,
halt state and repeated-server-error streak. A different scope cannot reuse the
guard. **The live scanner is not enabled or integrated.**

## VS Code judge demo

In the activated project environment, from the repository root:

```sh
python -m pytest -v tests/security/test_pinned_reader.py tests/security/test_httpx_boundary.py
python -m pytest -q
```

Use `.venv/bin/python` on Linux/macOS or `.\.venv\Scripts\python.exe` on
Windows if needed. The tests use mock sockets and an in-process TLS socketpair,
not an external target or DNS resolver. They show a shared budget cannot be
overspent by two runners, concurrent requests are sequential, rate limiting and
failed connections stop other runners, repeated errors accumulate across runners,
and guard/scope mismatches fail before socket creation.

The guard must be passed explicitly to each runner in the same scan; separate
guards are separate runs. The future scanner must enforce that invariant. It
still needs safe authentication and discovery, approved DNS-only resolution,
a total request deadline, live-data evidence handling, and independently
reviewed end-to-end safety. The experimental GET component can make real HTTPS
requests if directly invoked; never use it without written authorization and
review. The existing fixture demo is described in [the main guide](../VS_CODE_DEMO.md).
