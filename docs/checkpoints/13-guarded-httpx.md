# Checkpoint 13: guarded HTTPX boundary (offline verification)

> Update: checkpoint 21 disables production network execution pending safety review. Any earlier statement about direct network execution describes historical behavior.

The old standalone pinned reader implementation has been removed. An inert
module remains solely to prevent stale package builds from reviving it. The experimental HTTPX
runner uses exactly one guarded transport for its requests. It is **not wired
into the scanner or API**. Calling it directly can make real HTTPS connections;
do not do so without written organizer permission and independent safety review.

## VS Code judge demonstration

From the repository root, with the Python environment activated:

```sh
python -m pytest -v tests/security/test_httpx_boundary.py tests/security/test_pinned_reader.py
python -m pytest -q
```

Use `.venv/bin/python` on Linux/macOS or `.\.venv\Scripts\python.exe` on
Windows if the environment is not activated. The focused tests use mocked
sockets and an in-process TLS socketpair; they do not contact a real target.
They exercise exact host/port and operation checks at the transport, blocked
methods and bodies, per-instance budget, sequential execution, pinned IPv4/IPv6,
TLS hostname verification, TLS key-log prevention, request-header replacement,
response limits, halt conditions and no redirect following. They also verify the
old reader module raises an import error and cannot execute network traffic.

The HTTPX transport uses Python's HTTP/1.1 implementation only over its pinned
socket. At this checkpoint it supported **GET only**, a supplied literal IP and bearer
tokens. Checkpoint 16 subsequently adds a narrow scope-classified login. It does
not verify token identity, resolve DNS-only scopes, support query operations or
expose response headers. A run guard can be explicitly shared across instances (checkpoint 14); independent
guards have independent budgets. Checkpoint 15 adds a total network deadline,
not a general hard bound on all process work. These restrictions and
other incomplete production safety/evidence integration mean this is not a
complete live scanner. The fixture report remains a synthetic result; see the
[main demo guide](../VS_CODE_DEMO.md).
