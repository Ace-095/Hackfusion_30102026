# Checkpoint 12: experimental pinned HTTPS read component

**Not live-scan ready.** This narrowly scoped Python component is not integrated
into the scanner or API. Calling it directly with real scope and credentials can
make real HTTPS requests; do not do so without written organizer authorization
and independent safety review. The fixture API remains in-process only.

## VS Code judge demo — tests only, no external traffic

In the repository root with the project environment activated:

```sh
python -m pytest -v tests/security/test_pinned_reader.py
python -m pytest -q
```

On Linux/macOS, use `.venv/bin/python` if the environment is not active; on
Windows use `.\.venv\Scripts\python.exe`. Tests simulate TCP using mocks and
exercise actual TLS certificate verification through an in-process socket pair.
The synthetic certificate and public test key in `tests/fixtures/tls/` are for
tests only. No external target or DNS resolver is contacted.

The tests demonstrate exact classified GET-only scope checks before connecting,
pinning to an organizer-supplied literal IP, TLS hostname verification, no
redirect following, sequential requests, a per-instance budget, size limits,
halts and no automatic retries. They also check the supplied bearer-token mapping for named accounts and
rejection of malformed credentials; this does not verify token identity. TLS
session-key logging is disabled before the handshake. No credentials are persisted by
this component; returned body bytes are raw, may contain secrets and are not
approved for report persistence.

**Remaining:** no authentication/login, approved DNS resolution, live discovery,
scanner/API integration, shared budget across reader instances, absolute request
deadline, comprehensive live-data redaction, or live-target end-to-end test.
The existing fixture report remains a synthetic result; see the
[main demo](../VS_CODE_DEMO.md).
