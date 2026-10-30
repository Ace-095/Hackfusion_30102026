# Checkpoint 21: production network execution disabled

The experimental HTTPX boundary now fails closed before socket creation or DNS
in normal operation. There is no environment or API switch to enable it. The
fixture API still runs its in-process mock target.

## VS Code judge demo

From the repository root in an activated Python environment:

```sh
python -m pytest -v tests/security/test_live_disabled.py
python -m pytest -v tests/security/test_httpx_boundary.py tests/security/test_pinned_reader.py
python -m pytest -q
```

Use `.venv/bin/python` on Linux/macOS or `.\.venv\Scripts\python.exe` on
Windows if needed. The first group checks unmodified production behavior for GET,
login and direct transport calls, including an attempted environment override.
The other groups explicitly replace the gate in tests while using mock sockets
or an in-process TLS socketpair; they do not contact an external target or DNS.

This is a default-deny development hold, not protection against someone changing
or monkeypatching code. Live execution must stay disabled until the central
safety path, account/ownership readiness, evidence handling and end-to-end
integration are finished and independently reviewed, with written organizer
authorization. The [fixture demo](../VS_CODE_DEMO.md) remains explicitly synthetic.
