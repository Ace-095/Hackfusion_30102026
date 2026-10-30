# CanaryGate — shared foundation

CanaryGate is planned as an evidence-based API authorization testing system. This
repository currently contains **draft shared contracts and project setup only**.
It does not yet implement a safety guard, HTTP runner, authentication, ownership
verification, BOLA tests, reporting, or a working application. Do not use it to
scan any target or interpret model instances as security findings.

## Setup (Linux and Windows)

Use Python **3.11** on both machines, Git, and access to this existing repository.
From the repository root:

Linux/macOS:

```sh
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pytest
```

Windows PowerShell (with the Python 3.11 launcher installed):

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pytest
```

If PowerShell activation is restricted, use `.venv\Scripts\python.exe -m pip`
and `.venv\Scripts\python.exe -m pytest` directly. Dependencies are pinned in
`pyproject.toml`; the GitHub Actions workflow tests both Linux and Windows.

## Before parallel development

1. Obtain the complete frozen CanaryGate v3.2 specification. It is **not present**
   in this repository. Both developers must check every contract against section
   23 and resolve ambiguities before approval; the models here are a draft based
   only on the supplied plan, not a verified or frozen specification.
2. Review the shared contracts together, especially how setup outcomes and
   readiness gates, ownership and disclosure evidence, and results are linked.
   The proposed plan does not define all of these details. Record approval and
   freeze the agreed interfaces before independent implementation.
3. Confirm repository collaborator access, agree on ownership and protect the
   integration branch with reviews and passing CI if repository permissions allow.
   See [CONTRIBUTING.md](CONTRIBUTING.md) for the two-developer GitHub workflow.
4. Build the first offline end-to-end BOLA demonstration continuously rather than
   deferring integration. Fixture results must be explicitly labeled as such.

See [collaboration and milestones](docs/DEVELOPMENT.md) and
[contract review notes](docs/CONTRACTS.md).

## Safety baseline for future implementation

All network requests, including authentication and discovery, must pass through
one guard immediately before connection. Exact authorized scope, method, account
and budget must be enforced; redirects and remote `$ref` are disabled; safe YAML,
DNS validation and connection pinning, size limits, sequential execution, and
credential redaction are required. DELETE is always blocked; PUT/PATCH default to
blocked; only explicitly authorized login and creation operations are permitted.
Do not automatically retry state-changing requests. See the full specification
before implementing the guard. **No safety enforcement exists yet.**

Do not commit credentials, private target data, generated evidence, or reports.
The `Identity` model excludes its token from normal Pydantic serialization and
representation, but this is not a complete redaction system: claims, arbitrary
request/response dictionaries, logs and exceptions may still contain secrets.
