# CanaryGate — offline backend checkpoint

CanaryGate is planned as an evidence-based API authorization testing system.
This checkpoint implements **a synthetic offline read-BOLA pipeline**, scoped
authentication probes and bounded input/disclosure checks, with local SQLite
persistence and auditable minimized ownership observations, exposed through a provisional FastAPI interface. A separate bounded OpenAPI upload inspects a specification in memory without configuring or starting a scan. It cannot scan live targets. It is not
a complete implementation of the frozen specification or a production safety
guard. Fixture findings must never be represented as live-target results.

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

1. Review the [attached v3.2 specification](docs/spec/CanaryGate_v3.2_safety-corrected.md)
   and [safety addendum](docs/SAFETY_ADDENDUM.md). Both developers must check every
   contract against section 23 and agree before calling the contracts frozen.
2. Review the shared contracts together, especially how setup outcomes and
   readiness gates, ownership and disclosure evidence, and results are linked.
   The proposed plan does not define all of these details. Record approval and
   freeze the agreed interfaces before independent implementation.
3. Confirm repository collaborator access, agree on ownership and protect the
   integration branch with reviews and passing CI if repository permissions allow.
   See [CONTRIBUTING.md](CONTRIBUTING.md) for the two-developer GitHub workflow.
4. Build the first offline end-to-end BOLA demonstration continuously rather than
   deferring integration. Fixture results must be explicitly labeled as such.

See [collaboration and milestones](docs/DEVELOPMENT.md),
[contract review notes](docs/CONTRACTS.md), [API draft](docs/API.md), and
[decision and checkpoint log](docs/DECISIONS.md), and
[checkpoint 3 demo](docs/checkpoints/03-input-disclosure.md), and
[checkpoint 4 demo](docs/checkpoints/04-persistence.md), and
[checkpoint 5 demo](docs/checkpoints/05-observations.md), and
[checkpoint 6 demo](docs/checkpoints/06-spec-inspection.md), and
[checkpoint 7 demo](docs/checkpoints/07-disclosure.md), and
[checkpoint 8 demo](docs/checkpoints/08-enumeration.md), and
[checkpoint 9 demo](docs/checkpoints/09-enum-validation.md), and
[checkpoint 10 demo](docs/checkpoints/10-scope-validation.md), and
[checkpoint 11 demo](docs/checkpoints/11-preflight.md), and
[checkpoint 12 demo](docs/checkpoints/12-pinned-reader.md).

## Run the fixture API locally

```sh
python -m uvicorn canarygate.api.app:app --host 127.0.0.1 --port 8000
```

In a second terminal, run `python -m canarygate.demo`. The command prints the
fixture inventory, scan results and a local HTML report URL. The detailed
[VS Code and judge demo guide](docs/VS_CODE_DEMO.md) has Windows/Linux steps.
The provisional schema is available at `/openapi.json`. Swagger/ReDoc are disabled
because their default assets use external CDNs. This unauthenticated local
server must not be exposed to other users or the Internet. Fixture reports
persist in `.canarygate/fixture.sqlite3` relative to the working directory;
`CANARYGATE_DB_PATH` can select another local file. The API contracts are not
yet approved/frozen. The fixture redactor is not suitable for arbitrary live data.

## Safety baseline for future implementation

All network requests, including authentication and discovery, must pass through
one guard immediately before connection. Exact authorized scope, method, account
and budget must be enforced; redirects and remote `$ref` are disabled; safe YAML,
DNS validation and connection pinning, size limits, sequential execution, and
credential redaction are required. DELETE is always blocked; PUT/PATCH default to
blocked; only explicitly authorized login and creation operations are permitted.
Do not automatically retry state-changing requests. See the full specification
before implementing the guard. **The fixture-only guard is not a live-network guard; live execution is disabled.**

Do not commit credentials, private target data, generated evidence, or reports.
The `Identity` model excludes its token from normal Pydantic serialization and
representation, but this is not a complete redaction system: claims, arbitrary
request/response dictionaries, logs and exceptions may still contain secrets.
