# CanaryGate — offline backend checkpoint

CanaryGate is planned as an evidence-based API authorization testing system.
This checkpoint implements **a synthetic offline read-BOLA pipeline**, scoped
authentication probes and bounded input/disclosure checks, with local SQLite
persistence and auditable minimized ownership observations, exposed through a provisional FastAPI interface. A separate bounded OpenAPI upload inspects a specification in memory without configuring or starting a scan. The API cannot scan live targets. A separate experimental guarded HTTPX component is not connected to the scanner or API, and production network execution is disabled pending safety review. This is not
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
`python tools/p0_audit.py` prints the 35-row P0 acceptance audit and exits
non-zero on any dangling implementation/test reference or unclassified test file.

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
[checkpoint 12 demo](docs/checkpoints/12-pinned-reader.md), and
[checkpoint 13 demo](docs/checkpoints/13-guarded-httpx.md), and
[checkpoint 14 demo](docs/checkpoints/14-run-guard.md), and
[checkpoint 15 demo](docs/checkpoints/15-network-deadline.md), and
[checkpoint 16 demo](docs/checkpoints/16-guarded-login.md), and
[checkpoint 17 demo](docs/checkpoints/17-identity-observation.md), and
[checkpoint 18 demo](docs/checkpoints/18-identity-pair.md), and
[checkpoint 19 demo](docs/checkpoints/19-resource-harvest.md), and
[checkpoint 20 demo](docs/checkpoints/20-owner-baselines.md), and
[checkpoint 21 demo](docs/checkpoints/21-live-disabled.md), and
[checkpoint 22 demo](docs/checkpoints/22-verified-ownership.md), and
[checkpoint 23 demo](docs/checkpoints/23-read-bola-oracle.md), and
[checkpoint 24 demo](docs/checkpoints/24-independent-validation-plan.md), and
[checkpoint 25 demo](docs/checkpoints/25-fixture-detection-pipeline.md),
[checkpoint 26 P0 audit](docs/checkpoints/26-p0-audit.md) and
[checkpoint 27 generic proof-path integration](docs/checkpoints/27-generic-integration.md)
[checkpoint 28 generic offline scan integration](docs/checkpoints/28-generic-scan-integration.md)
[checkpoint 29 authentication checks](docs/checkpoints/29-authentication-checks.md)
and [checkpoint 30 input-validation and disclosure checks](docs/checkpoints/30-input-disclosure.md)
[checkpoint 31 nine-section report and authorization matrix](docs/checkpoints/31-report-and-matrix.md)
and [checkpoint 32 P0 acceptance audit](docs/checkpoints/32-p0-acceptance-audit.md).

## Run the fixture API locally

```sh
python -m uvicorn canarygate.api.app:app --host 127.0.0.1 --port 8000
```

Generic offline scenarios are exposed at `POST /api/scenario-scans` with a bundled
scenario id; see [checkpoint 28](docs/checkpoints/28-generic-scan-integration.md).
Authentication checks are exposed at `POST /api/authentication-scans`; see
[checkpoint 29](docs/checkpoints/29-authentication-checks.md). Input-validation
and disclosure checks are exposed at `POST /api/validation-scans`; see
[checkpoint 30](docs/checkpoints/30-input-disclosure.md). SCI interaction scans are exposed at `POST /api/interaction-scans`; see
[checkpoint 33](docs/checkpoints/33-sci-interaction.md). Any stored run renders
the frozen nine-section P0 report at `?view=p0`, and
`GET /api/authorization-matrix` shows partial authorization coverage with
untested cells; see [checkpoint 31](docs/checkpoints/31-report-and-matrix.md).

A deliberately vulnerable local test API, **TargetLab**, is available for
validation work. CanaryGate can collect evidence from it over loopback HTTPS via
`POST /api/lab-scans` (checkpoint 35), real read-BOLA validation through
`POST /api/lab-bola-scans` (checkpoint 36) and real control-interaction (SCI)
validation through `POST /api/lab-sci-scans` + `POST /api/lab-sci-resets`
(checkpoint 37); all require `CANARYGATE_TARGETLAB_CA` and are controlled
validation, not live scanning. `.venv/bin/python tools/demo.py` runs the complete
four-stage demonstration from a clean start, and `docs/JUDGE_DEFENCE.md` explains
every design decision: `.venv/bin/python -m targetlab` (loopback only, never deploy).
See [docs/TARGETLAB.md](docs/TARGETLAB.md) and
[checkpoint 34](docs/checkpoints/34-targetlab.md). Scanning it is **not**
implemented yet; the lab is a target, not a scanner transport.

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

Independent VAmPI and crAPI validation profiles are [preparation only](docs/validation/README.md); written organizer approval is required before scanning either, even locally.
