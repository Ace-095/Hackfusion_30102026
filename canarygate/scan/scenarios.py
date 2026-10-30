"""Bundled synthetic offline scenarios for the generic application workflow.

These are deterministic local recordings for demonstration and regression tests.
They are not organizer targets, lab instances, or live approvals.
"""
from canarygate.api.schemas import InventoryEndpoint
from canarygate.scan.offline import OfflineGuardedRunner
from canarygate.scan.plan import OfflineScenarioPlan
from canarygate.scan.transcript import OfflineTranscript, TranscriptEntry
from canarygate.scope.authorized import AuthorizedScope

SCOPE_HOST = "offline.invalid"
SCOPE_IP = "192.0.2.10"
AUTHORIZATION_LABEL = "synthetic-offline-scenario"
TOKENS = {"account-a": "offline-token-account-a", "account-b": "offline-token-account-b"}
ALPHA_PRIVATE = "synthetic-alpha-private"
BETA_PRIVATE = "synthetic-beta-private"

SCENARIO_IDS = ("synthetic-vulnerable", "synthetic-secure", "synthetic-metadata",
                "synthetic-leaky-denial", "synthetic-pagination-limit", "synthetic-guard-block")
DEFAULT_SCENARIO = "synthetic-vulnerable"


def _scope(budget):
    return AuthorizedScope.model_validate({
        "mode": "approved_lab", "scheme": "https", "hostname": SCOPE_HOST, "port": 443,
        "organizer_ip": SCOPE_IP, "written_authorization_reference": AUTHORIZATION_LABEL,
        "allowed_methods": ["GET"], "request_budget": budget,
        "accounts": [{"account": "account-a", "role": "user"},
                     {"account": "account-b", "role": "user"}],
        "operations": [
            {"method": "GET", "path": "/profile", "classification": "READ_ONLY"},
            {"method": "GET", "path": "/records", "classification": "READ_ONLY"},
            {"method": "GET", "path": "/records/ra", "classification": "READ_ONLY"},
            {"method": "GET", "path": "/records/rb", "classification": "READ_ONLY"},
        ],
    })


def _inventory():
    return [
        InventoryEndpoint(method="GET", path="/profile", parameters=[],
                          security=[{"bearerAuth": []}], expected_access="authenticated",
                          expected_source="offline scenario scope"),
        InventoryEndpoint(method="GET", path="/records", parameters=[],
                          security=[{"bearerAuth": []}], expected_access="authenticated",
                          expected_source="offline scenario scope"),
        InventoryEndpoint(method="GET", path="/records/{id}", parameters=[
                              {"name": "id", "in": "path", "required": True}],
                          security=[{"bearerAuth": []}], expected_access="authenticated",
                          expected_source="offline scenario scope"),
    ]


def _recipe():
    return {"discovery": {"method": "GET", "path": "/records"},
            "detail": {"method": "GET", "path": "/records/{id}"},
            "id_field": "id", "ownership_field": "owner", "ownership_model": "private",
            "private_field": "secret"}


def _entries(cross_status, cross_body, *, wrapped=False):
    def listing(account, record):
        row = {"id": record, "owner": account}
        return {"records": [row], "next": "2"} if wrapped else [row]

    return [
        TranscriptEntry(actor="account-a", method="GET", path="/profile", status=200,
                        body={"identity": "account-a"}),
        TranscriptEntry(actor="account-b", method="GET", path="/profile", status=200,
                        body={"identity": "account-b"}),
        TranscriptEntry(actor="account-a", method="GET", path="/records", status=200,
                        body=listing("account-a", "ra")),
        TranscriptEntry(actor="account-b", method="GET", path="/records", status=200,
                        body=listing("account-b", "rb")),
        TranscriptEntry(actor="account-a", method="GET", path="/records/ra", status=200,
                        body={"id": "ra", "owner": "account-a", "secret": ALPHA_PRIVATE}),
        TranscriptEntry(actor="account-b", method="GET", path="/records/rb", status=200,
                        body={"id": "rb", "owner": "account-b", "secret": BETA_PRIVATE}),
        TranscriptEntry(actor="account-a", method="GET", path="/records/rb",
                        status=cross_status, body=cross_body),
    ]


def _plan(scenario_id, *, budget=12, cross_status=200,
          cross_body=None, wrapped=False, recipe=None):
    policy = {"expected_access": "owner-only", "expected_source": "offline scenario policy"}
    return OfflineScenarioPlan(
        scenario_id=scenario_id, scope=_scope(budget), accounts=("account-a", "account-b"),
        resource_type="records", resource=recipe or _recipe(), profile_path="/profile",
        identity_field="identity", policy=policy, inventory=_inventory(),
        transcript=OfflineTranscript(entries=tuple(
            _entries(cross_status, cross_body, wrapped=wrapped))))


def build_scenario(scenario_id):
    """Return a validated plan for a known synthetic scenario id."""
    if scenario_id == "synthetic-vulnerable":
        return _plan(scenario_id, cross_body={"id": "rb", "owner": "account-b", "secret": BETA_PRIVATE})
    if scenario_id == "synthetic-secure":
        return _plan(scenario_id, cross_status=403, cross_body={"error": "forbidden"})
    if scenario_id == "synthetic-metadata":
        return _plan(scenario_id, cross_body={"id": "rb"})
    if scenario_id == "synthetic-leaky-denial":
        return _plan(scenario_id, cross_status=403,
                     cross_body={"error": "forbidden", "secret": BETA_PRIVATE})
    if scenario_id == "synthetic-pagination-limit":
        recipe = _recipe()
        recipe.update({"list_field": "records",
                       "pagination": {"next_field": "next", "parameter": "page", "max_pages": 1}})
        return _plan(scenario_id, wrapped=True, recipe=recipe,
                     cross_body={"id": "rb", "owner": "account-b", "secret": BETA_PRIVATE})
    if scenario_id == "synthetic-guard-block":
        return _plan(scenario_id, budget=6,
                     cross_body={"id": "rb", "owner": "account-b", "secret": BETA_PRIVATE})
    raise KeyError("unknown offline scenario")


def execute_offline_scenario(plan):
    """Run a bundled plan through the recorded guarded transport and return a run."""
    from canarygate.scan.generic import run_generic_scan
    tokens = {name: TOKENS[name] for name in plan.accounts}
    runner = OfflineGuardedRunner(plan.scope, tokens, plan.transcript)
    try:
        return run_generic_scan(runner, plan)
    finally:
        runner.close()
