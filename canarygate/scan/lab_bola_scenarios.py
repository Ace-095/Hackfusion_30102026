"""The fixed TargetLab read-BOLA scenario.

Nothing here is configurable beyond the port and the request budget: the
resource declarations, accounts and policy are constants because the lab is
ours. ``EXPECTED_VERDICTS`` is *ground truth for evaluation only*; the scan
never reads it (a test proves the verdicts are identical when it is removed).

The vulnerable endpoint (``/records/{id}``) ignores ownership. The secure one
(``/records/{id}/secure``) enforces it. Both share one owner-isolated collection
endpoint (``/records``) used for discovery and cross-list isolation.
"""
from dataclasses import dataclass

from canarygate.scope.authorized import AuthorizedScope
from canarygate.seed.recipe import Policy, Resource

SCENARIO_ID = "targetlab-bola"
TITLE = "TargetLab read-BOLA validation"
AUTHORIZATION_REFERENCE = "targetlab-local-controlled-validation"
POLICY_SOURCE = "targetlab declared record policy"

VULNERABLE_RESOURCE = Resource.model_validate({
    "discovery": {"method": "GET", "path": "/records"},
    "detail": {"method": "GET", "path": "/records/{id}"},
    "id_field": "id",
    "ownership_field": "owner",
    "ownership_model": "private",
    "private_field": "private_note",
})
SECURE_RESOURCE = Resource.model_validate({
    "discovery": {"method": "GET", "path": "/records"},
    "detail": {"method": "GET", "path": "/records/{id}/secure"},
    "id_field": "id",
    "ownership_field": "owner",
    "ownership_model": "private",
    "private_field": "private_note",
})

# Ground truth, used only to score the finished run. Deliberately not imported by
# the orchestrator's decision path.
EXPECTED_VERDICTS = {
    "LAB-BOLA-01": "SAFE",       # alice reads her own record
    "LAB-BOLA-02": "SAFE",       # bob reads his own record
    "LAB-BOLA-03": "CONFIRMED",  # alice reads bob's record (vulnerable route)
    "LAB-BOLA-04": "CONFIRMED",  # bob reads alice's record (vulnerable route)
    "LAB-BOLA-05": "SAFE",       # alice denied on bob's secure record
    "LAB-BOLA-06": "SAFE",       # bob denied on alice's secure record
}

CHECK_IDS = tuple(f"LAB-BOLA-{index:02d}" for index in range(1, 7))
MIN_BUDGET = 16
MAX_BUDGET = 40
DEFAULT_BUDGET = 20


@dataclass(frozen=True)
class LabBolaPlan:
    scenario_id: str
    title: str
    scope: AuthorizedScope
    credentials: dict
    accounts: tuple
    resource: Resource
    secure_resource: Resource
    profile_path: str
    identity_field: str
    policy: Policy


def build_bola_plan(port: int, *, budget: int = DEFAULT_BUDGET) -> LabBolaPlan:
    """Build the fixed plan. Reuses the checkpoint 35 scope builder."""
    from canarygate.scan.lab_scenarios import LAB_PASSWORDS, KNOWN_ACCOUNTS, build_lab_scope

    if not isinstance(port, int) or not 1024 <= port <= 65535:
        raise ValueError("a TargetLab port between 1024 and 65535 is required")
    if not isinstance(budget, int) or not MIN_BUDGET <= budget <= MAX_BUDGET:
        raise ValueError(f"a request budget between {MIN_BUDGET} and {MAX_BUDGET} is required")
    return LabBolaPlan(
        scenario_id=SCENARIO_ID, title=TITLE, scope=build_lab_scope(port, budget=budget),
        credentials=dict(LAB_PASSWORDS), accounts=KNOWN_ACCOUNTS,
        resource=VULNERABLE_RESOURCE, secure_resource=SECURE_RESOURCE,
        profile_path="/profile", identity_field="identity",
        policy=Policy(expected_access="owner-only", expected_source=POLICY_SOURCE))
