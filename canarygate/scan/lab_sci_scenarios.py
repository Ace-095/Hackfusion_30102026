"""The TargetLab control-interaction scenario.

The lab's declared flaw is a *state-dependent* one: an account whose last login
attempt was rejected as a bad credential skips the ownership check on the guarded
route for one read. Two controls therefore look correct in isolation while their
interaction leaks another account's private asset.

A run may select which ordered pair of the three provisioned demo accounts it
exercises: the requester (who sets the condition) and the asset owner (whose asset
is leaked). Everything else is fixed: the loopback port, the request budget and the
declared denial/rejection bodies. The rejection body is a lab contract, not
configuration.
"""
from dataclasses import dataclass

from canarygate.oracles.interaction import INTERACTION_CONTROLS
from canarygate.scope.authorized import AuthorizedScope
from canarygate.seed.recipe import Resource

SCENARIO_ID = "targetlab-sci"
TITLE = "TargetLab control-interaction validation"
POLICY_SOURCE = "targetlab declared interaction policy"
KIND = "AUTHN+AUTHZ"

LOGIN_PATH = "/login"
PROFILE_PATH = "/profile"
REJECTED_LOGIN_PROBE = "wrong_password"
DENIAL_BODY = {"error": "forbidden"}
REJECTION_BODY = {"error": "invalid_credentials"}

GUARDED_RESOURCE = Resource.model_validate({
    "discovery": {"method": "GET", "path": "/records"},
    "detail": {"method": "GET", "path": "/records/{id}/guarded"},
    "id_field": "id",
    "ownership_field": "owner",
    "ownership_model": "private",
    "private_field": "private_note",
})

# Requests the primary interaction needs, counted from the declared steps:
# 2 logins, 2 identity profiles, 2 discovery reads, 2 owner baselines for the
# ownership proof, 1 guarded denial baseline, 1 rejected login, 1 guarded read.
REQUIRED_REQUESTS = 11
RESET_REQUESTS = 7
MIN_REQUEST_BUDGET = 8
DEFAULT_REQUEST_BUDGET = 16
MAX_REQUEST_BUDGET = 40

# Declared ground truth, used only by the report-time evaluation. The scan never
# imports or reads this table (a test asserts the module does not mention it).
EXPECTED = {
    "SCI-01": "CONFIRMED",
    "RESET-01": "403",
    "RESET-02": "401",
    "RESET-03": "200",
    "RESET-04": "403",
}


def wrong_password_body(actor: str) -> str:
    """A well-formed login body with a wrong password and no real secret."""
    if not isinstance(actor, str) or not actor:
        raise ValueError("an account name is required")
    payload = {"username": actor, "password": f"targetlab-wrong-password-for-{actor}"}
    return '{"username": "%s", "password": "%s"}' % (payload["username"], payload["password"])


@dataclass(frozen=True)
class LabSciPlan:
    scenario_id: str
    title: str
    kind: str
    controls: tuple
    policy_source: str
    scope: AuthorizedScope
    credentials: dict
    accounts: tuple
    resource: Resource
    login_path: str
    profile_path: str
    probe: str
    denial_body: dict
    rejection_body: dict
    required_requests: int

    def probe_body(self, actor: str) -> str:
        return wrong_password_body(actor)


def _pair(actor, owner) -> tuple[str, str]:
    """Resolve the requested ordered pair of demo accounts."""
    from canarygate.scan.lab_scenarios import resolve_pair

    return resolve_pair(actor, owner)


def build_sci_plan(port: int, *, budget: int = DEFAULT_REQUEST_BUDGET,
                   actor: str | None = None, owner: str | None = None) -> LabSciPlan:
    """Build the interaction plan for one ordered pair; port, budget and pair vary."""
    from canarygate.scan.lab_scenarios import LAB_PASSWORDS, build_lab_scope

    if not isinstance(port, int) or not 1024 <= port <= 65535:
        raise ValueError("a TargetLab port between 1024 and 65535 is required")
    if (not isinstance(budget, int) or not MIN_REQUEST_BUDGET <= budget <= MAX_REQUEST_BUDGET):
        raise ValueError(f"a request budget between {MIN_REQUEST_BUDGET} and "
                         f"{MAX_REQUEST_BUDGET} is required")
    pair = _pair(actor, owner)
    return LabSciPlan(
        scenario_id=SCENARIO_ID, title=TITLE, kind=KIND,
        controls=tuple(INTERACTION_CONTROLS[KIND]), policy_source=POLICY_SOURCE,
        scope=build_lab_scope(port, budget=budget, accounts=pair,
                                input_probes=(REJECTED_LOGIN_PROBE,)),
        credentials={name: LAB_PASSWORDS[name] for name in pair}, accounts=pair, resource=GUARDED_RESOURCE,
        login_path=LOGIN_PATH, profile_path=PROFILE_PATH, probe=REJECTED_LOGIN_PROBE,
        denial_body=dict(DENIAL_BODY), rejection_body=dict(REJECTION_BODY),
        required_requests=REQUIRED_REQUESTS)
