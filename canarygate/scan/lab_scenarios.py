"""The single fixed TargetLab scenario: two accounts, known records, loopback HTTPS.

Nothing here is configurable beyond the port and the request budget. The account
names, passwords, record paths and expected policy are constants because the lab
is ours; loosening this into arbitrary configuration would turn a validation
harness into a general-purpose scanner.
"""
from dataclasses import dataclass

from canarygate.scope.authorized import (INPUT_PROBE_NAMES, TARGETLAB_HOST,
                                         TARGETLAB_OPERATIONS, AuthorizedScope)

SCENARIO_ID = "targetlab-evidence"
TITLE = "TargetLab loopback evidence collection"
AUTHORIZATION_REFERENCE = "targetlab-local-controlled-validation"

# Public, lab-only credentials. They are not secrets: the lab is loopback-only and
# these values are documented in docs/TARGETLAB.md.
LAB_PASSWORDS = {"alice": "alice-lab-password", "bob": "bob-lab-password"}
KNOWN_ACCOUNTS = ("alice", "bob")
OWN_RECORD = {"alice": "/records/ra", "bob": "/records/rb"}
OTHER_RECORD = {"alice": "/records/rb", "bob": "/records/ra"}
SECURE_ENDPOINT = "/records/rb/secure"
PROFILE_PATH = "/profile"
ADMIN_PATH = "/admin/users"

EXPECTED_POLICY = {
    "/profile": ("authenticated", "TargetLab authentication contract"),
    "/records/ra": ("owner-only", "TargetLab record policy"),
    "/records/rb": ("owner-only", "TargetLab record policy"),
    "/records/rb/secure": ("owner-only", "TargetLab record policy"),
    "/admin/users": ("role:admin", "TargetLab role policy"),
}


@dataclass(frozen=True)
class LabPlan:
    scenario_id: str
    title: str
    scope: AuthorizedScope
    credentials: dict
    owner_field: str = "owner"
    private_field: str = "private_note"
    identity_field: str = "identity"


def build_lab_scope(port: int, *, budget: int = 12, input_probes: tuple = ()) -> AuthorizedScope:
    """Build the fixed local_lab scope for one TargetLab port.

    ``input_probes`` is the only widening available, and it applies to the single
    declared authentication POST. Nothing else about the lab can be configured.
    """
    if not isinstance(input_probes, (tuple, list)) or any(
            probe not in INPUT_PROBE_NAMES for probe in input_probes):
        raise ValueError("unknown input probe")
    operations = []
    for (method, path), classification in sorted(TARGETLAB_OPERATIONS.items()):
        operation = {"method": method, "path": path, "classification": classification}
        if (method, path) == ("POST", "/login") and input_probes:
            operation["input_probes"] = tuple(input_probes)
        operations.append(operation)
    return AuthorizedScope.model_validate({
        "mode": "local_lab",
        "scheme": "https",
        "hostname": TARGETLAB_HOST,
        "port": port,
        "organizer_ip": TARGETLAB_HOST,
        "written_authorization_reference": AUTHORIZATION_REFERENCE,
        "allowed_methods": ["GET", "POST"],
        "request_budget": budget,
        "accounts": [{"account": name, "role": "user"} for name in KNOWN_ACCOUNTS],
        "operations": operations,
    })


def build_lab_plan(port: int, *, budget: int = 12) -> LabPlan:
    if not isinstance(port, int) or not 1024 <= port <= 65535:
        raise ValueError("a TargetLab port between 1024 and 65535 is required")
    if not isinstance(budget, int) or not 7 <= budget <= 40:
        raise ValueError("a request budget between 7 and 40 is required")
    return LabPlan(scenario_id=SCENARIO_ID, title=TITLE, scope=build_lab_scope(port, budget=budget),
                   credentials=dict(LAB_PASSWORDS))
