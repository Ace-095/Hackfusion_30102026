"""The TargetLab demo scenario: three accounts, three assets, loopback HTTPS.

The accounts, passwords, asset identifiers and expected policy are constants
because the lab is ours. What a run may choose is which *ordered pair* of the three
provisioned accounts it exercises (see ``lab_bola_scenarios`` and
``lab_sci_scenarios``); loosening anything else into configuration would turn a
validation harness into a general-purpose scanner.
"""
from dataclasses import dataclass

from canarygate.scope.authorized import (INPUT_PROBE_NAMES, TARGETLAB_HOST,
                                         TARGETLAB_OPERATIONS, AuthorizedScope)

SCENARIO_ID = "targetlab-evidence"
TITLE = "TargetLab loopback evidence collection"
AUTHORIZATION_REFERENCE = "targetlab-local-controlled-validation"

# Public, lab-only credentials. They are not secrets: the lab is loopback-only and
# these values are documented in docs/TARGETLAB.md. They never reach a run payload,
# a report or a browser page.
LAB_PASSWORDS = {
    "mallapa": "mallapa-lab-password",
    "sakshi": "sakshi-lab-password",
    "harsha": "harsha-lab-password",
}
#: Every demo account the lab provisions. A scan scopes all three so any ordered
#: pair can be exercised, but each BOLA/SCI run authenticates only the pair it needs.
KNOWN_ACCOUNTS = ("mallapa", "sakshi", "harsha")
ACCOUNT_ROLES = {
    "mallapa": "marketing_manager",
    "sakshi": "brand_designer",
    "harsha": "campaign_analyst",
}
ACCOUNT_TITLES = {
    "mallapa": "Marketing Manager",
    "sakshi": "Brand Designer",
    "harsha": "Campaign Analyst",
}
#: The synthetic Digital Asset Management assets, one private asset per account.
#: These are the same identifiers TargetLab serves; a test asserts they agree.
ASSET_IDS = {
    "mallapa": "MKT-2026-041",
    "sakshi": "BRD-2026-018",
    "harsha": "ADS-2026-027",
}
ASSET_TYPES = {
    "MKT-2026-041": "campaign_artwork",
    "BRD-2026-018": "brand_identity",
    "ADS-2026-027": "performance_report",
}
ASSET_LABELS = {
    "MKT-2026-041": "Unreleased campaign artwork",
    "BRD-2026-018": "Premium brand identity kit",
    "ADS-2026-027": "Confidential performance report",
}
OWN_RECORD = {account: f"/records/{asset}" for account, asset in ASSET_IDS.items()}
#: The fixed pair the checkpoint-34 evidence workflow reads. It is not a policy:
#: the read-BOLA and SCI workflows take an explicit pair from the request.
DEMO_PAIR = ("mallapa", "sakshi")
#: The minimum set of runs that together answer all nine account x asset cells:
#: each ordered pair here covers both directions of one unordered pair.
DEMO_COVERAGE_PAIRS = (("mallapa", "sakshi"), ("sakshi", "harsha"), ("harsha", "mallapa"))
OTHER_RECORD = {DEMO_PAIR[0]: OWN_RECORD[DEMO_PAIR[1]], DEMO_PAIR[1]: OWN_RECORD[DEMO_PAIR[0]]}
SECURE_ENDPOINT = OWN_RECORD[DEMO_PAIR[1]] + "/secure"
PROFILE_PATH = "/profile"
ADMIN_PATH = "/admin/users"

EXPECTED_POLICY = {
    "/profile": ("authenticated", "TargetLab authentication contract"),
    f"/records/{ASSET_IDS['mallapa']}": ("owner-only", "TargetLab record policy"),
    f"/records/{ASSET_IDS['sakshi']}": ("owner-only", "TargetLab record policy"),
    f"/records/{ASSET_IDS['harsha']}": ("owner-only", "TargetLab record policy"),
    f"/records/{ASSET_IDS['sakshi']}/secure": ("owner-only", "TargetLab record policy"),
    "/admin/users": ("role:admin", "TargetLab role policy"),
}


def demo_accounts() -> list[dict]:
    """The public demo catalog: names, titles and asset ids. No credential material.

    The interface renders this so a judge can see who owns which asset. It is
    derived from the same constants the scans use, so a label cannot drift from the
    account the scan actually authenticates.
    """
    return [{"account": account, "title": ACCOUNT_TITLES[account], "role": ACCOUNT_ROLES[account],
             "asset_id": ASSET_IDS[account], "asset_type": ASSET_TYPES[ASSET_IDS[account]],
             "asset_label": ASSET_LABELS[ASSET_IDS[account]]}
            for account in KNOWN_ACCOUNTS]


def demo_pairs() -> list[tuple[str, str]]:
    """Every ordered pair of distinct demo accounts: six cross-account directions."""
    return [(actor, owner) for actor in KNOWN_ACCOUNTS for owner in KNOWN_ACCOUNTS
            if actor != owner]


def resolve_pair(actor, owner) -> tuple[str, str]:
    """Validate one ordered pair of provisioned accounts; default the pair.

    This is the only variable part of a TargetLab run. Both names must be demo
    accounts the lab provisions and must differ, because a cross-account read needs
    two distinct identities. The pair is resolved the same way by every workflow so
    a request cannot end up exercising an identity the scope does not declare.
    """
    actor = DEMO_PAIR[0] if actor in (None, "") else actor
    owner = DEMO_PAIR[1] if owner in (None, "") else owner
    if not isinstance(actor, str) or not isinstance(owner, str):
        raise ValueError("a requester and a resource owner are required")
    if actor not in KNOWN_ACCOUNTS or owner not in KNOWN_ACCOUNTS:
        raise ValueError("the requester and owner must be provisioned demo accounts")
    if actor == owner:
        raise ValueError("the requester and the resource owner must differ")
    return actor, owner


def asset_owner_map() -> dict:
    """Asset id -> owning demo account, derived from the same constant as the lab."""
    return {asset: account for account, asset in ASSET_IDS.items()}


def build_lab_catalog() -> dict:
    """The public demo catalog the interface renders: who may request which asset.

    It contains no credential, token or private marker, and it declares no verdict.
    Every combination names the ordered pair of accounts a scan must run for that
    combination, so the interface never has to decide security semantics: it renders
    the catalog, launches the named pair, and displays the checks the backend
    actually produced.

    ``kind`` is a description of the *request*, not an outcome: a legitimate owner
    request is answered by the owner-baseline check of that pair's run, and a
    cross-account attempt by the cross-account check.
    """
    owners = asset_owner_map()
    accounts = demo_accounts()
    combinations = []
    for account in KNOWN_ACCOUNTS:
        for asset in ASSET_IDS.values():
            owner = owners[asset]
            legitimate = account == owner
            peer = (account if legitimate else owner)
            pair_actor, pair_owner = ((account, next(name for name in KNOWN_ACCOUNTS
                                                     if name != account))
                                      if legitimate else (account, owner))
            combinations.append({
                "actor": account, "asset_id": asset, "owner": owner,
                "kind": "legitimate_owner_request" if legitimate else "cross_account_attempt",
                "pair": {"actor": pair_actor, "owner": pair_owner},
            })
    return {
        "mode": "targetlab_demo",
        "dataset": "demo_tenant",
        "accounts": accounts,
        "pairs": [{"actor": actor, "owner": owner} for actor, owner in demo_pairs()],
        # Three runs are enough to answer all nine combinations: each run records both
        # owner baselines and both cross-account directions, so the minimum coverage is
        # one ordered pair per unordered pair. The six pairs above are every request the
        # API accepts, not the minimum a judge has to run.
        "coverage_pairs": [{"actor": actor, "owner": owner}
                           for actor, owner in DEMO_COVERAGE_PAIRS],
        "combinations": combinations,
        "notes": [
            "Synthetic Digital Asset Management tenant: three colleagues, one private asset each.",
            "No credential, token or private marker is part of this catalog.",
            "Verdicts are produced by the existing BOLA and interaction engines against the "
            "loopback TargetLab; this catalog only names which pair of accounts to run.",
            "The frozen offline fixture (alice/bob, scope.yaml) is a separate dataset and is "
            "labelled separately in the interface.",
            "`coverage_pairs` is the minimum set of runs that answers all nine combinations; "
            "`pairs` lists every ordered pair the API accepts.",
        ],
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


def build_lab_scope(port: int, *, budget: int = 12, input_probes: tuple = (),
                    accounts: tuple[str, str] | None = None) -> AuthorizedScope:
    """Build the fixed local_lab scope for one TargetLab port and one account pair.

    ``accounts`` selects which two provisioned identities the run declares, and
    ``input_probes`` widens the single authentication POST. Nothing else about the
    lab can be configured. The scope declares exactly the pair the run uses, so the
    identities in the evidence are the identities the scan authenticated.
    """
    if not isinstance(input_probes, (tuple, list)) or any(
            probe not in INPUT_PROBE_NAMES for probe in input_probes):
        raise ValueError("unknown input probe")
    if accounts is not None and (not isinstance(accounts, (tuple, list)) or len(accounts) != 2):
        raise ValueError("accounts must name exactly one requester and one owner")
    pair = resolve_pair(*accounts) if accounts is not None else DEMO_PAIR
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
        "accounts": [{"account": name, "role": ACCOUNT_ROLES[name]}
                     for name in pair],
        "operations": operations,
    })


def build_lab_plan(port: int, *, budget: int = 12) -> LabPlan:
    if not isinstance(port, int) or not 1024 <= port <= 65535:
        raise ValueError("a TargetLab port between 1024 and 65535 is required")
    if not isinstance(budget, int) or not 7 <= budget <= 40:
        raise ValueError("a request budget between 7 and 40 is required")
    return LabPlan(scenario_id=SCENARIO_ID, title=TITLE,
                   scope=build_lab_scope(port, budget=budget, accounts=DEMO_PAIR),
                   credentials={name: LAB_PASSWORDS[name] for name in DEMO_PAIR})
