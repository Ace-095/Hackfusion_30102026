"""Provisional frontend-facing API shapes, pending spec and team review."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool

from canarygate.models.result import Verdict


class Health(BaseModel):
    status: Literal["ok"]
    mode: Literal["fixture"]
    live_scanning: Literal[False]


class InventoryEndpoint(BaseModel):
    method: str
    path: str
    parameters: list[dict]
    security: list[dict]
    expected_access: str
    expected_source: str


class Inventory(BaseModel):
    mode: Literal["fixture"]
    endpoints: list[InventoryEndpoint]


class SpecInspection(BaseModel):
    mode: Literal["inventory_only"]
    live_scanning: Literal[False]
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    endpoint_count: int
    endpoints: list[InventoryEndpoint]
    message: str


class FixtureSetup(BaseModel):
    strategy: str
    authentication: str
    accounts: dict[str, str]
    resources: str
    ownership_verification: str
    bola_coverage: str
    reason: str | None


class SetupResponse(BaseModel):
    mode: Literal["fixture"]
    setup: FixtureSetup | None
    message: str


class EvidenceSummary(BaseModel):
    timestamp: str
    actor: str
    role: str
    method: str
    path: str
    status_code: int
    private_canary_matched: bool
    request: dict
    response: dict
    checklist: dict
    sha256: str
    redacted: Literal[True]


class FixtureEvidence(BaseModel):
    ownership: EvidenceSummary | None
    disclosure: EvidenceSummary | None


class SecurityCheck(BaseModel):
    id: str
    category: Literal["Authentication", "Input validation", "Disclosure"]
    verdict: Verdict
    reason: str
    evidence: EvidenceSummary | None
    remediation: str | None


class FixtureConstraints(BaseModel):
    mode: Literal["fixture"]
    scope: str
    requests_sent: int
    authentication_requests: int
    blocked_by_guard: int
    redirects_observed: int
    redirects_followed: int
    out_of_scope_requests_executed: int
    destructive_requests_executed: int
    external_requests_executed: int
    network_transport_enabled: Literal[False]
    halted_reason: str | None


class FixtureRun(BaseModel):
    id: str
    created_at: str
    mode: Literal["fixture"]
    status: Literal["completed", "failed"]
    endpoint: str
    actor: str
    account_role: str
    target_resource: str
    verified_owner: str
    expected_access: str
    expected_source: str
    setup: FixtureSetup
    evidence: FixtureEvidence
    checks: list[SecurityCheck]
    verdict: Verdict
    reason: str
    remediation: str | None
    # Empty on pre-checkpoint stored records; do not infer historical evidence.
    bola_checklist: dict[Literal["private_resource", "distinct_accounts", "ownership_verified",
                                 "owner_baseline", "private_baseline", "attacker_request",
                                 "response_checked", "private_disclosure", "policy_denies_access",
                                 "verified_denial"], StrictBool] = Field(default_factory=dict)
    scope_hash: str
    spec_hash: str
    inventory: list[InventoryEndpoint]
    constraints: FixtureConstraints


class FindingsResponse(BaseModel):
    mode: Literal["fixture"]
    findings: list[FixtureRun]


class MatrixCell(BaseModel):
    id: str
    endpoint: str
    actor: str
    target_resource: str
    expected_access: str
    expected_source: str
    verdict: Verdict


class MatrixResponse(BaseModel):
    mode: Literal["fixture"]
    cells: list[MatrixCell]

# Additive fixture-only observation contract. Existing FixtureRun responses and
# pre-checkpoint SQLite records remain unchanged.


class ObservationItem(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    id: Literal["alice-item", "bob-item", "[REDACTED]"] | None
    owner: Literal["alice", "bob", "[REDACTED]"] | None
    private_field_present: bool


class ObservationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    method: Literal["GET"]
    path: Literal["/items", "/items/alice-item", "/items/bob-item"]
    authorization: Literal["[REDACTED]", "not supplied"]


class ObservationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    status_code: int = Field(ge=100, le=599)
    items: list[ObservationItem] | None = Field(default=None, max_length=20)
    item_count: int | None = Field(default=None, ge=0)
    items_truncated: bool | None = None
    item: ObservationItem | None = None


class ObservationAssertions(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    own_resource_identified: bool | None = None
    peer_resource_excluded: bool | None = None
    owner_detail_matches: bool | None = None
    canary_matches_recipe: bool | None = None
    private_data_matches_owner_baseline: bool | None = None


class FixtureObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    phase: Literal["discovery", "owner_baseline", "cross_user_read"]
    timestamp: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$")
    actor: Literal["alice", "bob"]
    role: Literal["user"]
    request: ObservationRequest
    response: ObservationResponse
    assertions: ObservationAssertions
    redacted: Literal[True]
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ObservationSet(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    mode: Literal["fixture"]
    run_id: str
    coverage: Literal["RECORDED", "NOT_RECORDED"]
    observations: list[FixtureObservation] = Field(max_length=20)


class FixtureReportBundle(BaseModel):
    run: FixtureRun
    observation_set: ObservationSet


class FixtureSectionData(BaseModel):
    """Fixture-only nine-section projection, not the complete P0 report contract."""
    model_config = ConfigDict(extra="forbid")
    executive_summary: dict
    scope_accounts_seeding: dict
    endpoint_inventory: list[dict]
    findings: dict
    secured_endpoints: list[dict]
    skipped_and_inconclusive: list[dict]
    authorization_matrix: dict
    manual_interventions_and_inferences: dict
    constraint_checklist: dict


class FixtureSectionReport(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["fixture"]
    run_id: str
    sections: FixtureSectionData


class LabCatalogPair(BaseModel):
    """The ordered pair of demo accounts a scan authenticates for one combination."""

    model_config = ConfigDict(extra="forbid", strict=True)
    actor: str
    owner: str


class LabCatalogAccount(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    account: str
    title: str
    role: str
    asset_id: str
    asset_type: str
    asset_label: str


class LabCatalogCombination(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    actor: str
    asset_id: str
    owner: str
    kind: Literal["legitimate_owner_request", "cross_account_attempt"]
    pair: LabCatalogPair


class LabCatalog(BaseModel):
    """Public demo-tenant catalog. No credential and no verdict is part of it."""

    model_config = ConfigDict(extra="forbid", strict=True)
    mode: Literal["targetlab_demo"]
    dataset: Literal["demo_tenant"]
    accounts: list[LabCatalogAccount] = Field(min_length=3, max_length=3)
    pairs: list[LabCatalogPair] = Field(min_length=6, max_length=6)
    combinations: list[LabCatalogCombination] = Field(min_length=9, max_length=9)
    notes: list[str] = Field(min_length=1, max_length=8)
