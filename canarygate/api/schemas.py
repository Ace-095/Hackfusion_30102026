"""Provisional frontend-facing API shapes, pending spec and team review."""
from typing import Literal

from pydantic import BaseModel

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
    scope_hash: str
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
