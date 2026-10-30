"""Strict API/persistence contract for offline scenario scans."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator, model_validator

from canarygate.api.schemas import InventoryEndpoint
from canarygate.models.result import Verdict
from canarygate.oracles.read_bola import CHECKLIST_KEYS

_OWNERSHIP_KEYS = {"ownership_verified", "both_owner_baselines", "cross_list_isolation"}
_DISCLOSURE_KEYS = {"owner_baseline", "attacker_request", "response_checked",
                    "private_disclosure", "verified_denial"}


class ScenarioEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    phase: Literal["ownership", "disclosure"]
    timestamp: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$")
    actor: str = Field(pattern=r"^[A-Za-z0-9_.@-]{1,128}$")
    role: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,64}$")
    method: Literal["GET"]
    path_template: str = Field(pattern=r"^/[A-Za-z0-9_./{}~-]{1,511}$")
    status_code: int = Field(ge=100, le=599)
    checklist: dict[str, StrictBool]
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    redacted: Literal[True]

    @model_validator(mode="after")
    def allowed_flags(self):
        allowed = _OWNERSHIP_KEYS if self.phase == "ownership" else _DISCLOSURE_KEYS
        if not self.checklist or not set(self.checklist).issubset(allowed):
            raise ValueError("evidence checklist contains unsupported flags")
        return self


class ScenarioEvidencePair(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    ownership: ScenarioEvidence | None
    disclosure: ScenarioEvidence | None


class ScenarioAccount(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    account: str
    role: str


class ScenarioScope(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    origin: str = Field(pattern=r"^https?://[A-Za-z0-9.\-\[\]:]{1,255}$")
    hostname: str
    port: int = Field(ge=1, le=65535)
    written_authorization_reference: str = Field(pattern=r"^[ -~]{1,256}$")
    scope_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    request_budget: int = Field(gt=0, le=100000)
    accounts: list[ScenarioAccount] = Field(min_length=2, max_length=64)


class ScenarioRecipe(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    resource_type: str
    discovery: str
    detail: str
    id_field: str
    ownership_field: str
    ownership_model: Literal["private", "shared", "public"]
    private_field: str


class ScenarioPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    expected_access: str
    expected_source: str


class ScenarioSetup(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    authentication: Literal["SYNTHETIC_PREPROVISIONED"]
    ownership_verification: Literal["SUCCESS", "FAILED", "PARTIAL", "SKIPPED"]
    bola_coverage: Literal["SUCCESS", "FAILED", "BLOCKED", "SKIPPED"]
    reason: str | None = Field(default=None, max_length=512)


class ScenarioConstraints(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    requests_sent: int = Field(ge=0, le=100000)
    blocked_by_guard: int = Field(ge=0, le=100000)
    redirects_observed: int = Field(ge=0, le=100000)
    redirects_followed: int = Field(ge=0, le=100000)
    out_of_scope_requests_executed: Literal[0]
    destructive_requests_executed: Literal[0]
    external_requests_executed: Literal[0]
    budget_remaining: int = Field(ge=0, le=100000)
    network_transport_enabled: Literal[False]
    halted_reason: str | None


class ScenarioChecklist(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    values: dict[str, StrictBool]

    @model_validator(mode="after")
    def exact_keys(self):
        if set(self.values) != set(CHECKLIST_KEYS):
            raise ValueError("checklist must contain exactly the read-BOLA decision keys")
        return self


class ScenarioRun(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    id: str = Field(pattern=r"^[0-9a-fA-F-]{36}$")
    created_at: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$")
    mode: Literal["offline_scenario"]
    status: Literal["completed", "failed"]
    scenario_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")
    transport: Literal["offline_transcript"]
    network_transport_enabled: Literal[False]
    scope: ScenarioScope
    recipe: ScenarioRecipe
    policy: ScenarioPolicy
    setup: ScenarioSetup
    evidence: ScenarioEvidencePair
    checklist: dict[str, StrictBool]
    verdict: Verdict
    reason: str = Field(min_length=1, max_length=1024)
    remediation: str | None = Field(default=None, max_length=1024)
    constraints: ScenarioConstraints
    inventory: list[InventoryEndpoint] = Field(max_length=64)
    transcript_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    limitations: list[str] = Field(min_length=1, max_length=16)

    @field_validator("checklist")
    @classmethod
    def exact_checklist(cls, value):
        if set(value) != set(CHECKLIST_KEYS) or any(type(item) is not bool for item in value.values()):
            raise ValueError("checklist must contain exactly the decision booleans")
        return value


class ScenarioScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    scenario_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")


class ScenarioSectionData(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    executive_summary: dict
    scope_and_accounts: dict
    endpoint_inventory: list[dict]
    bola_evidence: dict
    outcome: dict
    constraints: dict
    limitations: list[str]


class ScenarioSectionReport(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    mode: Literal["offline_scenario"]
    id: str
    run_id: str
    sections: ScenarioSectionData
