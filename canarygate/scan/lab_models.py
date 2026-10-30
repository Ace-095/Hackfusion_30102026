"""Strict contract for TargetLab evidence runs (loopback HTTPS)."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

CHECK_IDS = ("LAB-01", "LAB-02", "LAB-03", "LAB-04", "LAB-05", "LAB-06", "LAB-07")
OBSERVATIONS = ("denied", "allowed_owner", "allowed_other", "unexpected_status",
                "unverified", "blocked_by_guard")


class LabCheck(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    id: str
    title: str = Field(min_length=1, max_length=120)
    endpoint: str = Field(pattern=r"^[A-Z]{3,16} /[A-Za-z0-9_{}./~-]{1,511}$")
    actor: str = Field(pattern=r"^[A-Za-z0-9_.@-]{1,128}$")
    status: int | None = Field(default=None, ge=100, le=599)
    observation: Literal["denied", "allowed_owner", "allowed_other", "unexpected_status",
                         "unverified", "blocked_by_guard"]
    verified: bool
    evidence: dict
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def known_id(self):
        if self.id not in CHECK_IDS:
            raise ValueError("unknown lab check id")
        if len(self.evidence) > 12:
            raise ValueError("evidence must stay bounded")
        return self


class LabSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    total: Literal[7]
    # Accounts that authenticated successfully (0-2); not part of the check tally.
    authenticated: int = Field(ge=0, le=2)
    denied: int = Field(ge=0, le=7)
    allowed: int = Field(ge=0, le=7)
    unverified: int = Field(ge=0, le=7)
    blocked: int = Field(default=0, ge=0, le=7)

    @model_validator(mode="after")
    def consistent(self):
        if self.denied + self.allowed + self.unverified + self.blocked != self.total:
            raise ValueError("lab summary totals are inconsistent")
        return self


class LabTransportInfo(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    mode: Literal["local_lab"]
    scheme: Literal["https"]
    destination: Literal["127.0.0.1"]
    port: int = Field(ge=1, le=65535)
    tls_verification: Literal["pinned_test_ca_with_hostname_check"]
    redirects: Literal["refused"]
    retries: Literal["none"]
    dns: Literal["not_used"]
    network_transport_enabled: Literal[True]
    production_networking: Literal[False]


class LabConstraints(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    requests_sent: int = Field(ge=0, le=100000)
    blocked_by_guard: int = Field(ge=0, le=100000)
    budget_remaining: int = Field(ge=0, le=100000)
    halted: bool
    redirects_observed: Literal[0]


class LabRun(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    id: str = Field(pattern=r"^[0-9a-fA-F-]{36}$")
    created_at: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$")
    mode: Literal["targetlab_https"]
    status: Literal["completed", "failed"]
    scenario_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")
    title: str = Field(min_length=1, max_length=120)
    scope: dict
    transport: LabTransportInfo
    checks: list[LabCheck] = Field(min_length=7, max_length=7)
    summary: LabSummary
    constraints: LabConstraints
    transcript_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    limitations: list[str] = Field(min_length=1, max_length=16)

    @model_validator(mode="after")
    def ordered_checks(self):
        if [check.id for check in self.checks] != list(CHECK_IDS):
            raise ValueError("lab checks must be present once each in canonical order")
        return self


class LabScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    port: int = Field(ge=1024, le=65535)
    request_budget: int = Field(default=12, ge=7, le=40)


class LabSectionData(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    executive_summary: dict
    scope_and_transport: dict
    checks: list[dict]
    constraints: dict
    limitations: list[str]


class LabSectionReport(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    mode: Literal["targetlab_https"]
    id: str
    run_id: str
    sections: LabSectionData
