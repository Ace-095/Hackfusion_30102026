"""Strict contract for TargetLab read-BOLA runs (loopback HTTPS, real requests)."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator

CHECK_IDS = ("LAB-BOLA-01", "LAB-BOLA-02", "LAB-BOLA-03",
             "LAB-BOLA-04", "LAB-BOLA-05", "LAB-BOLA-06")
DIRECTIONS = ("owner_baseline", "cross_account", "cross_account_secure")
VERDICT_ORDER = ("CONFIRMED", "SUSPECTED", "INCONCLUSIVE", "SKIPPED", "SAFE")


class LabBolaCheck(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    id: str
    title: str = Field(min_length=1, max_length=120)
    direction: Literal["owner_baseline", "cross_account", "cross_account_secure"]
    endpoint: str = Field(pattern=r"^[A-Z]{3,16} /[A-Za-z0-9_{}./~-]{1,511}$")
    actor: str = Field(pattern=r"^[A-Za-z0-9_.@-]{1,128}$")
    owner: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.@-]{1,128}$")
    status: int | None = Field(default=None, ge=100, le=599)
    verdict: Literal["CONFIRMED", "SUSPECTED", "SAFE", "INCONCLUSIVE", "SKIPPED"]
    reason: str = Field(min_length=1, max_length=1024)
    checklist: dict[str, StrictBool]
    evidence: dict
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    remediation: str | None = Field(default=None, max_length=1024)

    @model_validator(mode="after")
    def coherent_check(self):
        if self.id not in CHECK_IDS:
            raise ValueError("unknown TargetLab BOLA check id")
        if len(self.checklist) > 12 or len(self.evidence) > 16:
            raise ValueError("check evidence must stay bounded")
        if self.verdict == "CONFIRMED" and not self.remediation:
            raise ValueError("a confirmed BOLA finding requires a remediation")
        if self.verdict != "CONFIRMED" and self.remediation is not None:
            raise ValueError("only a confirmed finding carries a remediation")
        if self.verdict in {"SAFE", "CONFIRMED"} and self.status is None:
            raise ValueError("a deciding verdict requires a recorded status")
        if self.direction == "owner_baseline" and self.owner not in (None, self.actor):
            raise ValueError("an owner baseline reads the actor's own resource")
        return self


class LabBolaSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    total: Literal[6]
    confirmed: int = Field(ge=0, le=6)
    safe: int = Field(ge=0, le=6)
    suspected: int = Field(ge=0, le=6)
    inconclusive: int = Field(ge=0, le=6)
    skipped: int = Field(ge=0, le=6)

    @model_validator(mode="after")
    def consistent(self):
        if (self.confirmed + self.safe + self.suspected + self.inconclusive
                + self.skipped) != self.total:
            raise ValueError("BOLA summary totals are inconsistent")
        return self


class GroundTruthRow(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    check_id: str
    expected: str
    observed: str
    matched: bool

    @model_validator(mode="after")
    def known(self):
        if self.check_id not in CHECK_IDS:
            raise ValueError("unknown ground-truth check id")
        return self


class GroundTruthComparison(BaseModel):
    """Evaluated after the verdicts exist; never an input to the decision."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    source: Literal["declared_targetlab_ground_truth"]
    evaluated_after_verdicts: Literal[True]
    used_as_decision_input: Literal[False]
    rows: list[GroundTruthRow] = Field(min_length=6, max_length=6)
    matched: int = Field(ge=0, le=6)
    mismatched: int = Field(ge=0, le=6)
    statement: str = Field(min_length=1, max_length=512)


class LabBolaTransport(BaseModel):
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
    live_target_contacted: Literal[False]
    production_networking: Literal[False]


class LabBolaConstraints(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    requests_sent: int = Field(ge=0, le=100000)
    blocked_by_guard: int = Field(ge=0, le=100000)
    budget_remaining: int = Field(ge=0, le=100000)
    halted: bool
    redirects_observed: Literal[0]
    destructive_requests_executed: Literal[0]


class LabBolaRun(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    id: str = Field(pattern=r"^[0-9a-fA-F-]{36}$")
    created_at: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$")
    mode: Literal["targetlab_bola"]
    status: Literal["completed", "failed"]
    scenario_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")
    title: str = Field(min_length=1, max_length=120)
    verdict: Literal["CONFIRMED", "SUSPECTED", "SAFE", "INCONCLUSIVE", "SKIPPED"]
    reason: str = Field(min_length=1, max_length=1024)
    scope: dict
    transport: LabBolaTransport
    recipe: dict
    policy: dict
    ownership: dict
    checks: list[LabBolaCheck] = Field(min_length=6, max_length=6)
    summary: LabBolaSummary
    ground_truth: GroundTruthComparison
    constraints: LabBolaConstraints
    inventory: list[dict] = Field(max_length=32)
    evidence: dict
    checklist: dict[str, StrictBool]
    remediation: str | None = Field(default=None, max_length=1024)
    transcript_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    limitations: list[str] = Field(min_length=1, max_length=16)

    @model_validator(mode="after")
    def ordered_checks(self):
        if [check.id for check in self.checks] != list(CHECK_IDS):
            raise ValueError("BOLA checks must be present once each in canonical order")
        if self.verdict == "CONFIRMED" and not self.remediation:
            raise ValueError("a confirmed run requires a remediation")
        return self


class LabBolaScanRequest(BaseModel):
    """One read-BOLA run.

    ``actor`` and ``owner`` select the ordered pair of provisioned demo accounts.
    Omitted, the run uses the documented default pair. No field can name a host, a
    path, a credential or an expected verdict.
    """

    model_config = ConfigDict(extra="forbid", strict=True)
    port: int = Field(ge=1024, le=65535)
    request_budget: int = Field(default=20, ge=16, le=40)
    actor: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_-]{2,31}$")
    owner: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_-]{2,31}$")


class LabBolaSectionData(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    executive_summary: dict
    scope_and_transport: dict
    ownership: dict
    checks: list[dict]
    ground_truth: dict
    constraints: dict
    limitations: list[str]


class LabBolaSectionReport(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    mode: Literal["targetlab_bola"]
    id: str
    run_id: str
    sections: LabBolaSectionData
