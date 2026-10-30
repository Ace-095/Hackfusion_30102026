"""Strict contract for the TargetLab interaction run's companion artifacts.

The primary interaction run reuses the existing ``InteractionRun`` model (widened
by one mode); this module owns only what the lab adds: the reset proof and the
API request/report envelopes.
"""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator

RESET_IDS = ("RESET-01", "RESET-02", "RESET-03", "RESET-04")


class LabSciScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    port: int = Field(ge=1024, le=65535)
    request_budget: int = Field(default=16, ge=8, le=40)


class ResetCheck(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    id: str
    title: str = Field(min_length=1, max_length=160)
    endpoint: str = Field(pattern=r"^[A-Z]{3,16} /[A-Za-z0-9_{}./~-]{1,511}$")
    actor: str = Field(pattern=r"^[A-Za-z0-9_.@-]{1,128}$")
    expected_status: int = Field(ge=100, le=599)
    status: int | None = Field(default=None, ge=100, le=599)
    observed: str = Field(min_length=1, max_length=512)
    passed: StrictBool
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def coherent_check(self):
        if self.id not in RESET_IDS:
            raise ValueError("unknown reset check id")
        if self.passed and self.status != self.expected_status:
            raise ValueError("a passed reset check must record the expected status")
        return self


class LabResetProof(BaseModel):
    """A separate controlled scenario; it carries no security verdict of its own."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    id: str = Field(pattern=r"^[0-9a-fA-F-]{36}$")
    created_at: str = Field(
        pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$")
    mode: Literal["targetlab_sci_reset"]
    scenario_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")
    status: Literal["proven", "not_proven"]
    reason: str = Field(min_length=1, max_length=1024)
    port: int = Field(ge=1024, le=65535)
    checks: list[ResetCheck] = Field(min_length=4, max_length=4)
    isolation: dict
    disclosure: dict
    transport: dict
    requests: dict
    limitations: list[str] = Field(min_length=1, max_length=16)

    @model_validator(mode="after")
    def coherent_proof(self):
        if [check.id for check in self.checks] != list(RESET_IDS):
            raise ValueError("reset checks must be present once each in canonical order")
        all_passed = all(check.passed for check in self.checks)
        if self.status == "proven" and not all_passed:
            raise ValueError("a proven reset needs every check to pass")
        if self.status == "not_proven" and all_passed:
            raise ValueError("a failed reset must record a failing check")
        if self.isolation.get("runners") != 2:
            raise ValueError("the reset proof needs two isolated runs")
        return self


class LabSciSectionData(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    executive_summary: dict
    scope_and_accounts: dict
    baselines: list[dict]
    combined: dict
    decision: dict
    disclosure: dict
    ownership: dict
    evaluation: dict
    reset_verification: dict | None = None
    limitations: list[str]


class LabSciSectionReport(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    mode: Literal["targetlab_sci"]
    id: str
    run_id: str
    sections: LabSciSectionData
