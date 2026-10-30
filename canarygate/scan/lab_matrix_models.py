"""Strict contract for the TargetLab 3x3 authorization matrix.

The matrix is an *aggregation* of stored read-BOLA runs. It adds no oracle and no
verdict of its own: every tested cell carries the run id, check id and evidence
hash of the check that produced it, and an untested cell has no verdict at all.
An untested cell is therefore never rendered as SAFE — the two states are
different types of fact.
"""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

MATRIX_VERDICTS = ("CONFIRMED", "SUSPECTED", "SAFE", "INCONCLUSIVE", "SKIPPED")
MATRIX_STATES = ("tested", "untested")
ACTUAL_ACCESS = ("private_record_returned", "denied", "not_attempted",
                 "unverified_response", "no_evidence")
KINDS = ("legitimate_owner_request", "cross_account_attempt")
CHECK_PATTERN = r"^LAB-BOLA-0[1-6]$"
RUN_ID_PATTERN = r"^[0-9a-fA-F-]{36}$"
TIMESTAMP_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$"


def actual_access_for(verdict, checklist, direction) -> str:
    """Map stored evidence to one observed-access label. Never guesses.

    The label is derived only from the booleans the oracle recorded, in a fixed
    order, so a cell cannot display an outcome the evidence does not support. An
    owner baseline is a successful read of the caller's own asset; it is not a
    disclosure and must not be labelled as one.
    """
    if verdict not in MATRIX_VERDICTS:
        return "no_evidence"
    if direction == "owner_baseline":
        if verdict == "SKIPPED":
            return "not_attempted"
        return ("private_record_returned" if checklist.get("owner_baseline") is True
                else "unverified_response")
    if checklist.get("private_disclosure") is True:
        return "private_record_returned"
    if checklist.get("verified_denial") is True:
        return "denied"
    if verdict == "SKIPPED":
        return "not_attempted"
    return "unverified_response"


class LabMatrixEvidence(BaseModel):
    """Where a tested cell came from and what the stored check recorded."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    run_id: str = Field(pattern=RUN_ID_PATTERN)
    check_id: str = Field(pattern=CHECK_PATTERN)
    direction: Literal["owner_baseline", "cross_account"]
    verdict: Literal[MATRIX_VERDICTS]
    status: int | None = Field(default=None, ge=100, le=599)
    endpoint: str = Field(pattern=r"^[A-Z]{3,16} /[A-Za-z0-9_{}./~-]{1,511}$")
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    created_at: str = Field(pattern=TIMESTAMP_PATTERN)
    port: int = Field(ge=1, le=65535)
    requests_sent: int = Field(ge=0, le=100000)
    checklist_true: int = Field(ge=0, le=32)
    checklist_total: int = Field(ge=0, le=32)
    private_disclosure: bool
    verified_denial: bool
    ownership_verified: bool
    owner_baseline: bool


class LabMatrixSecure(BaseModel):
    """The secure-route counterpart of a cross-account cell, from the same run."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    run_id: str = Field(pattern=RUN_ID_PATTERN)
    check_id: str = Field(pattern=CHECK_PATTERN)
    verdict: Literal[MATRIX_VERDICTS]
    status: int | None = Field(default=None, ge=100, le=599)
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    verified_denial: bool


class LabMatrixCell(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    requester: str = Field(min_length=1, max_length=64)
    asset_id: str = Field(min_length=1, max_length=64)
    owner: str = Field(min_length=1, max_length=64)
    kind: Literal[KINDS]
    state: Literal[MATRIX_STATES]
    expected_access: Literal["owner-only"]
    actual_access: Literal[ACTUAL_ACCESS]
    verdict: Literal[MATRIX_VERDICTS] | None = None
    reason: str | None = Field(default=None, max_length=1024)
    evidence: LabMatrixEvidence | None = None
    secure: LabMatrixSecure | None = None
    stale: bool
    sources: int = Field(ge=0, le=1000)
    superseded_runs: list[str] = Field(default_factory=list, max_length=32)

    @model_validator(mode="after")
    def coherent_cell(self):
        if (self.kind == "legitimate_owner_request") != (self.requester == self.owner):
            raise ValueError("a cell's kind must match whether the requester owns the asset")
        if self.state == "untested":
            if any(item is not None for item in
                   (self.verdict, self.evidence, self.secure, self.reason)):
                raise ValueError("an untested cell carries no verdict, reason or evidence")
            if self.sources or self.superseded_runs or self.stale:
                raise ValueError("an untested cell has no sources and no staleness")
            if self.actual_access != "no_evidence":
                raise ValueError("an untested cell observed nothing")
            return self
        if self.evidence is None or self.verdict is None or not self.reason:
            raise ValueError("a tested cell needs its evidence, verdict and reason")
        if self.sources < 1:
            raise ValueError("a tested cell names at least one source run")
        if self.verdict != self.evidence.verdict:
            raise ValueError("the cell verdict must be the stored check's verdict")
        expected_direction = ("owner_baseline" if self.kind == "legitimate_owner_request"
                              else "cross_account")
        if self.evidence.direction != expected_direction:
            raise ValueError("the cell direction must match the check direction")
        if self.kind == "legitimate_owner_request" and self.secure is not None:
            raise ValueError("an owner baseline has no recorded secure counterpart")
        if self.secure is not None and self.secure.run_id != self.evidence.run_id:
            raise ValueError("the secure counterpart must come from the same run")
        if self.actual_access != actual_access_for(self.verdict, {
                "private_disclosure": self.evidence.private_disclosure,
                "verified_denial": self.evidence.verified_denial,
                "owner_baseline": self.evidence.owner_baseline},
                self.evidence.direction):
            raise ValueError("the observed-access label must follow the stored booleans")
        return self


class LabMatrixAccount(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    account: str
    title: str
    role: str
    asset_id: str
    asset_type: str
    asset_label: str


class LabMatrixSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    cells: Literal[9] = 9
    tested: int = Field(ge=0, le=9)
    untested: int = Field(ge=0, le=9)
    confirmed: int = Field(ge=0, le=9)
    suspected: int = Field(ge=0, le=9)
    safe: int = Field(ge=0, le=9)
    inconclusive: int = Field(ge=0, le=9)
    skipped: int = Field(ge=0, le=9)
    runs_considered: int = Field(ge=0, le=10000)
    ports: list[int] = Field(max_length=32)
    stale_cells: int = Field(ge=0, le=9)
    duplicated_cells: int = Field(ge=0, le=9)

    @model_validator(mode="after")
    def consistent(self):
        if self.tested + self.untested != self.cells:
            raise ValueError("matrix summary does not cover nine cells")
        if (self.confirmed + self.suspected + self.safe + self.inconclusive
                + self.skipped) != self.tested:
            raise ValueError("verdict counts must describe exactly the tested cells")
        return self


class LabMatrix(BaseModel):
    """Nine cells assembled from stored runs; no cell is ever inferred."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    mode: Literal["targetlab_matrix"]
    dataset: Literal["demo_tenant"]
    derived_from: Literal["stored_lab_bola_runs"]
    generated_at: str = Field(pattern=TIMESTAMP_PATTERN)
    accounts: list[LabMatrixAccount] = Field(min_length=3, max_length=3)
    cells: list[LabMatrixCell] = Field(min_length=9, max_length=9)
    summary: LabMatrixSummary
    notes: list[str] = Field(min_length=1, max_length=12)

    @model_validator(mode="after")
    def coherent_matrix(self):
        keys = [(cell.requester, cell.asset_id) for cell in self.cells]
        if len(set(keys)) != 9:
            raise ValueError("matrix cells must be the nine unique combinations")
        by_owner = {item.account: item.asset_id for item in self.accounts}
        for cell in self.cells:
            if by_owner.get(cell.owner) != cell.asset_id:
                raise ValueError("a cell's owner must own the cell's asset")
        if sum(cell.state == "tested" for cell in self.cells) != self.summary.tested:
            raise ValueError("summary tested count must match the cells")
        return self
