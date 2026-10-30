"""Strict contract for the TargetLab three-by-three asset matrix.

The matrix answers one question — *which of the nine account x asset combinations
has a stored check, and what did that check record?* — and nothing else. It adds
no oracle and computes no verdict: every tested cell carries the stored verdict,
the run id, the check id and the evidence digest it came from.

Two states are deliberately distinct:

* ``tested``   — a stored check answered this combination; ``verdict`` is that
  check's verdict and ``evidence`` describes where it came from;
* ``untested`` — no stored check answered it. There is no verdict at all, and the
  model refuses to carry one, so a missing result can never be rendered as SAFE,
  SKIPPED or INCONCLUSIVE. Absence of evidence is its own state, not a pass.
"""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

MATRIX_VERDICTS = ("CONFIRMED", "SUSPECTED", "SAFE", "INCONCLUSIVE", "SKIPPED")
MATRIX_STATES = ("tested", "untested")
ACTUAL_ACCESS = ("own_record_returned", "private_record_returned", "denied",
                 "not_attempted", "unverified_response", "no_evidence")
DIRECTIONS = ("owner_baseline", "cross_account")


def actual_access_for(direction: str, verdict: str, checklist: dict,
                      status: int | None) -> str:
    """Map stored booleans to one observed-access label. Never guesses.

    The label is derived only from facts the check already recorded; it is a
    presentation of the stored evidence, not a second decision. A confirmed cross
    read needs a recorded private disclosure, a safe one a verified denial, and an
    owner baseline needs the owner's own record to have come back.
    """
    if verdict == "SKIPPED":
        return "not_attempted"
    if checklist.get("verified_denial") is True:
        return "denied"
    if direction == "owner_baseline":
        if checklist.get("owner_baseline") is True and status == 200:
            return "own_record_returned"
        return "unverified_response"
    if checklist.get("private_disclosure") is True:
        return "private_record_returned"
    if status == 403:
        return "denied"
    return "unverified_response"


class LabMatrixEvidence(BaseModel):
    """Where a tested cell came from and what the stored check recorded."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    #: Stable pointer to the observation: ``<run id>#<check id>``.
    evidence_id: str = Field(pattern=r"^[0-9a-fA-F-]{36}#LAB-BOLA-0[1-6]$")
    run_id: str = Field(pattern=r"^[0-9a-fA-F-]{36}$")
    check_id: str = Field(pattern=r"^LAB-BOLA-0[1-6]$")
    direction: Literal["owner_baseline", "cross_account"]
    verdict: Literal[MATRIX_VERDICTS]
    status: int | None = Field(default=None, ge=100, le=599)
    endpoint: str = Field(pattern=r"^[A-Z]{3,16} /[A-Za-z0-9_{}./~-]{1,511}$")
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    created_at: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$")
    port: int = Field(ge=1, le=65535)
    #: The lab process that answered, when the lab published an identity header.
    lab_instance: str | None = Field(default=None, pattern=r"^[0-9a-f]{16}$")
    requests_sent: int = Field(ge=0, le=100000)
    checklist_true: int = Field(ge=0, le=12)
    checklist_total: int = Field(ge=0, le=12)
    private_disclosure: bool
    verified_denial: bool
    owner_baseline: bool
    #: The oracle's remediation text, present only on a confirmed check.
    remediation: str | None = Field(default=None, max_length=1024)


class LabMatrixSecure(BaseModel):
    """The secure-route counterpart of a cross-account cell, from the same run."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    run_id: str = Field(pattern=r"^[0-9a-fA-F-]{36}$")
    check_id: str = Field(pattern=r"^LAB-BOLA-0[1-6]$")
    status: int | None = Field(default=None, ge=100, le=599)
    verdict: Literal[MATRIX_VERDICTS]
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    verified_denial: bool


class LabMatrixCell(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    requester: str = Field(min_length=1, max_length=64)
    asset_id: str = Field(min_length=1, max_length=64)
    owner: str = Field(min_length=1, max_length=64)
    kind: Literal["legitimate_owner_request", "cross_account_attempt"]
    state: Literal[MATRIX_STATES]
    expected_access: Literal["owner-only"]
    actual_access: Literal[ACTUAL_ACCESS]
    verdict: Literal[MATRIX_VERDICTS] | None = None
    reason: str | None = Field(default=None, max_length=1024)
    evidence: LabMatrixEvidence | None = None
    secure: LabMatrixSecure | None = None
    stale: bool = False
    sources: int = Field(default=0, ge=0, le=1000)
    superseded_runs: list[str] = Field(default_factory=list, max_length=32)

    @model_validator(mode="after")
    def coherent_cell(self):
        if (self.kind == "legitimate_owner_request") != (self.requester == self.owner):
            raise ValueError("cell kind must match whether the requester owns the asset")
        if self.state == "untested":
            if any(item is not None for item in (self.verdict, self.evidence, self.secure,
                                                 self.reason)):
                raise ValueError("an untested cell carries no verdict, reason or evidence")
            if self.sources or self.superseded_runs or self.stale:
                raise ValueError("an untested cell has no sources and cannot be stale")
            if self.actual_access != "no_evidence":
                raise ValueError("an untested cell observed nothing")
            return self
        # Tested cells restate one stored check, and only that check.
        if self.evidence is None or self.verdict is None or not self.reason:
            raise ValueError("a tested cell needs its evidence, verdict and reason")
        if self.sources < 1:
            raise ValueError("a tested cell names at least one stored check")
        if self.verdict != self.evidence.verdict:
            raise ValueError("the cell verdict must be the stored check's verdict")
        expected_direction = ("owner_baseline" if self.kind == "legitimate_owner_request"
                              else "cross_account")
        if self.evidence.direction != expected_direction:
            raise ValueError("the stored check direction must match the cell kind")
        if self.kind == "legitimate_owner_request" and self.secure is not None:
            raise ValueError("an owner cell has no recorded cross-account secure check")
        if self.secure is not None:
            if self.secure.run_id != self.evidence.run_id:
                raise ValueError("the secure counterpart must come from the same run")
            if self.secure.check_id == self.evidence.check_id:
                raise ValueError("the secure counterpart must be a different check")
        computed = actual_access_for(
            self.evidence.direction, self.verdict,
            {"verified_denial": self.evidence.verified_denial,
             "private_disclosure": self.evidence.private_disclosure,
             "owner_baseline": self.evidence.owner_baseline},
            self.evidence.status)
        if self.actual_access != computed:
            raise ValueError("actual_access must follow the stored evidence")
        if self.verdict == "SAFE" and self.actual_access not in {"own_record_returned",
                                                                 "denied"}:
            raise ValueError("a SAFE cell must show a verified denial or an owner read")
        if self.verdict == "CONFIRMED" and self.actual_access != "private_record_returned":
            raise ValueError("a confirmed cell must show a recorded private disclosure")
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
    ports: list[int] = Field(default_factory=list, max_length=32)
    #: Distinct lab processes (``X-Lab-Instance``) the evidence came from.
    lab_instances: int = Field(ge=0, le=10000)
    stale_cells: int = Field(ge=0, le=9)
    duplicated_cells: int = Field(ge=0, le=9)

    @model_validator(mode="after")
    def consistent(self):
        if self.tested + self.untested != self.cells:
            raise ValueError("tested + untested must describe nine cells")
        if (self.confirmed + self.suspected + self.safe + self.inconclusive
                + self.skipped) != self.tested:
            raise ValueError("verdict counts must describe exactly the tested cells")
        if self.stale_cells > self.tested or self.duplicated_cells > self.tested:
            raise ValueError("stale and duplicated cells must be tested cells")
        return self


class LabMatrix(BaseModel):
    """Nine cells assembled from stored runs; no cell is ever inferred."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    mode: Literal["targetlab_matrix"]
    dataset: Literal["demo_tenant"]
    derived_from: Literal["stored_lab_bola_runs"]
    evaluated_after_verdicts: Literal[True]
    used_as_decision_input: Literal[False]
    generated_at: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
    accounts: list[LabMatrixAccount] = Field(min_length=3, max_length=3)
    cells: list[LabMatrixCell] = Field(min_length=9, max_length=9)
    summary: LabMatrixSummary
    notes: list[str] = Field(min_length=1, max_length=16)

    @model_validator(mode="after")
    def coherent_matrix(self):
        combos = [(cell.requester, cell.asset_id) for cell in self.cells]
        if len(set(combos)) != 9:
            raise ValueError("the matrix must contain nine distinct combinations")
        assets = {account.asset_id for account in self.accounts}
        expected = {(account.account, asset)
                    for account in self.accounts for asset in assets}
        if set(combos) != expected:
            raise ValueError("the matrix cells must be the catalog's nine combinations")
        by_account = {account.account: account for account in self.accounts}
        for cell in self.cells:
            if (cell.owner not in by_account
                    or by_account[cell.owner].asset_id != cell.asset_id):
                raise ValueError("a cell's asset must belong to the named owner")
        counted = sum(cell.state == "tested" for cell in self.cells)
        if counted != self.summary.tested:
            raise ValueError("the summary must count the cells it carries")
        return self
