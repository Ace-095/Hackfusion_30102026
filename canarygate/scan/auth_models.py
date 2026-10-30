"""Strict API and persistence contract for offline authentication runs."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator, model_validator

from canarygate.models.result import Verdict
from canarygate.scan.auth_transcript import PROBE_NAMES
from canarygate.scan.models import ScenarioConstraints, ScenarioScope

CHECK_IDS = ("AUTHN-01", "AUTHN-02", "AUTHN-03", "AUTHN-04a", "AUTHN-04b",
             "AUTHN-05", "AUTHN-06", "AUTHN-08")
IDENTITY_PROBE_KEYS = {"response_checked", "identity_observed", "identity_changed", "denial_body_checked"}
ROLE_PROBE_KEYS = {"response_checked", "capability_observed", "capability_granted", "denial_body_checked"}
LOGOUT_KEYS = {"logout_observed", "post_logout_rejected", "post_logout_accepted", "baseline_identity"}
API_KEY_KEYS = {"missing_key_checked", "invalid_key_checked", "identity_observed", "denial_body_checked"}
FLAGS_BY_CHECK = {
    "AUTHN-01": IDENTITY_PROBE_KEYS, "AUTHN-02": IDENTITY_PROBE_KEYS, "AUTHN-03": IDENTITY_PROBE_KEYS,
    "AUTHN-04a": IDENTITY_PROBE_KEYS, "AUTHN-04b": ROLE_PROBE_KEYS, "AUTHN-05": IDENTITY_PROBE_KEYS,
    "AUTHN-06": LOGOUT_KEYS, "AUTHN-08": API_KEY_KEYS,
}


class AuthenticationEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    phase: Literal["probe", "logout"]
    timestamp: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$")
    actor: str = Field(pattern=r"^[A-Za-z0-9_.@-]{1,128}$")
    role: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,64}$")
    method: Literal["GET", "POST"]
    path_template: str = Field(pattern=r"^/[A-Za-z0-9_./{}~-]{1,511}$")
    probe: Literal["missing", "malformed", "wrong_scheme", "jwt_sub", "jwt_role", "alg_none",
                   "api_key_missing", "api_key_invalid", "logout_reuse", "logout"]
    status_code: int = Field(ge=100, le=599)
    identity_effect: Literal["self", "target", "other", "unobserved"]
    capability: Literal["granted", "none", "unobserved"] | None = None
    denial_body_checked: StrictBool
    alternate_status_code: int | None = Field(default=None, ge=100, le=599)
    checklist: dict[str, StrictBool]
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    redacted: Literal[True]

    @field_validator("probe")
    @classmethod
    def known_probe(cls, value):
        if value not in PROBE_NAMES:
            raise ValueError("unknown probe in evidence")
        return value


class AuthenticationCheck(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    id: str
    category: Literal["Authentication"]
    verdict: Verdict
    reason: str = Field(min_length=1, max_length=1024)
    evidence: AuthenticationEvidence | None
    remediation: str | None = Field(default=None, max_length=1024)

    @field_validator("id")
    @classmethod
    def known_check(cls, value):
        if value not in CHECK_IDS:
            raise ValueError("unknown authentication check id")
        return value

    @model_validator(mode="after")
    def coherent_evidence(self):
        if self.evidence is None:
            if self.verdict in ("SAFE", "CONFIRMED"):
                raise ValueError("a deciding verdict requires evidence")
            return self
        allowed = FLAGS_BY_CHECK[self.id]
        if not self.evidence.checklist or not set(self.evidence.checklist).issubset(allowed):
            raise ValueError("evidence checklist contains unsupported flags")
        if self.evidence.path_template not in {"/profile", "/admin/users"}:
            raise ValueError("evidence path is not an offline authentication endpoint")
        if self.verdict == "CONFIRMED" and not self.remediation:
            raise ValueError("a confirmed authentication finding requires remediation")
        return self


class AuthenticationSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    total: Literal[8]
    executed: int = Field(ge=0, le=8)
    confirmed: int = Field(ge=0, le=8)
    suspected: int = Field(ge=0, le=8)
    safe: int = Field(ge=0, le=8)
    inconclusive: int = Field(ge=0, le=8)
    skipped: int = Field(ge=0, le=8)

    @model_validator(mode="after")
    def consistent_totals(self):
        counted = self.confirmed + self.suspected + self.safe + self.inconclusive + self.skipped
        if counted != self.total or self.executed != self.total - self.skipped:
            raise ValueError("authentication summary totals are inconsistent")
        return self


class AuthenticationRun(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    id: str = Field(pattern=r"^[0-9a-fA-F-]{36}$")
    created_at: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$")
    mode: Literal["offline_authentication"]
    status: Literal["completed", "failed"]
    scenario_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")
    title: str = Field(min_length=1, max_length=120)
    transport: Literal["offline_transcript"]
    network_transport_enabled: Literal[False]
    scheme: Literal["bearer_jwt", "bearer_opaque", "api_key"]
    claims_unverified: Literal[True]
    signature_verification: Literal["not_performed"]
    scope: ScenarioScope
    checks: list[AuthenticationCheck] = Field(min_length=8, max_length=8)
    summary: AuthenticationSummary
    constraints: ScenarioConstraints
    transcript_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    limitations: list[str] = Field(min_length=1, max_length=16)

    @model_validator(mode="after")
    def ordered_checks(self):
        ids = [check.id for check in self.checks]
        if ids != list(CHECK_IDS):
            raise ValueError("checks must be present once each in canonical order")
        return self


class AuthenticationScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    scenario_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")


class AuthenticationSectionData(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    executive_summary: dict
    scope_and_accounts: dict
    authentication_checks: list[dict]
    outcome: dict
    claims_policy: dict
    constraints: dict
    limitations: list[str]


class AuthenticationSectionReport(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    mode: Literal["offline_authentication"]
    id: str
    run_id: str
    sections: AuthenticationSectionData
