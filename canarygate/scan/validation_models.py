"""Strict API and persistence contract for offline input-validation runs."""
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from canarygate.models.result import Verdict
from canarygate.oracles.validation import INPUT_PROBE_NAMES
from canarygate.scope.authorized import AuthorizedScope

CHECK_ORDER = ("INPUT-05", "INPUT-06", "INPUT-07", "DISC-01", "DISC-02", "DISC-03", "DISC-04",
               "DISC-05", "DISC-06")
CHECK_TITLES = {
    "INPUT-05": "Unexpected extra JSON property",
    "INPUT-06": "Malformed JSON body",
    "INPUT-07": "Special characters in string fields",
    "DISC-01": "Stack trace or framework error text",
    "DISC-02": "Verbose internals in error responses",
    "DISC-03": "Sensitive fields disclosed by name or pattern",
    "DISC-04": "Excess fields beyond the response schema",
    "DISC-05": "Server, framework and debug headers",
    "DISC-06": "Existence enumeration through differing errors",
}
CHECK_CATEGORIES = {check_id: ("Input validation" if check_id.startswith("INPUT") else "Information disclosure")
                    for check_id in CHECK_ORDER}
VERDICTS = ("CONFIRMED", "INCONCLUSIVE", "SAFE", "SKIPPED", "SUSPECTED")
REMEDIATIONS = {
    "INPUT-05": "Reject unexpected properties, or ignore them without changing server state",
    "INPUT-06": "Reject malformed JSON with a bounded parse error before any processing",
    "INPUT-07": "Validate and encode string fields; return bounded errors instead of accepting raw input",
    "DISC-01": "Return generic error pages and disable framework debug output in production",
    "DISC-02": "Return generic error messages; never expose paths, SQL or library versions",
    "DISC-03": "Remove or redact sensitive fields from API responses",
    "DISC-04": "Serialise responses strictly from the declared response schema",
    "DISC-05": "Suppress server, framework and debug headers in production responses",
    "DISC-06": "Return indistinguishable error responses for existing and nonexistent resources",
}
_SENSITIVE_VALUE = re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key)\b\s*[:=]\s*(\"[^\"]*\"|\S+)")
_TIMESTAMP = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$"


def _bounded_evidence(value):
    def walk(node, depth=0):
        if depth > 8:
            raise ValueError("evidence is too deep")
        if isinstance(node, dict):
            for key, item in node.items():
                if not isinstance(key, str) or len(key) > 64:
                    raise ValueError("invalid evidence key")
                walk(item, depth + 1)
        elif isinstance(node, (list, tuple)):
            for item in node:
                walk(item, depth + 1)
        elif isinstance(node, str):
            if len(node) > 512 or _SENSITIVE_VALUE.search(node):
                raise ValueError("evidence text is too long or carries a sensitive value")
        elif not isinstance(node, (bool, int, float)) and node is not None:
            raise ValueError("unsupported evidence value")
    walk(value)
    return value


class ValidationCheck(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    id: str
    category: Literal["Input validation", "Information disclosure"]
    verdict: Verdict
    reason: str = Field(min_length=1, max_length=1024)
    request_probes: list[str] = Field(default_factory=list)
    evidence: dict | None = None
    remediation: str | None = Field(default=None, max_length=1024)

    @field_validator("id")
    @classmethod
    def known_check(cls, value):
        if value not in CHECK_ORDER:
            raise ValueError("unknown validation check id")
        return value

    @field_validator("request_probes")
    @classmethod
    def known_probes(cls, value):
        if len(set(value)) != len(value) or any(probe not in INPUT_PROBE_NAMES for probe in value):
            raise ValueError("unknown or repeated validation probe")
        return value

    @field_validator("evidence")
    @classmethod
    def bounded_evidence(cls, value):
        return None if value is None else _bounded_evidence(value)

    @model_validator(mode="after")
    def coherent_result(self):
        if self.category != CHECK_CATEGORIES[self.id]:
            raise ValueError("check category does not match the check id")
        if self.verdict in {"SAFE", "CONFIRMED", "SUSPECTED"} and self.evidence is None:
            raise ValueError("a decisive verdict requires recorded evidence")
        if self.verdict == "CONFIRMED" and not self.remediation:
            raise ValueError("a confirmed finding requires remediation")
        return self


class ValidationSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    total: Literal[9]
    executed: int = Field(ge=0, le=9)
    confirmed: int = Field(ge=0, le=9)
    suspected: int = Field(ge=0, le=9)
    safe: int = Field(ge=0, le=9)
    inconclusive: int = Field(ge=0, le=9)
    skipped: int = Field(ge=0, le=9)

    @model_validator(mode="after")
    def consistent_totals(self):
        counted = (self.confirmed + self.suspected + self.safe + self.inconclusive + self.skipped)
        if counted != self.total or self.executed != self.total - self.skipped:
            raise ValueError("validation summary totals are inconsistent")
        return self


class ValidationRun(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    id: str = Field(pattern=r"^[0-9a-fA-F-]{36}$")
    created_at: str = Field(pattern=_TIMESTAMP)
    mode: Literal["offline_validation"]
    status: Literal["completed", "failed"]
    scenario_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")
    title: str = Field(min_length=1, max_length=120)
    transport: Literal["offline_transcript"]
    network_transport_enabled: Literal[False]
    policy_source: Literal["offline validation scenario policy"]
    scope: AuthorizedScope
    accounts: list[str] = Field(min_length=1, max_length=2)
    checks: list[ValidationCheck]
    summary: ValidationSummary
    transcript_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    requests_sent: int = Field(ge=0, le=100000)
    blocked_by_guard: int = Field(ge=0, le=100000)
    budget_remaining: int = Field(ge=0, le=100000)
    limitations: list[str] = Field(min_length=1, max_length=16)

    @model_validator(mode="after")
    def strict_result(self):
        if [item.id for item in self.checks] != list(CHECK_ORDER):
            raise ValueError("validation checks must appear exactly once in canonical order")
        counted = {name: 0 for name in VERDICTS}
        for item in self.checks:
            counted[item.verdict] += 1
        expected = {"total": 9, "executed": 9 - counted["SKIPPED"], "confirmed": counted["CONFIRMED"],
                    "suspected": counted["SUSPECTED"], "safe": counted["SAFE"],
                    "inconclusive": counted["INCONCLUSIVE"], "skipped": counted["SKIPPED"]}
        if self.summary.model_dump() != expected:
            raise ValueError("summary does not match the check verdicts")
        if any(len(note) > 240 for note in self.limitations):
            raise ValueError("run limitations are unbounded")
        return self

    def verdicts(self):
        return {item.id: item.verdict for item in self.checks}


class ValidationScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    scenario_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")


class ValidationSectionData(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    executive_summary: dict
    scope_and_accounts: dict
    check_results: list[dict]
    outcome: dict
    limitations: list[str]


class ValidationSectionReport(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    mode: Literal["offline_validation"]
    id: str
    run_id: str
    sections: ValidationSectionData
