"""Strict API and persistence contract for offline SCI interaction runs."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator, model_validator

from canarygate.api.schemas import InventoryEndpoint
from canarygate.models.result import Verdict
from canarygate.oracles.interaction import (ATTRIBUTIONS, CHECKLIST_KEYS, IMPACTS, INTERACTION_KINDS,
                                            REMEDIATION_KEYS)
from canarygate.scan.models import ScenarioAccount

MODES = ("offline_interaction", "targetlab_sci")


class SciBaseline(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    id: str = Field(pattern=r"^[A-Z][A-Z0-9-]{2,15}$")
    control: Literal["Authentication", "Authorization", "Input validation", "Information disclosure"]
    endpoint: str = Field(min_length=1, max_length=600)
    action: Literal["get", "submit", "auth_probe"]
    probe: str | None = None
    verdict: Verdict
    reason: str = Field(min_length=1, max_length=1024)
    observable: StrictBool
    evidence: dict
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def bounded_evidence(self):
        if len(self.evidence) > 8:
            raise ValueError("baseline evidence is too large")
        for key, value in self.evidence.items():
            if not isinstance(key, str) or len(key) > 32:
                raise ValueError("invalid evidence key")
            if value is not None and (not isinstance(value, (str, int, bool))
                                      or (isinstance(value, str) and len(value) > 256)):
                raise ValueError("invalid evidence value")
        return self


class SciCombined(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    endpoint: str = Field(min_length=1, max_length=600)
    action: Literal["get_after", "submit", "auth_probe"]
    probe: str
    executed: StrictBool
    permitted: StrictBool
    verified: StrictBool
    status: int | None = Field(default=None, ge=100, le=599)
    impact: Literal["none", "private_data", "privileged_data", "internal_detail", "ambiguous"]
    observed: str = Field(min_length=1, max_length=512)

    @model_validator(mode="after")
    def coherent_combined(self):
        if self.executed and not self.permitted:
            raise ValueError("an executed combined leg must have been permitted")
        if self.verified and not self.executed:
            raise ValueError("an unexecuted combined leg cannot be verified")
        if self.status is not None and not self.executed:
            raise ValueError("an unexecuted combined leg has no status")
        return self


class InteractionRun(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    id: str = Field(pattern=r"^[0-9a-fA-F-]{36}$")
    created_at: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$")
    mode: Literal["offline_interaction", "targetlab_sci"]
    status: Literal["completed", "failed"]
    scenario_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")
    title: str = Field(min_length=1, max_length=120)
    interaction_kind: Literal["AUTHZ+INPUT_VALIDATION", "AUTHN+AUTHZ",
                              "INPUT_VALIDATION+INFORMATION_DISCLOSURE"]
    controls: list[str] = Field(min_length=2, max_length=2)
    policy_source: str = Field(min_length=1, max_length=120)
    scope: dict
    accounts: list[str] = Field(min_length=2, max_length=2)
    baselines: list[SciBaseline] = Field(min_length=2, max_length=4)
    combined: SciCombined
    verdict: Verdict
    reason: str = Field(min_length=1, max_length=1024)
    attribution: Literal["interaction_induced", "individual_failure", "incomplete_baseline",
                         "unverified_evidence", "ambiguous_impact", "no_demonstrated_impact",
                         "no_failure", "not_permitted"]
    remediation_key: str | None = None
    remediation: str | None = Field(default=None, max_length=1024)
    checklist: dict[str, StrictBool]
    transcript_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    requests_sent: int = Field(ge=0, le=100000)
    blocked_by_guard: int = Field(ge=0, le=100000)
    budget_remaining: int = Field(ge=0, le=100000)
    network_transport_enabled: StrictBool = False
    # Lab additions. An offline run must leave them unset; a loopback run must
    # carry them, so stored evidence always says which transport produced it.
    integration_origin: Literal["offline_transcript", "loopback_lab"] = "offline_transcript"
    transport: dict | None = None
    ownership: dict | None = None
    disclosure: dict | None = None
    inventory: list[InventoryEndpoint] = Field(max_length=16)
    limitations: list[str] = Field(min_length=1, max_length=16)

    @field_validator("controls")
    @classmethod
    def known_controls(cls, value):
        if len(set(value)) != len(value):
            raise ValueError("controls must be distinct")
        return value

    @model_validator(mode="after")
    def coherent_run(self):
        if self.remediation_key is not None and self.remediation_key not in REMEDIATION_KEYS.values():
            raise ValueError("unknown SCI remediation key")
        if (self.remediation_key is None) != (self.remediation is None):
            raise ValueError("remediation key and text must appear together")
        if self.verdict == "CONFIRMED":
            if self.attribution != "interaction_induced":
                raise ValueError("a confirmed interaction must be interaction-induced")
            if not all(self.checklist.get(key) is True for key in CHECKLIST_KEYS):
                raise ValueError("a confirmed interaction needs the complete evidence checklist")
            if self.remediation_key is None:
                raise ValueError("a confirmed interaction needs a remediation")
        else:
            if self.remediation_key is not None:
                raise ValueError("only a confirmed interaction carries a remediation")
            if all(self.checklist.get(key) is True for key in CHECKLIST_KEYS):
                raise ValueError("a non-confirmed interaction cannot carry a complete checklist")
        if set(self.checklist) != set(CHECKLIST_KEYS):
            raise ValueError("checklist must contain exactly the SCI decision keys")
        if self.combined.impact not in IMPACTS:
            raise ValueError("unknown combined impact")
        if self.attribution not in ATTRIBUTIONS:
            raise ValueError("unknown attribution")
        if self.interaction_kind not in INTERACTION_KINDS:
            raise ValueError("unknown interaction kind")
        if self.mode == "offline_interaction":
            # The offline path never opens a socket, and says so in one place.
            if self.network_transport_enabled:
                raise ValueError("an offline interaction run cannot enable networking")
            if self.integration_origin != "offline_transcript":
                raise ValueError("an offline interaction run uses a recorded transcript")
            if any(item is not None for item in (self.transport, self.ownership, self.disclosure)):
                raise ValueError("an offline interaction run carries no lab transport evidence")
        else:
            if not self.network_transport_enabled:
                raise ValueError("a loopback interaction run must declare its transport")
            if self.integration_origin != "loopback_lab":
                raise ValueError("a loopback interaction run declares its origin")
            for name in ("transport", "ownership", "disclosure"):
                if not isinstance(getattr(self, name), dict):
                    raise ValueError(f"a loopback interaction run requires {name} evidence")
            if self.transport.get("destination") != "127.0.0.1":
                raise ValueError("a loopback interaction run only targets 127.0.0.1")
            if self.transport.get("live_target_contacted") is not False:
                raise ValueError("a loopback lab run never contacts a live target")
        if not isinstance(self.scope, dict) or "accounts" not in self.scope:
            raise ValueError("scope projection is required")
        accounts = [item["account"] for item in self.scope["accounts"]]
        if accounts != list(self.accounts):
            raise ValueError("run accounts must match the scope accounts")
        for item in self.scope["accounts"]:
            ScenarioAccount.model_validate(item)
        return self


class InteractionScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    scenario_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")


class InteractionSectionData(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    executive_summary: dict
    scope_and_accounts: dict
    baselines: list[dict]
    combined: dict
    decision: dict
    limitations: list[str]


class InteractionSectionReport(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    mode: Literal["offline_interaction", "targetlab_sci"]
    id: str
    run_id: str
    sections: InteractionSectionData
