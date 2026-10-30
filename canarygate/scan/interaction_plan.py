"""Validated SCI plan: baselines, one combined leg, scope and recordings.

The plan fixes every action before execution. A caller cannot add a path, probe
or payload at runtime; the runner and the shared run guard authorize each action
against the validated scope.
"""
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from canarygate.api.schemas import InventoryEndpoint
from canarygate.oracles.interaction import INTERACTION_KINDS, INTERACTION_CONTROLS
from canarygate.oracles.validation import INPUT_PROBE_NAMES
from canarygate.scope.authorized import AuthorizedScope
from canarygate.scan.auth_transcript import AuthenticationTranscript
from canarygate.scan.interaction_transcript import InteractionTranscript
from canarygate.scan.transcript import OfflineTranscript
from canarygate.scan.validation_transcript import ValidationTranscript

SCI_POLICY_SOURCE = "offline SCI scenario policy"
_CONTROL = re.compile(r"^[A-Za-z][A-Za-z0-9 _-]{2,63}$")
_ENDPOINT = re.compile(r"^/[A-Za-z0-9_./~-]{0,511}$")
RUNNER_FOR_KIND = {
    "AUTHZ+INPUT_VALIDATION": "interaction",
    "AUTHN+AUTHZ": "auth",
    "INPUT_VALIDATION+INFORMATION_DISCLOSURE": "validation",
}


class BaselineAction(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    id: str = Field(pattern=r"^[A-Z][A-Z0-9-]{2,15}$")
    control: Literal["Authentication", "Authorization", "Input validation", "Information disclosure"]
    action: Literal["get", "submit", "auth_probe"]
    path: str = Field(pattern=_ENDPOINT.pattern)
    probe: str | None = None
    expectation: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def coherent_action(self):
        if self.action == "get" and self.probe is not None:
            raise ValueError("a plain read cannot carry a probe")
        if self.action == "submit" and self.probe not in INPUT_PROBE_NAMES:
            raise ValueError("a submission requires a declared input probe")
        if self.action == "auth_probe" and not isinstance(self.probe, str):
            raise ValueError("an authentication baseline requires a declared probe")
        return self


class CombinedAction(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    action: Literal["get_after", "submit", "auth_probe"]
    path: str = Field(pattern=_ENDPOINT.pattern)
    probe: str
    expected_access: str = Field(min_length=1, max_length=64)
    expected_source: str = Field(min_length=1, max_length=64)
    impact: dict

    @model_validator(mode="after")
    def coherent_impact(self):
        impact = self.impact
        if not isinstance(impact, dict) or len(impact) > 4:
            raise ValueError("impact contract must be a small object")
        if "signal" in impact:
            if impact.get("signal") not in {"stack_trace", "internal_error_detail",
                                            "version_header", "debug_header"}:
                raise ValueError("unknown disclosure signal")
            return self
        if not isinstance(impact.get("field"), str) or not re.fullmatch(
                r"[A-Za-z][A-Za-z0-9_.]{0,63}", impact["field"]):
            raise ValueError("impact field is invalid")
        if "equals" in impact and not isinstance(impact["equals"], str):
            raise ValueError("impact equality must be a string")
        if "present" in impact and impact["present"] is not True:
            raise ValueError("impact presence must be true when declared")
        if "equals" not in impact and "present" not in impact:
            raise ValueError("impact contract needs equals or present")
        return self


class InteractionPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    scenario_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")
    title: str = Field(min_length=1, max_length=120)
    kind: Literal["AUTHZ+INPUT_VALIDATION", "AUTHN+AUTHZ",
                  "INPUT_VALIDATION+INFORMATION_DISCLOSURE"]
    scope: AuthorizedScope
    accounts: tuple[str, str]
    login_path: str = Field(pattern=_ENDPOINT.pattern)
    baselines: tuple[BaselineAction, ...] = Field(min_length=2, max_length=4)
    combined: CombinedAction
    reads: OfflineTranscript
    probes: ValidationTranscript | None = None
    auth_probes: AuthenticationTranscript | None = None
    combined_reads: InteractionTranscript
    request_bodies: dict[str, str] = Field(default_factory=dict)
    auth_config: dict | None = None
    denial_body: dict = Field(default_factory=dict)
    private_marker_field: str | None = Field(default=None, pattern=r"^[A-Za-z][A-Za-z0-9_.]{0,63}$")
    extra_property_field: str | None = Field(default=None, pattern=r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
    disclosure_signal: str | None = None
    inventory: list[InventoryEndpoint] = Field(max_length=16)

    @model_validator(mode="after")
    def coherent_plan(self):
        runner = RUNNER_FOR_KIND[self.kind]
        scoped = {item.account for item in self.scope.accounts}
        if self.accounts[0] == self.accounts[1] or any(name not in scoped for name in self.accounts):
            raise ValueError("two distinct scoped accounts are required")
        operations = {(op.method, op.path): op for op in self.scope.operations}
        login = operations.get(("POST", self.login_path))
        if login is None or login.classification != "AUTHENTICATION":
            raise ValueError("login path must be the scoped authentication operation")
        actions = {item.action for item in self.baselines}
        if runner == "interaction":
            if self.probes is None or self.auth_probes is not None:
                raise ValueError("the interaction runner needs input probes only")
            if self.combined.action != "get_after" or not actions <= {"get", "submit"}:
                raise ValueError("AUTHZ+INPUT uses reads, submissions and one combined read")
            if self.combined.probe not in login.input_probes:
                raise ValueError("the combined leg needs a declared input probe")
        elif runner == "auth":
            if self.auth_probes is None or self.probes is not None:
                raise ValueError("the authentication runner needs crafted-credential probes only")
            if self.combined.action != "auth_probe" or not actions <= {"get", "auth_probe"}:
                raise ValueError("AUTHN+AUTHZ uses reads and crafted-credential probes")
            combined_operation = operations.get(("GET", self.combined.path))
            if combined_operation is None or self.combined.probe not in combined_operation.auth_probes:
                raise ValueError("the combined credential probe must be declared on that read")
        else:
            if self.probes is None or self.auth_probes is not None:
                raise ValueError("the validation runner needs input probes only")
            if self.combined.action != "submit" or not actions <= {"get", "submit"}:
                raise ValueError("INPUT+DISCLOSURE uses reads, one submission and one disclosure scan")
            if "signal" not in self.combined.impact:
                raise ValueError("the disclosure interaction needs a signal contract")
        if self.kind != "INPUT_VALIDATION+INFORMATION_DISCLOSURE" and "signal" in self.combined.impact:
            raise ValueError("only the disclosure interaction may use a signal contract")
        if self.private_marker_field is None and self.kind != "INPUT_VALIDATION+INFORMATION_DISCLOSURE":
            raise ValueError("an authorization interaction needs a private marker field")
        for entry in self.reads.entries:
            operation = operations.get((entry.method, entry.path))
            if entry.actor not in scoped or operation is None or operation.classification != "READ_ONLY":
                raise ValueError("read entry is outside the scoped read operations")
        if self.probes is not None:
            for entry in self.probes.entries:
                if entry.actor not in scoped or entry.path != self.login_path \
                        or entry.probe not in login.input_probes:
                    raise ValueError("probe entry is not permitted by the scoped authentication operation")
            if not set(self.request_bodies).issubset(INPUT_PROBE_NAMES) or len(self.request_bodies) > 8:
                raise ValueError("declared request bodies are invalid")
            if any(not isinstance(body, str) or not body or len(body) > 4096
                   for body in self.request_bodies.values()):
                raise ValueError("declared request body is invalid")
        for entry in self.combined_reads.entries:
            operation = operations.get((entry.method, entry.path))
            if entry.actor not in scoped or operation is None or operation.classification != "READ_ONLY":
                raise ValueError("combined read is outside the scoped read operations")
        return self

    @property
    def runner(self):
        return RUNNER_FOR_KIND[self.kind]

    def controls(self):
        return list(INTERACTION_CONTROLS[self.kind])

    def scope_sha256_input(self):
        return self.scope.model_dump(mode="json")


def validate_kind(value):
    if value not in INTERACTION_KINDS:
        raise ValueError("unknown interaction kind")
    return value
