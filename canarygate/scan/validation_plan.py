"""Validated offline plan for safe input-validation and disclosure checks."""
import re

from pydantic import BaseModel, ConfigDict, Field, model_validator

from canarygate.api.schemas import InventoryEndpoint
from canarygate.evidence.redaction import canonical_json
from canarygate.scan.transcript import OfflineTranscript
from canarygate.scan.validation_transcript import ValidationTranscript, combined_sha256
from canarygate.scope.authorized import AuthorizedScope

VALIDATION_POLICY_SOURCE = "offline validation scenario policy"
_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")


class ValidationPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    scenario_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")
    title: str = Field(min_length=1, max_length=120)
    scope: AuthorizedScope
    accounts: tuple[str, ...] = Field(min_length=1, max_length=2)
    login_path: str
    reads: OfflineTranscript
    probes: ValidationTranscript
    resource_template: str = Field(pattern=r"^/[A-Za-z0-9_./{}~-]{1,511}$")
    sensitive_path: str
    stack_trace_path: str
    internal_detail_path: str
    known_denied_path: str
    unknown_denied_path: str
    extra_property_field: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
    response_schemas: dict[str, dict] | None = None
    inventory: list[InventoryEndpoint] = Field(max_length=16)

    @model_validator(mode="after")
    def coherent_plan(self):
        scoped = {item.account for item in self.scope.accounts}
        if any(name not in scoped for name in self.accounts):
            raise ValueError("plan accounts must be scoped")
        operations = {(op.method, op.path): op for op in self.scope.operations}
        login = operations.get(("POST", self.login_path))
        if login is None or login.classification != "AUTHENTICATION":
            raise ValueError("login path must be the scoped authentication operation")
        for entry in self.probes.entries:
            if entry.actor not in self.accounts or entry.path != self.login_path \
                    or entry.probe not in login.input_probes:
                raise ValueError("probe entry is not permitted by the scoped authentication operation")
        resource_paths = (self.sensitive_path, self.stack_trace_path, self.internal_detail_path,
                          self.known_denied_path, self.unknown_denied_path)
        if len(set(resource_paths)) != len(resource_paths):
            raise ValueError("resource paths must be distinct")
        reads = {path: operations.get(("GET", path)) for path in resource_paths}
        for path, operation in reads.items():
            if operation is None or operation.classification != "READ_ONLY":
                raise ValueError("resource paths must be exact scoped reads")
        for entry in self.reads.entries:
            operation = operations.get((entry.method, entry.path))
            if entry.actor not in self.accounts or operation is None or operation.classification != "READ_ONLY":
                raise ValueError("read entry is outside the scoped read operations")
        if len({entry.probe for entry in self.probes.entries}) != len(self.probes.entries):
            raise ValueError("each validation probe may be recorded once per actor")
        if self.response_schemas is not None:
            if not isinstance(self.response_schemas, dict) or len(self.response_schemas) > 8 \
                    or len(canonical_json(self.response_schemas)) > 16384:
                raise ValueError("response schema contract is too large")
        return self

    def combined_sha256(self):
        return combined_sha256(self.reads, self.probes)
