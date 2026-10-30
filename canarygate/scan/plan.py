"""Validated generic offline scan plan: exact scope, recipe, policy and transcript."""
from pydantic import BaseModel, ConfigDict, Field, model_validator

from canarygate.api.schemas import InventoryEndpoint
from canarygate.scope.authorized import AuthorizedScope
from canarygate.scan.transcript import OfflineTranscript
from canarygate.seed.recipe import Policy, Resource

TRUSTED_SCENARIO_POLICY_SOURCE = "offline scenario policy"


class OfflineScenarioPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    scenario_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")
    scope: AuthorizedScope
    accounts: tuple[str, str]
    resource_type: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")
    resource: Resource
    profile_path: str
    identity_field: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
    policy: Policy
    inventory: list[InventoryEndpoint] = Field(max_length=64)
    transcript: OfflineTranscript

    @model_validator(mode="after")
    def coherent_plan(self):
        scoped = {item.account: item.role for item in self.scope.accounts}
        if self.accounts[0] == self.accounts[1] or any(name not in scoped for name in self.accounts):
            raise ValueError("two distinct scoped accounts are required")
        reads = {op.path for op in self.scope.operations
                 if op.method == "GET" and op.classification == "READ_ONLY"}
        required = {self.profile_path, self.resource.discovery.path, self.resource.detail.path}
        for path in required:
            if "{id}" in path:
                continue
            if path not in reads:
                raise ValueError("plan paths must be exact scoped read operations")
        if self.resource.detail.path.count("{id}") != 1:
            raise ValueError("detail template must contain exactly one {id}")
        for entry in self.transcript.entries:
            if entry.actor not in scoped:
                raise ValueError("transcript actor is not scoped")
            if entry.path.startswith(self.resource.detail.path.split("{id}")[0]):
                if entry.path not in reads:
                    raise ValueError("transcript detail path is not a scoped read")
            elif entry.path not in reads:
                raise ValueError("transcript path is not a scoped read")
        if self.policy.expected_source != TRUSTED_SCENARIO_POLICY_SOURCE:
            raise ValueError("untrusted offline scenario policy source")
        return self

    def account_roles(self):
        return {item.account: item.role for item in self.scope.accounts}
