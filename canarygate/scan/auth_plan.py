"""Validated offline authentication plan: scope, scheme, probes and recordings."""
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from canarygate.api.schemas import InventoryEndpoint
from canarygate.evidence.redaction import canonical_json
from canarygate.scan.auth_transcript import AuthenticationTranscript, combined_sha256
from canarygate.scan.transcript import OfflineTranscript
from canarygate.scope.authorized import AuthorizedScope

AUTH_POLICY_SOURCE = "offline authentication scenario policy"
_HEADER_NAME = re.compile(r"^[A-Za-z0-9-]{3,64}$")


class AuthenticationPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    scenario_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")
    title: str = Field(min_length=1, max_length=120)
    scope: AuthorizedScope
    accounts: tuple[str, str]
    scheme: Literal["bearer_jwt", "bearer_opaque", "api_key"]
    token_format: Literal["jwt", "opaque", "api_key"]
    api_key_header: str | None = None
    profile_path: str
    identity_field: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
    admin_path: str | None = None
    admin_capability_field: str | None = Field(default=None, pattern=r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
    logout_path: str | None = None
    denial_body: dict = Field(default_factory=dict)
    reads: OfflineTranscript
    probes: AuthenticationTranscript
    inventory: list[InventoryEndpoint] = Field(max_length=32)

    @model_validator(mode="after")
    def coherent_plan(self):
        scoped = {item.account for item in self.scope.accounts}
        if self.accounts[0] == self.accounts[1] or any(name not in scoped for name in self.accounts):
            raise ValueError("two distinct scoped accounts are required")
        operations = {(op.method, op.path): op for op in self.scope.operations}
        profile = operations.get(("GET", self.profile_path))
        if profile is None or profile.classification != "READ_ONLY":
            raise ValueError("profile path must be an exact scoped read")
        if (self.admin_path is None) != (self.admin_capability_field is None):
            raise ValueError("admin path and capability field must be declared together")
        if self.admin_path is not None:
            admin = operations.get(("GET", self.admin_path))
            if admin is None or admin.classification != "READ_ONLY":
                raise ValueError("admin path must be an exact scoped read")
        if self.logout_path is not None:
            logout = operations.get(("POST", self.logout_path))
            if logout is None or logout.classification != "AUTHENTICATION":
                raise ValueError("logout path must be the scoped authentication operation")
        if (self.token_format == "jwt") != (self.scheme == "bearer_jwt"):
            raise ValueError("JWT-format tokens require the bearer_jwt scheme")
        if (self.token_format == "api_key") != (self.scheme == "api_key"):
            raise ValueError("API-key tokens require the api_key scheme")
        if self.scheme == "api_key":
            if self.api_key_header is None or _HEADER_NAME.fullmatch(self.api_key_header) is None:
                raise ValueError("api-key scheme requires an exact header name")
        elif self.api_key_header is not None:
            raise ValueError("api-key header is only valid for the api-key scheme")
        for entry in self.reads.entries:
            operation = operations.get((entry.method, entry.path))
            if entry.actor not in scoped or operation is None or operation.classification != "READ_ONLY":
                raise ValueError("read entry is outside the scoped read operations")
        if len(self.denial_body) > 16 or len(canonical_json(self.denial_body)) > 4096:
            raise ValueError("denial body contract is too large")
        return self

    def account_roles(self):
        return {item.account: item.role for item in self.scope.accounts}

    def combined_sha256(self):
        return combined_sha256(self.reads, self.probes)
