"""Load strict scope data. No DNS, network access, or credential storage."""
from enum import Enum
from importlib.resources import files
from typing import Literal
import re

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from canarygate.models.scope import ScopeConfig


class OperationClass(str, Enum):
    READ_ONLY = "READ_ONLY"
    AUTHENTICATION = "AUTHENTICATION"
    STATE_CHANGING = "STATE_CHANGING"
    DESTRUCTIVE = "DESTRUCTIVE"


class ScopedOperation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    method: str
    path: str
    classification: OperationClass
    auth_probes: tuple[Literal["missing", "malformed", "wrong_scheme"], ...] = ()

    @model_validator(mode="after")
    def safe_probes(self):
        if self.auth_probes and (self.method != "GET" or self.classification != OperationClass.READ_ONLY):
            raise ValueError("authentication probes require a classified read-only GET")
        if len(set(self.auth_probes)) != len(self.auth_probes):
            raise ValueError("duplicate authentication probe")
        return self

    @field_validator("method")
    @classmethod
    def valid_method(cls, value):
        if not re.fullmatch(r"[A-Z]+", value):
            raise ValueError("method must be uppercase")
        return value

    @field_validator("path")
    @classmethod
    def exact_path(cls, value):
        if (not re.fullmatch(r"/[A-Za-z0-9_./~-]*", value) or "//" in value
                or any(part in {".", ".."} for part in value.split("/"))):
            raise ValueError("operation must have an exact, unencoded path")
        return value


class FixtureScope(ScopeConfig):
    model_config = ConfigDict(extra="forbid", frozen=True)
    accounts: list[str] = Field(min_length=1)
    operations: list[ScopedOperation] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_operations(self):
        keys = [(o.method, o.path) for o in self.operations]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate scoped operation")
        if len(set(self.accounts)) != len(self.accounts):
            raise ValueError("duplicate account")
        return self

    @property
    def origin(self):
        host = f"[{self.hostname}]" if ":" in self.hostname else self.hostname
        return f"{self.scheme}://{host}:{self.port}"


def load_scope(text: str) -> FixtureScope:
    if len(text.encode("utf-8")) > 64 * 1024:
        raise ValueError("scope too large")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError("invalid scope YAML") from exc
    if not isinstance(data, dict):
        raise ValueError("scope must be a mapping")
    return FixtureScope.model_validate(data)


def fixture_scope() -> FixtureScope:
    return load_scope(files("canarygate.offline").joinpath("scope.yaml").read_text(encoding="utf-8"))
