"""Strict recipe subset for the initial offline milestone, with no target URL."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from canarygate.seed.extraction import valid_selector


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Operation(StrictModel):
    method: str
    path: str


class Account(StrictModel):
    username: str
    role: str
    password_env: str | None = None


class Pagination(StrictModel):
    # Explicit body continuation token, not a URL. All next requests must match
    # independently scoped, exact query strings in the central fixture guard.
    next_field: str
    parameter: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,31}$")
    max_pages: int = Field(default=2, ge=1, le=4, strict=True)

    @field_validator("next_field")
    @classmethod
    def valid_next_field(cls, value):
        if not valid_selector(value):
            raise ValueError("invalid field selector")
        return value


class Resource(StrictModel):
    discovery: Operation
    detail: Operation
    id_field: str
    ownership_field: str
    ownership_model: Literal["private", "shared", "public"]
    private_field: str
    known_owner_canary: str | None = None
    list_field: str | None = None
    pagination: Pagination | None = None

    @field_validator("id_field", "ownership_field", "private_field", "list_field")
    @classmethod
    def valid_field_selector(cls, value):
        if value is not None and not valid_selector(value):
            raise ValueError("invalid field selector")
        return value

    @model_validator(mode="after")
    def wrapped_list_requires_termination_marker(self):
        if self.list_field and not self.pagination:
            raise ValueError("wrapped list requires explicit pagination termination")
        return self


class Setup(StrictModel):
    login: Operation
    accounts: dict[str, Account]
    resources: dict[str, Resource]


class Policy(StrictModel):
    expected_access: str
    expected_source: str


class FixtureRecipe(StrictModel):
    setup: Setup
    policy: Policy


def validate_fixture_recipe(data: dict) -> FixtureRecipe:
    # Unrecognized fields, including base_url and raw passwords, fail closed.
    return FixtureRecipe.model_validate(data)
