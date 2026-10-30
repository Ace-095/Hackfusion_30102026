"""Strict recipe subset for the initial offline milestone, with no target URL."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Operation(StrictModel):
    method: str
    path: str


class Account(StrictModel):
    username: str
    role: str
    password_env: str | None = None


class Resource(StrictModel):
    discovery: Operation
    detail: Operation
    id_field: str
    ownership_field: str
    ownership_model: Literal["private", "shared", "public"]
    private_field: str
    known_owner_canary: str | None = None


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
