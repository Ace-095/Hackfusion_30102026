"""Draft account identity contract."""

from pydantic import BaseModel, Field


class Identity(BaseModel):
    account: str
    role: str
    # Keep bearer tokens out of model dumps and representations by default.
    token: str | None = Field(default=None, exclude=True, repr=False)
    claims: dict = Field(default_factory=dict)
    password_env: str | None = None
