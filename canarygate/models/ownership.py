"""Draft resource ownership contract."""

from typing import Literal

from pydantic import BaseModel


class OwnedResource(BaseModel):
    resource_type: str
    resource_id: str
    owner: str
    ownership_model: Literal["private", "shared", "public"]
    ownership_verified: bool
    canary: str | None = None
    origin: str
