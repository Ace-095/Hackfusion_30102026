"""Draft scope contract; validation here does not replace the safety guard."""

import ipaddress
import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class ScopeConfig(BaseModel):
    scheme: Literal["http", "https"]
    hostname: str
    port: int = Field(ge=1, le=65535)
    allowed_methods: list[str] = Field(min_length=1)
    request_budget: int = Field(gt=0)

    @field_validator("hostname")
    @classmethod
    def exact_hostname(cls, value: str) -> str:
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            pass
        # Accept DNS names only, not URLs, wildcards, ports, or whitespace.
        try:
            ascii_name = value.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("invalid hostname") from exc
        labels = ascii_name.rstrip(".").split(".")
        if len(ascii_name) > 253 or not all(
            re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in labels
        ):
            raise ValueError("hostname must be an exact host, not a wildcard or URL")
        return value

    @field_validator("allowed_methods")
    @classmethod
    def exact_methods(cls, value: list[str]) -> list[str]:
        if any(not method or not method.isascii() or not method.isalpha() or method != method.upper() for method in value):
            raise ValueError("methods must be uppercase HTTP method names")
        return value
