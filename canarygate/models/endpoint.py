"""Draft endpoint inventory contract."""

from pydantic import BaseModel, field_validator


class Endpoint(BaseModel):
    method: str
    path: str
    parameters: list[dict]
    security: dict | None
    expected_access: str
    expected_source: str

    @field_validator("expected_access")
    @classmethod
    def valid_access(cls, value: str) -> str:
        if value not in {"public", "authenticated", "owner-only", "unknown"} and not (
            value.startswith("role:") and bool(value[5:].strip())
        ):
            raise ValueError("invalid expected access")
        return value
