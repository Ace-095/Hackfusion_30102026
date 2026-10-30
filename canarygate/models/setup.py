"""Draft setup status contract."""

from typing import Literal

from pydantic import BaseModel

SetupOutcome = Literal["SUCCESS", "PARTIAL", "FAILED", "SKIPPED", "NEEDS_MANUAL_INPUT"]


class SetupStatus(BaseModel):
    strategy: str
    authentication: dict
    resources: dict
    ownership_verification: str
    reason: str | None = None
    bola_coverage: str
