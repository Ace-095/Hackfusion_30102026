"""Draft finding/result contract."""

from typing import Literal

from pydantic import BaseModel

Verdict = Literal["CONFIRMED", "SUSPECTED", "SAFE", "INCONCLUSIVE", "SKIPPED"]


class Result(BaseModel):
    verdict: Verdict
    verdict_reason: str
    checklist: dict
    remediation_key: str
