"""Draft authorization matrix cell contract."""

from pydantic import BaseModel

from .result import Verdict


class MatrixCell(BaseModel):
    endpoint: str
    actor: str
    target_resource: str | None
    expected_access: str
    expected_source: str
    verdict: Verdict
