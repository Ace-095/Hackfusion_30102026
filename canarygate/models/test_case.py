"""Draft test case contract, not an executable test."""

from pydantic import BaseModel


class TestCase(BaseModel):
    id: str
    category: str
    endpoint: str
    actor: str
    target_resource: str | None = None
    request_template: dict
    non_destructive: bool
    evidence_required: list[str]
    verdict_rules: dict
    remediation_key: str
