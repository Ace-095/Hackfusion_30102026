"""Draft evidence contract; callers must redact and hash before construction."""

from datetime import datetime

from pydantic import BaseModel


class Evidence(BaseModel):
    timestamp: datetime
    account_role: str
    request: dict
    response: dict
    redacted: bool
    sha256: str
