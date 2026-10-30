"""Draft scan run contract."""

from datetime import datetime

from pydantic import BaseModel

from .result import Result
from .setup import SetupStatus


class ScanRun(BaseModel):
    run_id: str
    timestamp: datetime
    setup_status: SetupStatus
    results: list[Result]
    scope_hash: str
    interventions: list[str]
