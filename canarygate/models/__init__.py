"""Proposed shared contracts; not frozen pending specification and team review."""

from .endpoint import Endpoint
from .evidence import Evidence
from .identity import Identity
from .matrix import MatrixCell
from .ownership import OwnedResource
from .recipe import Recipe
from .result import Result, Verdict
from .scan import ScanRun
from .scope import ScopeConfig
from .setup import SetupOutcome, SetupStatus
from .test_case import TestCase

__all__ = [
    "Endpoint", "Evidence", "Identity", "MatrixCell", "OwnedResource", "Recipe",
    "Result", "ScanRun", "ScopeConfig", "SetupOutcome", "SetupStatus", "TestCase", "Verdict",
]
