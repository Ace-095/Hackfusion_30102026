"""Retired module: kept only as an inert packaging tombstone.

This prevents a stale build directory from accidentally shipping the former
standalone network reader after upgrading. All execution must go through the
guarded HTTPX boundary.
"""
raise ImportError("The standalone pinned reader was removed; use the guarded HTTPX boundary")
