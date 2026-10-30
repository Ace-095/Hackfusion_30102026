"""TargetLab: a deliberately vulnerable local API used to validate CanaryGate.

This package is a *test target*, not part of the scanner. It is intentionally
insecure, binds to loopback only, and must never be deployed or exposed.
"""
__all__ = ["create_lab_app"]
