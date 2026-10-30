"""Loopback enforcement for TargetLab.

The lab is a deliberately vulnerable service. It must never be reachable from
another machine and it must never talk to anything itself, so both directions
are constrained here rather than left to documentation.
"""
from __future__ import annotations

import ipaddress

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def host_name(header_value: str) -> str:
    """Extract a hostname from a Host header, tolerating a port and IPv6 brackets."""
    value = (header_value or "").strip().lower()
    if value.startswith("["):
        return value[1:].split("]", 1)[0]
    if value.count(":") == 1:
        return value.split(":", 1)[0]
    return value


def is_loopback_name(name: str) -> bool:
    if name in LOOPBACK_HOSTS:
        return True
    try:
        return ipaddress.ip_address(name).is_loopback
    except ValueError:
        return False


def assert_loopback_host(host: str) -> str:
    """Raise ValueError unless the bind host is loopback-only."""
    if not isinstance(host, str) or not host.strip():
        raise ValueError("a bind host is required")
    if not is_loopback_name(host.strip().lower()):
        raise ValueError(f"refusing to bind non-loopback host {host!r}; targetlab is local-only")
    return host
