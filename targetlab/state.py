"""Deterministic ground truth for TargetLab.

Every value here is synthetic and public on purpose: the lab exists so a scan can
be compared against a known answer. There are no real credentials, no customer
data and no external dependency.

The three deliberate flaws are declared as data too, so the documentation and
the tests cannot drift from the server:

* ``record_route``  - the plain record route ignores ownership (classic BOLA).
* ``guarded_route`` - the guarded record route skips ownership for an account
  whose last login attempt was rejected as malformed (the interaction flaw).
* ``trace_route``   - the error route returns a synthetic stack trace.
"""
from dataclasses import dataclass, field
from threading import Lock

LAB_NAME = "targetlab"
LAB_VERSION = "1.0"

# Two independent accounts with predictable, obviously fake credentials.
LAB_ACCOUNTS = {
    "alice": {"password": "alice-lab-password", "role": "user", "token": "lab-token-alice"},
    "bob": {"password": "bob-lab-password", "role": "user", "token": "lab-token-bob"},
}
TOKEN_TO_ACCOUNT = {account["token"]: name for name, account in LAB_ACCOUNTS.items()}

# Private markers: the string the scanner must never see unless the lab leaks it.
PRIVATE_MARKERS = {
    "alice": "targetlab-alice-private-marker",
    "bob": "targetlab-bob-private-marker",
}
TRACE_MARKER = "targetlab-trace-marker"

RECORDS = {
    "ra": {"id": "ra", "owner": "alice", "private_note": PRIVATE_MARKERS["alice"]},
    "rb": {"id": "rb", "owner": "bob", "private_note": PRIVATE_MARKERS["bob"]},
}

# Declared, machine-readable flaw map. Tests and docs read this instead of
# re-describing the behaviour in prose.
FLAWS = {
    "record_route": {
        "path": "/records/{record_id}",
        "kind": "BOLA",
        "description": "Returns any owner's record to any authenticated account.",
    },
    "guarded_route": {
        "path": "/records/{record_id}/guarded",
        "kind": "interaction",
        "description": ("Skips the ownership check for one read after that account's "
                        "login attempt was rejected as malformed."),
    },
    "trace_route": {
        "path": "/errors/trace",
        "kind": "information_disclosure",
        "description": "Returns a synthetic stack trace and an internal marker.",
    },
}
SECURE_PATHS = ("/records/{record_id}/secure", "/admin/users")


@dataclass
class LabState:
    """Mutable per-process state. A fresh app instance starts from a clean slate."""

    compatibility: set[str] = field(default_factory=set)
    logins: int = 0
    rejected_logins: int = 0
    _lock: Lock = field(default_factory=Lock, repr=False)

    def record_login(self) -> None:
        with self._lock:
            self.logins += 1

    def mark_rejected(self, account: str) -> None:
        """The deliberate flaw: a rejected malformed login leaves a legacy flag."""
        with self._lock:
            self.rejected_logins += 1
            if account in LAB_ACCOUNTS:
                self.compatibility.add(account)

    def clear(self, account: str) -> None:
        with self._lock:
            self.compatibility.discard(account)

    def is_compatible(self, account: str) -> bool:
        with self._lock:
            return account in self.compatibility

    def any_compatibility(self) -> bool:
        with self._lock:
            return bool(self.compatibility)

    def snapshot(self) -> dict:
        with self._lock:
            return {"logins": self.logins, "rejected_logins": self.rejected_logins,
                    "compatibility_accounts": sorted(self.compatibility)}
