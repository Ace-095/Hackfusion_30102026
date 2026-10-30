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

Three demo accounts (mallapa, sakshi, harsha) each own one asset, so every ordered
pair of distinct accounts is a cross-account read the lab can exercise.
"""
import uuid
from dataclasses import dataclass, field
from threading import Lock

LAB_NAME = "targetlab"
LAB_VERSION = "1.0"

# Three independent demo accounts for a synthetic Digital Asset Management API.
# The company in the story is fictional; so are the accounts, the assets and every
# value below. Credentials are predictable on purpose (the lab is loopback-only and
# documented in docs/TARGETLAB.md) and are never exposed to the browser.
#
# The accounts demonstrate *authorization*, not role-based access: every account has
# the same kind of grant (read your own asset) and differs only in which asset it
# owns. Role strings are descriptive metadata; nothing in the lab authorizes on them.
LAB_ACCOUNTS = {
    "mallapa": {"password": "mallapa-lab-password", "role": "marketing_manager",
                "title": "Marketing Manager", "token": "lab-token-mallapa"},
    "sakshi": {"password": "sakshi-lab-password", "role": "brand_designer",
               "title": "Brand Designer", "token": "lab-token-sakshi"},
    "harsha": {"password": "harsha-lab-password", "role": "campaign_analyst",
               "title": "Campaign Analyst", "token": "lab-token-harsha"},
}
ACCOUNT_ORDER = tuple(LAB_ACCOUNTS)
TOKEN_TO_ACCOUNT = {account["token"]: name for name, account in LAB_ACCOUNTS.items()}

# Private markers: the string the scanner must never see unless the lab leaks the
# record, and the value an owner baseline proves ownership with. Each is distinct,
# contains no asset id and is not an account name.
PRIVATE_MARKERS = {
    "mallapa": "targetlab-mallapa-private-marker",
    "sakshi": "targetlab-sakshi-private-marker",
    "harsha": "targetlab-harsha-private-marker",
}
TRACE_MARKER = "targetlab-trace-marker"

# One private asset per account. ``id``/``owner``/``private_note`` are the fields the
# ownership registry and the read-BOLA oracle read; the rest is business context so a
# judge can see *what* would leak, not only that something did. All values synthetic.
RECORDS = {
    "MKT-2026-041": {
        "id": "MKT-2026-041",
        "asset_id": "MKT-2026-041",
        "asset_type": "campaign_artwork",
        "owner": "mallapa",
        "campaign": "Summer Launch 2026",
        "launch_date": "2026-11-15",
        "budget": 250000,
        "private_note": PRIVATE_MARKERS["mallapa"],
    },
    "BRD-2026-018": {
        "id": "BRD-2026-018",
        "asset_id": "BRD-2026-018",
        "asset_type": "brand_identity",
        "owner": "sakshi",
        "brand": "Aurelia",
        "asset_version": "v4.2",
        "license_status": "Confidential",
        "private_note": PRIVATE_MARKERS["sakshi"],
    },
    "ADS-2026-027": {
        "id": "ADS-2026-027",
        "asset_id": "ADS-2026-027",
        "asset_type": "performance_report",
        "owner": "harsha",
        "campaign": "Diwali Acquisition",
        "roas": 4.8,
        "customer_acquisition_cost": 182,
        "private_note": PRIVATE_MARKERS["harsha"],
    },
}
#: One asset per account. Used by the reset proof and by tests.
ASSET_BY_OWNER = {record["owner"]: record["id"] for record in RECORDS.values()}

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

    #: Stable identity for this lab process, published on every response so a
    #: scanner can tell two lab instances apart even when they reuse a port. It
    #: carries no ground truth and changes when the process restarts.
    instance_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
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
