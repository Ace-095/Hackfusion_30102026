"""Minimized, independently hashed ownership observations for the fixture only."""
import copy
from datetime import datetime, timezone
import hmac

from pydantic import ValidationError

from canarygate.api.schemas import FixtureObservation
from canarygate.evidence.redaction import EvidenceIntegrityError, digest
from canarygate.seed.extraction import MISSING, extract

MAX_OBSERVATIONS = 20


def _item(value, *, id_field, owner_field, private_field):
    if not isinstance(value, dict):
        return None
    item_id = extract(value, id_field, None)
    owner = extract(value, owner_field, None)
    return {"id": item_id if item_id in ("alice-item", "bob-item", None) else "[REDACTED]",
            "owner": owner if owner in ("alice", "bob", None) else "[REDACTED]",
            "private_field_present": extract(value, private_field) is not MISSING}


def seal(observation):
    """Validate fixed fixture-only fields and hash the redacted record."""
    result = copy.deepcopy(observation)
    result["redacted"] = True
    result["sha256"] = digest({k: v for k, v in result.items() if k not in {"redacted", "sha256"}})
    # Round-trip to make all defaults explicit, then hash exactly what is stored.
    normalized = FixtureObservation.model_validate(result).model_dump(mode="json")
    normalized["sha256"] = digest({k: v for k, v in normalized.items() if k not in {"redacted", "sha256"}})
    return normalized


def verify(observation):
    try:
        normalized = FixtureObservation.model_validate(observation).model_dump(mode="json")
    except (ValidationError, TypeError, ValueError) as exc:
        raise EvidenceIntegrityError("invalid fixture observation") from exc
    if normalized != observation:
        raise EvidenceIntegrityError("non-canonical fixture observation")
    checksum = digest({k: v for k, v in normalized.items() if k not in {"redacted", "sha256"}})
    if not hmac.compare_digest(normalized["sha256"], checksum):
        raise EvidenceIntegrityError("fixture observation hash mismatch")
    return normalized


def capture(phase, account, response, *, id_field, owner_field, private_field, assertions):
    """Record statuses and allowlisted synthetic IDs, never raw headers/private data."""
    try:
        body = response.json()
    except (ValueError, UnicodeError, RecursionError):
        body = None
    items = None
    item = None
    total = None
    truncated = None
    if phase == "discovery" and isinstance(body, list):
        total = len(body)
        truncated = total > 20
        items = [_item(row, id_field=id_field, owner_field=owner_field, private_field=private_field)
                 for row in body[:20] if isinstance(row, dict)]
    elif phase != "discovery":
        item = _item(body, id_field=id_field, owner_field=owner_field, private_field=private_field)
    return seal({"phase": phase, "timestamp": datetime.now(timezone.utc).isoformat(),
                 "actor": account.username, "role": account.role,
                 "request": {"method": response.request.method, "path": response.request.url.path,
                             "authorization": "[REDACTED]" if "Authorization" in response.request.headers else "not supplied"},
                 "response": {"status_code": response.status_code, "items": items, "item_count": total,
                              "items_truncated": truncated, "item": item},
                 "assertions": assertions})


def prepare(observations):
    """Reject altered or non-allowlisted records before any database write."""
    if not isinstance(observations, list) or len(observations) > MAX_OBSERVATIONS:
        raise ValueError("invalid fixture observation collection")
    return [verify(record) for record in observations]
