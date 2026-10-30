import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from canarygate.database.store import FixtureStore
from canarygate.evidence.redaction import EvidenceIntegrityError, digest, redact, verify_evidence
from canarygate.offline.scan import run_fixture


def test_recursive_redaction_masks_sensitive_fields_and_credential_patterns():
    value = {"Authorization": "Bearer raw-token", "cookie": "session-secret",
             "nested": [{"password": "secretpw"}, {"description": "token=abc123; safe text"}],
             "header": "Basic abc123", "note": "synthetic-bob-private-canary"}
    result = redact(value)
    content = json.dumps(result)
    for secret in ("raw-token", "session-secret", "secretpw", "abc123", "synthetic-bob-private-canary"):
        assert secret not in content
    assert result["Authorization"] == "[REDACTED]"
    assert "safe text" in content


def test_store_minimizes_evidence_and_rehashes_after_redaction(tmp_path):
    store = FixtureStore(tmp_path / "test.sqlite3")
    store.initialize()
    run = run_fixture()
    run["reason"] = "Bearer SUPER-ACCESS-SECRET"
    ev = run["evidence"]["ownership"]
    ev["request"]["headers"]["Cookie"] = "private-cookie-value"
    ev["response"]["body"]["private_note"] = "unredacted-private-note"
    ev["response"]["body"]["extra"] = "arbitrary-private-value"
    ev["checklist"]["both_owner_baselines"] = "untrusted-checklist-value"
    ev["sha256"] = digest({key: value for key, value in ev.items() if key not in {"sha256", "redacted"}})
    stored = store.save(run)
    assert store.get(stored["id"]) == stored
    verify_evidence(stored)
    evidence = stored["evidence"]["ownership"]
    assert evidence["request"]["headers"] == {"Authorization": "[REDACTED]"}
    assert evidence["response"]["body"]["private_note"] == "[REDACTED]"
    assert "both_owner_baselines" not in evidence["checklist"]
    assert "extra" not in evidence["response"]["body"]
    for secret in (b"SUPER-ACCESS-SECRET", b"private-cookie-value", b"unredacted-private-note",
                   b"arbitrary-private-value", b"untrusted-checklist-value"):
        assert secret not in store.path.read_bytes()


def test_invalid_evidence_hash_is_rejected_without_inserting(tmp_path):
    store = FixtureStore(tmp_path / "test.sqlite3")
    store.initialize()
    run = run_fixture()
    run["evidence"]["ownership"]["status_code"] = 404
    with pytest.raises(EvidenceIntegrityError):
        store.save(run)
    assert store.list() == []


def test_duplicate_ids_are_not_overwritten_and_concurrent_writes_survive(tmp_path):
    store = FixtureStore(tmp_path / "test.sqlite3")
    store.initialize()
    runs = [run_fixture() for _ in range(6)]
    with ThreadPoolExecutor(max_workers=6) as pool:
        saved = list(pool.map(store.save, runs))
    assert {entry["id"] for entry in store.list()} == {entry["id"] for entry in saved}
    with pytest.raises(sqlite3.IntegrityError):
        store.save(runs[0])
    assert len(store.list()) == 6


def test_memory_database_is_rejected_instead_of_silently_losing_data():
    with pytest.raises(ValueError, match="file-backed"):
        FixtureStore(":memory:")
