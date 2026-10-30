"""SQLite storage for redacted, fixture-only scan results.

Each call uses its own connection and parameterized queries. Hashes detect
accidental changes but are not signatures or protection from a database writer.
"""
from contextlib import closing
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3
from uuid import UUID

from pydantic import ValidationError

from canarygate.api.schemas import FixtureRun
from canarygate.evidence.redaction import EvidenceIntegrityError, canonical_json, prepare_for_storage, verify_evidence
from canarygate.evidence.observations import prepare as prepare_observations

MAX_REPORT_BYTES = 2 * 1024 * 1024


def default_database_path() -> Path:
    return Path(os.environ.get("CANARYGATE_DB_PATH", ".canarygate/fixture.sqlite3"))


class FixtureStore:
    def __init__(self, path: str | Path):
        if str(path) == ":memory:":
            raise ValueError("fixture persistence requires a file-backed database")
        self.path = Path(path)

    def _connect(self):
        connection = sqlite3.connect(str(self.path), timeout=5.0)
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def initialize(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as conn, conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS fixture_runs (
                run_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                payload TEXT NOT NULL,
                sha256 TEXT NOT NULL
            )""")
            # Additive migration: legacy rows remain valid with no observation set.
            conn.execute("""CREATE TABLE IF NOT EXISTS fixture_observation_sets (
                run_id TEXT PRIMARY KEY REFERENCES fixture_runs(run_id),
                payload TEXT NOT NULL,
                sha256 TEXT NOT NULL
            )""")

    def save(self, run: dict, observations: list[dict] | None = None) -> dict:
        # Reject unexpected top-level fields instead of silently dropping them.
        if set(run) != set(FixtureRun.model_fields):
            raise ValueError("fixture run fields do not match the contract")
        try:
            UUID(run["id"])
            normalized = FixtureRun.model_validate(run).model_dump(mode="json")
        except (ValueError, ValidationError, TypeError, AttributeError) as exc:
            raise ValueError("invalid fixture run") from exc
        cleaned = prepare_for_storage(normalized)
        payload = canonical_json(cleaned)
        if len(payload.encode("utf-8")) > MAX_REPORT_BYTES:
            raise ValueError("fixture report exceeds storage limit")
        checksum = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        observation_payload = None
        if observations is not None:
            observation_payload = canonical_json(prepare_observations(observations))
            if len(observation_payload.encode("utf-8")) > MAX_REPORT_BYTES:
                raise ValueError("fixture observation set exceeds storage limit")
        with closing(self._connect()) as conn, conn:
            conn.execute("INSERT INTO fixture_runs (run_id, created_at, payload, sha256) VALUES (?, ?, ?, ?)",
                         (cleaned["id"], cleaned["created_at"], payload, checksum))
            if observation_payload is not None:
                observation_checksum = hashlib.sha256(observation_payload.encode("utf-8")).hexdigest()
                conn.execute("INSERT INTO fixture_observation_sets (run_id, payload, sha256) VALUES (?, ?, ?)",
                             (cleaned["id"], observation_payload, observation_checksum))
        return cleaned

    @staticmethod
    def _decode(row) -> dict:
        run_id, payload, checksum = row
        if (not isinstance(payload, str) or len(payload.encode("utf-8")) > MAX_REPORT_BYTES
                or not isinstance(checksum, str) or re.fullmatch(r"[0-9a-f]{64}", checksum) is None
                or not hmac.compare_digest(checksum, hashlib.sha256(payload.encode("utf-8")).hexdigest())):
            raise EvidenceIntegrityError("stored fixture report failed integrity verification")
        try:
            parsed = json.loads(payload)
            fields = set(FixtureRun.model_fields)
            if not isinstance(parsed, dict) or set(parsed) not in (fields, fields - {"bola_checklist"}):
                raise ValueError("stored run fields do not match the contract")
            result = FixtureRun.model_validate(parsed).model_dump(mode="json")
            if result["id"] != run_id:
                raise ValueError("run id mismatch")
            verify_evidence(result)
        except (ValueError, TypeError, KeyError) as exc:
            raise EvidenceIntegrityError("stored fixture report failed validation") from exc
        return result

    def get(self, run_id: str) -> dict | None:
        with closing(self._connect()) as conn, conn:
            row = conn.execute("SELECT run_id, payload, sha256 FROM fixture_runs WHERE run_id = ?", (run_id,)).fetchone()
        return None if row is None else self._decode(row)

    def get_observations(self, run_id: str) -> list[dict] | None:
        with closing(self._connect()) as conn, conn:
            row = conn.execute("SELECT payload, sha256 FROM fixture_observation_sets WHERE run_id = ?", (run_id,)).fetchone()
        if row is None:
            return None  # Pre-checkpoint run: no observations were recorded.
        payload, checksum = row
        if (not isinstance(payload, str) or len(payload.encode("utf-8")) > MAX_REPORT_BYTES
                or not isinstance(checksum, str) or re.fullmatch(r"[0-9a-f]{64}", checksum) is None
                or not hmac.compare_digest(checksum, hashlib.sha256(payload.encode("utf-8")).hexdigest())):
            raise EvidenceIntegrityError("stored fixture observation set failed integrity verification")
        try:
            return prepare_observations(json.loads(payload))
        except (ValueError, TypeError, KeyError) as exc:
            raise EvidenceIntegrityError("stored fixture observation set failed validation") from exc

    def list(self) -> list[dict]:
        with closing(self._connect()) as conn, conn:
            rows = conn.execute("SELECT run_id, payload, sha256 FROM fixture_runs ORDER BY rowid ASC").fetchall()
        return [self._decode(row) for row in rows]

    def latest(self) -> dict | None:
        with closing(self._connect()) as conn, conn:
            row = conn.execute("SELECT run_id, payload, sha256 FROM fixture_runs ORDER BY rowid DESC LIMIT 1").fetchone()
        return None if row is None else self._decode(row)
