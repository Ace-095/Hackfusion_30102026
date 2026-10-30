"""SQLite persistence for integrity-checked offline validation runs.

Only minimized runs are stored: no raw request or response bodies, no
credentials and no probe transcripts. Anything that does not satisfy the strict
model is rejected before it reaches the database.
"""
from contextlib import closing
import hashlib
import hmac
import json
from pathlib import Path
import re
import sqlite3

from pydantic import ValidationError

from canarygate.evidence.redaction import EvidenceIntegrityError, canonical_json, redact
from canarygate.scan.validation_models import ValidationRun

MAX_RUN_BYTES = 512 * 1024


class ValidationStore:
    def __init__(self, path):
        if str(path) == ":memory:":
            raise ValueError("validation persistence requires a file-backed database")
        self.path = Path(path)

    def _connect(self):
        connection = sqlite3.connect(str(self.path), timeout=5.0)
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def initialize(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as conn, conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS validation_runs (
                run_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                payload TEXT NOT NULL,
                sha256 TEXT NOT NULL
            )""")

    def save(self, run):
        if not isinstance(run, ValidationRun):
            raise ValueError("a validated validation run is required")
        try:
            normalized = ValidationRun.model_validate(run.model_dump(mode="json")).model_dump(mode="json")
        except (ValueError, ValidationError, TypeError, AttributeError) as exc:
            raise ValueError("invalid validation run") from exc
        cleaned = redact(normalized)
        payload = canonical_json(cleaned)
        if len(payload.encode("utf-8")) > MAX_RUN_BYTES:
            raise ValueError("validation run exceeds storage limit")
        checksum = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        with closing(self._connect()) as conn, conn:
            conn.execute("INSERT INTO validation_runs (run_id, created_at, payload, sha256) "
                         "VALUES (?, ?, ?, ?)",
                         (cleaned["id"], cleaned["created_at"], payload, checksum))
        return cleaned

    @staticmethod
    def _decode(row):
        run_id, payload, checksum = row
        if (not isinstance(payload, str) or len(payload.encode("utf-8")) > MAX_RUN_BYTES
                or not isinstance(checksum, str) or re.fullmatch(r"[0-9a-f]{64}", checksum) is None
                or not hmac.compare_digest(checksum, hashlib.sha256(payload.encode("utf-8")).hexdigest())):
            raise EvidenceIntegrityError("stored validation run failed integrity verification")
        try:
            parsed = json.loads(payload)
            if not isinstance(parsed, dict):
                raise ValueError("stored validation payload is not an object")
            result = ValidationRun.model_validate(parsed).model_dump(mode="json")
            if result["id"] != run_id:
                raise ValueError("validation run id mismatch")
            if redact(result) != result:
                raise EvidenceIntegrityError("stored validation run was not redacted")
        except (ValueError, ValidationError, TypeError, KeyError) as exc:
            raise EvidenceIntegrityError("stored validation run failed validation") from exc
        return result

    def get(self, run_id):
        if not isinstance(run_id, str) or not re.fullmatch(r"[0-9a-fA-F-]{36}", run_id):
            return None
        with closing(self._connect()) as conn, conn:
            row = conn.execute("SELECT run_id, payload, sha256 FROM validation_runs WHERE run_id = ?",
                               (run_id,)).fetchone()
        return None if row is None else self._decode(row)

    def list(self):
        with closing(self._connect()) as conn, conn:
            rows = conn.execute("SELECT run_id, payload, sha256 FROM validation_runs "
                                "ORDER BY rowid ASC").fetchall()
        return [self._decode(row) for row in rows]
