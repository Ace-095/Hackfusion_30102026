"""SQLite persistence for integrity-checked offline authentication runs.

Hashes detect accidental or naive database changes; they are not signatures.
Only minimized runs are stored: no raw bodies, credentials, tokens or probe
transcripts. The store rejects anything that does not satisfy the strict model.
"""
from contextlib import closing
import hashlib
import hmac
import json
from pathlib import Path
import re
import sqlite3
from uuid import UUID

from pydantic import ValidationError

from canarygate.evidence.redaction import EvidenceIntegrityError, canonical_json, digest, redact
from canarygate.scan.auth_models import AuthenticationRun

MAX_RUN_BYTES = 512 * 1024


def verify_authentication_evidence(run):
    for check in run["checks"]:
        evidence = check.get("evidence")
        if evidence is None:
            continue
        summary = {key: value for key, value in evidence.items() if key not in {"sha256", "redacted"}}
        if (evidence.get("redacted") is not True or not isinstance(evidence.get("sha256"), str)
                or re.fullmatch(r"[0-9a-f]{64}", evidence["sha256"]) is None
                or not hmac.compare_digest(evidence["sha256"], digest(summary))):
            raise EvidenceIntegrityError("authentication evidence failed integrity verification")


class AuthenticationStore:
    def __init__(self, path):
        if str(path) == ":memory:":
            raise ValueError("authentication persistence requires a file-backed database")
        self.path = Path(path)

    def _connect(self):
        connection = sqlite3.connect(str(self.path), timeout=5.0)
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def initialize(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as conn, conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS authentication_runs (
                run_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                payload TEXT NOT NULL,
                sha256 TEXT NOT NULL
            )""")

    def save(self, run):
        if not isinstance(run, dict) or set(run) != set(AuthenticationRun.model_fields):
            raise ValueError("authentication run fields do not match the contract")
        try:
            UUID(run["id"])
            verify_authentication_evidence(run)
            normalized = AuthenticationRun.model_validate(run).model_dump(mode="json")
        except (ValueError, ValidationError, TypeError, AttributeError) as exc:
            raise ValueError("invalid authentication run") from exc
        cleaned = redact(normalized)
        verify_authentication_evidence(cleaned)
        payload = canonical_json(cleaned)
        if len(payload.encode("utf-8")) > MAX_RUN_BYTES:
            raise ValueError("authentication run exceeds storage limit")
        checksum = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        with closing(self._connect()) as conn, conn:
            conn.execute("INSERT INTO authentication_runs (run_id, created_at, payload, sha256) "
                         "VALUES (?, ?, ?, ?)",
                         (cleaned["id"], cleaned["created_at"], payload, checksum))
        return cleaned

    @staticmethod
    def _decode(row):
        run_id, payload, checksum = row
        if (not isinstance(payload, str) or len(payload.encode("utf-8")) > MAX_RUN_BYTES
                or not isinstance(checksum, str) or re.fullmatch(r"[0-9a-f]{64}", checksum) is None
                or not hmac.compare_digest(checksum, hashlib.sha256(payload.encode("utf-8")).hexdigest())):
            raise EvidenceIntegrityError("stored authentication run failed integrity verification")
        try:
            parsed = json.loads(payload)
            if not isinstance(parsed, dict) or set(parsed) != set(AuthenticationRun.model_fields):
                raise ValueError("stored authentication fields do not match the contract")
            result = AuthenticationRun.model_validate(parsed).model_dump(mode="json")
            if result["id"] != run_id:
                raise ValueError("authentication run id mismatch")
            verify_authentication_evidence(result)
        except (ValueError, TypeError, KeyError) as exc:
            raise EvidenceIntegrityError("stored authentication run failed validation") from exc
        return result

    def get(self, run_id):
        if not isinstance(run_id, str) or not re.fullmatch(r"[0-9a-fA-F-]{36}", run_id):
            return None
        with closing(self._connect()) as conn, conn:
            row = conn.execute("SELECT run_id, payload, sha256 FROM authentication_runs WHERE run_id = ?",
                               (run_id,)).fetchone()
        return None if row is None else self._decode(row)

    def list(self):
        with closing(self._connect()) as conn, conn:
            rows = conn.execute("SELECT run_id, payload, sha256 FROM authentication_runs "
                                "ORDER BY rowid ASC").fetchall()
        return [self._decode(row) for row in rows]
