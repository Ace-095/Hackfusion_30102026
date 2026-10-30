"""SQLite persistence for integrity-checked TargetLab reset proofs.

A reset proof is a separate controlled scenario, not a security verdict, and is
stored apart from the interaction run it supports. Only minimized facts are kept:
status codes, declared expectations, digests and bounded notes.
"""
from contextlib import closing
import hashlib
import hmac
import json
from pathlib import Path
import sqlite3

from pydantic import ValidationError

from canarygate.evidence.redaction import EvidenceIntegrityError, canonical_json, redact
from canarygate.scan.lab_sci_models import LabResetProof

MAX_RUN_BYTES = 256 * 1024


class LabResetStore:
    def __init__(self, path):
        if str(path) == ":memory:":
            raise ValueError("reset persistence requires a file-backed database")
        self.path = Path(path)

    def _connect(self):
        connection = sqlite3.connect(str(self.path), timeout=5.0)
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def initialize(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as conn, conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS lab_sci_resets (
                proof_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                payload TEXT NOT NULL,
                sha256 TEXT NOT NULL
            )""")

    def save(self, proof):
        if not isinstance(proof, LabResetProof):
            raise ValueError("a validated reset proof is required")
        try:
            normalized = LabResetProof.model_validate(proof.model_dump(mode="json"))
            normalized = normalized.model_dump(mode="json")
        except (ValueError, ValidationError, TypeError, AttributeError) as exc:
            raise ValueError("invalid reset proof") from exc
        cleaned = redact(normalized)
        payload = canonical_json(cleaned)
        if len(payload.encode("utf-8")) > MAX_RUN_BYTES:
            raise ValueError("reset proof exceeds storage limit")
        checksum = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        with closing(self._connect()) as conn, conn:
            conn.execute("INSERT INTO lab_sci_resets (proof_id, created_at, payload, sha256) "
                         "VALUES (?, ?, ?, ?)",
                         (cleaned["id"], cleaned["created_at"], payload, checksum))
        return cleaned

    def get(self, proof_id):
        if not isinstance(proof_id, str) or len(proof_id) > 64:
            return None
        with closing(self._connect()) as conn:
            row = conn.execute("SELECT payload, sha256 FROM lab_sci_resets WHERE proof_id = ?",
                               (proof_id,)).fetchone()
        if row is None:
            return None
        payload, checksum = row
        if not hmac.compare_digest(hashlib.sha256(payload.encode("utf-8")).hexdigest(), checksum):
            raise EvidenceIntegrityError("stored reset proof failed integrity verification")
        try:
            return LabResetProof.model_validate(json.loads(payload)).model_dump(mode="json")
        except (ValueError, ValidationError) as exc:
            raise EvidenceIntegrityError("stored reset proof is not valid") from exc

    def list(self):
        with closing(self._connect()) as conn:
            rows = conn.execute("SELECT proof_id FROM lab_sci_resets ORDER BY created_at, proof_id"
                                ).fetchall()
        return [item for item in (self.get(row[0]) for row in rows) if item is not None]
