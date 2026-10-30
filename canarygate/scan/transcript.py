"""Bounded, deterministic recorded HTTP transcript for offline generic scans.

A transcript is local synthetic data, never a network client. It is validated
before use, kept in memory, and never persisted or returned by the API.
"""
import json
import re

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MAX_ENTRIES = 32
MAX_BODY_BYTES = 64 * 1024
MAX_TOTAL_BYTES = 512 * 1024
_ALLOWED_STATUSES = frozenset(range(200, 300)) | {400, 401, 403, 404, 409, 422, 500}
MAX_HEADERS = 8


class TranscriptEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    actor: str = Field(pattern=r"^[A-Za-z0-9_.@-]{1,128}$")
    method: str = Field(pattern=r"^GET$")
    path: str
    status: int
    body: dict | list | None = None
    # Recorded response headers are disclosure evidence (server/version/debug),
    # never request metadata. Values are bounded and never persisted raw.
    headers: dict[str, str] = Field(default_factory=dict, max_length=MAX_HEADERS)

    @field_validator("path")
    @classmethod
    def exact_path(cls, value):
        if (not re.fullmatch(r"/[A-Za-z0-9_./~-]{0,511}", value) or "//" in value
                or "?" in value or "#" in value or any(part in {".", ".."} for part in value.split("/"))):
            raise ValueError("transcript paths must be exact, unencoded and query-free")
        return value

    @field_validator("status")
    @classmethod
    def recorded_status(cls, value):
        if value not in _ALLOWED_STATUSES:
            raise ValueError("transcript status is not an allowed recorded response")
        return value

    @field_validator("headers")
    @classmethod
    def bounded_headers(cls, value):
        for key, item in value.items():
            if (not isinstance(key, str) or len(key) > 64 or not key.isascii()
                    or any(character.isspace() for character in key)
                    or not isinstance(item, str) or len(item) > 256 or not item.isprintable()):
                raise ValueError("invalid recorded header")
        return value

    def body_bytes(self):
        if self.body is None:
            return b""
        try:
            encoded = json.dumps(self.body, sort_keys=True, separators=(",", ":"),
                                 ensure_ascii=True, allow_nan=False)
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValueError("transcript body is not bounded JSON") from exc
        return encoded.encode("ascii")


class OfflineTranscript(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    entries: tuple[TranscriptEntry, ...] = Field(min_length=1, max_length=MAX_ENTRIES)

    @model_validator(mode="after")
    def bounded_and_unique(self):
        keys = [(entry.actor, entry.method, entry.path) for entry in self.entries]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate transcript entry")
        total = 0
        for entry in self.entries:
            size = len(entry.body_bytes())
            if size > MAX_BODY_BYTES:
                raise ValueError("transcript body exceeds limit")
            total += size
        if total > MAX_TOTAL_BYTES:
            raise ValueError("transcript exceeds total size limit")
        return self

    def sha256(self) -> str:
        import hashlib
        payload = json.dumps([entry.model_dump(mode="json") for entry in self.entries],
                             sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def responses(self):
        return {(entry.actor, entry.method, entry.path): entry for entry in self.entries}
