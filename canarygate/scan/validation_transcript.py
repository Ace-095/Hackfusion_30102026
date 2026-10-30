"""Bounded recorded responses for safe input-validation and disclosure probes.

Entries are local synthetic data. They are validated before use, held in memory
and never persisted or returned by the API.
"""
import hashlib
import json
import re

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from canarygate.oracles.validation import INPUT_PROBE_NAMES

MAX_ENTRIES = 16
MAX_BODY_BYTES = 64 * 1024
MAX_TOTAL_BYTES = 512 * 1024
MAX_HEADERS = 16
_ALLOWED_STATUSES = frozenset(range(200, 300)) | {400, 401, 403, 404, 409, 422, 500}
_HEADER_NAME = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_HEADER_VALUE = re.compile(r"^[\x20-\x7e]{0,256}$")


class ProbeEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    actor: str = Field(pattern=r"^[A-Za-z0-9_.@-]{1,128}$")
    method: str = Field(pattern=r"^POST$")
    path: str
    probe: str
    status: int
    body: dict | list | None = None
    headers: dict[str, str] = Field(default_factory=dict, max_length=MAX_HEADERS)

    @field_validator("probe")
    @classmethod
    def known_probe(cls, value):
        if value not in INPUT_PROBE_NAMES:
            raise ValueError("unknown input-validation probe")
        return value

    @field_validator("path")
    @classmethod
    def exact_path(cls, value):
        if (not re.fullmatch(r"/[A-Za-z0-9_./~-]{0,511}", value) or "//" in value
                or "?" in value or "#" in value
                or any(part in {".", ".."} for part in value.split("/"))):
            raise ValueError("probe paths must be exact, unencoded and query-free")
        return value

    @field_validator("status")
    @classmethod
    def recorded_status(cls, value):
        if value not in _ALLOWED_STATUSES:
            raise ValueError("probe status is not an allowed recorded response")
        return value

    @field_validator("headers")
    @classmethod
    def bounded_headers(cls, value):
        for key, item in value.items():
            if _HEADER_NAME.fullmatch(key) is None or not isinstance(item, str) \
                    or _HEADER_VALUE.fullmatch(item) is None:
                raise ValueError("invalid recorded header")
        return value

    def body_bytes(self):
        if self.body is None:
            return b""
        try:
            encoded = json.dumps(self.body, sort_keys=True, separators=(",", ":"),
                                 ensure_ascii=True, allow_nan=False)
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValueError("probe body is not bounded JSON") from exc
        return encoded.encode("ascii")


class ValidationTranscript(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    entries: tuple[ProbeEntry, ...] = Field(min_length=1, max_length=MAX_ENTRIES)

    @model_validator(mode="after")
    def bounded_and_unique(self):
        keys = [(entry.actor, entry.method, entry.path, entry.probe) for entry in self.entries]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate validation probe entry")
        total = 0
        for entry in self.entries:
            size = len(entry.body_bytes())
            if size > MAX_BODY_BYTES:
                raise ValueError("validation probe body exceeds limit")
            total += size
        if total > MAX_TOTAL_BYTES:
            raise ValueError("validation probe transcript exceeds total size limit")
        return self

    def sha256(self):
        payload = json.dumps([entry.model_dump(mode="json") for entry in self.entries],
                             sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def combined_sha256(reads, probes):
    return hashlib.sha256(f"{reads.sha256()}:{probes.sha256()}".encode("ascii")).hexdigest()
