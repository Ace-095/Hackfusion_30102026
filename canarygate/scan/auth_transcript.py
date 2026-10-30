"""Bounded recorded responses for crafted-credential authentication probes.

Entries are local synthetic data keyed by the exact probe that produced them.
They are validated before use and are never persisted or returned by the API.
"""
import hashlib
import json
import re

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from canarygate.scope.authorized import AUTH_PROBE_NAMES

MAX_ENTRIES = 32
MAX_BODY_BYTES = 64 * 1024
MAX_TOTAL_BYTES = 512 * 1024
PROBE_NAMES = AUTH_PROBE_NAMES + ("logout",)
_ALLOWED_STATUSES = frozenset(range(200, 300)) | {400, 401, 403, 404, 409, 422}


class AuthTranscriptEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    actor: str = Field(pattern=r"^[A-Za-z0-9_.@-]{1,128}$")
    method: str = Field(pattern=r"^(GET|POST)$")
    path: str
    probe: str
    status: int
    body: dict | list | None = None

    @field_validator("probe")
    @classmethod
    def known_probe(cls, value):
        if value not in PROBE_NAMES:
            raise ValueError("unknown authentication probe")
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

    @model_validator(mode="after")
    def method_probe_pairing(self):
        if self.method == "POST" and self.probe != "logout":
            raise ValueError("only the declared logout operation may use POST")
        if self.probe == "logout" and self.method != "POST":
            raise ValueError("logout observations must be recorded as POST")
        if self.probe == "logout_reuse" and self.method != "GET":
            raise ValueError("post-logout reuse is observed with a read")
        return self

    def body_bytes(self):
        if self.body is None:
            return b""
        try:
            encoded = json.dumps(self.body, sort_keys=True, separators=(",", ":"),
                                 ensure_ascii=True, allow_nan=False)
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValueError("probe body is not bounded JSON") from exc
        return encoded.encode("ascii")


class AuthenticationTranscript(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    entries: tuple[AuthTranscriptEntry, ...] = Field(min_length=1, max_length=MAX_ENTRIES)

    @model_validator(mode="after")
    def bounded_and_unique(self):
        keys = [(entry.actor, entry.method, entry.path, entry.probe) for entry in self.entries]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate authentication transcript entry")
        total = 0
        for entry in self.entries:
            size = len(entry.body_bytes())
            if size > MAX_BODY_BYTES:
                raise ValueError("authentication transcript body exceeds limit")
            total += size
        if total > MAX_TOTAL_BYTES:
            raise ValueError("authentication transcript exceeds total size limit")
        return self

    def sha256(self) -> str:
        payload = json.dumps([entry.model_dump(mode="json") for entry in self.entries],
                             sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def combined_sha256(reads, probes):
    """Hash both transcripts so a run identifies exactly one recorded plan."""
    return hashlib.sha256(f"{reads.sha256()}:{probes.sha256()}".encode("ascii")).hexdigest()
