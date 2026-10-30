"""Nominal guarded-read boundary and shared response-provenance checks.

Only the two explicit subclasses use this: the disabled guarded HTTPX transport
and the offline recorded-transcript runner. Arbitrary duck-typed objects are
not accepted by the registry or the BOLA oracle.
"""
import hashlib
import hmac
import threading
import weakref

import httpx

from canarygate.guard.policy import MAX_RESPONSE_BYTES

PAGINATION_METADATA_KEY = "canary_pagination_metadata_present"


class GuardedReadRunner:
    """Marker plus in-process provenance for a single scoped run.

    Subclasses must provide `_scope`, `supports_read_path()`, `get()`, `halt()`,
    `has_distinct_credentials()` and `stats()`. Nothing here is a network
    transport or a cryptographic attestation.
    """

    transport_label = "guarded_read"

    def __init__(self):
        # Weak keys keep raw responses out of long-lived runner state.
        self._read_records = weakref.WeakKeyDictionary()
        self._read_records_lock = threading.Lock()

    def _record_read(self, response, actor, path):
        if not isinstance(response, httpx.Response):
            raise ValueError("invalid response object")
        with self._read_records_lock:
            self._read_records[response] = (
                actor, path, response.status_code,
                hashlib.sha256(response.content).digest(),
                response.extensions.get(PAGINATION_METADATA_KEY))

    def verifies_recorded_read(self, response, actor, path):
        """Check same-run GET provenance and detect post-receipt mutation."""
        if not isinstance(response, httpx.Response) or not self.supports_read_path(path):
            return False
        with self._read_records_lock:
            record = self._read_records.get(response)
        if record is None or record[:3] != (actor, path, response.status_code):
            return False
        try:
            request = response.request
            return (request.method == "GET" and request.url == httpx.URL(self._scope.origin + path)
                    and request.extensions.get("canary_actor") == actor and not request.content
                    and len(response.content) <= MAX_RESPONSE_BYTES
                    and hmac.compare_digest(record[3], hashlib.sha256(response.content).digest())
                    and response.extensions.get(PAGINATION_METADATA_KEY) is record[4])
        except (AttributeError, RuntimeError, TypeError, ValueError):
            return False

    def supports_read_path(self, path):
        raise NotImplementedError

    def get(self, actor, path):
        raise NotImplementedError

    def halt(self):
        raise NotImplementedError

    def has_distinct_credentials(self, actor_a, actor_b):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError

    def close(self):
        raise NotImplementedError
