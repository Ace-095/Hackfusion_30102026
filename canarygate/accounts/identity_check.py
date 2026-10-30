"""Bounded identity observation using an explicitly scoped profile operation.

A single matching profile is an observation, not proof of distinct identities
or ownership. Callers must establish independent cross-account controls before
using it for any authorization verdict. This module is not wired to the API.
"""
from dataclasses import dataclass
import json
import re
from typing import Literal

from canarygate.network.guarded_httpx import GuardedHTTPXRunner


@dataclass(frozen=True)
class IdentityObservation:
    account: str
    status: Literal["MATCHED", "MISMATCH", "INCONCLUSIVE", "SKIPPED"]
    reason: str


def observe_identity(runner: GuardedHTTPXRunner, *, actor: str, path: str, identity_field: str) -> IdentityObservation:
    """Observe one explicitly declared profile field; never return response data."""
    if (not isinstance(runner, GuardedHTTPXRunner) or not isinstance(actor, str)
            or not isinstance(path, str) or not isinstance(identity_field, str)
            or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", identity_field)
            or actor not in {item.account for item in runner.scope.accounts}
            or not runner.supports_read_path(path)):
        return IdentityObservation(actor if isinstance(actor, str) else "", "SKIPPED",
                                   "Identity operation or account is not explicitly scoped")
    try:
        response = runner.get(actor, path)
    except ValueError:
        return IdentityObservation(actor, "INCONCLUSIVE", "Identity request was blocked or failed")
    if response.status_code != 200:
        return IdentityObservation(actor, "INCONCLUSIVE", "Identity response was not a successful profile")

    def unique_object(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError("duplicate key")
            obj[key] = value
        return obj

    try:
        data = json.loads(response.content, object_pairs_hook=unique_object)
    except (ValueError, UnicodeError, RecursionError):
        return IdentityObservation(actor, "INCONCLUSIVE", "Identity response was not unambiguous JSON")
    observed = data.get(identity_field) if isinstance(data, dict) else None
    if not isinstance(observed, str) or not observed:
        return IdentityObservation(actor, "INCONCLUSIVE", "Declared identity field was unavailable")
    if observed != actor:
        # Do not continue a run using a token that appears to identify another account.
        runner.halt()
        return IdentityObservation(actor, "MISMATCH", "Identity response did not match the scoped account")
    return IdentityObservation(actor, "MATCHED", "Profile field matched the scoped account; independent controls are still required")
