"""Ephemeral bounded discovery, not a verified ownership registry or live scan.

Never persist this object: identifiers may be private. A harvested ID, owner
field or isolated list is insufficient to establish ownership or a finding.
"""
from dataclasses import dataclass, field
import json
import re
from typing import Literal

from canarygate.accounts.identity_check import observe_identity_pair
from canarygate.network.boundary import GuardedReadRunner

MAX_LIST_ITEMS = 20


@dataclass(frozen=True)
class HarvestObservation:
    status: Literal["HARVESTED", "INCONCLUSIVE", "SKIPPED"]
    reason: str
    ids_a: tuple[str, ...] = field(default=(), repr=False)
    ids_b: tuple[str, ...] = field(default=(), repr=False)
    lists_disjoint: bool | None = None


def _list_ids(response, actor, id_field, owner_field):
    if response.status_code != 200:
        return None

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
        return None
    if not isinstance(data, list) or not 1 <= len(data) <= MAX_LIST_ITEMS:
        return None
    ids = []
    for item in data:
        if not isinstance(item, dict) or item.get(owner_field) != actor:
            return None
        value = item.get(id_field)
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value) or value in ids:
            return None
        ids.append(value)
    return tuple(ids)


def harvest_private_lists(runner: GuardedReadRunner, *, actor_a: str, actor_b: str,
                          profile_path: str, identity_field: str, list_path: str,
                          id_field: str, owner_field: str, ownership_model: str) -> HarvestObservation:
    """Observe two scoped list responses after separate account-profile controls."""
    if (ownership_model != "private" or not isinstance(runner, GuardedReadRunner)
            or not isinstance(list_path, str) or not runner.supports_read_path(list_path)
            or not all(isinstance(name, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", name)
                       for name in (id_field, owner_field)) or id_field == owner_field):
        return HarvestObservation("SKIPPED", "Private model, scoped list and explicit fields are required")
    identities = observe_identity_pair(runner, actor_a=actor_a, actor_b=actor_b,
                                       path=profile_path, identity_field=identity_field)
    if identities.status != "MATCHED_PAIR":
        status = "SKIPPED" if identities.status == "SKIPPED" else "INCONCLUSIVE"
        return HarvestObservation(status, "Two account-profile controls were not established")
    observed = []
    for actor in (actor_a, actor_b):
        try:
            response = runner.get(actor, list_path)
        except ValueError:
            return HarvestObservation("INCONCLUSIVE", "List request was blocked or failed")
        ids = _list_ids(response, actor, id_field, owner_field)
        if ids is None:
            return HarvestObservation("INCONCLUSIVE", "List response was incomplete or ambiguous")
        observed.append(ids)
    if set(observed[0]) & set(observed[1]):
        return HarvestObservation("INCONCLUSIVE", "List isolation was not observed", lists_disjoint=False)
    return HarvestObservation("HARVESTED", "Distinct lists observed; ownership is not yet verified",
                              ids_a=observed[0], ids_b=observed[1], lists_disjoint=True)
