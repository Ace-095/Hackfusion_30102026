"""Observe owner baselines, not a verified ownership registry or BOLA result.

Identifiers and private values are kept only in the returned in-memory object.
It is not approved for serialization, persistence, logging or reporting.
"""
from dataclasses import dataclass, field
import json
import re
from typing import Literal

from canarygate.network.boundary import GuardedReadRunner
from canarygate.seed.discovery import harvest_private_lists


@dataclass(frozen=True)
class OwnerBaselineObservation:
    status: Literal["BASELINES_OBSERVED", "INCONCLUSIVE", "SKIPPED"]
    reason: str
    # A separate independently reviewed policy and disclosure evidence remain
    # necessary. This provisional helper never certifies ownership by itself.
    ownership_verified: bool = field(default=False, init=False)
    id_a: str | None = field(default=None, repr=False)
    id_b: str | None = field(default=None, repr=False)
    private_a: str | None = field(default=None, repr=False)
    private_b: str | None = field(default=None, repr=False)


def _valid_template(value):
    if not isinstance(value, str) or len(value) > 512 or value.count('{id}') != 1:
        return False
    parts = value.split('/')
    if not value.startswith('/') or parts.count('{id}') != 1 or any(p in {'.', '..'} for p in parts):
        return False
    example = value.replace('{id}', 'sample')
    return bool(re.fullmatch(r'/[A-Za-z0-9_./~-]*', example)) and '//' not in example


def _baseline(response, actor, expected_id, id_field, owner_field, private_field):
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
        value = json.loads(response.content, object_pairs_hook=unique_object)
    except (ValueError, UnicodeError, RecursionError):
        return None
    if not isinstance(value, dict) or value.get(id_field) != expected_id or value.get(owner_field) != actor:
        return None
    private = value.get(private_field)
    if (not isinstance(private, str) or not private.strip() or len(private) > 4096
            or '*' in private or private.strip().casefold() in {'[redacted]', '<redacted>', 'redacted', '[masked]', '<masked>', 'masked', 'null', 'none'}):
        return None
    return private


def observe_owner_baselines(runner: GuardedReadRunner, *, actor_a: str, actor_b: str,
                            profile_path: str, identity_field: str, list_path: str,
                            detail_template: str, id_field: str, owner_field: str,
                            private_field: str, ownership_model: str) -> OwnerBaselineObservation:
    if (not _valid_template(detail_template) or not isinstance(private_field, str)
            or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,63}', private_field)
            or private_field.casefold() in {'id', 'owner', 'status'}
            or private_field.casefold() in {str(id_field).casefold(), str(owner_field).casefold()}):
        return OwnerBaselineObservation('SKIPPED', 'Exact detail template and distinct private field are required')
    harvest = harvest_private_lists(runner, actor_a=actor_a, actor_b=actor_b, profile_path=profile_path,
                                     identity_field=identity_field, list_path=list_path, id_field=id_field,
                                     owner_field=owner_field, ownership_model=ownership_model)
    if harvest.status != 'HARVESTED':
        return OwnerBaselineObservation(harvest.status, 'Account or resource-list prerequisites were not established')
    ids = (harvest.ids_a[0], harvest.ids_b[0])
    paths = tuple(detail_template.replace('{id}', value) for value in ids)
    if not all(runner.supports_read_path(path) for path in paths):
        return OwnerBaselineObservation('SKIPPED', 'Both exact owner-detail reads must be scoped')
    values = []
    for actor, item_id, path in zip((actor_a, actor_b), ids, paths):
        try:
            response = runner.get(actor, path)
        except ValueError:
            return OwnerBaselineObservation('INCONCLUSIVE', 'Owner detail request was blocked or failed')
        private = _baseline(response, actor, item_id, id_field, owner_field, private_field)
        if private is None or private in (actor_a, actor_b) or any(item_id in private for item_id in ids):
            return OwnerBaselineObservation('INCONCLUSIVE', 'Owner detail baseline was missing or ambiguous')
        values.append(private)
    if values[0] == values[1]:
        return OwnerBaselineObservation('INCONCLUSIVE', 'Owner private baselines are not distinct')
    return OwnerBaselineObservation('BASELINES_OBSERVED', 'Owner baselines observed; ownership is not verified',
                                    id_a=ids[0], id_b=ids[1], private_a=values[0], private_b=values[1])
