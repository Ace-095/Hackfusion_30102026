"""Fixture-only ownership registry based on guarded, observed HTTP responses.

The registry never runs a BOLA probe. It accepts only the in-process fixture
runner; it is not a live ownership registry and must not persist raw responses.
"""
from dataclasses import dataclass, field
import json
import re

from canarygate.guard.safety_guard import GuardRejected
from canarygate.models.ownership import OwnedResource
from canarygate.offline.runner import FixtureRunner
from canarygate.seed.recipe import Resource

MAX_LIST_ITEMS = 256


@dataclass(frozen=True)
class FixtureOwnershipResult:
    entries: tuple[OwnedResource, ...] = ()
    resource_status: str = 'SKIPPED'
    ownership_status: str = 'SKIPPED'
    reason: str = 'Ownership prerequisites were not met'
    ids: dict = field(default_factory=dict, repr=False)
    baselines: dict = field(default_factory=dict, repr=False)


def _json(response):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result
    def reject_constant(value):
        raise ValueError('invalid JSON constant')
    try:
        return json.loads(response.content, object_pairs_hook=unique, parse_constant=reject_constant)
    except (ValueError, UnicodeError, RecursionError):
        return None


def _safe_id(value):
    return isinstance(value, str) and bool(re.fullmatch(r'[A-Za-z0-9_-]{1,128}', value))


def _valid_detail(template):
    if not isinstance(template, str) or template.count('{id}') != 1 or len(template) > 512:
        return False
    parts = template.split('/')
    if not template.startswith('/') or parts.count('{id}') != 1 or any(p in ('.', '..') for p in parts):
        return False
    value = template.replace('{id}', 'sample')
    return bool(re.fullmatch(r'/[A-Za-z0-9_./~-]*', value)) and '//' not in value


def _unverified(resource_type, model, ids):
    return tuple(OwnedResource(resource_type=resource_type, resource_id=item_id, owner=actor,
                               ownership_model=model, ownership_verified=False, canary=None, origin='harvested')
                 for actor, item_id in ids.items())


def collect_fixture_ownership(runner, *, resource_type, resource, accounts, tokens,
                              on_discovery=None, on_exclusion=None, on_baseline=None):
    """Discover and verify two fixture resources through the existing guard.

    Only unambiguous complete private lists, distinct identities and IDs, both
    cross-list exclusions, and matching owner-detail 200 responses can verify.
    Shared/public candidates are recorded without asserting private isolation.
    """
    if (type(runner) is not FixtureRunner or not isinstance(resource, Resource)
            or not isinstance(resource_type, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', resource_type)
            or not isinstance(accounts, (tuple, list)) or len(accounts) != 2
            or not all(isinstance(a, str) and a in runner.scope.accounts for a in accounts)
            or accounts[0] == accounts[1] or not isinstance(tokens, dict)
            or any(tokens.get(a) != f'fixture-token-{a}' for a in accounts)):
        return FixtureOwnershipResult(reason='Two distinct fixture accounts and credentials are required')
    if (not resource.id_field or not resource.ownership_field
            or resource.ownership_field in {resource.id_field, 'id'}):
        return FixtureOwnershipResult(reason='A distinct explicit owner field is required')
    if (resource.discovery.method != 'GET' or resource.detail.method != 'GET'
            or not _valid_detail(resource.detail.path)):
        return FixtureOwnershipResult(reason='Scoped read-only discovery and detail operations are required')
    ids, lists = {}, {}
    for actor in accounts:
        try:
            response = runner.request(actor, 'GET', runner.scope.origin + resource.discovery.path, token=tokens[actor])
        except GuardRejected:
            return FixtureOwnershipResult(entries=_unverified(resource_type, resource.ownership_model, ids),
                                          resource_status='FAILED', reason='Discovery blocked by fixture safety guard')
        data = _json(response) if response.status_code == 200 else None
        pagination = any(name in response.headers for name in ('link', 'x-next-page', 'content-range', 'x-total-count'))
        valid = (isinstance(data, list) and len(data) <= MAX_LIST_ITEMS and not pagination
                 and all(isinstance(row, dict) and _safe_id(row.get(resource.id_field)) for row in data))
        item_ids = [row[resource.id_field] for row in data] if valid else []
        valid = bool(valid and len(item_ids) == len(set(item_ids)))
        candidates = [row[resource.id_field] for row in data
                      if row.get(resource.ownership_field) == actor] if valid else []
        if on_discovery is not None:
            on_discovery(actor, response, bool(candidates) if valid else None)
        if not valid or not candidates:
            return FixtureOwnershipResult(entries=_unverified(resource_type, resource.ownership_model, ids),
                                          resource_status='FAILED' if not valid else 'PARTIAL',
                                          reason='Fixture resource discovery incomplete or ambiguous')
        ids[actor], lists[actor] = candidates[0], set(item_ids)
    candidates = _unverified(resource_type, resource.ownership_model, ids)
    if ids[accounts[0]] == ids[accounts[1]]:
        return FixtureOwnershipResult(entries=candidates, resource_status='FAILED',
                                      reason='Discovered resource IDs are not distinct')
    if resource.ownership_model != 'private':
        return FixtureOwnershipResult(entries=candidates, resource_status='SUCCESS',
                                      reason='Shared or public resources are not verified as private')
    isolated = True
    for owner, other in ((accounts[0], accounts[1]), (accounts[1], accounts[0])):
        excluded = ids[owner] not in lists[other]
        if on_exclusion is not None:
            on_exclusion(other, excluded)
        isolated &= excluded
    if not isolated:
        return FixtureOwnershipResult(entries=candidates, resource_status='SUCCESS', ownership_status='FAILED',
                                      reason='Cross-account list isolation was not verified')
    baselines = {}
    for actor in accounts:
        path = resource.detail.path.replace('{id}', ids[actor])
        try:
            response = runner.request(actor, 'GET', runner.scope.origin + path, token=tokens[actor])
        except GuardRejected:
            return FixtureOwnershipResult(entries=candidates, resource_status='SUCCESS', ownership_status='FAILED',
                                          reason='Owner detail blocked by fixture safety guard')
        obj = _json(response) if response.status_code == 200 else None
        matches = (isinstance(obj, dict) and obj.get(resource.id_field) == ids[actor]
                   and obj.get(resource.ownership_field) == actor)
        if on_baseline is not None:
            on_baseline(actor, response, matches)
        if not matches:
            return FixtureOwnershipResult(entries=candidates, resource_status='SUCCESS', ownership_status='FAILED',
                                          reason='Owner baseline failed or was ambiguous')
        baselines[actor] = (response, obj)
    entries = tuple(OwnedResource(resource_type=resource_type, resource_id=ids[actor], owner=actor,
                                 ownership_model='private', ownership_verified=True, canary=None, origin='harvested')
                    for actor in accounts)
    return FixtureOwnershipResult(entries=entries, resource_status='SUCCESS', ownership_status='SUCCESS',
                                  reason='Fixture ownership verified by owner reads and cross-list isolation',
                                  ids=ids, baselines=baselines)
