"""One ownership registry for fixture and disabled guarded-HTTPX observations.

Only test fixtures and mocked HTTP are supported; live execution remains gated.
Transient responses and identifiers must never be persisted or logged.
"""
from dataclasses import dataclass, field, replace
import json
import re

from canarygate.guard.safety_guard import GuardRejected
from canarygate.models.ownership import OwnedResource
from canarygate.offline.runner import FixtureRunner
from canarygate.network.guarded_httpx import GuardedHTTPXRunner
from canarygate.seed.recipe import Resource
from canarygate.seed.extraction import MISSING, extract, valid_selector

MAX_LIST_ITEMS = 256


@dataclass(frozen=True)
class FixtureOwnershipResult:
    entries: tuple[OwnedResource, ...] = field(default=(), repr=False)
    resource_status: str = 'SKIPPED'
    ownership_status: str = 'SKIPPED'
    reason: str = 'Ownership prerequisites were not met'
    ids: dict = field(default_factory=dict, repr=False)
    baselines: dict = field(default_factory=dict, repr=False)
    source_runner: object = field(default=None, repr=False, compare=False)
    identity_accounts: tuple = field(default=(), repr=False)
    _proof: object = field(default=None, repr=False, compare=False)


# A fail-closed in-process provenance invariant, not a cryptographic signature.
# Only the shared collector issues this proof after both list exclusions and
# both owner reads. It is never serialized or used as durable evidence.
_REGISTRY_ISSUER = object()


@dataclass(frozen=True, repr=False)
class _RegistryProof:
    issuer: object
    snapshot: tuple
    resource_json: str


def _ownership_snapshot(result):
    entries = tuple((e.resource_type, e.resource_id, e.owner, e.ownership_model,
                     e.ownership_verified, e.canary, e.origin) for e in result.entries)
    ids = tuple(sorted(result.ids.items()))
    baselines = tuple(sorted((actor, id(pair[0]), id(pair[1])) for actor, pair in result.baselines.items()))
    return (entries, result.resource_status, result.ownership_status, ids, baselines,
            id(result.source_runner), result.identity_accounts)


def is_issued_guarded_ownership(result, resource):
    try:
        proof = result._proof
        return (type(proof) is _RegistryProof and proof.issuer is _REGISTRY_ISSUER
                and proof.snapshot == _ownership_snapshot(result)
                and proof.resource_json == Resource.model_validate(resource.model_dump()).model_dump_json())
    except (AttributeError, TypeError, ValueError, IndexError):
        return False


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



_PAGINATION_KEYS = {'next', 'nextpage', 'next_page', 'next_token', 'next_cursor',
                    'has_more', 'hasmore', 'more', 'pagination', 'page',
                    'total_pages', 'total', 'total_count', 'links'}


def _ambiguous_pagination(payload, declared_next):
    """Reject other common paging metadata outside the declared next selector.

    Inspect object metadata only, not resource items. This is deliberately
    conservative and cannot detect arbitrary server-specific paging conventions.
    """
    target = tuple(declared_next.split('.'))
    stack = [(payload, ())]
    nodes = 0
    while stack:
        value, path = stack.pop()
        nodes += 1
        if nodes > 10000 or len(path) > 32:
            return True
        if not isinstance(value, dict):
            continue
        for key, item in value.items():
            child = path + (key,)
            if key.casefold() in _PAGINATION_KEYS and target[:len(child)] != child:
                return True
            if isinstance(item, dict):
                stack.append((item, child))
    return False


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
    """Existing fixture entry point, sharing the registry with guarded HTTPX."""
    if (type(runner) is not FixtureRunner or not isinstance(accounts, (tuple, list))
            or len(accounts) != 2 or not isinstance(tokens, dict)
            or any(tokens.get(a) != f'fixture-token-{a}' for a in accounts)):
        return FixtureOwnershipResult(reason='Two distinct fixture accounts and credentials are required')
    return _collect_ownership(runner, resource_type=resource_type, resource=resource, accounts=accounts,
                              tokens=tokens, on_discovery=on_discovery, on_exclusion=on_exclusion,
                              on_baseline=on_baseline)


def collect_guarded_ownership(runner, *, resource_type, resource, accounts, profile_path, identity_field):
    """Same registry after two guarded profile controls; no live gate is enabled.

    The profile controls show observed identities, not authorization. The
    separate ownership and policy/disclosure requirements still apply.
    """
    if (type(runner) is not GuardedHTTPXRunner or not isinstance(accounts, (tuple, list))
            or len(accounts) != 2 or not all(isinstance(a, str) for a in accounts)):
        return FixtureOwnershipResult(reason='Two guarded accounts and profile controls are required')
    from canarygate.accounts.identity_check import observe_identity_pair
    identities = observe_identity_pair(runner, actor_a=accounts[0], actor_b=accounts[1],
                                       path=profile_path, identity_field=identity_field)
    if identities.status != 'MATCHED_PAIR':
        return FixtureOwnershipResult(reason='Two guarded account profile controls were not established')
    return _collect_ownership(runner, resource_type=resource_type, resource=resource, accounts=accounts,
                              tokens=None, identity_accounts=tuple(accounts))


def _collect_ownership(runner, *, resource_type, resource, accounts, tokens,
                       on_discovery=None, on_exclusion=None, on_baseline=None, identity_accounts=()):
    """Shared private-list, cross-exclusion and two-owner-baseline algorithm."""
    is_fixture = type(runner) is FixtureRunner
    scoped_accounts = (set(runner.scope.accounts) if is_fixture else
                       {item.account for item in runner.scope.accounts})
    if (not isinstance(resource, Resource) or not isinstance(resource_type, str)
            or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', resource_type)
            or not isinstance(accounts, (tuple, list)) or len(accounts) != 2
            or not all(isinstance(a, str) and a in scoped_accounts for a in accounts)
            or accounts[0] == accounts[1]):
        return FixtureOwnershipResult(reason='Two distinct scoped accounts and a resource are required')

    def read(actor, path):
        if is_fixture:
            return runner.request(actor, 'GET', runner.scope.origin + path, token=tokens[actor])
        return runner.get(actor, path)

    # Pydantic model_copy(update=...) can bypass validators; revalidate before
    # any request so a forged pagination configuration cannot widen the cap.
    try:
        resource = Resource.model_validate(resource.model_dump())
    except (ValueError, TypeError, AttributeError):
        return FixtureOwnershipResult(reason='Fixture resource configuration is invalid')
    if (not valid_selector(resource.id_field) or not valid_selector(resource.ownership_field)
            or resource.ownership_field.casefold() == resource.id_field.casefold()
            or resource.ownership_field.split('.')[-1].casefold() == 'id'):
        return FixtureOwnershipResult(reason='A distinct explicit owner field is required')
    if (resource.discovery.method != 'GET' or resource.detail.method != 'GET'
            or not _valid_detail(resource.detail.path) or '?' in resource.discovery.path
            or '#' in resource.discovery.path):
        return FixtureOwnershipResult(reason='Scoped read-only discovery and detail operations are required')
    ids, lists = {}, {}
    for actor in accounts:
        all_ids, own_ids, seen_tokens = [], [], set()
        next_token = None
        max_pages = resource.pagination.max_pages if resource.pagination else 1
        for page in range(max_pages):
            url = runner.scope.origin + resource.discovery.path
            if next_token is not None:
                url += '?' + resource.pagination.parameter + '=' + next_token
            try:
                response = read(actor, url[len(runner.scope.origin):])
            except (GuardRejected, ValueError):
                return FixtureOwnershipResult(entries=_unverified(resource_type, resource.ownership_model, ids),
                                              resource_status='FAILED', reason='Discovery was blocked or failed at the safety boundary')
            payload = _json(response) if response.status_code == 200 else None
            data = extract(payload, resource.list_field) if resource.list_field else payload
            pagination_headers = (any(name in response.headers for name in ('link', 'x-next-page', 'content-range', 'x-total-count'))
                                  or (not is_fixture and response.extensions.get('canary_pagination_metadata_present') is not False))
            valid = (isinstance(data, list) and len(all_ids) + len(data) <= MAX_LIST_ITEMS
                     and not pagination_headers
                     and (not resource.pagination or not _ambiguous_pagination(payload, resource.pagination.next_field))
                     and all(isinstance(row, dict)
                     and _safe_id(extract(row, resource.id_field)) for row in data))
            page_ids = [extract(row, resource.id_field) for row in data] if valid else []
            valid = bool(valid and len(all_ids + page_ids) == len(set(all_ids + page_ids)))
            candidates = [extract(row, resource.id_field) for row in data
                          if extract(row, resource.ownership_field) == actor] if valid else []
            if on_discovery is not None:
                on_discovery(actor, response, bool(candidates) if valid else None)
            if not valid:
                return FixtureOwnershipResult(entries=_unverified(resource_type, resource.ownership_model, ids),
                                              resource_status='FAILED', reason='Fixture resource discovery incomplete or ambiguous')
            all_ids.extend(page_ids)
            own_ids.extend(candidates)
            if resource.pagination is None:
                break
            continuation = extract(payload, resource.pagination.next_field)
            if continuation is None:
                break
            if (continuation is MISSING or not isinstance(continuation, str)
                    or not re.fullmatch(r'[A-Za-z0-9_-]{1,32}', continuation)
                    or continuation in seen_tokens or page + 1 >= max_pages):
                return FixtureOwnershipResult(entries=_unverified(resource_type, resource.ownership_model, ids),
                                              resource_status='FAILED', reason='Fixture pagination incomplete or ambiguous')
            seen_tokens.add(continuation)
            next_token = continuation
        if not own_ids:
            return FixtureOwnershipResult(entries=_unverified(resource_type, resource.ownership_model, ids),
                                          resource_status='PARTIAL', reason='Fixture resource discovery incomplete or ambiguous')
        ids[actor], lists[actor] = own_ids[0], set(all_ids)
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
            response = read(actor, path)
        except (GuardRejected, ValueError):
            return FixtureOwnershipResult(entries=candidates, resource_status='SUCCESS', ownership_status='FAILED',
                                          reason='Owner detail was blocked or failed at the safety boundary')
        obj = _json(response) if response.status_code == 200 else None
        matches = (isinstance(obj, dict) and extract(obj, resource.id_field) == ids[actor]
                   and extract(obj, resource.ownership_field) == actor)
        if on_baseline is not None:
            on_baseline(actor, response, matches)
        if not matches:
            return FixtureOwnershipResult(entries=candidates, resource_status='SUCCESS', ownership_status='FAILED',
                                          reason='Owner baseline failed or was ambiguous')
        baselines[actor] = (response, obj)
    entries = tuple(OwnedResource(resource_type=resource_type, resource_id=ids[actor], owner=actor,
                                 ownership_model='private', ownership_verified=True, canary=None, origin='harvested')
                    for actor in accounts)
    result = FixtureOwnershipResult(entries=entries, resource_status='SUCCESS', ownership_status='SUCCESS',
                                    reason='Ownership verified by owner reads and cross-list isolation',
                                    ids=ids, baselines=baselines,
                                    source_runner=None if is_fixture else runner,
                                    identity_accounts=identity_accounts)
    if not is_fixture:
        result = replace(result, _proof=_RegistryProof(_REGISTRY_ISSUER, _ownership_snapshot(result), resource.model_dump_json()))
    return result
