"""One two-part read-BOLA oracle for fixture and mocked guarded HTTPX reads.

No requests occur here. General policy and production evidence are not yet
supported; the only accepted policy/denial contract remains synthetic.
"""
import httpx

from canarygate.models.result import Result
from canarygate.network.guarded_httpx import GuardedHTTPXRunner
from canarygate.scope.loader import fixture_scope
from canarygate.seed.recipe import Resource
from canarygate.seed.registry import (FixtureOwnershipResult, _json, _safe_id, _valid_detail,
                                      is_issued_guarded_ownership)
from canarygate.seed.extraction import MISSING, extract, valid_selector

CHECKLIST_KEYS = (
    'private_resource', 'distinct_accounts', 'ownership_verified', 'owner_baseline',
    'private_baseline', 'attacker_request', 'response_checked', 'private_disclosure',
    'policy_denies_access', 'verified_denial',
)


def empty_checklist():
    return dict.fromkeys(CHECKLIST_KEYS, False)


def _request_matches(response, actor, path, source_runner=None):
    if source_runner is not None:
        return (type(source_runner) is GuardedHTTPXRunner
                and source_runner.verifies_recorded_read(response, actor, path))
    try:
        request = response.request
        return (request.method == 'GET' and request.url == httpx.URL(fixture_scope().origin + path)
                and request.headers.get('Authorization') == f'Bearer fixture-token-{actor}'
                and not request.content)
    except (AttributeError, RuntimeError, TypeError, ValueError):
        return False


def _private_marker(value, ids, actors):
    return (isinstance(value, str) and bool(value.strip()) and len(value) <= 4096
            and '*' not in value
            and value.strip().casefold() not in {'[redacted]', '<redacted>', 'redacted', '[masked]', '<masked>', 'masked', 'null', 'none'}
            and value not in actors and not any(item_id in value for item_id in ids))


def evaluate_read_bola(*, ownership, resource_type, resource, actor, owner, response,
                       expected_access, expected_source):
    """Evaluate observed fixture evidence; never issue a request or accept JWT claims.

    The source allowlist and denial body are deliberately limited to the bundled
    fixture contract. A Result contains booleans only, no raw bodies or tokens.
    """
    checks = empty_checklist()

    def result(verdict, reason):
        return Result(verdict=verdict, verdict_reason=reason, checklist=checks.copy(),
                      remediation_key='bola' if verdict == 'CONFIRMED' else '')

    if not isinstance(resource, Resource) or not isinstance(ownership, FixtureOwnershipResult):
        return result('INCONCLUSIVE', 'Fixture ownership evidence is missing')
    checks['private_resource'] = resource.ownership_model == 'private'
    source_runner = ownership.source_runner
    parties_valid = isinstance(actor, str) and isinstance(owner, str) and actor != owner
    fixture_identities = parties_valid and source_runner is None and {actor, owner} == {'alice', 'bob'}
    guarded_identities = False
    if parties_valid and type(source_runner) is GuardedHTTPXRunner and is_issued_guarded_ownership(ownership, resource):
        try:
            guarded_identities = (set(ownership.identity_accounts) == {actor, owner}
                                  and source_runner.has_distinct_credentials(actor, owner))
        except ValueError:
            guarded_identities = False
    checks['distinct_accounts'] = bool(fixture_identities or guarded_identities)
    checks['policy_denies_access'] = (expected_access == 'owner-only'
                                     and expected_source == 'synthetic fixture policy')
    if not checks['private_resource'] or not checks['distinct_accounts']:
        return result('INCONCLUSIVE', 'A distinct fixture actor and private resource are required')
    entries = [e for e in ownership.entries if e.owner in (actor, owner)]
    if (ownership.ownership_status != 'SUCCESS' or len(entries) != 2
            or {e.owner for e in entries} != {actor, owner}
            or any(e.ownership_verified is not True or e.ownership_model != 'private'
                   or e.resource_type != resource_type or not _safe_id(e.resource_id) for e in entries)):
        return result('INCONCLUSIVE', 'Verified private ownership evidence is missing')
    ids = {e.owner: e.resource_id for e in entries}
    if (ids[actor] == ids[owner] or ownership.ids != ids or not _valid_detail(resource.detail.path)
            or resource.detail.method != 'GET' or (resource.ownership_field.casefold() == resource.id_field.casefold()
                or resource.ownership_field.split('.')[-1].casefold() == 'id')):
        return result('INCONCLUSIVE', 'Ownership evidence is inconsistent')
    checks['ownership_verified'] = True
    values = {}
    for account in (actor, owner):
        baseline = ownership.baselines.get(account)
        if not isinstance(baseline, tuple) or len(baseline) != 2:
            return result('INCONCLUSIVE', 'Owner baseline evidence is missing')
        baseline_response = baseline[0]
        path = resource.detail.path.replace('{id}', ids[account])
        if (not isinstance(baseline_response, httpx.Response) or baseline_response.status_code != 200
                or len(baseline_response.content) > 64 * 1024 or not _request_matches(baseline_response, account, path, source_runner)):
            return result('INCONCLUSIVE', 'Owner baseline request failed or used the wrong identity')
        body = _json(baseline_response)
        if (not isinstance(body, dict) or extract(body, resource.id_field) != ids[account]
                or extract(body, resource.ownership_field) != account):
            return result('INCONCLUSIVE', 'Owner baseline response is ambiguous')
        values[account] = extract(body, resource.private_field, None)
    checks['owner_baseline'] = True
    field = resource.private_field
    if (not valid_selector(field)
            or field.split('.')[-1].casefold() in {'id', 'owner', 'status', 'user_id'}
            or field.casefold() in {resource.id_field.casefold(), resource.ownership_field.casefold()}
            or not _private_marker(values[owner], tuple(ids.values()), (actor, owner))
            or values[actor] == values[owner]
            or (resource.known_owner_canary is not None and values[owner] != resource.known_owner_canary)):
        return result('INCONCLUSIVE', 'Distinct private owner baseline evidence is missing')
    checks['private_baseline'] = True
    if not isinstance(response, httpx.Response):
        return result('INCONCLUSIVE', 'Cross-account response evidence is missing')
    path = resource.detail.path.replace('{id}', ids[owner])
    if not _request_matches(response, actor, path, source_runner):
        return result('INCONCLUSIVE', 'Cross-account request identity or target is inconsistent')
    checks['attacker_request'] = True
    if len(response.content) > 64 * 1024:
        return result('INCONCLUSIVE', 'Cross-account response exceeds the fixture limit')
    body = _json(response)
    if not isinstance(body, dict):
        return result('INCONCLUSIVE', 'Cross-account response body is empty or ambiguous')
    checks['response_checked'] = True
    observed_id = extract(body, resource.id_field)
    observed_owner = extract(body, resource.ownership_field)
    marker_matches = response.status_code == 200 and extract(body, field) == values[owner]
    checks['private_disclosure'] = bool(marker_matches and observed_id == ids[owner] and observed_owner == owner)
    # The fixture has exactly this denial contract. Status alone is insufficient.
    checks['verified_denial'] = (response.status_code == 403 and body == {'error': 'forbidden'}
                                 and values[owner] not in body['error'])
    if not checks['policy_denies_access']:
        return result('INCONCLUSIVE', 'A reliable fixture owner-only policy is not established')
    if checks['private_disclosure']:
        return result('CONFIRMED', 'Verified fixture ownership and cross-user private baseline disclosure')
    if (marker_matches and (observed_id is MISSING or observed_owner is MISSING)
            and (observed_id is MISSING or observed_id == ids[owner])
            and (observed_owner is MISSING or observed_owner == owner)):
        return result('SUSPECTED', 'Private marker observed, but response identity is incomplete')
    if checks['verified_denial']:
        return result('SAFE', 'The fixture denied the cross-user read with a checked denial body')
    return result('INCONCLUSIVE', 'No verified private disclosure or checked denial was established')
