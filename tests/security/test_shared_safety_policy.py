"""Both execution boundaries must enforce one shared safety-policy contract."""
import httpx
import pytest

from canarygate.guard import authorized_preflight, safety_guard
from canarygate.guard.policy import SafetyPolicyViolation, check_common
from canarygate.offline.runner import FixtureRunner
from canarygate.offline.target import FixtureTarget
from canarygate.scan import scenarios
from canarygate.scan.offline import OfflineGuardedRunner


def fixture_runner(handler=None):
    return FixtureRunner(handler or FixtureTarget().handle)


def offline_runner():
    plan = scenarios.build_scenario('synthetic-vulnerable')
    return OfflineGuardedRunner(plan.scope, {'account-a': 'offline-token-account-a',
                                             'account-b': 'offline-token-account-b'}, plan.transcript)


def test_common_policy_rejects_prohibited_methods_unknown_actors_and_exhausted_budget():
    for method in ('DELETE', 'PUT', 'PATCH', 'TRACE', 'CONNECT'):
        with pytest.raises(SafetyPolicyViolation):
            check_common('alice', method, frozenset({'alice'}), frozenset({'GET', 'POST'}), 5)
    with pytest.raises(SafetyPolicyViolation):
        check_common('eve', 'GET', frozenset({'alice'}), frozenset({'GET'}), 5)
    with pytest.raises(SafetyPolicyViolation):
        check_common('alice', 'BREW', frozenset({'alice'}), frozenset({'GET'}), 5)
    with pytest.raises(SafetyPolicyViolation):
        check_common('alice', 'GET', frozenset({'alice'}), frozenset({'GET'}), 0)
    assert check_common('alice', 'GET', frozenset({'alice'}), frozenset({'GET'}), 1) is None


def test_both_boundaries_call_the_shared_policy_and_raise_the_same_violation(monkeypatch):
    calls = []
    original = check_common
    def spy(*args, **kwargs):
        calls.append(args)
        return original(*args, **kwargs)
    monkeypatch.setattr(safety_guard, 'check_common', spy)
    monkeypatch.setattr(authorized_preflight, 'check_common', spy)
    fixture = fixture_runner()
    guard = fixture.guard
    with pytest.raises(SafetyPolicyViolation):
        guard.authorize('alice', 'DELETE', fixture.scope.origin + '/items')
    plan = scenarios.build_scenario('synthetic-vulnerable')
    offline = OfflineGuardedRunner(plan.scope, {'account-a': 'offline-token-account-a',
                                                'account-b': 'offline-token-account-b'}, plan.transcript)
    try:
        with pytest.raises(SafetyPolicyViolation):
            offline.guard.authorize('account-a', 'DELETE', plan.scope.origin + '/records')
        assert len(calls) >= 2
    finally:
        offline.close()
        fixture.close()


@pytest.mark.parametrize('method', ['DELETE', 'PUT', 'PATCH'])
def test_prohibited_methods_never_reach_fixture_handler_or_offline_transcript(method):
    touched = []
    fixture = fixture_runner(lambda request: touched.append(request) or httpx.Response(200))
    with pytest.raises(ValueError):
        fixture.guard.authorize('alice', method, fixture.scope.origin + '/items')
    assert touched == []
    plan = scenarios.build_scenario('synthetic-vulnerable')
    offline = OfflineGuardedRunner(plan.scope, {'account-a': 'offline-token-account-a',
                                                'account-b': 'offline-token-account-b'}, plan.transcript)
    try:
        with pytest.raises(ValueError):
            offline.guard.authorize('account-a', method, plan.scope.origin + '/records')
        assert offline.stats()['requests_sent'] == 0
    finally:
        offline.close()
        fixture.close()


def test_budget_exhaustion_is_blocked_identically_and_counted():
    plan = scenarios.build_scenario('synthetic-guard-block')
    offline = OfflineGuardedRunner(plan.scope, {'account-a': 'offline-token-account-a',
                                                'account-b': 'offline-token-account-b'}, plan.transcript)
    try:
        result = plan_test_run(offline, plan)
        assert result['constraints']['blocked_by_guard'] >= 1
        assert result['constraints']['requests_sent'] == plan.scope.request_budget
    finally:
        offline.close()


def plan_test_run(runner, plan):
    from canarygate.scan.generic import run_generic_scan
    return run_generic_scan(runner, plan)


def test_offline_runner_refuses_unscoped_paths_before_lookup_and_counts_blocked():
    plan = scenarios.build_scenario('synthetic-vulnerable')
    offline = OfflineGuardedRunner(plan.scope, {'account-a': 'offline-token-account-a',
                                                'account-b': 'offline-token-account-b'}, plan.transcript)
    try:
        with pytest.raises(ValueError):
            offline.get('account-a', '/records/../../profile')
        stats = offline.stats()
        assert stats['requests_sent'] == 0 and stats['blocked_by_guard'] == 1
    finally:
        offline.close()
