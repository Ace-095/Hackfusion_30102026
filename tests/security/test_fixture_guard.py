import httpx
import pytest

from canarygate.offline.runner import FixtureRunner, GuardRejected
from canarygate.offline.target import FixtureTarget


def test_forbidden_requests_never_reach_handler():
    calls = []
    def handler(req):
        calls.append(req)
        return httpx.Response(200)
    runner = FixtureRunner(handler)
    cases = [
        ("alice", "GET", "https://fixture.invalid.evil/items/bob-item", {}),
        ("alice", "GET", "https://fixture.invalid:444/items/bob-item", {}),
        ("alice", "GET", "https://user@fixture.invalid/items/bob-item", {}),
        ("alice", "GET", "http://fixture.invalid/items/bob-item", {}),
        ("alice", "GET", "https://fixture.invalid/items/bob-item?x=1", {}),
        ("alice", "DELETE", "https://fixture.invalid/items/bob-item", {}),
        ("alice", "PUT", "https://fixture.invalid/items/bob-item", {}),
        ("alice", "PATCH", "https://fixture.invalid/items/bob-item", {}),
        ("alice", "POST", "https://fixture.invalid/items/bob-item", {"json_body": {"account": "alice"}}),
        ("alice", "POST", "https://fixture.invalid/login", {"json_body": {"account": "bob"}}),
        ("mallory", "GET", "https://fixture.invalid/items/bob-item", {}),
        ("alice", "GET", "https://fixture.invalid/items/bob-item", {"token": "fixture-token-bob"}),
        ("alice", "GET", "https://fixture.invalid/items/%62ob-item", {"token": "fixture-token-alice"}),
    ]
    try:
        for actor, method, url, kwargs in cases:
            with pytest.raises(GuardRejected):
                runner.request(actor, method, url, **kwargs)
        assert calls == []
    finally:
        runner.close()


def test_budget_and_redirects():
    calls = []
    def handler(req):
        calls.append(str(req.url))
        return httpx.Response(302, headers={"Location": "https://elsewhere.invalid"})
    runner = FixtureRunner(handler, budget=1)
    try:
        response = runner.request("alice", "GET", "https://fixture.invalid/items/bob-item", token="fixture-token-alice")
        assert response.status_code == 302
        assert calls == ["https://fixture.invalid/items/bob-item"]
        with pytest.raises(GuardRejected, match="budget"):
            runner.request("alice", "GET", "https://fixture.invalid/items/bob-item", token="fixture-token-alice")
        assert len(calls) == 1
    finally:
        runner.close()


def test_oversized_fixture_response_is_rejected():
    runner = FixtureRunner(lambda req: httpx.Response(200, content=b"a" * (64 * 1024 + 1)))
    try:
        with pytest.raises(GuardRejected, match="too large"):
            runner.request("alice", "GET", "https://fixture.invalid/items/bob-item", token="fixture-token-alice")
    finally:
        runner.close()


def test_concurrent_callers_are_serialized_and_share_budget():
    from concurrent.futures import ThreadPoolExecutor
    from time import sleep

    active = 0
    max_active = 0
    calls = 0

    def handler(req):
        nonlocal active, max_active, calls
        active += 1
        calls += 1
        max_active = max(max_active, active)
        sleep(0.005)
        active -= 1
        return httpx.Response(200)

    runner = FixtureRunner(handler, budget=5)

    def attempt(_):
        try:
            return runner.request("alice", "GET", "https://fixture.invalid/items/bob-item", token="fixture-token-alice").status_code
        except GuardRejected:
            return None

    try:
        with ThreadPoolExecutor(max_workers=10) as pool:
            results = list(pool.map(attempt, range(10)))
        assert results.count(200) == 5
        assert results.count(None) == 5
        assert calls == 5
        assert max_active == 1
    finally:
        runner.close()
