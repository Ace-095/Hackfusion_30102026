"""The two new acceptance tests: operation classification and DNS isolation."""
import socket

import httpx
import pytest
from pydantic import ValidationError

from canarygate.guard.safety_guard import GuardRejected
from canarygate.offline.runner import FixtureRunner
from canarygate.offline.scan import fixture_recipe, run_fixture
from canarygate.scope.loader import FixtureScope, fixture_scope, load_scope
from canarygate.seed.recipe import validate_fixture_recipe


def test_operation_classification_blocks_destructive_and_unknown_get_before_transport():
    calls = []
    scope_data = fixture_scope().model_dump(mode="json")
    scope_data["operations"] += [
        {"method": "GET", "path": "/erase", "classification": "DESTRUCTIVE"},
        {"method": "GET", "path": "/mutate", "classification": "STATE_CHANGING"},
        {"method": "GET", "path": "/fake-login", "classification": "AUTHENTICATION"},
    ]
    scope = FixtureScope.model_validate(scope_data)
    runner = FixtureRunner(lambda req: calls.append(req) or httpx.Response(200), scope=scope)
    try:
        for path in ("/erase", "/mutate", "/unknown", "/fake-login"):
            with pytest.raises(GuardRejected):
                runner.request("alice", "GET", scope.origin + path, token="fixture-token-alice")
        assert calls == []
        assert runner.guard.blocked == 4
    finally:
        runner.close()
    scope_data["operations"][0]["classification"] = "UNRECOGNIZED"
    with pytest.raises(ValidationError):
        FixtureScope.model_validate(scope_data)


def test_fixture_mode_uses_no_dns_resolver_or_network_connection(monkeypatch):
    attempts = []
    def forbidden(*args, **kwargs):
        attempts.append((args, kwargs))
        raise AssertionError("DNS or network access attempted")
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "gethostbyname", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    result = run_fixture()
    assert result["verdict"] == "CONFIRMED"
    assert result["constraints"]["network_transport_enabled"] is False
    assert attempts == []


def test_scope_is_sole_target_authority_and_recipe_rejects_secrets_and_base_url():
    recipe = fixture_recipe()
    recipe["setup"]["base_url"] = "https://attacker.invalid"
    with pytest.raises(ValidationError):
        validate_fixture_recipe(recipe)
    recipe = fixture_recipe()
    recipe["setup"]["accounts"]["user_a"]["password"] = "do-not-store"
    with pytest.raises(ValidationError):
        validate_fixture_recipe(recipe)
    with pytest.raises((ValueError, ValidationError)):
        load_scope("scheme: https\nhostname: '*.example.com'\nport: 443\nallowed_methods: [GET]\nrequest_budget: 10\naccounts: [a]\noperations: []")


def test_metadata_or_reflected_resource_id_is_not_private_disclosure():
    recipe = fixture_recipe()
    recipe["setup"]["resources"]["items"]["private_field"] = "id"
    result = run_fixture(recipe=recipe)
    assert result["verdict"] == "SKIPPED"
    assert result["evidence"]["disclosure"] is None


def test_scope_mutation_cannot_widen_guard_after_initialization():
    calls = []
    scope = fixture_scope()
    runner = FixtureRunner(lambda req: calls.append(req) or httpx.Response(200), scope=scope)
    try:
        scope.accounts.append("mallory")
        scope.allowed_methods.append("DELETE")
        with pytest.raises(GuardRejected):
            runner.request("mallory", "GET", scope.origin + "/items/bob-item", token="fixture-token-mallory")
        with pytest.raises(GuardRejected):
            runner.request("alice", "DELETE", scope.origin + "/items/bob-item")
        assert calls == []
    finally:
        runner.close()


def test_reflected_resource_id_cannot_confirm_private_data():
    recipe = fixture_recipe()
    recipe["setup"]["resources"]["items"]["known_owner_canary"] = "reflected:bob-item"
    from canarygate.offline.target import FixtureTarget
    result = run_fixture(FixtureTarget(canary="reflected:bob-item"), recipe=recipe)
    assert result["verdict"] == "SKIPPED"
    assert result["evidence"]["disclosure"] is None


def test_malformed_url_fails_closed_before_transport():
    calls = []
    runner = FixtureRunner(lambda req: calls.append(req) or httpx.Response(200))
    try:
        with pytest.raises(GuardRejected):
            runner.request("alice", "GET", "https://fixture.invalid:bad/items/bob-item", token="fixture-token-alice")
        assert calls == []
    finally:
        runner.close()


def test_authentication_post_is_not_retried_on_error():
    calls = []
    runner = FixtureRunner(lambda req: calls.append(req) or httpx.Response(503))
    try:
        response = runner.request("alice", "POST", runner.scope.origin + "/login", json_body={"account": "alice"})
        assert response.status_code == 503
        assert len(calls) == 1
    finally:
        runner.close()


def test_authentication_probes_require_explicit_scope_and_never_bypass_guard():
    calls = []
    runner = FixtureRunner(lambda req: calls.append(req) or httpx.Response(401))
    try:
        # The approved fixture operation accepts the fixed, explicitly scoped probes.
        response = runner.request("alice", "GET", runner.scope.origin + "/items/alice-item", auth_probe="missing")
        assert response.status_code == 401
        assert len(calls) == 1 and "Authorization" not in calls[0].headers
        for path, probe in (("/items/bob-item", "missing"), ("/items/alice-item", "unknown")):
            with pytest.raises(GuardRejected):
                runner.request("alice", "GET", runner.scope.origin + path, auth_probe=probe)
        with pytest.raises(GuardRejected):
            runner.request("mallory", "GET", runner.scope.origin + "/items/alice-item", auth_probe="missing")
        with pytest.raises(GuardRejected):
            runner.request("alice", "GET", runner.scope.origin + "/items/alice-item", auth_probe="malformed", token="fixture-token-bob")
        assert len(calls) == 1
    finally:
        runner.close()


def test_only_exact_query_strings_in_fixture_scope_reach_transport():
    calls = []
    runner = FixtureRunner(lambda req: calls.append(req) or httpx.Response(200))
    try:
        for path in ("/search", "/search?limit=1", "/search?limit=notanumber", "/search?limit=999", "/search?limit=9"):
            runner.request("alice", "GET", runner.scope.origin + path, token="fixture-token-alice")
        assert len(calls) == 5
        for path in ("/search?limit=2", "/search?limit=%31", "/search?limit=1&extra=1",
                     "/search?", "/search?limit=1#fragment", "/items/bob-item?limit=1"):
            with pytest.raises(GuardRejected):
                runner.request("alice", "GET", runner.scope.origin + path, token="fixture-token-alice")
        assert len(calls) == 5
    finally:
        runner.close()


def test_repeated_5xx_and_lockout_stop_future_fixture_requests():
    for status, expected_reason, allowed_count in ((500, "repeated server errors", 2),
                                                    (423, "account lockout or rate limit", 1),
                                                    (429, "account lockout or rate limit", 1)):
        calls = []
        runner = FixtureRunner(lambda req: calls.append(req) or httpx.Response(status))
        try:
            for _ in range(allowed_count):
                assert runner.request("alice", "GET", runner.scope.origin + "/items/alice-item", token="fixture-token-alice").status_code == status
            with pytest.raises(GuardRejected, match="halted"):
                runner.request("alice", "GET", runner.scope.origin + "/items/alice-item", token="fixture-token-alice")
            assert len(calls) == allowed_count
            assert runner.halted_reason == expected_reason
        finally:
            runner.close()


def test_appending_query_scope_after_guard_creation_cannot_widen_permissions():
    from canarygate.scope.loader import ScopedOperation
    scope = fixture_scope()
    calls = []
    runner = FixtureRunner(lambda req: calls.append(req) or httpx.Response(200), scope=scope)
    try:
        scope.operations.append(ScopedOperation(method="GET", path="/search", query="limit=2", classification="READ_ONLY"))
        with pytest.raises(GuardRejected):
            runner.request("alice", "GET", scope.origin + "/search?limit=2", token="fixture-token-alice")
        assert calls == []
    finally:
        runner.close()
