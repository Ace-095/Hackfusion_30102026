from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from canarygate.models import (
    Endpoint, Evidence, Identity, MatrixCell, OwnedResource, Recipe, Result,
    ScanRun, ScopeConfig, SetupStatus, TestCase as CaseContract,
)


def test_scope_requires_exact_host_and_budget():
    data = dict(scheme="https", hostname="api.example.invalid", port=443,
                allowed_methods=["GET"], request_budget=5)
    assert ScopeConfig(**data).hostname == "api.example.invalid"
    for bad_host in ("*.example.invalid", "https://example.invalid", "example.invalid/path", "example.invalid:443", "bad\nhost", ""):
        with pytest.raises(ValidationError):
            ScopeConfig(**{**data, "hostname": bad_host})
    with pytest.raises(ValidationError):
        ScopeConfig(**{**data, "request_budget": 0})
    with pytest.raises(ValidationError):
        ScopeConfig(**{**data, "allowed_methods": ["*"]})


@pytest.mark.parametrize("access", ["public", "authenticated", "role:admin", "owner-only", "unknown"])
def test_expected_access_values(access):
    endpoint = Endpoint(method="GET", path="/items", parameters=[], security=None,
                        expected_access=access, expected_source="spec")
    assert endpoint.expected_access == access


@pytest.mark.parametrize("access", ["role:", "role:  ", "admin"])
def test_invalid_expected_access(access):
    with pytest.raises(ValidationError):
        Endpoint(method="GET", path="/items", parameters=[], security=None,
                 expected_access=access, expected_source="spec")


def test_identity_token_is_not_dumped_or_represented():
    alice = Identity(account="alice", role="user", token="secret-token")
    bob = Identity(account="bob", role="user")
    alice.claims["id"] = "alice"
    assert bob.claims == {}
    assert alice.token == "secret-token"
    assert "secret-token" not in repr(alice)
    assert "token" not in alice.model_dump()
    assert "secret-token" not in alice.model_dump_json()


def test_contracts_can_represent_an_offline_scan():
    resource = OwnedResource(resource_type="item", resource_id="b1", owner="bob",
                             ownership_model="private", ownership_verified=True,
                             origin="fixture")
    recipe = Recipe(accounts={}, login={}, resources={})
    case = CaseContract(id="bola-1", category="read-bola", endpoint="GET /items/{id}",
                        actor="alice", target_resource=resource.resource_id,
                        request_template={}, non_destructive=True,
                        evidence_required=["ownership", "disclosure"], verdict_rules={},
                        remediation_key="authorization")
    evidence = Evidence(timestamp=datetime.now(timezone.utc), account_role="user",
                        request={}, response={}, redacted=True, sha256="fixture-hash")
    result = Result(verdict="INCONCLUSIVE", verdict_reason="Not executed",
                    checklist={}, remediation_key=case.remediation_key)
    matrix = MatrixCell(endpoint=case.endpoint, actor=case.actor,
                        target_resource=case.target_resource, expected_access="owner-only",
                        expected_source="fixture", verdict=result.verdict)
    setup = SetupStatus(strategy="fixture", authentication={}, resources={},
                        ownership_verification="SKIPPED", bola_coverage="SKIPPED")
    run = ScanRun(run_id="fixture", timestamp=evidence.timestamp, setup_status=setup,
                  results=[result], scope_hash="fixture-hash", interventions=[])
    assert recipe.resources == {}
    assert matrix.verdict == run.results[0].verdict == "INCONCLUSIVE"


def test_invalid_verdict_and_ownership_model_are_rejected():
    with pytest.raises(ValidationError):
        Result(verdict="PASS", verdict_reason="", checklist={}, remediation_key="")
    with pytest.raises(ValidationError):
        OwnedResource(resource_type="item", resource_id="1", owner="bob",
                      ownership_model="unknown", ownership_verified=False, origin="fixture")
