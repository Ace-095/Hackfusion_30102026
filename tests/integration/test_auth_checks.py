import json
import socket

import pytest

from canarygate.offline.scan import run_fixture
from canarygate.offline.target import FixtureTarget


def checks_by_id(result):
    return {check["id"]: check for check in result["checks"]}


@pytest.mark.parametrize("behavior,expected,status", [
    ("reject", "SAFE", 401),
    ("bypass", "CONFIRMED", 200),
    ("empty", "INCONCLUSIVE", 200),
    ("redirect", "INCONCLUSIVE", 302),
])
def test_actual_probe_responses_determine_auth_verdicts(behavior, expected, status, monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError("offline fixture tried to use network or DNS")
    monkeypatch.setattr(socket.socket, "connect", no_network)
    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    result = run_fixture(FixtureTarget(auth_behavior=behavior))
    checks = checks_by_id(result)
    for check_id in ("AUTHN-01", "AUTHN-02", "AUTHN-03"):
        check = checks[check_id]
        assert check["verdict"] == expected
        assert check["evidence"]["status_code"] == status
        assert check["evidence"]["private_canary_matched"] is (expected == "CONFIRMED")
        assert (check["remediation"] is not None) is (expected == "CONFIRMED")
    assert result["constraints"]["redirects_followed"] == 0
    assert result["constraints"]["requests_sent"] == 10
    assert "synthetic-alice-private-note" not in json.dumps(result)
    assert "fixture-token-" not in json.dumps(result)
    assert "malformed-fixture" not in json.dumps(result)
    assert "synthetic-fixture" not in json.dumps(result)


def test_missing_credential_evidence_does_not_invent_an_auth_header():
    checks = checks_by_id(run_fixture())
    assert checks["AUTHN-01"]["evidence"]["request"]["headers"] == {}
    assert checks["AUTHN-02"]["evidence"]["request"]["headers"] == {"Authorization": "[REDACTED]"}


def test_skipped_setup_does_not_report_unrun_probes_safe():
    checks = checks_by_id(run_fixture(FixtureTarget(bob_login=False)))
    assert all(check["verdict"] == "SKIPPED" for check in checks.values())
    assert all(check["evidence"] is None for check in checks.values())


def test_auth_evidence_hashes_are_over_redacted_summaries():
    import hashlib
    result = run_fixture(FixtureTarget(auth_behavior="bypass"))
    for check_id in ("AUTHN-01", "AUTHN-02", "AUTHN-03"):
        evidence = checks_by_id(result)[check_id]["evidence"]
        assert evidence["redacted"] is True
        canonical = {k: v for k, v in evidence.items() if k not in {"sha256", "redacted"}}
        digest = hashlib.sha256(json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        assert evidence["sha256"] == digest


def test_scope_blocked_probe_is_skipped_but_oversized_response_is_inconclusive():
    import httpx
    from canarygate.offline.auth_checks import run_auth_checks
    from canarygate.offline.runner import FixtureRunner

    calls = []
    runner = FixtureRunner(lambda req: calls.append(req) or httpx.Response(200, content=b"x" * 65537))
    try:
        def unused_summary(*args, **kwargs):
            raise AssertionError("no response body should be summarized")
        blocked = run_auth_checks(runner, actor="alice", role="user", path="/items/bob-item", token="opaque",
                                  private_field="private_note", baseline="private", summary=unused_summary)
        assert [c["verdict"] for c in blocked[:3]] == ["SKIPPED"] * 3
        assert calls == []
        executed = run_auth_checks(runner, actor="alice", role="user", path="/items/alice-item", token="opaque",
                                   private_field="private_note", baseline="private", summary=unused_summary)
        assert [c["verdict"] for c in executed[:3]] == ["INCONCLUSIVE"] * 3
        assert all("executed" in c["reason"] for c in executed[:3])
        assert len(calls) == 3
    finally:
        runner.close()
