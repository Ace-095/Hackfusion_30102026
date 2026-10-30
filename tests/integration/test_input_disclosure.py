import hashlib
import json
import socket

import pytest

from canarygate.offline.scan import run_fixture
from canarygate.offline.target import FixtureTarget


class RecordingTarget(FixtureTarget):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.requests = []

    def handle(self, request):
        self.requests.append((request.method, request.url.path, request.url.query))
        return super().handle(request)


def checks(result):
    return {item["id"]: item for item in result["checks"]}


@pytest.mark.parametrize("behavior,verdict,status", [
    ("strict", "SAFE", 400),
    ("accept", "SUSPECTED", 200),
    ("empty_error", "INCONCLUSIVE", 400),
    ("redirect", "INCONCLUSIVE", 302),
])
def test_input_verdicts_follow_actual_scoped_fixture_responses(behavior, verdict, status, monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError("fixture tried to open a network connection or resolve DNS")
    monkeypatch.setattr(socket.socket, "connect", no_network)
    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    target = RecordingTarget(validation_behavior=behavior)
    result = run_fixture(target)
    found = checks(result)
    for check_id in ("INPUT-01", "INPUT-02", "INPUT-04"):
        assert found[check_id]["verdict"] == verdict
        assert found[check_id]["evidence"]["status_code"] == status
        assert found[check_id]["evidence"]["checklist"]["valid_control_observed"] is True
    assert result["verdict"] == "CONFIRMED"  # The independent BOLA scenario remains vulnerable.
    assert result["constraints"]["requests_sent"] == 14
    assert result["constraints"]["redirects_followed"] == 0
    search = [(method, path, query) for method, path, query in target.requests if path == "/search"]
    assert search == [("GET", "/search", b"limit=1"), ("GET", "/search", b""),
                      ("GET", "/search", b"limit=notanumber"), ("GET", "/search", b"limit=999")]
    assert all(method in {"GET", "POST"} for method, _, _ in target.requests)
    for check_id in ("DISC-01", "DISC-02", "DISC-05"):
        assert found[check_id]["verdict"] == ("INCONCLUSIVE" if behavior == "redirect" else "SAFE")


@pytest.mark.parametrize("behavior,check_id,signature,raw_secret", [
    ("traceback", "DISC-01", "stack_trace", "Traceback (most recent call last)"),
    ("verbose", "DISC-02", "internal_error_detail", "SQLSTATE 42P01"),
    ("version", "DISC-05", "version_header", "FixtureFramework/1.2.3"),
])
def test_disclosure_checks_detect_observed_signatures_without_leaking_raw_details(behavior, check_id, signature, raw_secret):
    result = run_fixture(FixtureTarget(disclosure_behavior=behavior))
    check = checks(result)[check_id]
    assert check["verdict"] == "CONFIRMED"
    assert check["evidence"]["checklist"]["disclosure_signature"] == signature
    assert check["remediation"]
    assert raw_secret not in json.dumps(result)
    evidence = check["evidence"]
    canonical = {k: v for k, v in evidence.items() if k not in {"sha256", "redacted"}}
    assert evidence["sha256"] == hashlib.sha256(json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def test_repeated_server_errors_halt_without_reporting_unperformed_checks_safe():
    target = RecordingTarget(validation_behavior="server_error", disclosure_behavior="traceback")
    result = run_fixture(target)
    found = checks(result)
    assert result["constraints"]["halted_reason"] == "repeated server errors"
    assert result["constraints"]["requests_sent"] == 13  # control plus two failed inputs, no third input
    assert found["INPUT-01"]["verdict"] == found["INPUT-02"]["verdict"] == "INCONCLUSIVE"
    assert found["INPUT-04"]["verdict"] == "SKIPPED"
    assert found["DISC-01"]["verdict"] == "CONFIRMED"  # observed before halt
    assert found["DISC-05"]["verdict"] == "INCONCLUSIVE"  # absence cannot be established
    assert len([r for r in target.requests if r[1] == "/search"]) == 3


def test_lockout_halts_following_requests_and_partial_disclosure_coverage():
    target = RecordingTarget(validation_behavior="lockout")
    result = run_fixture(target)
    found = checks(result)
    assert result["constraints"]["halted_reason"] == "account lockout or rate limit"
    assert result["constraints"]["requests_sent"] == 12
    assert found["INPUT-01"]["verdict"] == "INCONCLUSIVE"
    assert found["INPUT-02"]["verdict"] == found["INPUT-04"]["verdict"] == "SKIPPED"
    assert found["DISC-01"]["verdict"] == "INCONCLUSIVE"


def test_missing_identity_keeps_validation_and_disclosure_unperformed():
    found = checks(run_fixture(FixtureTarget(bob_login=False)))
    for check_id in ("INPUT-01", "INPUT-02", "INPUT-04", "DISC-01", "DISC-02", "DISC-05"):
        assert found[check_id]["verdict"] == "SKIPPED"
        assert found[check_id]["evidence"] is None


def test_unapproved_validation_inputs_are_skipped_before_transport():
    import httpx
    from canarygate.offline.input_checks import run_input_checks
    from canarygate.offline.runner import FixtureRunner
    from canarygate.offline.scan import inventory
    from canarygate.scope.loader import FixtureScope, fixture_scope

    data = fixture_scope().model_dump(mode="json")
    data["operations"] = [op for op in data["operations"] if op["path"] != "/search"]
    calls = []
    runner = FixtureRunner(lambda req: calls.append(req) or httpx.Response(200), scope=FixtureScope.model_validate(data))
    try:
        result = run_input_checks(runner, actor="alice", role="user", token="fixture-token-alice",
                                  endpoints=inventory(), summary=lambda *args, **kwargs: None)
        assert calls == []
        for item in result:
            assert item["verdict"] == "SKIPPED"
            assert item["evidence"] is None
    finally:
        runner.close()


def test_failed_valid_control_does_not_mark_invalid_inputs_safe():
    import httpx
    from canarygate.offline.input_checks import run_input_checks
    from canarygate.offline.runner import FixtureRunner
    from canarygate.offline.scan import inventory

    calls = []
    runner = FixtureRunner(lambda req: calls.append(req) or httpx.Response(400, json={"error": "Invalid limit"}))
    try:
        items = run_input_checks(runner, actor="alice", role="user", token="fixture-token-alice",
                                 endpoints=inventory(), summary=lambda *args, **kwargs: None)
        found = {item["id"]: item for item in items}
        assert len(calls) == 1  # Only the valid control was attempted.
        for check_id in ("INPUT-01", "INPUT-02", "INPUT-04"):
            assert found[check_id]["verdict"] == "SKIPPED"
        for check_id in ("DISC-01", "DISC-02", "DISC-05"):
            assert found[check_id]["verdict"] == "INCONCLUSIVE"
    finally:
        runner.close()
