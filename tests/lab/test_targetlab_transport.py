"""Containment and live-evidence tests for the loopback-only TargetLab transport.

Two kinds of proof live here:

* admission: a TargetLab transport cannot be built from a competition scope, and
  a lab scope cannot point anywhere except the literal address 127.0.0.1;
* behaviour: against a real HTTPS TargetLab on loopback, the transport collects
  the declared evidence, refuses redirects, never retries, never resolves a
  hostname, and refuses to spend past its request budget.

Nothing here contacts a non-loopback address.
"""
import json
import socket
import ssl

import pytest

import targetlab.testing as lab_server  # noqa: E402
from canarygate.network.targetlab import TargetLabRefused, TargetLabRunner, TargetLabTransport
from canarygate.scan.lab_generic import run_lab_evidence
from canarygate.scan.lab_scenarios import LAB_PASSWORDS, build_lab_plan, build_lab_scope


def scope_for(port, *, budget=12, operations=None):
    scope = build_lab_scope(port, budget=budget)
    if operations is None:
        return scope
    data = scope.model_dump()
    data["operations"] = operations
    return type(scope).model_validate(data)


def competition_scope(port=8765):
    return {
        "mode": "competition", "scheme": "https", "hostname": "api.organizer.example",
        "port": port, "organizer_ip": "203.0.113.10",
        "written_authorization_reference": "competition-approval-001",
        "allowed_methods": ["GET"], "request_budget": 10,
        "accounts": [{"account": "account-a", "role": "user"}],
        "operations": [{"method": "GET", "path": "/profile", "classification": "READ_ONLY"}],
    }


# --- admission ---------------------------------------------------------------

@pytest.mark.parametrize("host", ["127.0.0.2", "10.0.0.5", "192.168.1.10", "example.com",
                                  "localhost", "::1", "0.0.0.0"])
def test_only_the_loopback_literal_is_accepted(host):
    from canarygate.scope.authorized import AuthorizedScope

    data = build_lab_scope(8765).model_dump()
    data["hostname"] = host
    data["organizer_ip"] = host
    with pytest.raises(ValueError):
        AuthorizedScope.model_validate(data)


@pytest.mark.parametrize("mode", ["competition", "approved_lab"])
def test_existing_modes_cannot_point_at_loopback(mode):
    from canarygate.scope.authorized import AuthorizedScope

    data = competition_scope()
    data["mode"] = mode
    data["hostname"] = "127.0.0.1"
    data["organizer_ip"] = "127.0.0.1"
    with pytest.raises(ValueError):
        AuthorizedScope.model_validate(data)


def test_transport_requires_a_local_lab_scope():
    from canarygate.scope.authorized import AuthorizedScope

    other = AuthorizedScope.model_validate(competition_scope())
    with pytest.raises(TargetLabRefused):
        TargetLabTransport(other, ca_file=lab_server.TARGETLAB_CERT)


def test_transport_requires_a_ca_file():
    scope = build_lab_scope(8765)
    with pytest.raises(TargetLabRefused):
        TargetLabTransport(scope, ca_file="/nonexistent/ca.pem")


def test_undeclared_paths_are_refused_before_any_connection():
    with lab_server.CountingTlsServer() as server:
        scope = build_lab_scope(server.port)
        transport = TargetLabTransport(scope, ca_file=lab_server.TARGETLAB_CERT)
        for path in ("/lab/ground-truth", "/records/MKT-2026-041/../../etc/passwd", "/admin"):
            with pytest.raises(TargetLabRefused):
                transport.request("mallapa", "GET", path, token="lab-token-mallapa")
        assert server.hits == 0
        assert transport.requests_sent == 0


def test_runner_refuses_unscoped_reads_without_contacting_the_server():
    with lab_server.LabTlsServer() as lab:
        plan = build_lab_plan(lab.port)
        runner = TargetLabRunner(plan.scope, plan.credentials, ca_file=lab_server.TARGETLAB_CERT)
        try:
            assert runner.login("mallapa") is not False
            with pytest.raises(TargetLabRefused):
                runner.get("mallapa", "/lab/ground-truth")
        finally:
            runner.close()


def test_credentials_must_belong_to_scoped_accounts():
    scope = build_lab_scope(8765)
    with pytest.raises(ValueError):
        TargetLabRunner(scope, {"mallory": "x"}, ca_file=lab_server.TARGETLAB_CERT)


# --- live loopback evidence --------------------------------------------------

@pytest.fixture()
def lab():
    with lab_server.LabTlsServer() as server:
        yield server


def test_live_scan_collects_the_declared_ground_truth(lab):
    plan = build_lab_plan(lab.port)
    runner = TargetLabRunner(plan.scope, plan.credentials, ca_file=lab_server.TARGETLAB_CERT)
    try:
        run = run_lab_evidence(plan, runner)
    finally:
        runner.close()
    checks = {check.id: check for check in run.checks}
    assert run.status == "completed"
    assert checks["LAB-01"].observation == "allowed_owner"
    assert checks["LAB-02"].observation == "allowed_owner"
    assert checks["LAB-03"].observation == "allowed_owner"
    assert checks["LAB-03"].evidence["owner_matches_actor"] is True
    assert checks["LAB-04"].evidence["owner_matches_actor"] is True
    assert checks["LAB-05"].observation == "allowed_other"
    assert checks["LAB-05"].evidence["owner_matches_actor"] is False
    assert checks["LAB-05"].evidence["private_marker_present"] is True
    assert checks["LAB-06"].observation == "denied"
    assert checks["LAB-07"].observation == "denied"
    assert all(check.verified for check in run.checks)
    assert run.summary.authenticated == 2
    assert run.summary.denied == 2
    assert run.summary.allowed == 5
    assert run.summary.unverified == 0
    assert run.summary.blocked == 0
    assert run.constraints.requests_sent == 9
    assert run.constraints.budget_remaining == 3
    assert run.constraints.redirects_observed == 0
    assert run.transport.destination == "127.0.0.1"
    assert run.transport.tls_verification == "pinned_test_ca_with_hostname_check"
    assert run.transport.retries == "none" and run.transport.redirects == "refused"
    assert run.transport.dns == "not_used"
    assert run.transport.network_transport_enabled is True
    assert run.transport.production_networking is False


def test_run_payload_carries_no_credentials_or_private_markers(lab):
    plan = build_lab_plan(lab.port)
    runner = TargetLabRunner(plan.scope, plan.credentials, ca_file=lab_server.TARGETLAB_CERT)
    try:
        run = run_lab_evidence(plan, runner)
    finally:
        runner.close()
    text = json.dumps(run.model_dump(mode="json"))
    for secret in ("lab-token-mallapa", "lab-token-sakshi", *LAB_PASSWORDS.values(),
                   "targetlab-mallapa-private-marker", "targetlab-sakshi-private-marker"):
        assert secret not in text
    assert run.constraints.requests_sent <= plan.scope.request_budget


def test_request_budget_is_enforced_and_blocked_reads_are_reported(lab):
    plan = build_lab_plan(lab.port, budget=7)
    runner = TargetLabRunner(plan.scope, plan.credentials, ca_file=lab_server.TARGETLAB_CERT)
    try:
        run = run_lab_evidence(plan, runner)
    finally:
        runner.close()
    checks = {check.id: check for check in run.checks}
    assert checks["LAB-05"].observation == "allowed_other"
    assert checks["LAB-06"].observation == "blocked_by_guard"
    assert checks["LAB-07"].observation == "blocked_by_guard"
    assert checks["LAB-06"].status is None
    assert run.summary.blocked == 2
    assert run.constraints.requests_sent == 7
    assert run.constraints.budget_remaining == 0
    assert run.constraints.blocked_by_guard >= 2
    assert run.status == "failed"  # not every declared check was observed


def test_a_second_login_in_one_run_is_refused(lab):
    plan = build_lab_plan(lab.port)
    runner = TargetLabRunner(plan.scope, plan.credentials, ca_file=lab_server.TARGETLAB_CERT)
    try:
        assert runner.login("mallapa") is True
        with pytest.raises(ValueError):
            runner.login("mallapa")
        stats = runner.stats()
        assert stats["requests_sent"] == 1
        assert stats["blocked_by_guard"] >= 1
    finally:
        runner.close()


def test_redirects_are_refused_and_never_followed():
    with lab_server.CountingTlsServer(redirect=True) as server:
        scope = build_lab_scope(server.port)
        transport = TargetLabTransport(scope, ca_file=lab_server.TARGETLAB_CERT)
        with pytest.raises(TargetLabRefused):
            transport.request("mallapa", "GET", "/health", token="lab-token-mallapa")
        assert server.hits == 1          # exactly one attempt: nothing was followed
        assert transport.stats()["redirects_observed"] >= 0
        assert transport.stats()["halted"] is True


def test_a_server_error_is_returned_once_and_never_retried():
    with lab_server.CountingTlsServer(status=500) as server:
        scope = build_lab_scope(server.port)
        transport = TargetLabTransport(scope, ca_file=lab_server.TARGETLAB_CERT)
        response = transport.request("mallapa", "GET", "/health", token="lab-token-mallapa")
        assert response.status_code == 500
        assert server.hits == 1
        assert transport.requests_sent == 1


def test_no_hostname_resolution_is_performed(lab, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("the TargetLab transport must not resolve any hostname")

    plan = build_lab_plan(lab.port)
    runner = TargetLabRunner(plan.scope, plan.credentials, ca_file=lab_server.TARGETLAB_CERT)
    try:
        with monkeypatch.context() as guard:
            guard.setattr(socket, "getaddrinfo", forbidden)
            guard.setattr(socket, "gethostbyname", forbidden)
            run = run_lab_evidence(plan, runner)
    finally:
        runner.close()
    assert run.summary.allowed == 5 and run.summary.denied == 2


def test_a_wrong_ca_fails_closed(lab):
    plan = build_lab_plan(lab.port)
    runner = TargetLabRunner(plan.scope, plan.credentials, ca_file=lab_server.OTHER_CERT)
    try:
        with pytest.raises(TargetLabRefused):
            runner.login("mallapa")
    finally:
        runner.close()


def test_certificate_hostname_mismatch_is_rejected(lab):
    context = ssl.create_default_context(cafile=str(lab_server.TARGETLAB_CERT))
    with socket.create_connection(("127.0.0.1", lab.port), timeout=5) as raw:
        with pytest.raises(ssl.SSLCertVerificationError):
            context.wrap_socket(raw, server_hostname="api.organizer.example")


def test_an_unreachable_loopback_port_fails_without_retrying():
    port = lab_server.free_port()
    plan = build_lab_plan(port)
    runner = TargetLabRunner(plan.scope, plan.credentials, ca_file=lab_server.TARGETLAB_CERT)
    try:
        with pytest.raises(TargetLabRefused):
            runner.login("mallapa")
        assert runner.stats()["halted"] is True
    finally:
        runner.close()
