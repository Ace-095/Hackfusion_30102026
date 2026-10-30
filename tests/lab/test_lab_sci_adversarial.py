"""Adversarial evidence handling for the TargetLab SCI workflow.

Each case breaks exactly one link in the evidence chain. None of them may yield
CONFIRMED (or a clean SAFE) from incomplete evidence.
"""
import dataclasses
import json

import pytest

import targetlab.testing as lab_server
from canarygate.network.targetlab import TargetLabRefused, TargetLabRunner
from canarygate.oracles.interaction import Baseline, Combined, decide
from canarygate.scan.lab_sci import (disclosure_impact, guarded_denial_verdict,
                                     rejection_verdict)
from canarygate.scan.lab_sci_scenarios import (DENIAL_BODY, GUARDED_RESOURCE, REJECTION_BODY,
                                               build_sci_plan, wrong_password_body)
from canarygate.seed.extraction import extract
from canarygate.seed.registry import collect_guarded_ownership


@pytest.fixture()
def lab():
    with lab_server.LabTlsServer() as server:
        yield server


def runner_for(lab, *, plan=None):
    plan = plan or build_sci_plan(lab.port)
    return TargetLabRunner(plan.scope, plan.credentials, ca_file=str(lab_server.TARGETLAB_CERT))


def ownership_for(runner, accounts=("mallapa", "sakshi")):
    for account in accounts:
        runner.login(account)
    return collect_guarded_ownership(runner, resource_type="record", resource=GUARDED_RESOURCE,
                                     accounts=accounts, profile_path="/profile",
                                     identity_field="identity")


# --------------------------------------------------------------- denial mapping
def test_a_checked_denial_is_the_only_clean_authorization_baseline():
    assert guarded_denial_verdict(403, dict(DENIAL_BODY), DENIAL_BODY)[0] == "SAFE"
    for status, body in ((403, {"error": "forbidden", "detail": "x"}), (403, {}),
                         (403, None), (401, dict(DENIAL_BODY)), (500, dict(DENIAL_BODY)),
                         (302, dict(DENIAL_BODY))):
        verdict, reason, observable = guarded_denial_verdict(status, body, DENIAL_BODY)
        assert verdict == "INCONCLUSIVE", (status, body)
        assert observable is False
        assert reason


def test_an_undened_cross_account_read_is_an_individual_failure():
    verdict, reason, observable = guarded_denial_verdict(
        200, {"id": "rb", "owner": "sakshi", "private_note": "x"}, DENIAL_BODY)
    assert (verdict, observable) == ("CONFIRMED", True)
    assert "on its own" in reason


# ----------------------------------------------------------- rejection mapping
def test_only_the_exact_rejection_is_a_passing_authentication_baseline():
    verdict, reason, observable = rejection_verdict(
        401, dict(REJECTION_BODY), REJECTION_BODY, "mallapa", "sakshi")
    assert (verdict, observable) == ("SAFE", True)
    for status, body in ((401, {"error": "other"}), (422, {"error": "invalid_request"}),
                         (400, None), (500, dict(REJECTION_BODY))):
        verdict, _, _ = rejection_verdict(status, body, REJECTION_BODY, "mallapa", "sakshi")
        assert verdict == "INCONCLUSIVE", (status, body)


def test_an_accepted_rejected_login_is_an_individual_failure():
    verdict, _, observable = rejection_verdict(
        200, {"token": "x", "identity": "mallapa", "role": "user"},
        REJECTION_BODY, "mallapa", "sakshi")
    assert (verdict, observable) == ("CONFIRMED", True)


def test_an_ambiguous_rejection_response_never_passes():
    for body in (None, {}, [], {"error": 5}, {"error": ""}):
        verdict, _, _ = rejection_verdict(401, body, REJECTION_BODY, "mallapa", "sakshi")
        assert verdict == "INCONCLUSIVE", body


# ------------------------------------------------------- disclosure verification
def test_disclosure_requires_the_owner_baseline_marker_and_the_owner_identity():
    body = {"id": "rb", "owner": "sakshi", "private_note": "targetlab-sakshi-private-marker"}
    impact, reason = disclosure_impact(body, owner_baseline="targetlab-sakshi-private-marker",
                                       owner_id="rb", owner="sakshi", private_field="private_note")
    assert impact == "private_data"
    # Right marker, wrong owner identity in the body: ambiguous, never CONFIRMED.
    impact, _ = disclosure_impact({**body, "owner": "mallapa"},
                                  owner_baseline="targetlab-sakshi-private-marker",
                                  owner_id="rb", owner="sakshi", private_field="private_note")
    assert impact == "ambiguous"
    # Wrong marker, missing marker, empty marker and a redacted marker are never impact.
    for value in ("targetlab-mallapa-private-marker", None, "", "[redacted]", "***"):
        impact, _ = disclosure_impact({**body, "private_note": value},
                                      owner_baseline="targetlab-sakshi-private-marker",
                                      owner_id="rb", owner="sakshi", private_field="private_note")
        assert impact == "none", value


def test_disclosure_of_another_account_marker_is_not_the_owner_marker():
    body = {"id": "ra", "owner": "mallapa", "private_note": "targetlab-mallapa-private-marker"}
    impact, _ = disclosure_impact(body, owner_baseline="targetlab-sakshi-private-marker",
                                  owner_id="rb", owner="sakshi", private_field="private_note")
    assert impact == "none"


# ------------------------------------------------------- oracle-level fail-closed
def _decision(baselines, *, executed=True, permitted=True, verified=True, status=200,
              impact="private_data"):
    return decide(kind="AUTHN+AUTHZ", baselines=baselines,
                  combined=Combined(executed=executed, permitted=permitted, verified=verified,
                                    status=status, impact=impact, observed="test"))


def test_a_missing_baseline_never_confirms():
    """A control without its own baseline fails closed at the decision boundary."""
    passing = Baseline(id="SCI-AUTHN", control="Authentication", verdict="SAFE")
    with pytest.raises(ValueError):
        _decision([passing])


def test_an_unobserved_baseline_never_confirms():
    decision = _decision([Baseline(id="SCI-AUTHN", control="Authentication", verdict="SAFE"),
                          Baseline(id="SCI-AUTHZ", control="Authorization", verdict="SAFE",
                                   observable=False)])
    assert decision.verdict == "INCONCLUSIVE"
    assert decision.attribution in {"incomplete_baseline", "individual_failure"}


def test_an_already_failing_control_is_not_an_interaction():
    decision = _decision([Baseline(id="SCI-AUTHN", control="Authentication", verdict="CONFIRMED"),
                          Baseline(id="SCI-AUTHZ", control="Authorization", verdict="SAFE")])
    assert decision.verdict == "INCONCLUSIVE"
    assert decision.attribution == "individual_failure"


def test_unverified_reordered_or_ambiguous_evidence_never_confirms():
    safe_pair = [Baseline(id="SCI-AUTHN", control="Authentication", verdict="SAFE"),
                 Baseline(id="SCI-AUTHZ", control="Authorization", verdict="SAFE")]
    assert _decision(safe_pair, verified=False).verdict == "INCONCLUSIVE"
    assert _decision(safe_pair, impact="ambiguous").verdict == "INCONCLUSIVE"
    assert _decision(safe_pair, permitted=False).verdict == "SKIPPED"
    assert _decision(safe_pair, executed=False).verdict == "SKIPPED"


# ------------------------------------------------------------ transport evidence
def test_a_stale_response_from_another_runner_is_not_evidence(lab):
    plan = build_sci_plan(lab.port)
    first = runner_for(lab, plan=plan)
    second = runner_for(lab, plan=plan)
    try:
        first.login("mallapa")
        stale = first.get("mallapa", "/records/MKT-2026-041")
        assert first.verifies_recorded_read(stale, "mallapa", "/records/MKT-2026-041") is True
        # A different run must not accept another run's response object.
        assert second.verifies_recorded_read(stale, "mallapa", "/records/MKT-2026-041") is False
    finally:
        first.close()
        second.close()


def test_a_mutated_combined_response_is_not_evidence(lab):
    runner = runner_for(lab)
    try:
        ownership = ownership_for(runner)
        assert ownership.ownership_status == "SUCCESS"
        response = runner.get("mallapa", "/records/BRD-2026-018/guarded")
        assert response.status_code == 403
        response._content = b'{"id": "rb", "owner": "sakshi", "private_note": "x"}'
        assert runner.verifies_recorded_read(response, "mallapa", "/records/BRD-2026-018/guarded") is False
    finally:
        runner.close()


def test_a_duplicate_probe_is_blocked_by_the_guard(lab):
    runner = runner_for(lab)
    try:
        runner.login("mallapa")
        body = wrong_password_body("mallapa")
        first = runner.submit("mallapa", "/login", "wrong_password", body)
        assert first.status_code == 401
        with pytest.raises(ValueError):
            runner.submit("mallapa", "/login", "wrong_password", body)
        assert runner.stats()["requests_sent"] == 2
    finally:
        runner.close()


def test_a_second_successful_login_is_blocked_in_the_same_run(lab):
    runner = runner_for(lab)
    try:
        assert runner.login("mallapa") is True
        with pytest.raises(ValueError):
            runner.login("mallapa")
    finally:
        runner.close()


def test_the_probe_cannot_target_another_path(lab):
    runner = runner_for(lab)
    try:
        runner.login("mallapa")
        with pytest.raises((TargetLabRefused, ValueError)):
            runner.submit("mallapa", "/records/BRD-2026-018", "wrong_password", wrong_password_body("mallapa"))
        with pytest.raises(ValueError):
            runner.submit("mallapa", "/login", "not_a_probe", wrong_password_body("mallapa"))
    finally:
        runner.close()


def test_the_ground_truth_route_stays_unreachable(lab):
    runner = runner_for(lab)
    try:
        runner.login("mallapa")
        for path in ("/lab/ground-truth", "/lab/ground-truth/", "/openapi.json",
                     "/records/BRD-2026-018/guarded/"):
            with pytest.raises((TargetLabRefused, ValueError)):
                runner.get("mallapa", path)
    finally:
        runner.close()


def test_a_scope_that_cannot_reach_the_lab_is_refused():
    from canarygate.scope.authorized import AuthorizedScope

    data = build_sci_plan(8765).scope.model_dump()
    for host in ("127.0.0.2", "192.168.0.10", "example.com", "::1"):
        with pytest.raises(ValueError):
            AuthorizedScope.model_validate({**data, "hostname": host, "organizer_ip": host})


def test_owner_baselines_are_distinct_and_marker_bearing(lab):
    """The owner baseline the disclosure proof relies on must be real and private."""
    runner = runner_for(lab)
    try:
        ownership = ownership_for(runner)
        assert ownership.ownership_status == "SUCCESS"
        markers = {}
        for actor in ("mallapa", "sakshi"):
            body = json.loads(ownership.baselines[actor][0].content)
            assert body["owner"] == actor
            markers[actor] = extract(body, GUARDED_RESOURCE.private_field)
        assert markers["mallapa"] != markers["sakshi"]
        assert all(isinstance(value, str) and value for value in markers.values())
    finally:
        runner.close()


def test_the_redactor_scrubs_every_lab_fixture_secret():
    """Defence in depth: a leak would be scrubbed, not only asserted against."""
    from canarygate.evidence.redaction import redact

    for secret in ("lab-token-mallapa", "lab-token-sakshi", "mallapa-lab-password",
                   "sakshi-lab-password", "targetlab-mallapa-private-marker",
                   "targetlab-sakshi-private-marker", "targetlab-trace-marker",
                   "targetlab-wrong-password-for-mallapa"):
        assert redact({"value": f"before {secret} after"})["value"] == "before [REDACTED] after"


def test_a_denied_final_read_is_safe_and_a_data_free_success_is_not():
    safe_pair = [Baseline(id="SCI-AUTHN", control="Authentication", verdict="SAFE"),
                 Baseline(id="SCI-AUTHZ", control="Authorization", verdict="SAFE")]
    denied = _decision(safe_pair, status=403, impact="none")
    assert denied.verdict == "SAFE" and denied.attribution == "no_failure"
    changed = _decision(safe_pair, status=200, impact="none")
    assert changed.verdict == "SUSPECTED"
    assert changed.attribution == "no_demonstrated_impact"


def test_a_shared_or_public_resource_cannot_support_the_interaction(lab):
    plan = dataclasses.replace(
        build_sci_plan(lab.port),
        resource=type(GUARDED_RESOURCE).model_validate(
            {**GUARDED_RESOURCE.model_dump(), "ownership_model": "shared"}))
    runner = runner_for(lab, plan=plan)
    try:
        from canarygate.scan.lab_sci import run_lab_sci_scan

        run = run_lab_sci_scan(plan, runner)
        assert run.verdict != "CONFIRMED"
        assert run.status == "failed"
        assert run.ownership["status"] != "SUCCESS"
        assert all(item.verdict != "SAFE" for item in run.baselines)
    finally:
        runner.close()


def test_a_swapped_token_cannot_establish_the_interaction(lab):
    """If a token appears to identify another account, the run stops and claims nothing."""
    from canarygate.scan.lab_sci import run_lab_sci_scan

    plan = build_sci_plan(lab.port)
    runner = runner_for(lab, plan=plan)
    try:
        assert runner.login("mallapa") is True
        assert runner.login("sakshi") is True
        runner._tokens["mallapa"] = runner._tokens["sakshi"]
        run = run_lab_sci_scan(plan, runner)
        assert run.verdict != "CONFIRMED"
        assert run.combined.executed is False
        assert run.combined.impact == "none"
    finally:
        runner.close()


def test_the_sequence_is_what_makes_the_difference(lab):
    """The same request, same actor, same path: denied first, leaking third."""
    from canarygate.scan.lab_sci import run_lab_sci_scan

    plan = build_sci_plan(lab.port)
    runner = runner_for(lab, plan=plan)
    try:
        run = run_lab_sci_scan(plan, runner)
    finally:
        runner.close()
    authorization, authentication = run.baselines
    assert authorization.evidence["sequence"] == 1
    assert authentication.evidence["sequence"] == 2
    assert run.combined.executed is True
    # Identical endpoint and actor, opposite outcomes: only the rejected login intervened.
    assert authorization.endpoint == run.combined.endpoint
    assert authorization.evidence["status"] == 403
    assert run.combined.status == 200
    assert run.attribution == "interaction_induced"
