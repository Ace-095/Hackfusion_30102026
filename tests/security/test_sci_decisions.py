"""SCI decision engine: interaction-induced failure versus individual failure.

Pure rules, no I/O. These tests fix the contract before the engine exists.
"""
import pytest

from canarygate.oracles.interaction import CHECKLIST_KEYS, Baseline, Combined, decide


def baseline(check_id="AUTHZ-01", control="Authorization", verdict="SAFE", observable=True):
    return Baseline(id=check_id, control=control, verdict=verdict, observable=observable)


def combined(*, executed=True, permitted=True, verified=True, status=200,
             impact="privileged_data", observed="bounded observation"):
    return Combined(executed=executed, permitted=permitted, verified=verified,
                    status=status, impact=impact, observed=observed)


def test_checklist_has_the_eight_documented_keys():
    assert CHECKLIST_KEYS == ("baselines_executed", "baselines_observable", "baselines_passed",
                              "combined_executed", "combined_verified", "policy_violated",
                              "impact_demonstrated", "not_explained_by_individual")


def test_both_controls_pass_and_the_combination_leaks_data():
    decision = decide(kind="AUTHZ+INPUT_VALIDATION",
                      baselines=[baseline("AUTHZ-01", "Authorization"),
                                 baseline("INPUT-07", "Input validation")],
                      combined=combined(impact="privileged_data"))
    assert decision.verdict == "CONFIRMED"
    assert decision.attribution == "interaction_induced"
    assert decision.remediation_key == "sci_authorization"
    assert all(decision.checklist[key] is True for key in CHECKLIST_KEYS)
    assert "interaction" in decision.reason.lower()


def test_a_secure_combination_after_passing_baselines_is_safe():
    decision = decide(kind="AUTHZ+INPUT_VALIDATION",
                      baselines=[baseline(), baseline("INPUT-07", "Input validation")],
                      combined=combined(status=403, impact="none", observed="checked denial"))
    assert decision.verdict == "SAFE"
    assert decision.attribution == "no_failure"
    assert decision.checklist["policy_violated"] is False


def test_an_already_failing_control_prevents_a_confirmed_interaction():
    decision = decide(kind="AUTHZ+INPUT_VALIDATION",
                      baselines=[baseline(verdict="CONFIRMED"), baseline("INPUT-07", "Input validation")],
                      combined=combined(impact="privileged_data"))
    assert decision.verdict == "INCONCLUSIVE"
    assert decision.attribution == "individual_failure"
    assert "AUTHZ-01" in decision.reason
    assert decision.verdict != "CONFIRMED"


def test_incomplete_baseline_is_inconclusive():
    decision = decide(kind="AUTHZ+INPUT_VALIDATION",
                      baselines=[baseline(observable=False, verdict="INCONCLUSIVE"),
                                 baseline("INPUT-07", "Input validation")],
                      combined=combined())
    assert decision.verdict == "INCONCLUSIVE"
    assert decision.attribution == "incomplete_baseline"


def test_an_unpermitted_combination_is_skipped():
    decision = decide(kind="AUTHZ+INPUT_VALIDATION",
                      baselines=[baseline(), baseline("INPUT-07", "Input validation")],
                      combined=combined(executed=False, permitted=False, verified=False,
                                        status=None, impact="none"))
    assert decision.verdict == "SKIPPED"
    assert decision.attribution == "not_permitted"
    assert "scope" in decision.reason.lower() or "guard" in decision.reason.lower()


def test_a_budget_blocked_combination_is_skipped_with_a_reason():
    decision = decide(kind="AUTHN+AUTHZ", baselines=[baseline(), baseline("AUTHN-05", "Authentication")],
                      combined=combined(executed=False, permitted=False, verified=False,
                                        status=None, impact="none",
                                        observed="blocked by the shared run guard: budget exhausted"))
    assert decision.verdict == "SKIPPED"
    assert "budget" in decision.reason.lower()


def test_unverified_evidence_cannot_confirm():
    decision = decide(kind="AUTHZ+INPUT_VALIDATION",
                      baselines=[baseline(), baseline("INPUT-07", "Input validation")],
                      combined=combined(verified=False, impact="privileged_data"))
    assert decision.verdict == "INCONCLUSIVE"
    assert decision.attribution == "unverified_evidence"


def test_a_response_change_without_security_impact_is_never_confirmed():
    decision = decide(kind="AUTHZ+INPUT_VALIDATION",
                      baselines=[baseline(), baseline("INPUT-07", "Input validation")],
                      combined=combined(status=200, impact="none", observed="200 with a different message"))
    assert decision.verdict == "SUSPECTED"
    assert decision.attribution == "no_demonstrated_impact"
    assert decision.remediation_key is None


def test_ambiguous_impact_is_inconclusive():
    decision = decide(kind="AUTHZ+INPUT_VALIDATION",
                      baselines=[baseline(), baseline("INPUT-07", "Input validation")],
                      combined=combined(impact="ambiguous"))
    assert decision.verdict == "INCONCLUSIVE"
    assert decision.attribution == "ambiguous_impact"


@pytest.mark.parametrize("kind,impact,key", [
    ("AUTHZ+INPUT_VALIDATION", "privileged_data", "sci_authorization"),
    ("AUTHN+AUTHZ", "private_data", "sci_authentication"),
    ("INPUT_VALIDATION+INFORMATION_DISCLOSURE", "internal_detail", "sci_disclosure"),
])
def test_each_interaction_kind_maps_to_its_own_remediation(kind, impact, key):
    decision = decide(kind=kind,
                      baselines=[baseline(), baseline("CTRL-02", "Input validation")],
                      combined=combined(impact=impact))
    assert decision.verdict == "CONFIRMED"
    assert decision.remediation_key == key


def test_unknown_interaction_kind_is_rejected():
    with pytest.raises(ValueError):
        decide(kind="BOLA+BFLA", baselines=[baseline()], combined=combined())
