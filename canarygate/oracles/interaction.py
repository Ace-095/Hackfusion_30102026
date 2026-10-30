"""SCI decision rules: when two passing controls combine into a weakness.

A Security Control Interaction (SCI) finding is only CONFIRMED when both
individual controls were executed, observable and passing, and the combined
exchange violates the declared policy with a demonstrated impact. An already
failing control, missing baseline or unverified response can never be reported as
an interaction-induced failure.

This module is pure: it performs no I/O and never issues a request.
"""
from dataclasses import dataclass
from typing import Literal

INTERACTION_KINDS = ("AUTHZ+INPUT_VALIDATION", "AUTHN+AUTHZ",
                     "INPUT_VALIDATION+INFORMATION_DISCLOSURE")
INTERACTION_CONTROLS = {
    "AUTHZ+INPUT_VALIDATION": ("Authorization", "Input validation"),
    "AUTHN+AUTHZ": ("Authentication", "Authorization"),
    "INPUT_VALIDATION+INFORMATION_DISCLOSURE": ("Input validation", "Information disclosure"),
}
REMEDIATION_KEYS = {
    "AUTHZ+INPUT_VALIDATION": "sci_authorization",
    "AUTHN+AUTHZ": "sci_authentication",
    "INPUT_VALIDATION+INFORMATION_DISCLOSURE": "sci_disclosure",
}
SCI_REMEDIATIONS = {
    "sci_authorization":
        "Re-run object and role authorization after input handling on every code path; never let "
        "an accepted request property influence the access decision.",
    "sci_authentication":
        "Enforce credential verification identically on every protected route, at the resource "
        "handler, not only at the profile or login endpoint.",
    "sci_disclosure":
        "Apply the same response filtering and error handling to every error path, including "
        "validation failures; never return framework or database detail.",
}
IMPACTS = ("none", "private_data", "privileged_data", "internal_detail", "ambiguous")
ATTRIBUTIONS = ("interaction_induced", "individual_failure", "incomplete_baseline",
                "unverified_evidence", "ambiguous_impact", "no_demonstrated_impact",
                "no_failure", "not_permitted")
CHECKLIST_KEYS = ("baselines_executed", "baselines_observable", "baselines_passed",
                  "combined_executed", "combined_verified", "policy_violated",
                  "impact_demonstrated", "not_explained_by_individual")
_EVIDENCE_IMPACTS = frozenset({"private_data", "privileged_data", "internal_detail"})


@dataclass(frozen=True)
class Baseline:
    id: str
    control: str
    verdict: str
    observable: bool = True


@dataclass(frozen=True)
class Combined:
    executed: bool
    permitted: bool
    verified: bool
    status: int | None
    impact: str
    observed: str


@dataclass(frozen=True)
class Decision:
    verdict: Literal["CONFIRMED", "SUSPECTED", "SAFE", "INCONCLUSIVE", "SKIPPED"]
    reason: str
    attribution: str
    checklist: dict[str, bool]
    remediation_key: str | None


def _checklist(**values):
    return {key: bool(values.get(key, False)) for key in CHECKLIST_KEYS}


def decide(*, kind: str, baselines, combined: Combined) -> Decision:
    if kind not in INTERACTION_KINDS:
        raise ValueError("unknown interaction kind")
    baselines = tuple(baselines)
    if not baselines:
        raise ValueError("at least one control baseline is required")
    if combined.impact not in IMPACTS:
        raise ValueError("unknown interaction impact")
    if any(item.verdict not in {"CONFIRMED", "SUSPECTED", "SAFE", "INCONCLUSIVE", "SKIPPED"}
           for item in baselines):
        raise ValueError("unknown baseline verdict")

    executed = combined.executed
    observable = all(item.observable for item in baselines)
    passed = all(item.observable and item.verdict == "SAFE" for item in baselines)
    failing = [item.id for item in baselines if item.observable and item.verdict == "CONFIRMED"]
    incomplete = [item.id for item in baselines if not item.observable
                  or item.verdict in {"INCONCLUSIVE", "SKIPPED"}]

    if not combined.permitted:
        return Decision("SKIPPED",
                        "The combined exchange was not permitted by the scope or the shared "
                        f"run guard; not executed. Observed: {combined.observed}",
                        "not_permitted",
                        _checklist(baselines_executed=True, baselines_observable=observable,
                                   baselines_passed=passed, combined_executed=False),
                        None)
    if failing:
        return Decision("INCONCLUSIVE",
                        f"The individual control {failing[0]} already fails on its own; the combined "
                        "behaviour cannot be attributed to the interaction",
                        "individual_failure",
                        _checklist(baselines_executed=True, baselines_observable=observable,
                                   baselines_passed=False, combined_executed=executed,
                                   combined_verified=combined.verified),
                        None)
    if not observable or incomplete:
        return Decision("INCONCLUSIVE",
                        "The individual control baseline was not observable, so the interaction "
                        "cannot be established",
                        "incomplete_baseline",
                        _checklist(baselines_executed=True, baselines_observable=False,
                                   baselines_passed=False, combined_executed=executed,
                                   combined_verified=combined.verified),
                        None)
    if not executed:
        return Decision("SKIPPED", "The combined exchange was not executed in this run",
                        "not_permitted",
                        _checklist(baselines_executed=True, baselines_observable=True,
                                   baselines_passed=passed),
                        None)
    if not combined.verified:
        return Decision("INCONCLUSIVE",
                        "The combined response could not be verified in this run; it cannot "
                        "support a finding",
                        "unverified_evidence",
                        _checklist(baselines_executed=True, baselines_observable=True,
                                   baselines_passed=passed, combined_executed=True),
                        None)
    if combined.impact == "ambiguous" or combined.status is None:
        return Decision("INCONCLUSIVE",
                        "The combined response was ambiguous; it established neither a security "
                        "impact nor correct handling",
                        "ambiguous_impact",
                        _checklist(baselines_executed=True, baselines_observable=True,
                                   baselines_passed=passed, combined_executed=True,
                                   combined_verified=True),
                        None)
    if combined.impact in _EVIDENCE_IMPACTS and passed:
        controls = " and ".join(INTERACTION_CONTROLS[kind]).lower()
        reason = (f"The {controls} controls each passed alone, but their interaction demonstrated "
                  f"{combined.impact.replace('_', ' ')}; neither control alone explains this outcome")
        return Decision("CONFIRMED", reason, "interaction_induced",
                        _checklist(baselines_executed=True, baselines_observable=True,
                                   baselines_passed=True, combined_executed=True,
                                   combined_verified=True, policy_violated=True,
                                   impact_demonstrated=True, not_explained_by_individual=True),
                        REMEDIATION_KEYS[kind])
    if combined.impact in _EVIDENCE_IMPACTS:
        # Impact observed, but at least one baseline is not SAFE (SUSPECTED only).
        return Decision("SUSPECTED",
                        "The combined exchange showed a possible impact, but an individual "
                        "control did not pass cleanly, so the interaction is not established",
                        "unproven_impact",
                        _checklist(baselines_executed=True, baselines_observable=True,
                                   baselines_passed=False, combined_executed=True,
                                   combined_verified=True, impact_demonstrated=True),
                        None)
    if isinstance(combined.status, int) and 400 <= combined.status < 500:
        return Decision("SAFE",
                        f"The combined exchange was denied with status {combined.status}; both "
                        "controls held under the interaction",
                        "no_failure",
                        _checklist(baselines_executed=True, baselines_observable=True,
                                   baselines_passed=True, combined_executed=True,
                                   combined_verified=True),
                        None)
    return Decision("SUSPECTED",
                    "The combined response changed behaviour but demonstrated no security "
                    "impact; never reported as CONFIRMED",
                    "no_demonstrated_impact",
                    _checklist(baselines_executed=True, baselines_observable=True,
                               baselines_passed=True, combined_executed=True,
                               combined_verified=True),
                    None)
