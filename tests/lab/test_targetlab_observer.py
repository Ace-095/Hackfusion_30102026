"""The transport observer is telemetry about completed requests, nothing more.

These tests pin three properties that make the loading screen trustworthy:

* one event per request, in order, carrying the lab's own status code;
* the observer cannot change a request, a response or a verdict;
* an observer that raises cannot break a scan.
"""
import pytest

from canarygate.network.targetlab import TargetLabRunner
from canarygate.scan.lab_bola import run_lab_bola_scan
from canarygate.scan.lab_bola_scenarios import build_bola_plan
from targetlab.testing import TARGETLAB_CERT, LabTlsServer


def _scan(port, observer):
    plan = build_bola_plan(port)
    runner = TargetLabRunner(plan.scope, plan.credentials, ca_file=str(TARGETLAB_CERT),
                             observer=observer)
    try:
        return run_lab_bola_scan(plan, runner)
    finally:
        runner.close()


def test_one_event_per_request_in_the_order_the_lab_answered_them():
    events = []
    with LabTlsServer() as lab:
        run = _scan(lab.port, events.append)
    assert len(events) == run.constraints.requests_sent == 18
    # The transport's `requests_sent` is monotonic across the events, which is
    # what lets a reader order them without trusting the wall clock.
    assert [event["requests_sent"] for event in events] == list(range(1, 19))
    # Every event names a declared TargetLab route and the actor that sent it.
    paths = {event["path"] for event in events}
    assert paths <= {"/login", "/profile", "/records", "/records/MKT-2026-041",
                     "/records/BRD-2026-018", "/records/MKT-2026-041/secure",
                     "/records/BRD-2026-018/secure"}
    assert {event["actor"] for event in events} <= {"mallapa", "sakshi", "harsha"}
    assert {event["method"] for event in events} == {"GET", "POST"}
    # The statuses are the lab's own. On the secure route an owner reading its own
    # record succeeds and a cross-account read is refused, and the feed says so.
    owners = {"MKT-2026-041": "mallapa", "BRD-2026-018": "sakshi"}
    secure = [event for event in events if event["path"].endswith("/secure")]
    assert secure
    for event in secure:
        asset = event["path"].split("/")[2]
        expected = 200 if owners[asset] == event["actor"] else 403
        assert event["status"] == expected, event
    assert any(event["status"] == 403 for event in secure)
    assert any(event["status"] == 200 for event in secure)
    # Durations are measured, bounded and never negative.
    assert all(0 <= event["elapsed_ms"] < 60_000 for event in events)


def test_the_observer_cannot_change_the_run():
    baseline = None
    with LabTlsServer() as lab:
        baseline = _scan(lab.port, None)
    seen = []
    with LabTlsServer() as lab:
        observed = _scan(lab.port, seen.append)
    assert seen
    # Same verdicts, same evidence, same counters: observation is passive.
    assert [check.verdict for check in observed.checks] == [check.verdict for check in baseline.checks]
    assert [check.evidence_sha256 for check in observed.checks] == \
        [check.evidence_sha256 for check in baseline.checks]
    assert observed.constraints.requests_sent == baseline.constraints.requests_sent


def test_a_raising_observer_cannot_break_a_scan():
    def explode(event):
        raise RuntimeError("telemetry failure")

    with LabTlsServer() as lab:
        run = _scan(lab.port, explode)
    assert run.verdict == "CONFIRMED"
    assert run.constraints.requests_sent == 18


def test_an_observer_that_is_not_callable_is_ignored():
    with LabTlsServer() as lab:
        plan = build_bola_plan(lab.port)
        runner = TargetLabRunner(plan.scope, plan.credentials, ca_file=str(TARGETLAB_CERT),
                                 observer="not-a-function")
        try:
            run = run_lab_bola_scan(plan, runner)
        finally:
            runner.close()
    assert run.verdict == "CONFIRMED"
