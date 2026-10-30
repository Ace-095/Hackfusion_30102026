"""Unit tests for the flight recorder's event adapter.

These tests feed :func:`canarygate.ui.replay.build_replay` payloads that are
shaped exactly like the backend's responses (observations, checks, evidence
parts) but are constructed here so edge cases the fixture cannot produce on
demand — repeated identical requests, missing evidence, skipped probes — are
provable.

No backend module is imported for the payloads and nothing here touches a
database: the adapter is a pure function over two JSON documents.
"""
from canarygate.ui.replay import build_replay

BASE = "2026-10-30T10:"


def observation(phase, actor, path, status, second, *, method="GET", minute="00", role="user"):
    return {
        "phase": phase,
        "timestamp": f"{BASE}{minute}:{second:02d}.000000+00:00",
        "actor": actor,
        "role": role,
        "request": {"method": method, "path": path, "authorization": "[REDACTED]"},
        "response": {"status_code": status, "items": None, "item_count": None,
                     "items_truncated": None, "item": None},
        "assertions": {"owner_detail_matches": True},
        "redacted": True,
        "sha256": f"{phase}-{actor}-{second}".ljust(64, "0"),
    }


def evidence_part(actor, path, status, second, *, method="GET", minute="00", checklist=None):
    return {
        "timestamp": f"{BASE}{minute}:{second:02d}.500000+00:00",
        "actor": actor,
        "role": "user",
        "method": method,
        "path": path,
        "status_code": status,
        "request": {"headers": {"Authorization": "[REDACTED]"}},
        "response": {"body": {"id": "item", "owner": actor, "private_note": "[REDACTED]"}},
        "checklist": checklist or {},
        "sha256": "a" * 64,
        "redacted": True,
    }


def run_with(observations, ownership=None, disclosure=None, checks=None):
    return {
        "id": "8b1c0f7e-0000-4000-8000-000000000000",
        "mode": "fixture",
        "status": "completed",
        "endpoint": "GET /items/{id}",
        "actor": "alice",
        "verdict": "CONFIRMED",
        "reason": "Verified ownership and cross-user private baseline disclosure",
        "remediation": None,
        "evidence": {"ownership": ownership, "disclosure": disclosure},
        "checks": checks or [],
    }


def observation_set(records, coverage="RECORDED"):
    return {"mode": "fixture", "run_id": "x", "coverage": coverage, "observations": records}


def marked(replay, part):
    return [event["n"] for event in replay["events"] if event["evidence_part"] == part]


def test_repeated_identical_requests_are_matched_by_phase_not_by_order():
    """Alice reads Bob's item during discovery *and* as the disclosure probe.

    Same actor, method, path and status, different phase. The disclosure evidence
    must annotate the cross_user_read event, never the discovery one.
    """
    records = [
        observation("discovery", "alice", "/items", 200, 1),
        observation("discovery", "alice", "/items/bob-item", 200, 2),      # early leak
        observation("owner_baseline", "bob", "/items/bob-item", 200, 3),
        observation("cross_user_read", "alice", "/items/bob-item", 200, 4),
    ]
    replay = build_replay(
        "fixture",
        run_with(records,
                 ownership=evidence_part("bob", "/items/bob-item", 200, 3),
                 disclosure=evidence_part("alice", "/items/bob-item", 200, 4)),
        observation_set(records),
    )

    by_phase = {(event["phase"], event["n"]) for event in replay["events"]}
    assert ("discovery", 2) in by_phase and ("cross_user_read", 4) in by_phase
    assert marked(replay, "disclosure") == [4], replay["events"]
    assert marked(replay, "ownership") == [3]


def test_repeated_probe_uses_the_timestamp_nearest_the_evidence():
    """A retried request must not steal the annotation from the captured one."""
    records = [
        observation("cross_user_read", "alice", "/items/bob-item", 200, 3),
        observation("cross_user_read", "alice", "/items/bob-item", 200, 9),   # later retry
    ]
    replay = build_replay(
        "fixture",
        run_with(records, disclosure=evidence_part("alice", "/items/bob-item", 200, 3)),
        observation_set(records),
    )
    assert marked(replay, "disclosure") == [1]
    assert replay["events"][0]["evidence_basis"].startswith("phase")


def test_repeated_owner_baseline_does_not_move_the_ownership_annotation():
    records = [
        observation("owner_baseline", "bob", "/items/bob-item", 200, 2),
        observation("owner_baseline", "bob", "/items/bob-item", 200, 8),   # later retry
        observation("cross_user_read", "alice", "/items/bob-item", 200, 9),
    ]
    replay = build_replay(
        "fixture",
        run_with(records, ownership=evidence_part("bob", "/items/bob-item", 200, 2)),
        observation_set(records),
    )
    assert marked(replay, "ownership") == [1]
    # The ambiguity is disclosed rather than silently resolved.
    assert any("share the identity" in note or "matched" in note for note in replay["derived_notes"])


def test_identity_only_fallback_when_no_phase_matches():
    """Unusual payloads still annotate, and say the phase did not match."""
    records = [
        observation("probe", "bob", "/items/bob-item", 200, 2),
        observation("cross_user_read", "alice", "/items/bob-item", 200, 4),
    ]
    replay = build_replay(
        "fixture",
        run_with(records, ownership=evidence_part("bob", "/items/bob-item", 200, 2)),
        observation_set(records),
    )
    assert marked(replay, "ownership") == [1]
    assert "identity" in replay["events"][0]["evidence_basis"]


def test_unmatched_evidence_is_reported_not_invented():
    records = [observation("cross_user_read", "alice", "/items/bob-item", 200, 4)]
    replay = build_replay(
        "fixture",
        run_with(records,
                 ownership=evidence_part("bob", "/items/other", 200, 2),
                 disclosure=evidence_part("alice", "/items/bob-item", 200, 4)),
        observation_set(records),
    )
    assert marked(replay, "ownership") == []
    assert marked(replay, "disclosure") == [1]
    assert any("ownership" in note and "does not correspond" in note
               for note in replay["derived_notes"])


def test_skipped_checks_produce_no_events():
    skipped = {"id": "AUTHN-06", "category": "Authentication", "verdict": "SKIPPED",
               "reason": "Logout check not implemented", "evidence": None, "remediation": None}
    executed = {"id": "AUTHN-01", "category": "Authentication", "verdict": "SAFE",
                "reason": "rejected", "remediation": None,
                "evidence": {"phase": "probe", "timestamp": f"{BASE}00:05.000000+00:00",
                             "actor": "alice", "role": "user", "method": "GET",
                             "path": "/items/alice-item", "status_code": 401,
                             "request": {"headers": {}}, "response": {"body": None},
                             "checklist": {"denial_body_checked": True},
                             "sha256": "b" * 64, "redacted": True}}
    records = [observation("cross_user_read", "alice", "/items/bob-item", 200, 4)]
    replay = build_replay("fixture", run_with(records, checks=[executed, skipped]),
                          observation_set(records))
    probe_ids = [event["check_id"] for event in replay["events"] if event["source"] == "probe"]
    assert probe_ids == ["AUTHN-01"]
    assert replay["event_count"] == 2
    assert any(event["source"] == "observation" for event in replay["events"])


def test_inconclusive_and_unknown_verdicts_render_as_recorded():
    def check(check_id, verdict):
        return {"id": check_id, "category": "Disclosure", "verdict": verdict,
                "reason": "not enough evidence", "remediation": None,
                "evidence": {"phase": "probe", "timestamp": f"{BASE}00:06.000000+00:00",
                             "actor": "alice", "role": "user", "method": "GET",
                             "path": "/search", "status_code": 400,
                             "request": {"headers": {}}, "response": {"body": {}},
                             "checklist": {"response_checked": None},
                             "sha256": "c" * 64, "redacted": True}}

    records = [observation("cross_user_read", "alice", "/items/bob-item", 200, 4)]
    replay = build_replay(
        "fixture",
        run_with(records, checks=[check("DISC-01", "INCONCLUSIVE"), check("DISC-02", "SAFE")]),
        observation_set(records),
    )
    verdicts = [event["check_verdict"] for event in replay["events"] if event["source"] == "probe"]
    assert verdicts == ["INCONCLUSIVE", "SAFE"]
    assert all(event["status_band"] == "denied" for event in replay["events"]
               if event["source"] == "probe")


def test_missing_observation_coverage_is_unavailable_rather_than_empty():
    replay = build_replay("fixture", run_with([]), observation_set([], coverage="NOT_RECORDED"))
    assert replay["mode"] == "unavailable"
    assert replay["events"] == []
    assert "no recorded observations" in replay["mode_note"]

    empty = build_replay("fixture", run_with([]), observation_set([]))
    assert empty["mode"] == "unavailable"


def test_sequence_mode_never_claims_ordering_by_time():
    run = {"id": "x", "created_at": f"{BASE}00:00.000000+00:00", "mode": "offline_scenario",
           "verdict": "CONFIRMED", "reason": "r",
           "evidence": {"ownership": evidence_part("account-b", "/records/{id}", 200, 0),
                        "disclosure": evidence_part("account-a", "/records/{id}", 200, 0)}}
    replay = build_replay("read-bola", run)
    assert replay["mode"] == "sequence"
    assert [event["evidence_part"] for event in replay["events"]] == ["ownership", "disclosure"]
    assert all(event["offset_ms"] is None and event["offset_label"] is None
               for event in replay["events"])


# --------------------------------------------------------------------------- #
# Ambiguity, ties and unusable timestamps
# --------------------------------------------------------------------------- #
def test_equally_plausible_candidates_are_marked_ambiguous_not_silently_chosen():
    """Both requests are 500 ms from the evidence summary: neither is provable."""
    records = [
        observation("cross_user_read", "alice", "/items/bob-item", 200, 3),
        observation("cross_user_read", "alice", "/items/bob-item", 200, 4),
    ]
    # The evidence summary sits exactly between the two captures.
    record = evidence_part("alice", "/items/bob-item", 200, 3)
    record["timestamp"] = "2026-10-30T10:00:03.500000+00:00"
    replay = build_replay("fixture", run_with(records, disclosure=record),
                          observation_set(records))

    marked_events = [event for event in replay["events"] if event["evidence_part"] == "disclosure"]
    assert len(marked_events) == 1
    assert marked_events[0]["evidence_ambiguous"] is True
    assert "ambiguous:" in marked_events[0]["evidence_basis"]
    assert "2 captured requests" in marked_events[0]["evidence_basis"]
    assert any("ambiguous" in note for note in replay["derived_notes"])


def test_identical_requests_inside_the_window_still_resolve_when_one_is_clearly_nearer():
    records = [
        observation("cross_user_read", "alice", "/items/bob-item", 200, 3),
        observation("cross_user_read", "alice", "/items/bob-item", 200, 4),
    ]
    # 200 ms from the first, 800 ms from the second: a clear nearest match.
    record = evidence_part("alice", "/items/bob-item", 200, 3)
    record["timestamp"] = "2026-10-30T10:00:03.200000+00:00"
    replay = build_replay("fixture", run_with(records, disclosure=record),
                          observation_set(records))

    marked = [event for event in replay["events"] if event["evidence_part"] == "disclosure"][0]
    assert marked["n"] == 1
    assert marked["evidence_ambiguous"] is False
    assert "nearest capture timestamp (200 ms" in marked["evidence_basis"]


def test_missing_timestamps_make_a_multi_candidate_match_ambiguous():
    records = [
        observation("cross_user_read", "alice", "/items/bob-item", 200, 3),
        observation("cross_user_read", "alice", "/items/bob-item", 200, 4),
    ]
    for record in records:
        record["timestamp"] = None
    record = evidence_part("alice", "/items/bob-item", 200, 3)
    record["timestamp"] = None
    replay = build_replay("fixture", run_with(records, disclosure=record),
                          observation_set(records))

    marked = [event for event in replay["events"] if event["evidence_part"] == "disclosure"][0]
    assert marked["evidence_ambiguous"] is True
    assert "no usable timestamp" in marked["evidence_basis"]
    # The page still orders the events; it just cannot place the evidence by time.
    assert [event["offset_ms"] for event in replay["events"]] == [None, None]


def test_malformed_timestamps_are_treated_as_missing_and_never_crash():
    records = [
        observation("cross_user_read", "alice", "/items/bob-item", 200, 3),
        observation("cross_user_read", "alice", "/items/bob-item", 200, 4),
    ]
    records[0]["timestamp"] = "not-a-timestamp"
    records[1]["timestamp"] = ""
    record = evidence_part("alice", "/items/bob-item", 200, 3)
    record["timestamp"] = "2026-13-45T99:99:99"
    replay = build_replay("fixture", run_with(records, disclosure=record),
                          observation_set(records))

    marked = [event for event in replay["events"] if event["evidence_part"] == "disclosure"][0]
    assert marked["evidence_ambiguous"] is True
    assert all(event["offset_ms"] is None for event in replay["events"])


def test_missing_timestamp_with_a_single_candidate_is_not_called_ambiguous():
    records = [observation("cross_user_read", "alice", "/items/bob-item", 200, 3)]
    records[0]["timestamp"] = None
    record = evidence_part("alice", "/items/bob-item", 200, 3)
    record["timestamp"] = None
    replay = build_replay("fixture", run_with(records, disclosure=record),
                          observation_set(records))

    marked = replay["events"][0]
    assert marked["evidence_part"] == "disclosure"
    assert marked["evidence_ambiguous"] is False


def test_candidates_outside_the_matching_window_are_not_used():
    records = [observation("cross_user_read", "alice", "/items/bob-item", 200, 3)]
    record = evidence_part("alice", "/items/bob-item", 200, 3)
    record["timestamp"] = "2026-10-30T10:05:03.000000+00:00"   # five minutes later
    replay = build_replay("fixture", run_with(records, disclosure=record),
                          observation_set(records))

    marked = replay["events"][0]
    assert marked["evidence_part"] == "disclosure"
    assert marked["evidence_ambiguous"] is False
    assert "outside the 5000 ms window" in marked["evidence_basis"]


def test_ambiguous_association_renders_a_warning_not_a_claim():
    """The rendered page must not read as proof when the match is ambiguous."""
    from canarygate.ui.routes import BUILD_FACTS, NAV_GROUPS
    from canarygate.ui.templating import templates

    records = [
        observation("cross_user_read", "alice", "/items/bob-item", 200, 3),
        observation("cross_user_read", "alice", "/items/bob-item", 200, 4),
    ]
    record = evidence_part("alice", "/items/bob-item", 200, 3)
    record["timestamp"] = "2026-10-30T10:00:03.500000+00:00"
    replay = build_replay("fixture", run_with(records, disclosure=record),
                          observation_set(records))

    context = dict(replay)
    context.update(active="scans", nav_groups=NAV_GROUPS, build_facts=BUILD_FACTS,
                   provisional=True)
    html = templates.env.get_template("replay.html").render(**context)

    assert 'class="replay-warn"' in html
    assert "Ambiguous association" in html
    assert "may describe either request" in html
    assert "unconfirmed" in html
    assert "not proof on its own" in html
    # The definitive wording used for settled matches must be gone.
    assert "This exact request is the backend's disclosure evidence" not in html
