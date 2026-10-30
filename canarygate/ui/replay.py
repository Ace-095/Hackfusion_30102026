"""Flight recorder: turn stored backend evidence into an ordered replay.

This module is a **read-only adapter**. It makes no requests of its own, calls no
backend mutation, and invents no event, timestamp or verdict. It reshapes data
that the API already returned:

* ``GET /api/scan/{id}``             -> ``evidence.ownership``, ``evidence.disclosure``,
                                        ``checks[]`` (each with its own ``evidence``)
* ``GET /api/scan/{id}/observations`` -> the fixture recipe's captured observations

Two honesty rules drive the whole design:

1. **A timeline needs capture timestamps.** Only fixture runs have them, and only
   per request. Transcript runs (read-BOLA scenarios, authentication scenarios)
   stamp every recorded probe with the run's creation instant, so their events
   cannot be ordered by time. They are rendered as a *sequence* (backend list
   order) and the page says so.
2. **Evidence cards annotate events; they are not extra events.** The ownership
   and disclosure evidence objects describe the same requests as two of the
   observations, one layer of interpretation later. Emitting them as separate
   timeline entries would make one request look like two.
"""
from datetime import datetime

# Presentation labels for the phase names the backend emits. The backend phase
# string is always rendered next to the label, so nothing is hidden by this map.
PHASE_LABELS = {
    "discovery": "Discover the collection",
    "owner_baseline": "Owner reads their own resource",
    "cross_user_read": "Cross-user read",
}

# What an observation's own assertions allow us to say about it. These are
# restatements of backend fields, not new analysis.
PHASE_WHY = {
    "discovery": (
        "The backend lists what each account can see. Isolation here is what makes "
        "a later cross-user read meaningful."
    ),
    "owner_baseline": (
        "Owns the resource and reads it successfully. This is the baseline the "
        "disclosure event will be compared against."
    ),
    "cross_user_read": (
        "A different account requests the resource. The response below decides "
        "whether anything actually crossed the boundary."
    ),
}

_STATUS_BANDS = (
    (200, 299, "ok"),
    (300, 399, "redirect"),
    (400, 403, "denied"),
    (404, 404, "absent"),
    (500, 599, "error"),
)


def _band(status):
    if not isinstance(status, int):
        return "none"
    for low, high, name in _STATUS_BANDS:
        if low <= status <= high:
            return name
    return "other"


def _parse(timestamp):
    """Parse an ISO-8601 backend timestamp; return None instead of guessing."""
    if not isinstance(timestamp, str) or not timestamp:
        return None
    try:
        return datetime.fromisoformat(timestamp)
    except ValueError:
        return None


def _span_label(milliseconds):
    """Human duration without pretending to more precision than we have."""
    if not isinstance(milliseconds, int):
        return None
    if milliseconds < 1000:
        return f"{milliseconds} ms"
    return f"{milliseconds / 1000:.2f} s"


def _auth_note(value):
    """Normalise the two shapes of redacted Authorization metadata."""
    if isinstance(value, dict):
        return "supplied · redacted" if "Authorization" in value else "not supplied"
    if isinstance(value, str) and value:
        return value.replace("[REDACTED]", "supplied · redacted")
    return "not recorded"


def _tri(values):
    """Preserve the backend's tri-state assertions in render order."""
    if not isinstance(values, dict):
        return []
    return [{"key": key, "value": value} for key, value in values.items()]


def _observation_event(record, index):
    request = record.get("request") or {}
    response = record.get("response") or {}
    phase = record.get("phase") or ""
    return {
        "n": index,
        "source": "observation",
        "phase": phase,
        "phase_label": PHASE_LABELS.get(phase, phase.replace("_", " ")),
        "check_id": None,
        "category": None,
        "check_verdict": None,
        "reason": None,
        "title": PHASE_LABELS.get(phase, phase.replace("_", " ") or "Recorded request"),
        "actor": record.get("actor"),
        "role": record.get("role"),
        "method": request.get("method"),
        "path": request.get("path"),
        "status": response.get("status_code"),
        "status_band": _band(response.get("status_code")),
        "timestamp": record.get("timestamp"),
        "assertions": _tri(record.get("assertions")),
        "checklist": [],
        "evidence_part": None,
        "why": PHASE_WHY.get(phase),
        "sha256": record.get("sha256"),
        "redacted": record.get("redacted", True),
        "request_auth": _auth_note(request.get("authorization")),
        "response_summary": _response_summary(record),
    }


def _response_summary(record):
    """A few allowlisted facts from the minimized response, nothing raw."""
    response = record.get("response") or {}
    lines = []
    if response.get("item_count") is not None:
        lines.append({"label": "items returned", "value": response.get("item_count")})
    if response.get("items_truncated") is not None:
        lines.append({"label": "list truncated", "value": response.get("items_truncated")})
    item = response.get("item")
    if isinstance(item, dict):
        if item.get("id") is not None:
            lines.append({"label": "item id", "value": item.get("id")})
        if item.get("owner") is not None:
            lines.append({"label": "item owner", "value": item.get("owner")})
        if item.get("private_field_present") is not None:
            lines.append({"label": "private field present", "value": item.get("private_field_present")})
    items = response.get("items")
    if isinstance(items, list) and items:
        lines.append({"label": "items listed", "value": len(items)})
    return lines


def _probe_event(check, evidence, index):
    return {
        "n": index,
        "source": "probe",
        "phase": evidence.get("phase") or "probe",
        "phase_label": "Security probe",
        "check_id": check.get("id"),
        "category": check.get("category"),
        "check_verdict": check.get("verdict"),
        "reason": check.get("reason"),
        "title": f"{check.get('id')} · {check.get('category')} probe",
        "actor": evidence.get("actor"),
        "role": evidence.get("role"),
        "method": evidence.get("method"),
        "path": evidence.get("path") or evidence.get("path_template"),
        "status": evidence.get("status_code"),
        "status_band": _band(evidence.get("status_code")),
        "timestamp": evidence.get("timestamp"),
        "assertions": [],
        "checklist": _tri(evidence.get("checklist")),
        "evidence_part": None,
        "why": None,
        "sha256": evidence.get("sha256"),
        "redacted": evidence.get("redacted", True),
        "request_auth": _auth_note((evidence.get("request") or {}).get("headers")),
        "response_summary": [
            {"label": "response body", "value": (evidence.get("response") or {}).get("body")}
        ] if isinstance(evidence.get("response"), dict) else [],
    }


def _evidence_only_event(part, evidence, index):
    return {
        "n": index,
        "source": "evidence",
        "phase": evidence.get("phase") or part,
        "phase_label": "Evidence part",
        "check_id": None,
        "category": None,
        "check_verdict": None,
        "reason": None,
        "title": f"{part.capitalize()} evidence",
        "actor": evidence.get("actor"),
        "role": evidence.get("role"),
        "method": evidence.get("method"),
        "path": evidence.get("path") or evidence.get("path_template"),
        "status": evidence.get("status_code"),
        "status_band": _band(evidence.get("status_code")),
        "timestamp": None,
        "assertions": [],
        "checklist": _tri(evidence.get("checklist")),
        "evidence_part": part,
        "why": None,
        "sha256": evidence.get("sha256"),
        "redacted": evidence.get("redacted", True),
        "request_auth": _auth_note((evidence.get("request") or {}).get("headers")),
        "response_summary": [
            {"label": "response body", "value": (evidence.get("response") or {}).get("body")}
        ] if isinstance(evidence.get("response"), dict) else [],
    }


def _attach_evidence_parts(events, run):
    """Mark which events the run's two evidence parts describe.

    Matching is by *identity of the recorded request* (actor + method + path +
    status), never by position, and the match is reported on the page so the
    reader can check it. Evidence objects are not emitted as extra events.
    """
    notes = []
    evidence = run.get("evidence") or {}
    for part in ("ownership", "disclosure"):
        record = evidence.get(part)
        if not isinstance(record, dict):
            continue
        key = (
            record.get("actor"),
            record.get("method"),
            record.get("path") or record.get("path_template"),
            record.get("status_code"),
        )
        matches = [
            event for event in events
            if (event["actor"], event["method"], event["path"], event["status"]) == key
        ]
        if not matches:
            notes.append(
                f"The {part} evidence part does not correspond to a captured request in "
                "this run's observation set, so it is not marked on the timeline."
            )
            continue
        target = matches[-1]
        target["evidence_part"] = part
        target["why"] = {
            "ownership": (
                "This exact request is the backend's ownership evidence: the resource "
                "was confirmed to belong to the other account."
            ),
            "disclosure": (
                "This exact request is the backend's disclosure evidence: private data "
                "crossed the account boundary."
            ),
        }[part]
        if len(matches) > 1:
            notes.append(
                f"{len(matches)} captured requests match the {part} evidence identity; "
                "the last one in capture order is marked."
            )
    return notes


def _fixture_replay(run, observation_set):
    coverage = (observation_set or {}).get("coverage")
    records = list((observation_set or {}).get("observations") or [])

    if coverage != "RECORDED" or not records:
        return {
            "mode": "unavailable",
            "mode_note": (
                "The backend reports no recorded observations for this run "
                f"(coverage: {coverage or 'unknown'}). There is nothing to replay, and this "
                "page will not synthesise a sequence from the run summary."
            ),
        }

    events = []
    for record in records:
        events.append(_observation_event(record, 0))

    for check in run.get("checks") or []:
        evidence = check.get("evidence")
        if not isinstance(evidence, dict) or not evidence.get("timestamp"):
            # A SKIPPED check never performed a request; it has no event.
            continue
        events.append(_probe_event(check, evidence, 0))

    parsed = [(_parse(event["timestamp"]), position, event) for position, event in enumerate(events)]
    missing = [event for parsed_ts, _, event in parsed if parsed_ts is None]
    parsed.sort(key=lambda row: (row[0] or datetime.min, row[1]))
    ordered = [event for _, _, event in parsed]

    for index, event in enumerate(ordered, start=1):
        event["n"] = index

    start = _parse(ordered[0]["timestamp"]) if ordered else None
    for event in ordered:
        stamp = _parse(event["timestamp"])
        event["offset_ms"] = int((stamp - start).total_seconds() * 1000) if (stamp and start) else None
        event["offset_label"] = _span_label(event["offset_ms"])

    notes = [
        "Order is the backend's own capture timestamp for each request. Ties keep the "
        "order the API returned.",
    ]
    if missing:
        notes.append(
            f"{len(missing)} event(s) carried no parseable timestamp and were placed last."
        )
    notes.extend(_attach_evidence_parts(ordered, run))

    unique_times = {event["timestamp"] for event in ordered}
    if len(unique_times) != len(ordered):
        notes.append(
            "Some events share a timestamp to the microsecond; their relative order is "
            "the order the backend returned."
        )

    probes = sum(1 for event in ordered if event["source"] == "probe")
    observations = sum(1 for event in ordered if event["source"] == "observation")
    return {
        "mode": "timeline",
        "mode_note": (
            "Each event below is one request the backend recorded while producing this "
            "run, ordered by its capture timestamp. Nothing is reconstructed."
        ),
        "events": ordered,
        "event_count": len(ordered),
        "observation_count": observations,
        "probe_count": probes,
        "span_ms": (ordered[-1]["offset_ms"] or 0) if ordered else 0,
        "span_label": _span_label((ordered[-1]["offset_ms"] or 0) if ordered else 0),
        "coverage": coverage,
        "derived_notes": notes,
    }


def _transcript_replay(run, kind):
    """Scenario / authentication runs: backend order is available, wall clock is not."""
    events = []
    if kind == "read-bola":
        evidence = run.get("evidence") or {}
        for part in ("ownership", "disclosure"):
            record = evidence.get(part)
            if isinstance(record, dict):
                events.append(_evidence_only_event(part, record, 0))
        note = (
            "This is an offline transcript run. Its two evidence parts are returned in "
            "phase order, and the backend stamps both with the same instant, so this is a "
            "sequence — not a measured timeline."
        )
    else:
        for check in run.get("checks") or []:
            evidence = check.get("evidence")
            if isinstance(evidence, dict):
                events.append(_probe_event(check, evidence, 0))
        note = (
            "This is an offline transcript run. The backend returns its recorded probes "
            "in transcript order but stamps them all with the run's creation instant, so "
            "this is a sequence — not a measured timeline."
        )

    if not events:
        return {
            "mode": "unavailable",
            "mode_note": (
                "This run recorded no requests. Its verdict, reason and constraints are on "
                "the run page; there is no sequence to step through."
            ),
        }

    for index, event in enumerate(events, start=1):
        event["n"] = index
        event["offset_ms"] = None
        event["offset_label"] = None

    return {
        "mode": "sequence",
        "mode_note": note,
        "events": events,
        "event_count": len(events),
        "observation_count": 0,
        "probe_count": sum(1 for event in events if event["source"] == "probe"),
        "span_ms": None,
        "coverage": "RECORDED",
        "derived_notes": [
            "Order is the order the backend returned these records in. No timestamp "
            "ordering is claimed, because every record shares one instant.",
            "A true per-request timeline for transcript runs needs a backend field for "
            "capture time (see gap G13 in docs/UI.md).",
        ],
    }


def build_replay(kind, run, observation_set=None):
    """Return the replay view model for one stored run.

    ``kind`` is ``"fixture"``, ``"read-bola"`` or ``"authentication"`` — the
    route that produced ``run`` — so the adapter never has to guess which
    backend shape it was given.
    """
    if kind == "fixture":
        replay = _fixture_replay(run, observation_set)
    else:
        replay = _transcript_replay(run, kind)

    replay.setdefault("events", [])
    replay.setdefault("event_count", len(replay["events"]))
    replay.setdefault("observation_count", 0)
    replay.setdefault("probe_count", 0)
    replay.setdefault("span_ms", None)
    replay.setdefault("coverage", None)
    replay.setdefault("derived_notes", [])
    replay["kind"] = kind
    replay["run"] = run
    return replay
