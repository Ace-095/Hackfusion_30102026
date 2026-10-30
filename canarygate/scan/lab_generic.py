"""Evidence collection against a running TargetLab over loopback HTTPS.

This workflow deliberately stops at *observation*. It authenticates both
accounts, reads the declared routes once each, verifies that every response is
the object the transport recorded, and stores bounded facts. It does not emit
BOLA or SCI verdicts: that mapping is checkpoint 36/37 work, and doing it here
would let the lab's known answers leak into the decision logic.

No retries, no redirects, no external DNS, and no raw bodies are retained.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from canarygate.evidence.redaction import digest
from canarygate.scan.lab_models import (LabCheck, LabConstraints, LabRun, LabSummary,
                                        LabTransportInfo)
from canarygate.scan.lab_scenarios import (ADMIN_PATH, EXPECTED_POLICY, KNOWN_ACCOUNTS,
                                           OTHER_RECORD, OWN_RECORD, PROFILE_PATH,
                                           SECURE_ENDPOINT)

LIMITATIONS = (
    "Loopback-only controlled validation against a lab written by the same team; "
    "this is not live-organizer validation and cannot measure real-world detection quality.",
    "Evidence is bounded to booleans and status codes; response bodies, tokens and "
    "passwords are never stored or reported.",
    "The transport is pinned to 127.0.0.1 with a test-only CA; redirects are refused "
    "and no request is ever retried.",
    "This checkpoint collects evidence only; it deliberately emits no BOLA or SCI "
    "verdict. Verdict mapping is checkpoint 36/37 work.",
    "Seven requests are executed in a fixed order; nothing here can be widened to "
    "another host, path or account.",
)


def _json_body(response):
    try:
        body = json.loads(response.content)
    except (ValueError, UnicodeError, RecursionError):
        return None
    return body if isinstance(body, dict) else None


def _observe(status, *, owner, actor, identity=None, expect_identity=False):
    if status in (401, 403):
        return "denied"
    if 200 <= status < 300:
        if expect_identity:
            return "allowed_owner" if identity == actor else "unverified"
        if owner is None:
            return "unverified"
        return "allowed_owner" if owner == actor else "allowed_other"
    return "unexpected_status"


def _check(check_id, title, actor, method, path, response, *, verified, plan,
           expect_identity=False, distinct=False):
    body = _json_body(response)
    owner = body.get(plan.owner_field) if body else None
    identity = body.get(plan.identity_field) if body else None
    marker = body.get(plan.private_field) if body else None
    observation = (_observe(response.status_code, owner=owner, actor=actor, identity=identity,
                            expect_identity=expect_identity) if verified else "unverified")
    evidence = {
        "owner_present": isinstance(owner, str),
        "owner_matches_actor": (owner == actor) if isinstance(owner, str) else None,
        "identity_present": isinstance(identity, str),
        "identity_matches_actor": (identity == actor) if isinstance(identity, str) else None,
        "private_marker_present": isinstance(marker, str) and bool(marker),
        "distinct_credentials": distinct,
        "body_sha256": digest(body) if body is not None else None,
    }
    return LabCheck(id=check_id, title=title, endpoint=f"{method} {path}", actor=actor,
                    status=response.status_code, observation=observation,
                    verified=verified, evidence=evidence, evidence_sha256=digest(evidence))


def run_lab_evidence(plan, runner, *, store=None):
    """Collect the seven declared TargetLab observations in a fixed order."""
    checks = []
    authenticated = {}
    for actor in KNOWN_ACCOUNTS:
        runner.login(actor)
        authenticated[actor] = runner.token_for(actor) is not None
    distinct = runner.has_distinct_credentials(*KNOWN_ACCOUNTS)

    def read(actor, path):
        """Return (response, verified, blocked). A guard refusal is not an error."""
        try:
            response = runner.get(actor, path)
        except ValueError:
            return None, False, True
        return response, runner.verifies_recorded_read(response, actor, path), False

    for check_id, actor in (("LAB-01", "alice"), ("LAB-02", "bob")):
        if not authenticated[actor]:
            checks.append(_failed_login_check(check_id, actor, plan))
            continue
        response, verified, blocked = read(actor, PROFILE_PATH)
        if blocked:
            checks.append(_blocked_check(check_id, actor, "GET", PROFILE_PATH))
            continue
        checks.append(_check(check_id, f"{actor} authenticated identity", actor, "GET",
                             PROFILE_PATH, response, verified=verified, plan=plan,
                             expect_identity=True, distinct=distinct))

    for check_id, actor in (("LAB-03", "alice"), ("LAB-04", "bob")):
        if not authenticated[actor]:
            checks.append(_failed_login_check(check_id, actor, plan))
            continue
        response, verified, blocked = read(actor, OWN_RECORD[actor])
        if blocked:
            checks.append(_blocked_check(check_id, actor, "GET", OWN_RECORD[actor]))
            continue
        checks.append(_check(check_id, f"{actor} reads own private record", actor, "GET",
                             OWN_RECORD[actor], response, verified=verified, plan=plan,
                             distinct=distinct))

    for check_id, actor, path, title in (
            ("LAB-05", "alice", OTHER_RECORD["alice"], "alice reads bob's private record"),
            ("LAB-06", "alice", SECURE_ENDPOINT, "alice is denied on bob's secure record"),
            ("LAB-07", "alice", ADMIN_PATH, "alice is denied the admin collection")):
        if not authenticated[actor]:
            checks.append(_failed_login_check(check_id, actor, plan))
            continue
        response, verified, blocked = read(actor, path)
        if blocked:
            checks.append(_blocked_check(check_id, actor, "GET", path))
            continue
        checks.append(_check(check_id, title, actor, "GET", path, response,
                             verified=verified, plan=plan, distinct=distinct))

    checks = sorted(checks, key=lambda item: item.id)
    counts = {"authenticated": int(authenticated["alice"]) + int(authenticated["bob"]),
              "denied": sum(item.observation == "denied" for item in checks),
              "allowed": sum(item.observation in {"allowed_owner", "allowed_other"} for item in checks),
              "unverified": sum(item.observation in {"unverified", "unexpected_status"} for item in checks),
              "blocked": sum(item.observation == "blocked_by_guard" for item in checks)}
    stats = runner.stats()
    scope = runner.scope
    run = LabRun(
        id=str(uuid.uuid4()),
        created_at=datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        mode="targetlab_https",
        status="completed" if all(item.verified for item in checks) else "failed",
        scenario_id=plan.scenario_id,
        title=plan.title,
        scope={"mode": scope.mode, "origin": scope.origin, "hostname": scope.hostname,
               "port": scope.port, "request_budget": scope.request_budget,
               "written_authorization_reference": scope.written_authorization_reference,
               "accounts": [{"account": item.account, "role": item.role} for item in scope.accounts],
               "expected_policy": {path: {"expected_access": access, "source": source}
                                   for path, (access, source) in EXPECTED_POLICY.items()}},
        transport=LabTransportInfo(mode="local_lab", scheme="https", destination="127.0.0.1",
                                   port=scope.port,
                                   tls_verification="pinned_test_ca_with_hostname_check",
                                   redirects="refused", retries="none", dns="not_used",
                                   network_transport_enabled=True, production_networking=False),
        checks=checks,
        summary=LabSummary(total=7, **counts),
        constraints=LabConstraints(requests_sent=stats["requests_sent"],
                                   blocked_by_guard=stats["blocked_by_guard"],
                                   budget_remaining=stats["budget_remaining"],
                                   halted=stats["halted"], redirects_observed=0),
        transcript_sha256=digest([item.model_dump() for item in checks]),
        limitations=list(LIMITATIONS),
    )
    if store is not None:
        return store.save(run)
    return run


def _blocked_check(check_id, actor, method, path):
    evidence = {"blocked_by_guard": True, "request_sent": False}
    return LabCheck(id=check_id, title=f"{actor} request blocked by the run guard",
                    endpoint=f"{method} {path}", actor=actor, status=None,
                    observation="blocked_by_guard", verified=False, evidence=evidence,
                    evidence_sha256=digest(evidence))


def _failed_login_check(check_id, actor, plan):
    evidence = {"login_succeeded": False, "distinct_credentials": False}
    return LabCheck(id=check_id, title=f"{actor} authentication failed", endpoint=f"POST /login",
                    actor=actor, status=401, observation="unverified", verified=False,
                    evidence=evidence, evidence_sha256=digest(evidence))
