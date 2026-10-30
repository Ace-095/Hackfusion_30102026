"""Execute a synthetic read-BOLA check through scoped, guarded mock requests."""
from datetime import datetime, timezone
from importlib.resources import files
import hashlib
import json
from uuid import uuid4

from .runner import FixtureRunner, GuardRejected
from .target import FixtureTarget
from .auth_checks import pending_checks, run_auth_checks
from .enumeration import run_enumeration_check
from .input_checks import pending_input_checks, run_input_checks
from canarygate.evidence.observations import capture as capture_observation, seal as seal_observation
from canarygate.seed.recipe import validate_fixture_recipe
from canarygate.seed.extraction import extract
from canarygate.seed import registry
from canarygate.oracles import read_bola
from canarygate.spec.parser import parse_inventory


def inventory():
    return parse_inventory(files("canarygate.offline").joinpath("fixture.yaml").read_text(encoding="utf-8"))


def fixture_recipe() -> dict:
    return json.loads(files("canarygate.offline").joinpath("recipe.json").read_text(encoding="utf-8"))


def _summary(actor: str, role: str, response, matched: bool, **checklist) -> dict:
    # Only safe request metadata and explicitly allowlisted fixture fields are
    # persisted. No Authorization values, raw response bodies or private values.
    body = None
    try:
        raw = response.json()
        if isinstance(raw, dict):
            body = {key: raw[key] for key in ("id", "owner") if isinstance(raw.get(key), str)}
            if body.get("id") not in (None, "alice-item", "bob-item"):
                body["id"] = "[REDACTED]"
            if body.get("owner") not in (None, "alice", "bob"):
                body["owner"] = "[REDACTED]"
            if "private_note" in raw:
                body["private_note"] = "[REDACTED]"
    except (ValueError, UnicodeError, RecursionError):
        pass
    summary = {"timestamp": datetime.now(timezone.utc).isoformat(), "actor": actor, "role": role,
               "method": response.request.method, "path": response.request.url.path,
               "status_code": response.status_code, "private_canary_matched": matched,
               "request": {"headers": {"Authorization": "[REDACTED]"} if "Authorization" in response.request.headers else {}},
               "response": {"body": body}, "checklist": checklist}
    digest = hashlib.sha256(json.dumps(summary, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {**summary, "sha256": digest, "redacted": True}


def _object(response):
    if response.status_code != 200:
        return None
    try:
        value = response.json()
        return value if isinstance(value, dict) else None
    except (ValueError, UnicodeError, RecursionError):
        return None


def run_fixture(target: FixtureTarget | None = None, *, recipe: dict | None = None,
                observation_sink: list | None = None) -> dict:
    target = target or FixtureTarget()
    # Only bundled configuration reaches the API; tests vary trusted fixture inputs.
    data = validate_fixture_recipe(recipe if recipe is not None else fixture_recipe())
    setup, policy = data.setup, data.policy
    runner = FixtureRunner(target.handle)
    scope_bytes = files("canarygate.offline").joinpath("scope.yaml").read_bytes()
    spec_bytes = files("canarygate.offline").joinpath("fixture.yaml").read_bytes()
    fixture_inventory = parse_inventory(spec_bytes.decode("utf-8"))
    resource_type, resource = next(iter(setup.resources.items()), (None, None))
    account_a, account_b = setup.accounts.get("user_a"), setup.accounts.get("user_b")
    setup_status = {"strategy": "recipe_read_only_discovery", "authentication": "SKIPPED",
                    "accounts": {}, "resources": "SKIPPED", "ownership_verification": "SKIPPED",
                    "bola_coverage": "SKIPPED", "reason": "Setup incomplete"}
    result = {"id": str(uuid4()), "created_at": datetime.now(timezone.utc).isoformat(),
              "mode": "fixture", "status": "completed", "endpoint": "",
              "actor": account_a.username if account_a else "", "account_role": account_a.role if account_a else "",
              "target_resource": "", "verified_owner": "", "expected_access": policy.expected_access,
              "expected_source": policy.expected_source, "setup": setup_status,
              "evidence": {"ownership": None, "disclosure": None},
              "checks": pending_checks() + pending_input_checks(),
              "verdict": "SKIPPED", "reason": "Setup incomplete", "remediation": None,
              "bola_checklist": read_bola.empty_checklist(),
              "scope_hash": hashlib.sha256(scope_bytes).hexdigest(),
              "spec_hash": hashlib.sha256(spec_bytes).hexdigest(),
              "inventory": fixture_inventory, "constraints": {}}

    def skip(reason, *, gate=None, status="SKIPPED"):
        if gate:
            setup_status[gate] = status
        setup_status["reason"] = reason
        result["reason"] = reason
        return result

    def request(account, operation, *, token=None, body=None, path=None):
        return runner.request(account.username, operation.method, runner.scope.origin + (path or operation.path), token=token, json_body=body)

    def observe(phase, account, response, **assertions):
        if observation_sink is None:
            return None
        record = capture_observation(phase, account, response, id_field=resource.id_field,
                                     owner_field=resource.ownership_field,
                                     private_field=resource.private_field, assertions=assertions)
        observation_sink.append(record)
        return record

    def update_observation(record, **assertions):
        if record is not None:
            record["assertions"].update(assertions)
            record.update(seal_observation(record))

    try:
        if not account_a or not account_b or not resource or account_a.username == account_b.username:
            return skip("Two distinct fixture identities and a resource recipe are required")
        result["endpoint"] = f"{resource.detail.method} {resource.detail.path}"
        tokens = {}
        for account in (account_a, account_b):
            response = request(account, setup.login, body={"account": account.username})
            payload = _object(response)
            token = payload.get("token") if payload else None
            if not isinstance(token, str) or not token:
                setup_status["accounts"][account.username] = "FAILED"
                return skip(f"Fixture authentication unavailable for {account.username}", gate="authentication", status="PARTIAL")
            tokens[account.username] = token
            setup_status["accounts"][account.username] = "SUCCESS"
        setup_status["authentication"] = "SUCCESS"
        result["checks"] = pending_checks(token=tokens[account_a.username]) + pending_input_checks()
        account_map = {account_a.username: account_a, account_b.username: account_b}
        discovery_observations, baseline_observations = {}, {}

        def discovery(actor, response, identified):
            discovery_observations[actor] = observe(
                "discovery", account_map[actor], response, own_resource_identified=identified)

        def exclusion(actor, excluded):
            update_observation(discovery_observations.get(actor), peer_resource_excluded=excluded)

        def baseline(actor, response, matched):
            baseline_observations[actor] = observe(
                "owner_baseline", account_map[actor], response, owner_detail_matches=matched)

        ownership = registry.collect_fixture_ownership(
            runner, resource_type=resource_type, resource=resource,
            accounts=(account_a.username, account_b.username), tokens=tokens,
            on_discovery=discovery, on_exclusion=exclusion, on_baseline=baseline)
        setup_status["resources"] = ownership.resource_status
        setup_status["ownership_verification"] = ownership.ownership_status
        oracle_args = dict(ownership=ownership, resource_type=resource_type, resource=resource,
                           actor=account_a.username, owner=account_b.username,
                           expected_access=policy.expected_access, expected_source=policy.expected_source)
        readiness = read_bola.evaluate_read_bola(**oracle_args, response=None)
        result["bola_checklist"] = readiness.checklist
        if ownership.ownership_status != "SUCCESS":
            return skip(ownership.reason)
        ids, baselines = ownership.ids, ownership.baselines
        owner_response, owner_body = baselines[account_b.username]
        private_value = extract(owner_body, resource.private_field, None)
        if resource.known_owner_canary:
            update_observation(baseline_observations[account_b.username],
                               canary_matches_recipe=private_value == resource.known_owner_canary)
        if not readiness.checklist["private_baseline"]:
            return skip(readiness.verdict_reason, gate="bola_coverage", status="FAILED")
        result["target_resource"] = ids[account_b.username]
        result["verified_owner"] = account_b.username
        result["evidence"]["ownership"] = _summary(account_b.username, account_b.role, owner_response, True,
                                                   both_owner_baselines=True, cross_list_isolation=True)
        setup_status["ownership_verification"] = "SUCCESS"
        path = resource.detail.path.replace("{id}", ids[account_b.username])
        attacker_response = request(account_a, resource.detail, token=tokens[account_a.username], path=path)
        decision = read_bola.evaluate_read_bola(**oracle_args, response=attacker_response)
        result["bola_checklist"] = decision.checklist
        disclosed = decision.checklist["private_disclosure"]
        observe("cross_user_read", account_a, attacker_response,
                private_data_matches_owner_baseline=disclosed)
        result["evidence"]["disclosure"] = _summary(account_a.username, account_a.role, attacker_response, disclosed,
                                                    matches_owner_private_baseline=disclosed)
        setup_status["bola_coverage"] = "SUCCESS"
        setup_status["reason"] = None
        result["verdict"], result["reason"] = decision.verdict, decision.verdict_reason
        if decision.remediation_key == "bola":
            result["remediation"] = "Enforce object-level authorization for every resource read."
        # OpenAPI establishes authentication requirements, not ownership policy.
        auth_required = any(e["path"] == resource.detail.path and e["method"] == resource.detail.method
                            and e["expected_access"] == "authenticated" for e in fixture_inventory)
        auth_observations = {}
        actor_private = extract(baselines[account_a.username][1], resource.private_field, None)
        if (auth_required and "." not in resource.private_field and isinstance(actor_private, str) and actor_private and actor_private != private_value
                and not any(value in actor_private for value in (ids[account_a.username], ids[account_b.username]))
                and actor_private not in {account_a.username, account_b.username}):
            actor_path = resource.detail.path.replace("{id}", ids[account_a.username])
            result["checks"] = (run_auth_checks(runner, actor=account_a.username, role=account_a.role,
                                                path=actor_path, token=tokens[account_a.username],
                                                private_field=resource.private_field, baseline=actor_private,
                                                summary=_summary, observations=auth_observations) + pending_input_checks())
        # These bounded validation inputs are fixture-specific, read-only, and
        # separately allow-listed by the exact scoped path and query.
        auth_checks = result["checks"][:len(pending_checks())]
        result["checks"] = auth_checks + run_input_checks(
            runner, actor=account_a.username, role=account_a.role,
            token=tokens[account_a.username], endpoints=fixture_inventory, summary=_summary,
            spec_text=spec_bytes.decode("utf-8"))
        enumeration = run_enumeration_check(runner, actor=account_a.username, role=account_a.role,
                                            baseline=auth_observations.get("missing"),
                                            owner_verified=setup_status["ownership_verification"] == "SUCCESS",
                                            summary=_summary)
        result["checks"] = [enumeration if check["id"] == "DISC-06" else check for check in result["checks"]]
        return result
    except (GuardRejected, ValueError, KeyError, TypeError):
        result["status"] = "failed"
        result["verdict"] = "INCONCLUSIVE"
        result["reason"] = "Fixture execution failed; no security conclusion"
        setup_status["reason"] = result["reason"]
        return result
    finally:
        result["constraints"] = {"mode": "fixture", "scope": runner.scope.origin,
                                 "requests_sent": runner.requests_sent,
                                 "authentication_requests": runner.authentication_requests,
                                 "blocked_by_guard": runner.guard.blocked,
                                 "redirects_observed": runner.redirects_observed,
                                 "redirects_followed": 0,
                                 "out_of_scope_requests_executed": 0,
                                 "destructive_requests_executed": 0,
                                 "external_requests_executed": 0,
                                 "network_transport_enabled": False,
                                 "halted_reason": runner.halted_reason}
        runner.close()
