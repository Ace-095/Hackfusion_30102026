"""Execute a synthetic read-BOLA check through scoped, guarded mock requests."""
from datetime import datetime, timezone
from importlib.resources import files
import hashlib
import json
import re
from uuid import uuid4

from .runner import FixtureRunner, GuardRejected
from .target import FixtureTarget
from canarygate.seed.recipe import validate_fixture_recipe
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
            if "private_note" in raw:
                body["private_note"] = "[REDACTED]"
    except (ValueError, UnicodeError):
        pass
    summary = {"timestamp": datetime.now(timezone.utc).isoformat(), "actor": actor, "role": role,
               "method": response.request.method, "path": response.request.url.path,
               "status_code": response.status_code, "private_canary_matched": matched,
               "request": {"headers": {"Authorization": "[REDACTED]"}},
               "response": {"body": body}, "checklist": checklist}
    digest = hashlib.sha256(json.dumps(summary, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {**summary, "sha256": digest, "redacted": True}


def _object(response):
    if response.status_code != 200:
        return None
    try:
        value = response.json()
        return value if isinstance(value, dict) else None
    except (ValueError, UnicodeError):
        return None


def _item_list(response):
    if response.status_code != 200:
        return None
    try:
        value = response.json()
        return value if isinstance(value, list) and all(isinstance(item, dict) for item in value) else None
    except (ValueError, UnicodeError):
        return None


def _safe_id(value):
    return isinstance(value, str) and bool(re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value))


def run_fixture(target: FixtureTarget | None = None, *, recipe: dict | None = None) -> dict:
    target = target or FixtureTarget()
    # Only bundled configuration reaches the API; tests vary trusted fixture inputs.
    data = validate_fixture_recipe(recipe if recipe is not None else fixture_recipe())
    setup, policy = data.setup, data.policy
    runner = FixtureRunner(target.handle)
    scope_bytes = files("canarygate.offline").joinpath("scope.yaml").read_bytes()
    resource = next(iter(setup.resources.values()), None)
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
              "verdict": "SKIPPED", "reason": "Setup incomplete", "remediation": None,
              "scope_hash": hashlib.sha256(scope_bytes).hexdigest(), "constraints": {}}

    def skip(reason, *, gate=None, status="SKIPPED"):
        if gate:
            setup_status[gate] = status
        setup_status["reason"] = reason
        result["reason"] = reason
        return result

    def request(account, operation, *, token=None, body=None, path=None):
        return runner.request(account.username, operation.method, runner.scope.origin + (path or operation.path), token=token, json_body=body)

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
        if resource.ownership_model != "private":
            return skip("Resource is not private; read-BOLA check not applicable")
        if resource.private_field in {resource.id_field, resource.ownership_field, "id", "status", "owner"}:
            return skip("Configured disclosure field is not private", gate="resources", status="FAILED")
        lists = {}
        ids = {}
        for account in (account_a, account_b):
            response = request(account, resource.discovery, token=tokens[account.username])
            items = _item_list(response)
            if items is None:
                return skip(f"Resource discovery failed for {account.username}", gate="resources", status="FAILED")
            candidates = [item.get(resource.id_field) for item in items
                          if item.get(resource.ownership_field) == account.username and _safe_id(item.get(resource.id_field))]
            if not candidates:
                return skip(f"No own resource discovered for {account.username}", gate="resources", status="PARTIAL")
            lists[account.username] = items
            ids[account.username] = candidates[0]
        if ids[account_a.username] == ids[account_b.username]:
            return skip("Discovered resource IDs are not distinct", gate="resources", status="FAILED")
        setup_status["resources"] = "SUCCESS"
        # Both other-account lists must exclude the resource before ownership is verified.
        isolated = all(not any(item.get(resource.id_field) == ids[owner.username] for item in lists[other.username])
                       for owner, other in ((account_a, account_b), (account_b, account_a)))
        if not isolated:
            return skip("Cross-account list isolation was not verified", gate="ownership_verification", status="FAILED")
        baselines = {}
        for account in (account_a, account_b):
            if resource.detail.path.count("{id}") != 1:
                return skip("Invalid detail path template", gate="ownership_verification", status="FAILED")
            path = resource.detail.path.replace("{id}", ids[account.username])
            response = request(account, resource.detail, token=tokens[account.username], path=path)
            obj = _object(response)
            if not obj or obj.get(resource.id_field) != ids[account.username] or obj.get(resource.ownership_field) != account.username:
                return skip(f"Owner baseline failed for {account.username}", gate="ownership_verification", status="FAILED")
            baselines[account.username] = (response, obj)
        owner_response, owner_body = baselines[account_b.username]
        private_value = owner_body.get(resource.private_field)
        other_value = baselines[account_a.username][1].get(resource.private_field)
        if (not isinstance(private_value, str) or not private_value or private_value == other_value
                or any(value in private_value for value in (ids[account_a.username], ids[account_b.username]))
                or private_value in {account_a.username, account_b.username}
                or (resource.known_owner_canary and private_value != resource.known_owner_canary)):
            return skip("Private owner baseline could not be verified", gate="ownership_verification", status="FAILED")
        result["target_resource"] = ids[account_b.username]
        result["verified_owner"] = account_b.username
        result["evidence"]["ownership"] = _summary(account_b.username, account_b.role, owner_response, True,
                                                   both_owner_baselines=True, cross_list_isolation=True)
        setup_status["ownership_verification"] = "SUCCESS"
        path = resource.detail.path.replace("{id}", ids[account_b.username])
        attacker_response = request(account_a, resource.detail, token=tokens[account_a.username], path=path)
        attacker_body = _object(attacker_response)
        disclosed = bool(attacker_body and attacker_body.get(resource.private_field) == private_value)
        result["evidence"]["disclosure"] = _summary(account_a.username, account_a.role, attacker_response, disclosed,
                                                    matches_owner_private_baseline=disclosed)
        setup_status["bola_coverage"] = "SUCCESS"
        setup_status["reason"] = None
        if policy.expected_access != "owner-only":
            result["verdict"], result["reason"] = "INCONCLUSIVE", "Owner-only access is not established"
        elif disclosed:
            result["verdict"], result["reason"] = "CONFIRMED", "Verified fixture ownership and cross-user private baseline disclosure"
            result["remediation"] = "Enforce object-level authorization for every resource read."
        elif attacker_response.status_code == 403:
            result["verdict"], result["reason"] = "SAFE", "The fixture denied the cross-user read"
        else:
            result["verdict"], result["reason"] = "INCONCLUSIVE", "No private baseline disclosure established"
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
                                 "network_transport_enabled": False}
        runner.close()
