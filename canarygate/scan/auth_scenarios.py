"""Bundled synthetic authentication scenarios for the offline application flow.

Tokens are syntactically JWT-shaped or opaque placeholders created for this
demonstration. The JWT signature segment is a fixed placeholder: this project
has no key material, never verifies a signature, and never treats a decoded
claim as identity or privilege.
"""
import base64
import json

from canarygate.api.schemas import InventoryEndpoint
from canarygate.oracles.authn_probes import (
    API_KEY_SKIP_REASON,
    JWT_SKIP_REASON,
    NO_ADMIN_REASON,
    NO_LOGOUT_REASON,
    craft_token,
)
from canarygate.scan.auth_plan import AUTH_POLICY_SOURCE, AuthenticationPlan
from canarygate.scan.auth_runner import AuthRunnerConfig, OfflineAuthRunner
from canarygate.scan.auth_transcript import AuthTranscriptEntry, AuthenticationTranscript
from canarygate.scan.transcript import OfflineTranscript, TranscriptEntry
from canarygate.scope.authorized import AuthorizedScope

SCOPE_HOST = "offline.invalid"
SCOPE_IP = "192.0.2.10"
AUTHORIZATION_LABEL = "synthetic-offline-authentication"
PLACEHOLDER_SIGNATURE = base64.urlsafe_b64encode(b"offline-placeholder-signature").decode("ascii").rstrip("=")
API_KEY_VALID = "offline-api-key-account-a"
API_KEY_INVALID = "invalid-offline-api-key"
ACCOUNT_A = "account-a"
ACCOUNT_B = "account-b"

__all__ = ["API_KEY_INVALID", "API_KEY_SKIP_REASON", "API_KEY_VALID", "AUTH_POLICY_SOURCE",
           "JWT_SKIP_REASON", "NO_ADMIN_REASON", "NO_LOGOUT_REASON", "SCENARIO_IDS",
           "account_token", "build_auth_scenario", "config_for", "runner_for",
           "scope_without_probes"]


def _segment(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def account_token(account):
    """Return a synthetic JWT-shaped credential; never a real or verified token."""
    if account not in (ACCOUNT_A, ACCOUNT_B):
        raise KeyError("unknown synthetic account")
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": account, "role": "user", "exp": 4102444800, "iss": "offline-synthetic"}
    return f"{_segment(header)}.{_segment(payload)}.{PLACEHOLDER_SIGNATURE}"


OPAQUE_TOKENS = {ACCOUNT_A: "offline-opaque-token-account-a",
                 ACCOUNT_B: "offline-opaque-token-account-b"}
API_KEY_TOKENS = {ACCOUNT_A: API_KEY_VALID, ACCOUNT_B: "offline-api-key-account-b"}


def _scope(*, profile_probes, admin_probes=(), logout=False, budget=16):
    operations = [{"method": "GET", "path": "/profile", "classification": "READ_ONLY",
                   "auth_probes": tuple(profile_probes)}]
    if admin_probes:
        operations.append({"method": "GET", "path": "/admin/users",
                           "classification": "READ_ONLY", "auth_probes": tuple(admin_probes)})
    if logout:
        operations.append({"method": "POST", "path": "/logout", "classification": "AUTHENTICATION"})
    return AuthorizedScope.model_validate({
        "mode": "approved_lab", "scheme": "https", "hostname": SCOPE_HOST, "port": 443,
        "organizer_ip": SCOPE_IP, "written_authorization_reference": AUTHORIZATION_LABEL,
        "allowed_methods": ["GET", "POST"] if logout else ["GET"],
        "request_budget": budget,
        "accounts": [{"account": ACCOUNT_A, "role": "user"},
                     {"account": ACCOUNT_B, "role": "user"}],
        "operations": operations,
    })


JWT_SCOPE = _scope(profile_probes=("missing", "malformed", "wrong_scheme", "jwt_sub",
                                   "alg_none", "logout_reuse"),
                   admin_probes=("jwt_role",), logout=True)
NO_ADMIN_SCOPE = _scope(profile_probes=("missing", "malformed", "wrong_scheme", "jwt_sub",
                                        "alg_none", "logout_reuse"), logout=True)
OPAQUE_SCOPE = _scope(profile_probes=("missing", "malformed", "wrong_scheme"))
API_KEY_SCOPE = _scope(profile_probes=("missing", "malformed", "wrong_scheme",
                                       "api_key_missing", "api_key_invalid"))


def scope_without_probes():
    """Same shape with no crafted-probe permission; used to prove fail-closed."""
    return _scope(profile_probes=(), logout=False)


def _inventory(admin=False, logout=False, api_key=False):
    security = [{"apiKeyAuth": []}] if api_key else [{"bearerAuth": []}]
    entries = [InventoryEndpoint(method="GET", path="/profile", parameters=[], security=security,
                                 expected_access="authenticated", expected_source="offline scenario scope")]
    if admin:
        entries.append(InventoryEndpoint(method="GET", path="/admin/users", parameters=[],
                                         security=security, expected_access="admin",
                                         expected_source="offline scenario scope"))
    if logout:
        entries.append(InventoryEndpoint(method="POST", path="/logout", parameters=[], security=security,
                                         expected_access="authenticated",
                                         expected_source="offline scenario scope"))
    return entries


def _reads(identity_body, admin=False):
    entries = [TranscriptEntry(actor=ACCOUNT_A, method="GET", path="/profile", status=200,
                               body=identity_body)]
    if admin:
        entries.append(TranscriptEntry(actor=ACCOUNT_A, method="GET", path="/admin/users",
                                       status=403, body={"error": "forbidden"}))
    return OfflineTranscript(entries=tuple(entries))


DENIAL = {}


def _probes(rows, logout=False):
    entries = [AuthTranscriptEntry(actor=ACCOUNT_A, method="GET", path=path, probe=probe,
                                   status=status, body=body) for probe, path, status, body in rows]
    if logout:
        entries.append(AuthTranscriptEntry(actor=ACCOUNT_A, method="POST", path="/logout",
                                           probe="logout", status=204, body=None))
    return AuthenticationTranscript(entries=tuple(entries))


def _plan(scenario_id, *, title, scope, scheme, token_format, probes, admin=False,
          logout=False, admin_capability_field=None):
    return AuthenticationPlan(
        scenario_id=scenario_id, title=title, scope=scope, accounts=(ACCOUNT_A, ACCOUNT_B),
        scheme=scheme, token_format=token_format,
        api_key_header="X-API-Key" if scheme == "api_key" else None,
        profile_path="/profile", identity_field="identity",
        admin_path="/admin/users" if admin else None,
        admin_capability_field=admin_capability_field if admin else None,
        logout_path="/logout" if logout else None,
        denial_body=dict(DENIAL),
        reads=_reads({"identity": ACCOUNT_A} if admin or logout else {"status": "ok"}, admin=admin),
        probes=probes, inventory=_inventory(admin=admin, logout=logout, api_key=scheme == "api_key"))


def _denied(probe, path):
    return (probe, path, 401, DENIAL)


def _build(scenario_id):
    if scenario_id == "synthetic-jwt-secure":
        rows = [_denied("missing", "/profile"), _denied("malformed", "/profile"),
                _denied("wrong_scheme", "/profile"), _denied("jwt_sub", "/profile"),
                _denied("alg_none", "/profile"), _denied("logout_reuse", "/profile"),
                ("jwt_role", "/admin/users", 403, DENIAL)]
        return _plan(scenario_id, title="JWT crafted tokens rejected", scope=JWT_SCOPE,
                     scheme="bearer_jwt", token_format="jwt", admin=True, logout=True,
                     admin_capability_field="admin_capability", probes=_probes(rows, logout=True))
    if scenario_id == "synthetic-jwt-sub-confirmed":
        rows = [_denied("missing", "/profile"), _denied("malformed", "/profile"),
                _denied("wrong_scheme", "/profile"),
                ("jwt_sub", "/profile", 200, {"identity": ACCOUNT_B}),
                _denied("alg_none", "/profile"), _denied("logout_reuse", "/profile"),
                ("jwt_role", "/admin/users", 403, DENIAL)]
        return _plan(scenario_id, title="Modified subject changes effective identity", scope=JWT_SCOPE,
                     scheme="bearer_jwt", token_format="jwt", admin=True, logout=True,
                     admin_capability_field="admin_capability", probes=_probes(rows, logout=True))
    if scenario_id == "synthetic-jwt-role-confirmed":
        rows = [_denied("missing", "/profile"), _denied("malformed", "/profile"),
                _denied("wrong_scheme", "/profile"), _denied("jwt_sub", "/profile"),
                _denied("alg_none", "/profile"), _denied("logout_reuse", "/profile"),
                ("jwt_role", "/admin/users", 200, {"admin_capability": True})]
        return _plan(scenario_id, title="Modified role grants admin capability", scope=JWT_SCOPE,
                     scheme="bearer_jwt", token_format="jwt", admin=True, logout=True,
                     admin_capability_field="admin_capability", probes=_probes(rows, logout=True))
    if scenario_id == "synthetic-jwt-no-observability":
        rows = [("missing", "/profile", 200, {"status": "ok"}),
                ("malformed", "/profile", 200, {"status": "ok"}),
                ("wrong_scheme", "/profile", 200, {"status": "ok"}),
                ("jwt_sub", "/profile", 200, {"status": "ok"}),
                ("alg_none", "/profile", 200, {"status": "ok"}),
                ("logout_reuse", "/profile", 200, {"status": "ok"})]
        return _plan(scenario_id, title="Accepted tokens with unobservable effects", scope=NO_ADMIN_SCOPE,
                     scheme="bearer_jwt", token_format="jwt", logout=True,
                     probes=_probes(rows, logout=True))
    if scenario_id == "synthetic-jwt-opaque":
        rows = [_denied("missing", "/profile"), _denied("malformed", "/profile"),
                _denied("wrong_scheme", "/profile")]
        return _plan(scenario_id, title="Opaque bearer tokens", scope=OPAQUE_SCOPE,
                     scheme="bearer_opaque", token_format="opaque", probes=_probes(rows))
    if scenario_id == "synthetic-api-key":
        rows = [_denied("missing", "/profile"), _denied("malformed", "/profile"),
                _denied("wrong_scheme", "/profile"), _denied("api_key_missing", "/profile"),
                _denied("api_key_invalid", "/profile")]
        return _plan(scenario_id, title="API-key scheme rejects missing and invalid keys",
                     scope=API_KEY_SCOPE, scheme="api_key", token_format="api_key",
                     probes=_probes(rows))
    if scenario_id == "synthetic-api-key-accepted":
        rows = [_denied("missing", "/profile"), _denied("malformed", "/profile"),
                _denied("wrong_scheme", "/profile"),
                ("api_key_missing", "/profile", 200, {"identity": ACCOUNT_A}),
                ("api_key_invalid", "/profile", 200, {"identity": ACCOUNT_A})]
        return _plan(scenario_id, title="API-key scheme accepts a missing key", scope=API_KEY_SCOPE,
                     scheme="api_key", token_format="api_key", probes=_probes(rows))
    raise KeyError("unknown offline authentication scenario")


SCENARIO_IDS = ("synthetic-jwt-secure", "synthetic-jwt-sub-confirmed",
                "synthetic-jwt-role-confirmed", "synthetic-jwt-no-observability",
                "synthetic-jwt-opaque", "synthetic-api-key", "synthetic-api-key-accepted")


def build_auth_scenario(scenario_id):
    if scenario_id not in SCENARIO_IDS:
        raise KeyError("unknown offline authentication scenario")
    return _build(scenario_id)


def _tokens(plan):
    if plan.token_format == "jwt":
        return {account: account_token(account) for account in plan.accounts}
    if plan.token_format == "api_key":
        return dict(API_KEY_TOKENS)
    return dict(OPAQUE_TOKENS)


def config_for(plan):
    """Build the validated credentials for a plan; nothing here is persisted."""
    token = account_token(plan.accounts[0])
    oauth = "Basic b2ZmbGluZTpvZmZsaW5l"
    if plan.scheme == "api_key":
        credentials = {"missing": None, "malformed": API_KEY_INVALID, "wrong_scheme": f"Bearer {API_KEY_VALID}",
                       "api_key_missing": None, "api_key_invalid": API_KEY_INVALID}
    elif plan.scheme == "bearer_opaque":
        credentials = {"missing": None, "malformed": "Bearer not-a-jwt", "wrong_scheme": oauth}
    else:
        credentials = {"missing": None, "malformed": "Bearer not-a-jwt", "wrong_scheme": oauth,
                       "jwt_sub": "Bearer " + craft_token(token, sub=ACCOUNT_B),
                       "jwt_role": "Bearer " + craft_token(token, role="admin"),
                       "alg_none": "Bearer " + craft_token(token, alg_none=True)}
        if plan.logout_path is not None:
            credentials["logout_reuse"] = "Bearer " + token
    return AuthRunnerConfig(scheme=plan.scheme, header_name=plan.api_key_header or "Authorization",
                            profile_path=plan.profile_path, logout_path=plan.logout_path,
                            credentials=credentials)


def runner_for(plan, *, budget=None):
    scope = plan.scope
    if budget is not None:
        scope = AuthorizedScope.model_validate({**scope.model_dump(), "request_budget": budget})
    return OfflineAuthRunner(scope, _tokens(plan), plan.reads, plan.probes, config=config_for(plan))
