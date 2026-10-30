"""Bundled synthetic scenarios for the offline input-validation and disclosure flow.

Every response is a recorded local fixture. Nothing here contacts a network,
and no request body, response body or credential is persisted.
"""
from canarygate.api.schemas import InventoryEndpoint
from canarygate.scan.transcript import OfflineTranscript, TranscriptEntry
from canarygate.scan.validation_plan import ValidationPlan
from canarygate.scan.validation_runner import OfflineValidationRunner, ValidationRunnerConfig
from canarygate.scan.validation_transcript import ProbeEntry, ValidationTranscript
from canarygate.scope.authorized import AuthorizedScope

SCOPE_HOST = "offline.invalid"
SCOPE_IP = "192.0.2.10"
AUTHORIZATION_LABEL = "synthetic-offline-validation"
ACCOUNT_A = "account-a"
ACCOUNT_B = "account-b"
LOGIN_PATH = "/login"
INPUT_PROBES = ("control", "extra_property", "malformed_json", "special_characters")

# Declared request bodies. They never attempt exploitation, extraction or state damage.
REQUEST_BODIES = {
    "control": '{"username": "account-a", "password": "offline-valid-credential"}',
    "extra_property": '{"username": "account-a", "password": "offline-valid-credential", "is_admin": true}',
    "malformed_json": '{"username": "account-a", "password": ',
    "special_characters": '{"username": "account\\u0027a\\u003cb\\u003e", "password": "\\u0000null"}',
}

KNOWN = "account-a"
SENSITIVE_PATH = "/profile"
TRACE_PATH = "/errors/trace"
INTERNAL_PATH = "/errors/internal"
KNOWN_DENIED_PATH = "/accounts/account-b/profile"
UNKNOWN_DENIED_PATH = "/accounts/nobody/profile"

__all__ = ["INPUT_PROBES", "LOGIN_PATH", "REQUEST_BODIES", "SCENARIO_IDS", "build_validation_scenario",
           "config_for", "runner_for", "scope_without_input_probes"]

_CLOSED_PROFILE_SCHEMA = {"200": {"type": "object", "additionalProperties": False,
                                  "properties": {"identity": {"type": "string"}}}}


def _scope(*, input_probes, budget=24):
    return AuthorizedScope.model_validate({
        "mode": "approved_lab", "scheme": "https", "hostname": SCOPE_HOST, "port": 443,
        "organizer_ip": SCOPE_IP, "written_authorization_reference": AUTHORIZATION_LABEL,
        "allowed_methods": ["GET", "POST"], "request_budget": budget,
        "accounts": [{"account": ACCOUNT_A, "role": "user"}, {"account": ACCOUNT_B, "role": "user"}],
        "operations": [
            {"method": "POST", "path": LOGIN_PATH, "classification": "AUTHENTICATION",
             "input_probes": tuple(input_probes)},
            {"method": "GET", "path": SENSITIVE_PATH, "classification": "READ_ONLY"},
            {"method": "GET", "path": TRACE_PATH, "classification": "READ_ONLY"},
            {"method": "GET", "path": INTERNAL_PATH, "classification": "READ_ONLY"},
            {"method": "GET", "path": KNOWN_DENIED_PATH, "classification": "READ_ONLY"},
            {"method": "GET", "path": UNKNOWN_DENIED_PATH, "classification": "READ_ONLY"},
        ],
    })


VALIDATION_SCOPE = _scope(input_probes=INPUT_PROBES)


def scope_without_input_probes():
    """Same operation shape with no declared probes; used to prove fail-closed."""
    return _scope(input_probes=())


def _inventory():
    return [
        InventoryEndpoint(method="POST", path=LOGIN_PATH, parameters=[], security=[],
                          expected_access="public", expected_source="offline scenario scope"),
        InventoryEndpoint(method="GET", path=SENSITIVE_PATH, parameters=[],
                          security=[{"bearerAuth": []}], expected_access="authenticated",
                          expected_source="offline scenario scope"),
        InventoryEndpoint(method="GET", path=TRACE_PATH, parameters=[], security=[],
                          expected_access="public", expected_source="offline scenario scope"),
        InventoryEndpoint(method="GET", path=INTERNAL_PATH, parameters=[], security=[],
                          expected_access="public", expected_source="offline scenario scope"),
        InventoryEndpoint(method="GET", path=KNOWN_DENIED_PATH, parameters=[],
                          security=[{"bearerAuth": []}], expected_access="authenticated",
                          expected_source="offline scenario scope"),
        InventoryEndpoint(method="GET", path=UNKNOWN_DENIED_PATH, parameters=[],
                          security=[{"bearerAuth": []}], expected_access="public",
                          expected_source="offline scenario scope"),
    ]


def _reads(rows):
    return OfflineTranscript(entries=tuple(
        TranscriptEntry(actor=KNOWN, method="GET", path=path, status=status, body=body, headers=headers)
        for path, status, body, headers in rows))


def _probes(rows):
    return ValidationTranscript(entries=tuple(
        ProbeEntry(actor=KNOWN, method="POST", path=LOGIN_PATH, probe=probe, status=status,
                   body=body, headers=headers)
        for probe, status, body, headers in rows))


def _plan(scenario_id, title, *, reads, probes, schemas=_CLOSED_PROFILE_SCHEMA, budget=24):
    return ValidationPlan(
        scenario_id=scenario_id, title=title, scope=VALIDATION_SCOPE,
        accounts=(ACCOUNT_A, ACCOUNT_B), login_path=LOGIN_PATH,
        reads=reads, probes=probes, resource_template=SENSITIVE_PATH,
        sensitive_path=SENSITIVE_PATH, stack_trace_path=TRACE_PATH, internal_detail_path=INTERNAL_PATH,
        known_denied_path=KNOWN_DENIED_PATH, unknown_denied_path=UNKNOWN_DENIED_PATH,
        extra_property_field="is_admin", response_schemas=schemas, inventory=_inventory())


def _build(scenario_id):
    if scenario_id == "synthetic-validation-secure":
        reads = _reads([(SENSITIVE_PATH, 200, {"identity": ACCOUNT_A}, {}),
                        (TRACE_PATH, 400, {"error": "invalid request"}, {}),
                        (INTERNAL_PATH, 400, {"error": "invalid request"}, {}),
                        (KNOWN_DENIED_PATH, 403, {"error": "forbidden"}, {}),
                        (UNKNOWN_DENIED_PATH, 403, {"error": "forbidden"}, {})])
        probes = _probes([("control", 200, {"identity": ACCOUNT_A}, {}),
                          ("extra_property", 422, {"error": "unexpected property: is_admin"}, {}),
                          ("malformed_json", 422, {"error": "malformed JSON body"}, {}),
                          ("special_characters", 422, {"error": "invalid characters in username"}, {})])
        return _plan(scenario_id, "Strict validation and minimal error responses", reads=reads,
                     probes=probes)
    if scenario_id == "synthetic-validation-weak":
        reads = _reads([(SENSITIVE_PATH, 200,
                         {"identity": ACCOUNT_A, "password_hash": "synthetic-digest",
                          "session": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhY2NvdW50LWEifQ.c2lnbmF0dXJl"},
                         {"server": "fixture-server/1.4.2"}),
                        (TRACE_PATH, 500, {"error": "Traceback (most recent call last): TypeError"}, {}),
                        (INTERNAL_PATH, 400, {"error": "SQLSTATE 22P02 invalid_text_representation"}, {}),
                        (KNOWN_DENIED_PATH, 403, {"error": "account exists but is not yours"}, {}),
                        (UNKNOWN_DENIED_PATH, 404, {"error": "no such account"}, {})])
        probes = _probes([("control", 200, {"identity": ACCOUNT_A}, {}),
                          ("extra_property", 200, {"identity": ACCOUNT_A, "is_admin": True}, {}),
                          ("malformed_json", 200, {"identity": ACCOUNT_A}, {}),
                          ("special_characters", 200, {"identity": ACCOUNT_A}, {})])
        return _plan(scenario_id, "Lax validation with verbose errors and extra fields", reads=reads,
                     probes=probes)
    if scenario_id == "synthetic-validation-unobservable":
        reads = _reads([(SENSITIVE_PATH, 200, {"opaque": True}, {"x-debug-mode": "verbose"}),
                        (TRACE_PATH, 400, {"error": "invalid request"}, {}),
                        (INTERNAL_PATH, 400, {"error": "invalid request"}, {}),
                        (KNOWN_DENIED_PATH, 500, {"error": "db error"}, {}),
                        (UNKNOWN_DENIED_PATH, 500, {"error": "db error"}, {})])
        probes = _probes([("control", 401, {"error": "invalid credentials"}, {}),
                          ("extra_property", 401, {"error": "invalid credentials"}, {}),
                          ("malformed_json", 401, {"error": "invalid credentials"}, {}),
                          ("special_characters", 401, {"error": "invalid credentials"}, {})])
        return _plan(scenario_id, "Uniform rejections with unobservable semantics", reads=reads,
                     probes=probes, schemas=None)
    if scenario_id == "synthetic-validation-malformed-responses":
        nested = {"identity": ACCOUNT_A}
        for _ in range(40):
            nested = {"identity": nested}
        reads = _reads([(SENSITIVE_PATH, 200, nested, {"server": "plain"},),
                        (TRACE_PATH, 400, {"error": "invalid request"}, {}),
                        (INTERNAL_PATH, 400, {"error": "invalid request"}, {}),
                        (KNOWN_DENIED_PATH, 200, {"identity": ACCOUNT_B}, {}),
                        (UNKNOWN_DENIED_PATH, 404, {"error": "no such account"}, {})])
        probes = _probes([("control", 200, {"identity": ACCOUNT_A}, {}),
                          ("extra_property", 200, None, {}),
                          ("malformed_json", 400, {"error": "x" * 600}, {}),
                          ("special_characters", 409, {"error": "conflict"}, {})])
        return _plan(scenario_id, "Adversarial recorded responses that must not read as SAFE", reads=reads,
                     probes=probes, schemas={"200": {"type": "object",
                                                     "properties": {"identity": {"type": "string"}}}})
    raise KeyError("unknown offline validation scenario")


SCENARIO_IDS = ("synthetic-validation-secure", "synthetic-validation-weak",
                "synthetic-validation-unobservable", "synthetic-validation-malformed-responses")


def build_validation_scenario(scenario_id):
    if scenario_id not in SCENARIO_IDS:
        raise KeyError("unknown offline validation scenario")
    return _build(scenario_id)


def config_for(plan):
    """Declared request bodies for a plan; held in memory only."""
    return ValidationRunnerConfig(login_path=plan.login_path, requests=dict(REQUEST_BODIES))


def runner_for(plan, *, budget=None):
    scope = plan.scope
    if budget is not None:
        scope = AuthorizedScope.model_validate({**scope.model_dump(), "request_budget": budget})
    tokens = {ACCOUNT_A: "offline-validation-token-account-a",
              ACCOUNT_B: "offline-validation-token-account-b"}
    return OfflineValidationRunner(scope, tokens, plan.reads, plan.probes,
                                   config=ValidationRunnerConfig(login_path=plan.login_path,
                                                                 requests=dict(REQUEST_BODIES)))
