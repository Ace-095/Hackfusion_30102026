"""Bundled synthetic SCI scenarios: interactions executed through the application.

Every scenario is a deterministic local recording. The individual baselines and
the combined exchange go through the same guarded offline runner; nothing here
is a live target, a lab instance or an organizer approval.
"""
from canarygate.api.schemas import InventoryEndpoint
from canarygate.scan.auth_plan import AuthenticationPlan
from canarygate.scan.auth_runner import AuthRunnerConfig, OfflineAuthRunner
from canarygate.scan.auth_transcript import AuthenticationTranscript, AuthTranscriptEntry
from canarygate.scan.interaction_plan import BaselineAction, CombinedAction, InteractionPlan
from canarygate.scan.interaction_runner import OfflineInteractionRunner
from canarygate.scan.interaction_transcript import CombinedReadEntry, InteractionTranscript
from canarygate.scan.transcript import OfflineTranscript, TranscriptEntry
from canarygate.scan.validation_plan import ValidationPlan
from canarygate.scan.validation_runner import OfflineValidationRunner, ValidationRunnerConfig
from canarygate.scan.validation_transcript import ProbeEntry, ValidationTranscript
from canarygate.scope.authorized import AuthorizedScope

SCOPE_HOST = "offline.invalid"
SCOPE_IP = "192.0.2.11"
AUTHORIZATION_LABEL = "synthetic-sci-scenario"
ACCOUNT_A, ACCOUNT_B = "account-a", "account-b"
TOKENS = {ACCOUNT_A: "offline-sci-token-account-a", ACCOUNT_B: "offline-sci-token-account-b"}
LOGIN_PATH = "/login"
PROFILE_PATH = "/profile"
AUTHZ_PATH = "/records/rb"
ADMIN_PATH = "/admin/users"
TRACE_PATH = "/errors/trace"
BETA_PRIVATE = "synthetic-beta-private"
SCI_SECRET = "sci-interaction-secret-value"
DENIAL = {"error": "forbidden"}
INPUT_PROBES = ("control", "extra_property", "malformed_json", "special_characters")
REQUEST_BODIES = {
    "control": '{"username": "account-a", "password": "offline-valid-credential"}',
    "extra_property": '{"username": "account-a", "password": "offline-valid-credential", '
                      '"is_admin": true}',
    "malformed_json": '{"username": "account-a", "password": ',
    "special_characters": '{"username": "account\\u0027a\\u003cb\\u003e", '
                          '"password": "\\u0000null"}',
}
ALG_NONE = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhY2NvdW50LWEifQ."
SCENARIO_IDS = (
    "synthetic-sci-authz-input-confirmed",
    "synthetic-sci-authz-input-secure",
    "synthetic-sci-individual-failure",
    "synthetic-sci-incomplete-baseline",
    "synthetic-sci-unpermitted",
    "synthetic-sci-budget-exhausted",
    "synthetic-sci-secret-redaction",
    "synthetic-sci-variation",
    "synthetic-sci-authn-authz",
    "synthetic-sci-input-disclosure",
)
DEFAULT_SCENARIO = "synthetic-sci-authz-input-confirmed"


def _scope(budget, *, include_admin=True, auth_probes=()):
    operations = [
        {"method": "GET", "path": PROFILE_PATH, "classification": "READ_ONLY",
         **({"auth_probes": list(auth_probes)} if auth_probes else {})},
        {"method": "GET", "path": AUTHZ_PATH, "classification": "READ_ONLY",
         **({"auth_probes": list(auth_probes)} if auth_probes else {})},
        {"method": "GET", "path": TRACE_PATH, "classification": "READ_ONLY"},
        {"method": "POST", "path": LOGIN_PATH, "classification": "AUTHENTICATION",
         "input_probes": list(INPUT_PROBES)},
    ]
    if include_admin:
        operations.append({"method": "GET", "path": ADMIN_PATH, "classification": "READ_ONLY"})
    return AuthorizedScope.model_validate({
        "mode": "approved_lab", "scheme": "https", "hostname": SCOPE_HOST, "port": 443,
        "organizer_ip": SCOPE_IP, "written_authorization_reference": AUTHORIZATION_LABEL,
        "allowed_methods": ["GET", "POST"], "request_budget": budget,
        "accounts": [{"account": ACCOUNT_A, "role": "user"},
                     {"account": ACCOUNT_B, "role": "user"}],
        "operations": operations,
    })


def _inventory(*, include_admin=True):
    entries = [
        InventoryEndpoint(method="GET", path=PROFILE_PATH, parameters=[],
                          security=[{"bearerAuth": []}], expected_access="authenticated",
                          expected_source="offline SCI scenario scope"),
        InventoryEndpoint(method="GET", path=AUTHZ_PATH, parameters=[],
                          security=[{"bearerAuth": []}], expected_access="owner-only",
                          expected_source="offline SCI scenario scope"),
        InventoryEndpoint(method="GET", path=TRACE_PATH, parameters=[],
                          security=[{"bearerAuth": []}], expected_access="authenticated",
                          expected_source="offline SCI scenario scope"),
        InventoryEndpoint(method="POST", path=LOGIN_PATH, parameters=[],
                          security=[], expected_access="public",
                          expected_source="offline SCI scenario scope"),
    ]
    if include_admin:
        entries.append(InventoryEndpoint(method="GET", path=ADMIN_PATH, parameters=[],
                                         security=[{"bearerAuth": []}], expected_access="role:admin",
                                         expected_source="offline SCI scenario scope"))
    return entries


AUTHZ_BASELINE = BaselineAction(
    id="AUTHZ-01", control="Authorization", action="get", path=AUTHZ_PATH,
    expectation="another account's private record is denied")
INPUT_BASELINE = BaselineAction(
    id="INPUT-07", control="Input validation", action="submit", path=LOGIN_PATH,
    probe="special_characters",
    expectation="hostile characters are rejected with a bounded error")
AUTHN_BASELINE = BaselineAction(
    id="AUTHN-05", control="Authentication", action="auth_probe", path=PROFILE_PATH,
    probe="alg_none", expectation="an unsigned alg:none token is rejected")
INPUT_JSON_BASELINE = BaselineAction(
    id="INPUT-06", control="Input validation", action="submit", path=LOGIN_PATH,
    probe="malformed_json", expectation="a malformed JSON body is rejected with a bounded error")
DISCLOSURE_BASELINE = BaselineAction(
    id="DISC-01", control="Information disclosure", action="get", path=TRACE_PATH,
    expectation="no stack trace or framework error text is returned")

_KIND1_PROBES = (
    ProbeEntry(actor=ACCOUNT_A, method="POST", path=LOGIN_PATH, probe="control",
               status=200, body={"identity": ACCOUNT_A}),
    ProbeEntry(actor=ACCOUNT_A, method="POST", path=LOGIN_PATH, probe="special_characters",
               status=422, body={"error": "invalid characters in username"}),
    ProbeEntry(actor=ACCOUNT_A, method="POST", path=LOGIN_PATH, probe="extra_property",
               status=200, body={"identity": ACCOUNT_A}),
    ProbeEntry(actor=ACCOUNT_A, method="POST", path=LOGIN_PATH, probe="malformed_json",
               status=400, body={"error": "malformed JSON body"}),
)


def _kind1_plan(scenario_id, title, *, budget=12, authz_status=403, authz_body=None,
                combined_status=200, combined_body=None, include_admin=True,
                combined_entry=True):
    reads = (TranscriptEntry(actor=ACCOUNT_A, method="GET", path=AUTHZ_PATH,
                             status=authz_status, body=authz_body),)
    combined_entries = ()
    if combined_entry:
        combined_entries = (CombinedReadEntry(actor=ACCOUNT_A, method="GET", path=ADMIN_PATH,
                                              probe="extra_property", status=combined_status,
                                              body=combined_body),)
    return InteractionPlan(
        scenario_id=scenario_id, title=title, kind="AUTHZ+INPUT_VALIDATION",
        scope=_scope(budget, include_admin=include_admin), accounts=(ACCOUNT_A, ACCOUNT_B),
        login_path=LOGIN_PATH,
        baselines=(AUTHZ_BASELINE, INPUT_BASELINE),
        combined=CombinedAction(action="get_after", path=ADMIN_PATH, probe="extra_property",
                                expected_access="role:admin",
                                expected_source="offline SCI scenario scope",
                                impact={"field": "role", "equals": "admin"}),
        reads=OfflineTranscript(entries=reads),
        probes=ValidationTranscript(entries=_KIND1_PROBES),
        combined_reads=InteractionTranscript(entries=combined_entries),
        request_bodies=dict(REQUEST_BODIES), denial_body=dict(DENIAL),
        private_marker_field="secret", extra_property_field="is_admin",
        inventory=_inventory(include_admin=include_admin))


def _kind2_plan(scenario_id="synthetic-sci-authn-authz"):
    return InteractionPlan(
        scenario_id=scenario_id,
        title="Unsigned token rejected at the profile route but honoured on a resource route",
        kind="AUTHN+AUTHZ",
        scope=_scope(12, auth_probes=("alg_none",)), accounts=(ACCOUNT_A, ACCOUNT_B),
        login_path=LOGIN_PATH,
        baselines=(AUTHN_BASELINE, AUTHZ_BASELINE),
        combined=CombinedAction(action="auth_probe", path=AUTHZ_PATH, probe="alg_none",
                                expected_access="owner-only",
                                expected_source="offline SCI scenario scope",
                                impact={"field": "secret", "present": True}),
        reads=OfflineTranscript(entries=(
            TranscriptEntry(actor=ACCOUNT_A, method="GET", path=AUTHZ_PATH,
                            status=403, body=DENIAL),)),
        auth_probes=AuthenticationTranscript(entries=(
            AuthTranscriptEntry(actor=ACCOUNT_A, method="GET", path=PROFILE_PATH,
                                probe="alg_none", status=401, body={"error": "invalid token"}),
            AuthTranscriptEntry(actor=ACCOUNT_A, method="GET", path=AUTHZ_PATH,
                                probe="alg_none", status=200,
                                body={"id": "rb", "owner": ACCOUNT_B, "secret": BETA_PRIVATE}),
        )),
        combined_reads=InteractionTranscript(entries=()),
        auth_config={"scheme": "bearer_jwt", "header_name": "Authorization",
                     "profile_path": PROFILE_PATH, "logout_path": None,
                     "credentials": {"alg_none": ALG_NONE}},
        denial_body={"error": "invalid token"}, private_marker_field="secret",
        inventory=_inventory())


def _kind3_plan(scenario_id="synthetic-sci-input-disclosure"):
    return InteractionPlan(
        scenario_id=scenario_id,
        title="Validation error path returns framework internals the disclosure baseline missed",
        kind="INPUT_VALIDATION+INFORMATION_DISCLOSURE",
        scope=_scope(12, include_admin=False), accounts=(ACCOUNT_A, ACCOUNT_B),
        login_path=LOGIN_PATH,
        baselines=(INPUT_JSON_BASELINE, DISCLOSURE_BASELINE),
        combined=CombinedAction(action="submit", path=LOGIN_PATH, probe="extra_property",
                                expected_access="reject unexpected properties",
                                expected_source="offline SCI scenario scope",
                                impact={"signal": "stack_trace"}),
        reads=OfflineTranscript(entries=(
            TranscriptEntry(actor=ACCOUNT_A, method="GET", path=TRACE_PATH,
                            status=400, body={"error": "invalid request"}),)),
        probes=ValidationTranscript(entries=(
            ProbeEntry(actor=ACCOUNT_A, method="POST", path=LOGIN_PATH, probe="control",
                       status=200, body={"identity": ACCOUNT_A}),
            ProbeEntry(actor=ACCOUNT_A, method="POST", path=LOGIN_PATH, probe="malformed_json",
                       status=400, body={"error": "malformed JSON body"}),
            ProbeEntry(actor=ACCOUNT_A, method="POST", path=LOGIN_PATH, probe="extra_property",
                       status=400,
                       body={"error": "unexpected property: is_admin",
                             "detail": "Traceback (most recent call last): TypeError"}),
        )),
        combined_reads=InteractionTranscript(entries=()),
        request_bodies=dict(REQUEST_BODIES), denial_body=dict(DENIAL),
        extra_property_field="is_admin", disclosure_signal="stack_trace",
        inventory=_inventory(include_admin=False))


ADMIN_LEAK = {"users": [{"account": ACCOUNT_B, "email": "account-b@example.invalid"}],
              "role": "admin"}
SECRET_LEAK = {"users": [{"account": ACCOUNT_B, "email": SCI_SECRET}], "role": "admin"}


def build_interaction_scenario(scenario_id):
    """Return a validated plan for a known synthetic SCI scenario id."""
    if scenario_id == "synthetic-sci-authz-input-confirmed":
        return _kind1_plan(scenario_id, "Accepted unexpected property reaches an admin route",
                           combined_body=ADMIN_LEAK)
    if scenario_id == "synthetic-sci-authz-input-secure":
        return _kind1_plan(scenario_id, "Both controls hold under the combined exchange",
                           combined_status=403, combined_body=DENIAL)
    if scenario_id == "synthetic-sci-individual-failure":
        return _kind1_plan(scenario_id, "Authorization already fails on its own",
                           authz_status=200,
                           authz_body={"id": "rb", "owner": ACCOUNT_B, "secret": BETA_PRIVATE},
                           combined_body=ADMIN_LEAK)
    if scenario_id == "synthetic-sci-incomplete-baseline":
        return _kind1_plan(scenario_id, "Authorization baseline was not observable",
                           authz_status=404, authz_body={"error": "not found"},
                           combined_body=ADMIN_LEAK)
    if scenario_id == "synthetic-sci-unpermitted":
        return _kind1_plan(scenario_id, "Combined read is outside the authorized scope",
                           include_admin=False, combined_entry=False)
    if scenario_id == "synthetic-sci-budget-exhausted":
        return _kind1_plan(scenario_id, "Budget exhausted before the combined exchange",
                           budget=2, combined_body=ADMIN_LEAK)
    if scenario_id == "synthetic-sci-secret-redaction":
        return _kind1_plan(scenario_id, "Combined response carries a private value",
                           combined_body=SECRET_LEAK)
    if scenario_id == "synthetic-sci-variation":
        return _kind1_plan(scenario_id, "Combined response varies without security impact",
                           combined_status=200,
                           combined_body={"status": "ok", "role": "user"})
    if scenario_id == "synthetic-sci-authn-authz":
        return _kind2_plan()
    if scenario_id == "synthetic-sci-input-disclosure":
        return _kind3_plan()
    raise KeyError("unknown SCI scenario")


def runner_for(plan, *, budget=None):
    scope = plan.scope
    if budget is not None:
        scope = AuthorizedScope.model_validate({**scope.model_dump(), "request_budget": budget})
    if plan.runner == "interaction":
        return OfflineInteractionRunner(
            scope, TOKENS, plan.reads, plan.probes, plan.combined_reads,
            config=ValidationRunnerConfig(login_path=plan.login_path,
                                          requests=dict(plan.request_bodies)))
    if plan.runner == "auth":
        return OfflineAuthRunner(scope, TOKENS, plan.reads, plan.auth_probes,
                                 config=AuthRunnerConfig(**plan.auth_config))
    return OfflineValidationRunner(
        scope, TOKENS, plan.reads, plan.probes,
        config=ValidationRunnerConfig(login_path=plan.login_path,
                                      requests=dict(plan.request_bodies)))
