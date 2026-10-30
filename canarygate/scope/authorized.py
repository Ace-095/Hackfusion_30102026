"""Validate organizer scope data without resolving hosts or enabling traffic.

This is a provisional backend contract, not a live request guard or a proof that
an approval reference is genuine. The fixture scanner never reads this scope.
"""
import ipaddress
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
import yaml
from yaml.tokens import AliasToken, AnchorToken

from canarygate.models.scope import ScopeConfig

MAX_SCOPE_BYTES = 64 * 1024
# The single loopback destination permitted by the local_lab mode.
TARGETLAB_HOST = "127.0.0.1"
# Fixed allow-list of TargetLab routes. This is a constant, never configuration:
# a local_lab scope cannot widen beyond these exact paths. The lab's
# /lab/ground-truth route is deliberately absent so a scanner can never read the
# answers it is being scored against.
TARGETLAB_OPERATIONS = {
    ("GET", "/health"): "READ_ONLY",
    ("GET", "/profile"): "READ_ONLY",
    ("GET", "/admin/users"): "READ_ONLY",
    ("GET", "/records"): "READ_ONLY",
    ("GET", "/records/ra"): "READ_ONLY",
    ("GET", "/records/rb"): "READ_ONLY",
    ("GET", "/records/ra/secure"): "READ_ONLY",
    ("GET", "/records/rb/secure"): "READ_ONLY",
    ("GET", "/records/ra/guarded"): "READ_ONLY",
    ("GET", "/records/rb/guarded"): "READ_ONLY",
    ("GET", "/diagnostics/banner"): "READ_ONLY",
    ("GET", "/errors/trace"): "READ_ONLY",
    ("POST", "/login"): "AUTHENTICATION",
}
AUTH_PROBE_NAMES = ("missing", "malformed", "wrong_scheme", "jwt_sub", "jwt_role",
                    "alg_none", "api_key_missing", "api_key_invalid", "logout_reuse")
AuthProbeName = Literal["missing", "malformed", "wrong_scheme", "jwt_sub", "jwt_role",
                        "alg_none", "api_key_missing", "api_key_invalid", "logout_reuse"]
# ``wrong_password`` is the one probe TargetLab needs: a well-formed login body
# carrying a wrong password. A broken-JSON body never reaches the lab's account
# state machine, so it cannot exercise the declared interaction.
INPUT_PROBE_NAMES = ("control", "extra_property", "malformed_json", "special_characters",
                     "wrong_password")
InputProbeName = Literal["control", "extra_property", "malformed_json", "special_characters",
                         "wrong_password"]


class _ScopeLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                raise ValueError("scope merge keys are not permitted")
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise ValueError("scope mapping keys must be unique strings")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def _unicast_ip(value: str) -> str:
    if "%" in value:
        raise ValueError("IP zone identifiers are not permitted")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("address must be a single literal IP") from exc
    effective = address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped else address
    if effective.is_unspecified or effective.is_multicast or str(effective) == "255.255.255.255":
        raise ValueError("non-unicast destinations are not supported")
    return str(address)


def _reference(value: str) -> str:
    if not value or value != value.strip() or not value.isprintable() or len(value) > 256:
        raise ValueError("invalid written authorization reference")
    return value


class AuthorizedAccount(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    account: str = Field(pattern=r"^[A-Za-z0-9_.@-]{1,128}$")
    role: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,64}$")


class AuthorizedOperation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    method: str = Field(pattern=r"^[A-Z]{1,16}$")
    path: str
    classification: Literal["READ_ONLY", "AUTHENTICATION", "STATE_CHANGING", "DESTRUCTIVE"]
    creation_authorization_reference: str | None = None
    # Crafted-credential probes run only where the written scope permits them.
    auth_probes: tuple[AuthProbeName, ...] = ()
    # Body-carrying validation probes are permitted only on the exact
    # authentication POST, each at most once, where the scope declares them.
    input_probes: tuple[InputProbeName, ...] = ()

    @field_validator("path")
    @classmethod
    def exact_path(cls, value):
        if (not re.fullmatch(r"/[A-Za-z0-9_./~-]{0,511}", value) or "//" in value
                or any(part in {".", ".."} for part in value.split("/"))):
            raise ValueError("operation path must be exact and unencoded")
        return value

    @field_validator("creation_authorization_reference")
    @classmethod
    def valid_creation_reference(cls, value):
        return None if value is None else _reference(value)

    @model_validator(mode="after")
    def classification_rules(self):
        if self.classification == "READ_ONLY" and self.method not in {"GET", "HEAD", "OPTIONS"}:
            raise ValueError("read-only classification conflicts with method")
        if self.auth_probes:
            if self.method != "GET" or self.classification != "READ_ONLY":
                raise ValueError("authentication probes require an exact read-only GET operation")
            if len(set(self.auth_probes)) != len(self.auth_probes):
                raise ValueError("duplicate authentication probe")
        if self.input_probes:
            if self.method != "POST" or self.classification != "AUTHENTICATION":
                raise ValueError("input probes require the exact authentication POST operation")
            if len(set(self.input_probes)) != len(self.input_probes):
                raise ValueError("duplicate input probe")
        if self.classification == "AUTHENTICATION" and self.method != "POST":
            raise ValueError("only an exact POST login can be classified as authentication")
        if self.classification == "STATE_CHANGING":
            if self.method != "POST" or self.creation_authorization_reference is None:
                raise ValueError("resource creation requires exact POST and written authorization")
        elif self.creation_authorization_reference is not None:
            raise ValueError("creation authorization is only valid for state-changing operations")
        return self


class AuthorizedScope(ScopeConfig):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    mode: Literal["competition", "approved_lab", "local_lab"]
    allowed_methods: tuple[str, ...] = Field(min_length=1, max_length=16)
    request_budget: int = Field(gt=0, le=100000)
    written_authorization_reference: str
    organizer_ip: str | None = None
    approved_resolver: Literal["organizer_approved_system"] | None = None
    accounts: tuple[AuthorizedAccount, ...] = Field(min_length=1, max_length=64)
    operations: tuple[AuthorizedOperation, ...] = Field(min_length=1, max_length=512)

    @model_validator(mode="before")
    @classmethod
    def freeze_yaml_sequences(cls, value):
        if isinstance(value, dict):
            value = dict(value)
            for field in ("allowed_methods", "accounts", "operations"):
                if isinstance(value.get(field), list):
                    value[field] = tuple(value[field])
            operations = []
            for operation in value.get("operations") or ():
                if isinstance(operation, dict):
                    for field_name in ("auth_probes", "input_probes"):
                        if isinstance(operation.get(field_name), list):
                            operation = {**operation, field_name: tuple(operation[field_name])}
                operations.append(operation)
            if operations:
                value["operations"] = tuple(operations)
        return value

    @field_validator("hostname")
    @classmethod
    def canonical_hostname(cls, value):
        if "%" in value or value.endswith("."):
            raise ValueError("scoped or trailing-dot hostnames are not permitted")
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return value.encode("idna").decode("ascii").lower()
        return _unicast_ip(value)

    @field_validator("written_authorization_reference")
    @classmethod
    def valid_reference(cls, value):
        return _reference(value)

    @field_validator("organizer_ip")
    @classmethod
    def exact_ip(cls, value):
        if value is None:
            return None
        return _unicast_ip(value)

    @model_validator(mode="after")
    def coherent_scope(self):
        if self.organizer_ip is None and self.approved_resolver is None:
            raise ValueError("organizer IP or explicitly approved resolver is required")
        if len(set(self.allowed_methods)) != len(self.allowed_methods):
            raise ValueError("duplicate allowed method")
        names = [item.account for item in self.accounts]
        if len(set(names)) != len(names):
            raise ValueError("duplicate account")
        keys = [(item.method, item.path) for item in self.operations]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate operation")
        if any(item.method not in self.allowed_methods for item in self.operations):
            raise ValueError("operation method not in scope allowlist")
        if sum(item.classification == "AUTHENTICATION" for item in self.operations) > 1:
            raise ValueError("only one exact authentication operation is permitted")
        try:
            literal_host = ipaddress.ip_address(self.hostname)
        except ValueError:
            literal_host = None
        if literal_host is not None and self.organizer_ip is not None and literal_host != ipaddress.ip_address(self.organizer_ip):
            raise ValueError("literal host conflicts with organizer IP")
        if self.mode == "local_lab":
            self._validate_local_lab()
        else:
            # TargetLab mode must be explicitly selected. A competition or
            # approved-lab scope can never point at loopback, so a lab target
            # cannot be reached by accident through another mode.
            if self.hostname == TARGETLAB_HOST or self.organizer_ip == TARGETLAB_HOST:
                raise ValueError("loopback destinations require local_lab mode")
        return self

    def _validate_local_lab(self):
        if self.hostname != TARGETLAB_HOST or self.organizer_ip != TARGETLAB_HOST:
            raise ValueError("local_lab requires the exact loopback destination 127.0.0.1")
        if self.scheme != "https":
            raise ValueError("local_lab requires https")
        if self.approved_resolver is not None:
            raise ValueError("local_lab never resolves hostnames")
        for operation in self.operations:
            expected = TARGETLAB_OPERATIONS.get((operation.method, operation.path))
            if expected is None:
                raise ValueError("operation is not a declared TargetLab route")
            if expected != operation.classification:
                raise ValueError("TargetLab route classification does not match its declared class")

    @property
    def origin(self):
        host = f"[{self.hostname}]" if ":" in self.hostname else self.hostname
        return f"{self.scheme}://{host}:{self.port}"


def load_authorized_scope(text: str) -> AuthorizedScope:
    """Validate a bounded YAML string. Does not perform IO, DNS or requests."""
    if not isinstance(text, str) or len(text.encode("utf-8")) > MAX_SCOPE_BYTES:
        raise ValueError("scope is too large or invalid")
    try:
        if any(isinstance(token, (AliasToken, AnchorToken)) for token in yaml.scan(text)):
            raise ValueError("scope aliases and anchors are not permitted")
        data = yaml.load(text, Loader=_ScopeLoader)
        if not isinstance(data, dict):
            raise ValueError("scope must be a mapping")
        return AuthorizedScope.model_validate(data)
    except (yaml.YAMLError, TypeError, ValueError, RecursionError) as exc:
        raise ValueError("invalid or unsupported organizer scope") from exc
