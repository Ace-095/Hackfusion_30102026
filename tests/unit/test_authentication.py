import base64
import json

import pytest

from canarygate.oracles.authentication import is_supported_jwt
from canarygate.offline.auth_checks import JWT_REASON, pending_checks


def segment(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def test_jwt_detection_requires_json_objects_and_alg_header():
    token = segment({"alg": "HS256"}) + "." + segment({"sub": "alice"}) + ".not-verified"
    assert is_supported_jwt(token)
    assert not is_supported_jwt("opaque.with.dots")
    assert not is_supported_jwt(segment({"typ": "JWT"}) + "." + segment({"sub": "alice"}) + ".sig")
    assert not is_supported_jwt(segment({"alg": "none"}) + "." + segment(["not", "an", "object"]) + ".")
    assert not is_supported_jwt("a" * 8193)
    # Detection alone does not authorize or produce a SAFE verdict.
    jwt_checks = {c["id"]: c for c in pending_checks(token=token)}
    assert jwt_checks["AUTHN-04a"]["verdict"] == "SKIPPED"
    assert "not implemented" in jwt_checks["AUTHN-04a"]["reason"]
    opaque_checks = {c["id"]: c for c in pending_checks(token="opaque.with.dots")}
    assert opaque_checks["AUTHN-05"]["verdict"] == "SKIPPED"
    assert opaque_checks["AUTHN-05"]["reason"] == JWT_REASON


def test_public_id_or_empty_response_never_proves_an_authentication_bypass():
    from canarygate.oracles.authentication import auth_verdict
    assert auth_verdict(200, {"id": "alice-item"}, private_field="id", baseline="alice-item")[0] == "INCONCLUSIVE"
    assert auth_verdict(200, {}, private_field="private_note", baseline="private")[0] == "INCONCLUSIVE"
    assert auth_verdict(403, {}, private_field="private_note", baseline="private")[0] == "SAFE"
