import httpx
import pytest


def json_response(body, status=200):
    return httpx.Response(status, json=body)


def test_sensitive_names_and_redaction_are_inspected_without_returning_values():
    from canarygate.oracles.disclosure import inspect_sensitive_json
    assert inspect_sensitive_json(json_response({"nested": [{"PASSWORD_HASH": "example-secret"}]})) == (True, True)
    assert inspect_sensitive_json(json_response({"api-key": "example-key"})) == (True, True)
    assert inspect_sensitive_json(json_response({"token": "example-token"})) == (True, True)
    assert inspect_sensitive_json(json_response({"token_count": 8, "password_hint": "words"})) == (False, True)
    for value in (None, "", "[REDACTED]", "***", "********", "[MASKED]"):
        assert inspect_sensitive_json(json_response({"password": value})) == (False, True)
    assert inspect_sensitive_json(json_response({"password": {"nested": "value"}})) == (False, False)
    assert inspect_sensitive_json(httpx.Response(200, text="not json")) == (False, False)
    assert inspect_sensitive_json(httpx.Response(200, text='{"password":"secret"}')) == (False, False)


def test_sensitive_traversal_has_bounded_depth():
    from canarygate.oracles.disclosure import inspect_sensitive_json
    body = "leaf"
    for _ in range(40):
        body = {"nested": body}
    assert inspect_sensitive_json(json_response(body)) == (False, False)


def test_top_level_schema_comparison_requires_explicit_closed_simple_contract():
    from canarygate.oracles.disclosure import inspect_extra_fields
    schema = {"200": {"type": "object", "additionalProperties": False, "properties": {"results": {"type": "array"}}}}
    assert inspect_extra_fields(json_response({"results": []}), schema) == (False, True)
    assert inspect_extra_fields(json_response({"results": [], "unexpected": "sensitive"}), schema) == (True, True)
    assert inspect_extra_fields(json_response({"results": []}, status=500), schema) == (False, False)
    assert inspect_extra_fields(json_response([]), schema) == (False, False)
    assert inspect_extra_fields(httpx.Response(200, text="not-json"), schema) == (False, False)
    for invalid in ({}, {"200": {"type": "object", "properties": {}}},
                    {"200": {"type": "object", "additionalProperties": True, "properties": {}}},
                    {"200": {"type": "object", "additionalProperties": False, "properties": {}, "patternProperties": {"^x": {}}}},
                    {"200": {"type": "object", "additionalProperties": False, "properties": {}, "allOf": []}}):
        assert inspect_extra_fields(json_response({"x": 1}), invalid) == (False, False)
