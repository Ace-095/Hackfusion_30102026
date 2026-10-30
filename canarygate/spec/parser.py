"""Parse a bounded local OpenAPI document; never read or fetch external refs."""
import json
import math
import re
from urllib.parse import unquote

import yaml

METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
MAX_SPEC_BYTES = 128 * 1024
MAX_ENDPOINTS = 1000
MAX_PARAMETERS = 200
MAX_INVENTORY_BYTES = 1024 * 1024


class _UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML with unambiguous, JSON-compatible mapping keys."""

    def construct_mapping(self, node, deep=False):
        mapping = {}
        for key_node, value_node in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                raise ValueError("YAML merge keys are not supported")
            key = self.construct_object(key_node, deep=deep)
            if type(key) is int:
                key = str(key)  # YAML response status keys such as 200.
            if not isinstance(key, str):
                raise ValueError("specification mapping keys must be strings")
            if key in mapping:
                raise ValueError("duplicate specification key")
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def _validate_json_scalars(value):
    if value is None or type(value) in (str, bool, int):
        return
    if type(value) is float and math.isfinite(value):
        return
    raise ValueError("unsupported specification scalar")


def _validate_parameters(parameters):
    if not isinstance(parameters, list) or len(parameters) > MAX_PARAMETERS:
        raise ValueError("invalid or excessive parameters")
    seen = set()
    for item in parameters:
        if not isinstance(item, dict):
            raise ValueError("invalid parameter")
        name, location = item.get("name"), item.get("in")
        if not isinstance(name, str) or not name or location not in ("query", "header", "path", "cookie"):
            raise ValueError("invalid parameter name or location")
        if "required" in item and type(item["required"]) is not bool:
            raise ValueError("invalid parameter required flag")
        if location == "path" and item.get("required") is not True:
            raise ValueError("path parameters must be required")
        key = (name, location)
        if key in seen:
            raise ValueError("duplicate parameter")
        seen.add(key)


def _validate_security(security):
    if not isinstance(security, list) or len(security) > MAX_PARAMETERS:
        raise ValueError("invalid security declaration")
    for requirement in security:
        if not isinstance(requirement, dict):
            raise ValueError("invalid security declaration")
        for name, scopes in requirement.items():
            if not name or not isinstance(scopes, list) or len(scopes) > MAX_PARAMETERS or any(not isinstance(scope, str) for scope in scopes):
                raise ValueError("invalid security requirement")


def _resolve_local_refs(doc):
    remaining = 50000

    def lookup(ref):
        if not isinstance(ref, str) or not ref.startswith("#/"):
            raise ValueError("only local JSON pointer references are supported")
        node = doc
        for encoded in ref[2:].split("/"):
            if re.search(r"%(?![0-9a-fA-F]{2})", encoded):
                raise ValueError("invalid reference encoding")
            segment = unquote(encoded, errors="strict")
            if re.search(r"~(?![01])", segment):
                raise ValueError("invalid JSON pointer escaping")
            segment = segment.replace("~1", "/").replace("~0", "~")
            if segment in {".", ".."}:
                raise ValueError("reference path traversal prohibited")
            if isinstance(node, dict) and segment in node:
                node = node[segment]
            elif isinstance(node, list) and segment.isascii() and segment.isdigit() and int(segment) < len(node):
                node = node[int(segment)]
            else:
                raise ValueError("unresolved local reference")
        return node

    def walk(node, active):
        nonlocal remaining
        remaining -= 1
        if remaining < 0:
            raise ValueError("reference expansion limit exceeded")
        if not isinstance(node, (dict, list)):
            _validate_json_scalars(node)
            return node
        if id(node) in active:
            raise ValueError("cyclic references or YAML aliases are not supported")
        active = active | {id(node)}
        if isinstance(node, list):
            return [walk(item, active) for item in node]
        if "$ref" in node:
            resolved = walk(lookup(node["$ref"]), active)
            siblings = {key: walk(value, active) for key, value in node.items() if key != "$ref"}
            if siblings:
                if not isinstance(resolved, dict):
                    raise ValueError("reference siblings require an object")
                return {**resolved, **siblings}
            return resolved
        return {key: walk(value, active) for key, value in node.items()}

    try:
        return walk(doc, set())
    except (RecursionError, UnicodeDecodeError) as exc:
        raise ValueError("invalid or deeply nested specification") from exc


def parse_inventory(text: str) -> list[dict]:
    if len(text.encode("utf-8")) > MAX_SPEC_BYTES:
        raise ValueError("specification too large")
    try:
        doc = yaml.load(text, Loader=_UniqueKeyLoader)
    except (yaml.YAMLError, RecursionError, TypeError, ValueError) as exc:
        raise ValueError("invalid YAML") from exc
    if not isinstance(doc, dict) or not re.match(r"^3\.(0|1)\.\d+(?:[-+].*)?$", str(doc.get("openapi", ""))):
        raise ValueError("expected OpenAPI 3.0 or 3.1")
    doc = _resolve_local_refs(doc)
    paths = doc.get("paths")
    if not isinstance(paths, dict):
        raise ValueError("paths must be a mapping")
    if "security" in doc:
        _validate_security(doc["security"])
    inventory = []
    for path, path_item in paths.items():
        if not isinstance(path, str) or not path.startswith("/") or not isinstance(path_item, dict):
            raise ValueError("invalid path item")
        inherited_parameters = path_item.get("parameters", [])
        _validate_parameters(inherited_parameters)
        seen_methods = set()
        for method, operation in path_item.items():
            if not isinstance(method, str):
                raise ValueError("invalid path item key")
            if method.lower() not in METHODS:
                continue
            if method.lower() in seen_methods:
                raise ValueError("duplicate operation")
            seen_methods.add(method.lower())
            if not isinstance(operation, dict):
                raise ValueError("invalid operation")
            parameters = operation.get("parameters", [])
            _validate_parameters(parameters)
            # Operation-level parameters with the same (name, in) override path-level ones.
            operation_keys = {(item.get("name"), item.get("in")) for item in parameters}
            merged = [item for item in inherited_parameters if (item.get("name"), item.get("in")) not in operation_keys] + parameters
            security = operation.get("security", doc.get("security", []))
            _validate_security(security)
            public = not security or any(not requirement for requirement in security)
            if len(inventory) >= MAX_ENDPOINTS:
                raise ValueError("too many endpoints")
            inventory.append({"method": method.upper(), "path": path, "parameters": merged,
                              "security": security,
                              "expected_access": "public" if public else "authenticated",
                              "expected_source": "openapi.operation.security" if "security" in operation else "openapi.global.security" if "security" in doc else "openapi.default"})
    # Bound serialized expansion too: a small YAML alias can repeat a large string
    # many times without exceeding the input or node limits.
    encoded_size = 0
    for chunk in json.JSONEncoder(ensure_ascii=True, separators=(",", ":")).iterencode(inventory):
        encoded_size += len(chunk)  # ensure_ascii produces one byte per character
        if encoded_size > MAX_INVENTORY_BYTES:
            raise ValueError("expanded inventory too large")
    return inventory
