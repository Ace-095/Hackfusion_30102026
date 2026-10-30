"""Parse a bounded local OpenAPI document; never read or fetch external refs."""
import re
from urllib.parse import unquote

import yaml

METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
MAX_SPEC_BYTES = 128 * 1024


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
        doc = yaml.safe_load(text)
    except (yaml.YAMLError, RecursionError) as exc:
        raise ValueError("invalid YAML") from exc
    if not isinstance(doc, dict) or not re.match(r"^3\.(0|1)\.\d+(?:[-+].*)?$", str(doc.get("openapi", ""))):
        raise ValueError("expected OpenAPI 3.0 or 3.1")
    doc = _resolve_local_refs(doc)
    paths = doc.get("paths")
    if not isinstance(paths, dict):
        raise ValueError("paths must be a mapping")
    inventory = []
    for path, path_item in paths.items():
        if not isinstance(path, str) or not path.startswith("/") or not isinstance(path_item, dict):
            raise ValueError("invalid path item")
        inherited_parameters = path_item.get("parameters", [])
        if not isinstance(inherited_parameters, list) or any(not isinstance(item, dict) for item in inherited_parameters):
            raise ValueError("invalid path parameters")
        for method, operation in path_item.items():
            if not isinstance(method, str):
                raise ValueError("invalid path item key")
            if method.lower() not in METHODS:
                continue
            if not isinstance(operation, dict):
                raise ValueError("invalid operation")
            parameters = operation.get("parameters", [])
            if not isinstance(parameters, list) or any(not isinstance(item, dict) for item in parameters):
                raise ValueError("invalid operation parameters")
            # Operation-level parameters with the same (name, in) override path-level ones.
            operation_keys = {(item.get("name"), item.get("in")) for item in parameters}
            merged = [item for item in inherited_parameters if (item.get("name"), item.get("in")) not in operation_keys] + parameters
            security = operation.get("security", doc.get("security", []))
            if not isinstance(security, list) or any(not isinstance(item, dict) for item in security):
                raise ValueError("invalid security declaration")
            public = not security or any(not requirement for requirement in security)
            inventory.append({"method": method.upper(), "path": path, "parameters": merged,
                              "security": security,
                              "expected_access": "public" if public else "authenticated",
                              "expected_source": "openapi.operation.security" if "security" in operation else "openapi.global.security" if "security" in doc else "openapi.default"})
    return inventory
