import pytest

from canarygate.spec.parser import parse_inventory


def test_security_inheritance_and_overrides():
    text = '''
openapi: 3.1.0
security: [{bearer: []}]
paths:
  /a:
    get: {responses: {}}
    post: {security: [], responses: {}}
  /b:
    get: {security: [{}, {bearer: []}], responses: {}}
'''
    entries = parse_inventory(text)
    assert [(e["expected_access"], e["expected_source"]) for e in entries] == [
        ("authenticated", "openapi.global.security"),
        ("public", "openapi.operation.security"),
        ("public", "openapi.operation.security"),
    ]


def test_local_reference_resolution_and_parameter_override():
    text = '''
openapi: 3.0.3
paths:
  /items/{id}:
    parameters: [{$ref: '#/components/parameters/id'}]
    get:
      parameters: [{name: id, in: path, required: true, description: operation override}]
      responses: {}
  /other/{id}:
    get:
      parameters: [{$ref: '#/components/parameters/id'}]
      responses: {}
components:
  parameters:
    id: {name: id, in: path, required: true}
'''
    entries = parse_inventory(text)
    assert len(entries[0]["parameters"]) == 1
    assert entries[0]["parameters"][0]["description"] == "operation override"
    assert entries[1]["parameters"] == [{"name": "id", "in": "path", "required": True}]


@pytest.mark.parametrize("reference", ["https://attacker.invalid/spec.yaml", "file:///etc/passwd", "../local.yaml", "#/components/../paths", "#/components/missing"])
def test_unsafe_or_unresolved_references_are_rejected(reference):
    text = f'openapi: 3.0.0\npaths: {{}}\ncomponents:\n  schemas:\n    Thing: {{$ref: "{reference}"}}\n'
    with pytest.raises(ValueError):
        parse_inventory(text)


def test_unsafe_yaml_and_oversize_are_rejected():
    with pytest.raises(ValueError):
        parse_inventory('!!python/object/apply:os.system ["echo unsafe"]')
    with pytest.raises(ValueError, match="too large"):
        parse_inventory("a" * (128 * 1024 + 1))


def test_cyclic_yaml_alias_is_rejected():
    document = 'openapi: 3.0.3\npaths: {}\nx-cycle: &cycle [*cycle]\n'
    with pytest.raises(ValueError, match="cyclic"):
        parse_inventory(document)


def test_cyclic_local_refs_are_rejected():
    document = 'openapi: 3.0.3\npaths: {}\ncomponents:\n  schemas:\n    A: {$ref: "#/components/schemas/A"}\n'
    with pytest.raises(ValueError, match="cyclic"):
        parse_inventory(document)
