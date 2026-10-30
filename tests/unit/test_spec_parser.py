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


@pytest.mark.parametrize("document", [
    'openapi: 3.0.3\nopenapi: 3.1.0\npaths: {}\n',
    'openapi: 3.0.3\npaths: {}\nsecurity: [{auth: []}, {auth: bad}]\n',
    'openapi: 3.0.3\npaths: {/x: {get: {parameters: [{name: x, in: nope}]}}}\n',
    'openapi: 3.0.3\npaths: {/x: {get: {parameters: [{name: x, in: query}, {name: x, in: query}]}}}\n',
    'openapi: 3.0.3\npaths: {"/x/{id}": {get: {parameters: [{name: id, in: path}]}}}\n',
    'openapi: 3.0.3\npaths: {}\nx-binary: !!binary SGVsbG8=\n',
    'openapi: 3.0.3\npaths: {}\nx-not-a-number: .nan\n',
    'openapi: 3.0.3\npaths: {}\nx-value: &base {a: b}\nx-other: {<<: *base}\n',
    'openapi: 3.0.3\npaths: {/x: {get: {}, GET: {}}}\n',
    'openapi: 3.0.3\npaths: {}\ncomponents: {responses: {200: {}, "200": {}}}\n',
])
def test_ambiguous_or_unsupported_documents_fail_closed(document):
    with pytest.raises(ValueError):
        parse_inventory(document)


def test_unquoted_numeric_response_codes_are_supported():
    doc = 'openapi: 3.0.3\npaths: {/x: {get: {responses: {200: {description: OK}}}}}\n'
    assert parse_inventory(doc)[0]["path"] == "/x"


def test_reference_expansion_and_endpoint_count_are_bounded():
    doc = 'openapi: 3.0.3\npaths:\n' + ''.join(f'  /p{i}: {{get: {{}}}}\n' for i in range(1001))
    with pytest.raises(ValueError, match="too many endpoints"):
        parse_inventory(doc)
    doc = 'openapi: 3.0.3\npaths: {}\nx-bomb: &base [a, a, a, a, a, a, a, a, a, a]\nx-l1: &l1 [*base, *base, *base, *base, *base, *base, *base, *base, *base, *base]\nx-l2: &l2 [*l1, *l1, *l1, *l1, *l1, *l1, *l1, *l1, *l1, *l1]\nx-l3: &l3 [*l2, *l2, *l2, *l2, *l2, *l2, *l2, *l2, *l2, *l2]\nx-l4: [*l3, *l3, *l3, *l3, *l3, *l3, *l3, *l3, *l3, *l3]\n'
    with pytest.raises(ValueError, match="expansion limit"):
        parse_inventory(doc)


def test_expanded_inventory_size_is_bounded_even_with_large_aliased_strings():
    long_value = 's' * 12000
    params = ', '.join(f'{{name: p{i}, in: query, description: *long}}' for i in range(100))
    doc = f'openapi: 3.0.3\nx-long: &long "{long_value}"\npaths: {{/x: {{get: {{parameters: [{params}]}}}}}}\n'
    with pytest.raises(ValueError, match="expanded inventory too large"):
        parse_inventory(doc)
