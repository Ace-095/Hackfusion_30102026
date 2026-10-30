import hashlib
import json
import socket

import pytest
from fastapi.testclient import TestClient

from canarygate.api.app import create_app
from canarygate.spec.parser import MAX_SPEC_BYTES

SPEC = b'''openapi: 3.0.3
info: {title: Synthetic upload, version: '1.0'}
servers: [{url: 'https://must-not-be-contacted.invalid'}]
security: [{bearer: []}]
paths:
  /widgets/{id}:
    parameters: [{$ref: '#/components/parameters/identifier'}]
    get: {responses: {200: {description: OK}}}
    delete: {security: [], responses: {204: {description: OK}}}
components:
  parameters:
    identifier: {name: id, in: path, required: true, schema: {type: string}}
  securitySchemes:
    bearer: {type: http, scheme: bearer}
'''


def test_inspection_is_in_memory_and_does_not_alter_fixture_or_access_network(tmp_path, monkeypatch):
    db = tmp_path / 'fixture.sqlite3'
    def forbidden(*args, **kwargs):
        raise AssertionError('network or DNS used')
    with TestClient(create_app(db)) as client:
        # After TestClient starts: Windows asyncio internally uses a socketpair.
        with monkeypatch.context() as isolated:
            isolated.setattr(socket.socket, 'connect', forbidden)
            isolated.setattr(socket, 'getaddrinfo', forbidden)
            response = client.post('/api/spec/upload', content=SPEC, headers={'content-type': 'application/yaml'})
            assert response.status_code == 200
            result = response.json()
            assert result['mode'] == 'inventory_only' and result['live_scanning'] is False
            assert result['sha256'] == hashlib.sha256(SPEC).hexdigest() and result['endpoint_count'] == 2
            assert [(ep['method'], ep['path'], ep['expected_access']) for ep in result['endpoints']] == [
                ('GET', '/widgets/{id}', 'authenticated'), ('DELETE', '/widgets/{id}', 'public')]
            assert result['endpoints'][0]['parameters'][0]['name'] == 'id'
            assert 'not saved or used by fixture scans' in result['message']
            fixture_inventory = client.get('/api/endpoints').json()
            assert fixture_inventory['mode'] == 'fixture'
            assert all(ep['path'] != '/widgets/{id}' for ep in fixture_inventory['endpoints'])
            scan = client.post('/api/scan').json()
            assert scan['mode'] == 'fixture' and scan['verdict'] == 'CONFIRMED'
            assert all(ep['path'] != '/widgets/{id}' for ep in scan['inventory'])
            assert scan['constraints']['network_transport_enabled'] is False
    assert b'must-not-be-contacted.invalid' not in db.read_bytes()
    assert b'/widgets/{id}' not in db.read_bytes()
    with TestClient(create_app(db)) as client:
        assert client.get('/api/endpoints').json() == fixture_inventory


def test_raw_json_and_utf8_bom_are_supported(tmp_path):
    spec = {'openapi': '3.1.0', 'paths': {'/health': {'get': {'security': []}}}}
    body = b'\xef\xbb\xbf' + json.dumps(spec).encode()
    with TestClient(create_app(tmp_path / 'fixture.sqlite3')) as client:
        result = client.post('/api/spec/upload', content=body, headers={'content-type': 'application/json; charset=utf-8'}).json()
    assert result['sha256'] == hashlib.sha256(body).hexdigest()
    assert result['endpoints'][0]['expected_access'] == 'public'


@pytest.mark.parametrize('body', [
    b'not an openapi document',
    b'\xff\xfe\x00',
    b'openapi: 3.0.3\npaths: {}\ncomponents: {schemas: {X: {$ref: "https://attacker.invalid/x"}}}\n',
    b'openapi: 3.0.3\npaths: {}\ncomponents: {schemas: {X: {$ref: "file:///etc/passwd"}}}\n',
    b'openapi: 3.0.3\npaths: {}\nx: &loop [*loop]\n',
    b'openapi: 3.0.3\npaths: {}\nsecurity: [{bearer: bad}]\n',
    b'!!python/object/apply:os.system ["echo unsafe"]',
])
def test_bad_specifications_receive_generic_422(tmp_path, body):
    with TestClient(create_app(tmp_path / 'fixture.sqlite3')) as client:
        result = client.post('/api/spec/upload', content=body, headers={'content-type': 'text/plain'})
    assert result.status_code == 422
    assert result.json() == {'detail': 'Invalid or unsupported OpenAPI specification'}


def test_size_and_media_types_are_checked_even_for_streamed_body(tmp_path):
    with TestClient(create_app(tmp_path / 'fixture.sqlite3')) as client:
        assert client.post('/api/spec/upload', content=SPEC).status_code == 415
        assert client.post('/api/spec/upload', content=SPEC, headers={'content-type': 'multipart/form-data'}).status_code == 415
        assert client.post('/api/spec/upload', content=SPEC, headers={'content-type': 'application/json', 'content-encoding': 'gzip'}).status_code == 415
        assert client.post('/api/spec/upload', content=SPEC, headers={'content-type': 'text/plain', 'content-length': str(MAX_SPEC_BYTES + 1)}).status_code == 413
        assert client.post('/api/spec/upload', content=SPEC, headers={'content-type': 'text/plain', 'content-length': '9' * 5000}).status_code == 413
        stream = (b'a' * 8192 for _ in range(17))
        assert client.post('/api/spec/upload', content=stream, headers={'content-type': 'text/plain'}).status_code == 413
        assert client.post('/api/spec/upload', content=SPEC, headers={'content-type': 'text/plain'}).status_code == 200
