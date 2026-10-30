"""JWT metadata is unverified and never authorizes a request or finding."""
import base64
import json

from canarygate.offline.auth_checks import pending_checks
from canarygate.oracles.authentication import inspect_jwt_metadata, is_supported_jwt


def enc(raw): return base64.urlsafe_b64encode(raw).decode().rstrip('=')
def jwt(header, payload, signature='fake'): return enc(header)+'.'+enc(payload)+'.'+signature


def test_claim_metadata_is_ephemeral_unverified_and_does_not_change_verdicts():
    token=jwt(b'{"alg":"HS256"}',b'{"sub":"account-private","role":"admin","exp":123456}')
    metadata=inspect_jwt_metadata(token)
    assert metadata is not None and metadata.claims_unverified is True
    assert metadata.algorithm=='HS256' and metadata.subject=='account-private' and metadata.role=='admin' and metadata.expiration==123456
    assert token not in repr(metadata) and 'account-private' not in repr(metadata) and 'admin' not in repr(metadata)
    checks={c['id']:c for c in pending_checks(token=token)}
    assert all(checks[n]['verdict']=='SKIPPED' for n in ('AUTHN-04a','AUTHN-04b','AUTHN-05'))


def test_duplicate_keys_nonfinite_json_and_excessive_nesting_are_not_supported():
    payloads=[b'{"sub":"a","sub":"b"}', b'{"exp":NaN}', b'{"x":'+b'['*1200+b'0'+b']'*1200+b'}']
    for body in payloads:
        token=jwt(b'{"alg":"HS256"}',body)
        assert inspect_jwt_metadata(token) is None and not is_supported_jwt(token)
    assert inspect_jwt_metadata(jwt(b'{"alg":"HS256","alg":"none"}',b'{}')) is None


def test_invalid_metadata_types_are_not_treated_as_identity():
    token=jwt(b'{"alg":"HS256"}',json.dumps({'sub':{'id':'alice'},'role':['admin'],'exp':True}).encode())
    metadata=inspect_jwt_metadata(token)
    assert metadata and metadata.subject is None and metadata.role is None and metadata.expiration is None
    assert metadata.claims_unverified is True
