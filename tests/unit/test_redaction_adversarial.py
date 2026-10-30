"""Known-shape redaction regressions; not proof for arbitrary secret encodings."""
import json

from canarygate.evidence.redaction import redact, REDACTED


def test_nested_alternate_secret_keys_and_arrays_preserve_non_sensitive_metadata():
    raw = {'status_code': 403, 'method':'GET', 'ownership_verified':True,
           'headers': {'X-Api-Key':'s01', 'X-Auth-Token':'s02', 'Cookie':'s03', 'Set-Cookie':'s04'},
           'items': [{'refreshToken':'s05', 'accessToken':'s06', 'clientSecret':'s07',
                      'passwordHash':'s08', 'sessionId':'s09', 'nested':[{'apiKey':'s10'}, {'pwd':'s11'}],
                      'tokens':{'value':'s12'}, 'credentials':[{'password':'s13'}]}]}
    clean=redact(raw)
    assert clean['status_code']==403 and clean['method']=='GET' and clean['ownership_verified'] is True
    assert all(value==REDACTED for value in clean['headers'].values())
    assert all(clean['items'][0][key]==REDACTED for key in ('refreshToken','accessToken','clientSecret','passwordHash','sessionId'))
    assert clean['items'][0]['nested']==[{'apiKey':REDACTED},{'pwd':REDACTED}]
    assert not any(f's{i:02d}' in json.dumps(clean) for i in range(1,14))
    assert clean['items'][0]['tokens']==REDACTED and clean['items'][0]['credentials']==REDACTED


def test_bounded_known_assignment_and_cookie_patterns_in_error_and_debug_strings():
    raw={'error':'Authorization: Bearer bearer-7e1\nCookie: sessionid=ck-82; theme=dark\n'
                 'refreshToken=ref-99 api_key=key-43 password=pass-71',
         'debug':['Set-Cookie: sid=sid-54; HttpOnly', 'x-api-key: key-26']}
    clean=redact(raw)
    for secret in ('bearer-7e1','ck-82','ref-99','key-43','pass-71','sid-54','key-26'):
        assert secret not in json.dumps(clean)
    assert '[REDACTED]' in clean['error'] and '[REDACTED]' in clean['debug'][0]
