import httpx

from canarygate.oracles.disclosure import disclosure_signals
from canarygate.oracles.validation import input_verdict


def test_validation_oracle_is_conservative():
    assert input_verdict(400, {"error": "Invalid limit"})[0] == "SAFE"
    assert input_verdict(422, {"error": "Invalid limit"})[0] == "SAFE"
    assert input_verdict(400, {})[0] == "INCONCLUSIVE"
    assert input_verdict(400, {"error": "Traceback (most recent call last): invalid limit"})[0] == "INCONCLUSIVE"
    assert input_verdict(200)[0] == "SUSPECTED"  # acceptance may be a documented default
    assert input_verdict(302)[0] == input_verdict(500)[0] == "INCONCLUSIVE"


def test_disclosure_signatures_do_not_treat_generic_errors_as_tracebacks():
    generic = httpx.Response(400, json={"error": "Invalid limit"}, headers={"Server": "example"})
    assert disclosure_signals(generic) == set()
    trace = httpx.Response(500, text='Traceback (most recent call last):\n  File "/srv/app.py", line 3')
    assert disclosure_signals(trace) == {"stack_trace", "internal_error_detail"}
    version = httpx.Response(400, headers={"X-Powered-By": "Example/2.3"})
    assert disclosure_signals(version) == {"version_header"}
