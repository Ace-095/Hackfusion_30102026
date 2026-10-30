"""A lab process needs a stable identity, not just a port.

Two TargetLab processes can reuse the same ephemeral port (and do, across
restarts). A port alone therefore cannot tell a judge whether two stored runs
describe the *same* lab process, so TargetLab publishes an instance id on every
response and the transport records it as operational metadata.

The id is not ground truth: it says nothing about the lab's declared flaws, and
the scanner never stores a raw response header. Only this one bounded value is
captured, and a change mid-run halts the run, because evidence that spans two
lab processes is not one continuous observation.
"""
import re

import pytest

import targetlab.testing as lab_server
from canarygate.network.targetlab import TargetLabRefused, TargetLabRunner, TargetLabTransport
from canarygate.scan.lab_scenarios import build_lab_plan, build_lab_scope

INSTANCE = re.compile(r"^[0-9a-f]{16}$")


def test_each_lab_process_publishes_its_own_instance_id():
    with lab_server.LabTlsServer() as first, lab_server.LabTlsServer() as second:
        assert INSTANCE.match(first.instance_id), first.instance_id
        assert INSTANCE.match(second.instance_id), second.instance_id
        assert first.instance_id != second.instance_id


def test_the_instance_id_is_stable_for_the_life_of_the_process():
    import ssl

    import httpx

    context = ssl.create_default_context(cafile=str(lab_server.TARGETLAB_CERT))
    with lab_server.LabTlsServer() as server:
        seen = set()
        for _ in range(2):
            response = httpx.get(f"https://{server.host}:{server.port}/health",
                                 verify=context, trust_env=False)
            seen.add(response.headers["x-lab-instance"])
        assert seen == {server.instance_id}


def test_the_transport_records_the_instance_it_talked_to():
    with lab_server.LabTlsServer() as server:
        scope = build_lab_scope(server.port, budget=12)
        transport = TargetLabTransport(scope, ca_file=lab_server.TARGETLAB_CERT)
        transport.request("mallapa", "GET", "/health", token="lab-token-mallapa")
        assert transport.lab_instance == server.instance_id


def test_a_runner_surfaces_the_same_instance_for_the_run_payload():
    with lab_server.LabTlsServer() as server:
        plan = build_lab_plan(server.port)
        runner = TargetLabRunner(plan.scope, plan.credentials,
                                 ca_file=lab_server.TARGETLAB_CERT)
        try:
            assert runner.login("mallapa") is True
            assert runner.lab_instance == server.instance_id
        finally:
            runner.close()


def test_a_changed_instance_mid_run_halts_instead_of_merging_evidence():
    with lab_server.CountingTlsServer(instance="0" * 16, change_after=1) as server:
        scope = build_lab_scope(server.port, budget=12)
        transport = TargetLabTransport(scope, ca_file=lab_server.TARGETLAB_CERT)
        first = transport.request("mallapa", "GET", "/health", token="lab-token-mallapa")
        assert first.status_code == 200
        with pytest.raises(TargetLabRefused):
            transport.request("mallapa", "GET", "/health", token="lab-token-mallapa")
        assert transport.stats()["halted"] is True


def test_a_response_without_the_header_is_tolerated_as_an_unknown_instance():
    with lab_server.CountingTlsServer() as server:
        scope = build_lab_scope(server.port, budget=12)
        transport = TargetLabTransport(scope, ca_file=lab_server.TARGETLAB_CERT)
        transport.request("mallapa", "GET", "/health", token="lab-token-mallapa")
        # Older labs do not set the header; the run is still valid evidence, it
        # simply cannot be attributed to a named instance.
        assert transport.lab_instance is None


def test_a_malformed_instance_header_fails_closed():
    with lab_server.CountingTlsServer(instance="NOT-AN-INSTANCE") as server:
        scope = build_lab_scope(server.port, budget=12)
        transport = TargetLabTransport(scope, ca_file=lab_server.TARGETLAB_CERT)
        with pytest.raises(TargetLabRefused):
            transport.request("mallapa", "GET", "/health", token="lab-token-mallapa")
        assert transport.stats()["halted"] is True
