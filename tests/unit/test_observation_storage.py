import sqlite3
from contextlib import closing

import httpx
import pytest

from canarygate.database.store import FixtureStore
from canarygate.evidence.observations import capture, prepare
from canarygate.evidence.redaction import EvidenceIntegrityError, digest
from canarygate.offline.scan import run_fixture
from canarygate.seed.recipe import validate_fixture_recipe
from canarygate.offline.scan import fixture_recipe


def test_observations_are_allowlisted_bounded_and_do_not_store_arbitrary_data():
    account = validate_fixture_recipe(fixture_recipe()).setup.accounts["user_a"]
    request = httpx.Request("GET", "https://fixture.invalid/items", headers={"Authorization": "Bearer secret-token"})
    body = [{"id": "alice-item", "owner": "alice", "private_note": "hidden"}]
    body += [{"id": f"secret-resource-{i}", "owner": "private-owner", "password": "hidden"} for i in range(24)]
    response = httpx.Response(200, json=body, request=request)
    obs = capture("discovery", account, response, id_field="id", owner_field="owner", private_field="private_note",
                  assertions={"own_resource_identified": True})
    assert obs["response"]["item_count"] == 25 and obs["response"]["items_truncated"] is True
    assert len(obs["response"]["items"]) == 20
    assert obs["response"]["items"][1]["id"] == "[REDACTED]"
    assert obs["response"]["items"][1]["owner"] == "[REDACTED]"
    assert obs["request"]["authorization"] == "[REDACTED]"
    rendered = str(obs)
    for sensitive in ("secret-token", "secret-resource", "private-owner", "hidden"):
        assert sensitive not in rendered
    assert prepare([obs]) == [obs]


def test_invalid_observation_never_gets_persisted(tmp_path):
    store = FixtureStore(tmp_path / "fixture.sqlite3")
    store.initialize()
    observations = []
    run = run_fixture(observation_sink=observations)
    observations[0]["unexpected"] = "secret-value"
    observations[0]["sha256"] = digest({key: value for key, value in observations[0].items() if key not in {"sha256", "redacted"}})
    with pytest.raises(EvidenceIntegrityError):
        store.save(run, observations)
    assert store.get(run["id"]) is None
    assert b"secret-value" not in store.path.read_bytes()


def test_run_and_observations_are_inserted_atomically(tmp_path):
    db = tmp_path / "fixture.sqlite3"
    store = FixtureStore(db)
    store.initialize()
    observations = []
    run = run_fixture(observation_sink=observations)
    with closing(sqlite3.connect(db)) as conn, conn:
        conn.execute("CREATE TRIGGER fail_observations BEFORE INSERT ON fixture_observation_sets BEGIN SELECT RAISE(ABORT, 'injected failure'); END")
    with pytest.raises(sqlite3.IntegrityError):
        store.save(run, observations)
    assert store.get(run["id"]) is None
    assert store.get_observations(run["id"]) is None
