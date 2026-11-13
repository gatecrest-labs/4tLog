"""Run the real FAZClient / self-test / threat poll against recorded answers.

One fixture directory per FortiAnalyzer release under
tests/fixtures/faz_<version>/, captured with scripts/record_faz_fixture.py.
Dropping a new directory in puts that release under test (add its
expectations to EXPECTED).

The lab FortiAnalyzer behind faz_8.0.2 receives no logs, so FortiView and log
search return zero rows: these tests pin request acceptance and error
behaviour, not row field names.
"""

import datetime
from pathlib import Path

import pytest

from app.faz_client import FAZClient
from app.faz_recorder import ReplayTransport
from app.faz_selftest import run_selftest

FIXTURES = Path(__file__).parent / "fixtures"

# Requests whose params embed a value computed from "now" (time windows) or
# differ from the self-test's own variant (limits, severity filters), so they
# match on method + url. Task ids stay exact: they come from the recorded submit.
LOOSE = (
    r"/fortiview/adom/[^/]+/[^/]+/run(/\d+)?",
    r"/logview/adom/[^/]+/logsearch(/\d+)?",
    r"/eventmgmt/adom/[^/]+/alerts/count",
)

# fixture dir -> (train, summary, ids of checks the appliance rejects)
EXPECTED = {
    "faz_8.0.2": (
        "8.0",
        {"ok": 16, "denied": 0, "error": 2, "skipped": 0},
        {"fortiview_top_threats", "fortiview_top_countries"},
    ),
}


@pytest.fixture(autouse=True)
def _no_real_polling_sleep(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda *_: None)


def _client(name):
    c = FAZClient(host="faz.invalid", token="fixture", adom="root")
    c._post = ReplayTransport(FIXTURES / name / "exchanges.json", loose_urls=LOOSE).post
    return c


def test_every_fixture_directory_has_expectations():
    found = {p.parent.name for p in FIXTURES.glob("faz_*/exchanges.json")}
    assert found == set(EXPECTED)


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_version_is_detected(name):
    assert _client(name).version.train == EXPECTED[name][0]


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_selftest_offline_matches_the_recorded_appliance(name):
    report = run_selftest(_client(name))
    errors = {c["id"] for c in report["checks"] if c["status"] == "error"}
    assert report["summary"] == EXPECTED[name][1], [
        (c["id"], c["status"], c["message"]) for c in report["checks"]
    ]
    assert errors == EXPECTED[name][2]


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_recorded_fortiview_submits_all_carry_a_device_scope(name):
    # FAZ 8.0.2 rejects an unscoped run (-32005 "No eligible device(s)").
    import json

    ex = json.loads((FIXTURES / name / "exchanges.json").read_text())["exchanges"]
    submits = [
        e["request"]["params"][0]
        for e in ex
        if e["request"]["method"] == "add"
        and e["request"]["params"][0]["url"].startswith("/fortiview/")
    ]
    assert submits
    assert all(p.get("device") for p in submits)


def test_8_0_2_threat_poll_completes_despite_the_rejected_ips_filters():
    from app.threat_stats_cache import _poll_one_target

    now = datetime.datetime.now(datetime.timezone.utc)
    result = _poll_one_target(_client("faz_8.0.2"), now)
    assert result["alerts_unacked_total"] >= 0
    assert result["top_signatures"] == []
    assert result["top_source_countries"] == []
    assert result["failed_admin_logins_24h"] == 0


def test_client_sends_a_device_scope_on_every_fortiview_submit():
    # Guards the code, not the fixture: an unscoped run is rejected by 8.0.2.
    c = _client("faz_8.0.2")
    inner, sent = c._post, []

    def spy(body):
        sent.append(body)
        return inner(body)

    c._post = spy
    run_selftest(c)
    submits = [
        b["params"][0]
        for b in sent
        if b["method"] == "add" and b["params"][0]["url"].startswith("/fortiview/")
    ]
    assert len(submits) == 11  # 7 threat views + 4 SD-WAN views
    assert all(p["device"] == [{"devid": "All_FortiGate"}] for p in submits)
