"""Connection Timeline in demo mode: end to end against the synthetic
FortiAnalyzer, with no network, and the demo FAZ's log-search paging."""

import datetime
import ipaddress

import pytest

from app import conn_timeline_job, demo_faz
from app.demo_faz import FEATURED_HOSTS
from app.faz_client import FAZClient
from tests.test_demo_mode import BRANCHES, HQ, _login, app, demo_on, no_network  # noqa: F401


@pytest.fixture
def inline_jobs(monkeypatch):
    conn_timeline_job.STORE.clear()
    monkeypatch.setattr(conn_timeline_job, "spawn", lambda target: target())
    yield
    conn_timeline_job.STORE.clear()


def _build(client, headers, **payload):
    resp = client.post("/api/conn-timeline", json=payload, headers=headers)
    assert resp.status_code == 202, resp.get_json()
    job = client.get(f"/api/conn-timeline/{resp.get_json()['job_id']}").get_json()
    assert job["status"] == "done", job
    return job["result"]


def test_jump_server_timeline_end_to_end(app, no_network, inline_jobs):  # noqa: F811
    client, headers = _login(app)
    page = client.get("/conn-timeline")
    assert page.status_code == 200
    assert b"10.10.20.50" in page.data  # demo host shortcut

    result = _build(client, headers, target="Gatecrest HQ", host="10.10.20.50", direction="either")
    assert result["preset"] == "1h"
    assert result["coverage"]["complete"] is True
    assert result["coverage"]["matched"] == result["coverage"]["fetched"] == result["rows"]
    assert result["rows"] > 0
    labels = {lane["label"] for lane in result["lanes"]}
    assert len(labels) >= 2  # more than one firewall saw it
    policies = {p["policyid"]: p for p in result["policies"]}
    assert policies["30"]["label"] == "30 · Jump-to-Servers"
    verdicts = {f[2] for f in result["flows"]}
    assert 0 in verdicts  # allowed traffic
    for ip in result["peers"]:
        assert ipaddress.ip_address(ip) != ipaddress.ip_address("10.10.20.50")


def test_busy_host_pages_past_one_thousand_rows(app, no_network, inline_jobs):  # noqa: F811
    client, headers = _login(app)
    result = _build(client, headers, target="Gatecrest HQ", host="10.10.10.53", preset="1h")
    cov = result["coverage"]
    assert cov["fetched"] > 1000
    assert cov["complete"] is True and cov["matched"] == cov["fetched"]


def test_seven_day_window_on_a_busy_host_is_partial(app, no_network, inline_jobs, monkeypatch):  # noqa: F811
    from app.routes import conn_timeline_routes

    monkeypatch.setattr(conn_timeline_routes.Config, "CONN_TIMELINE_MAX_ROWS", 20000)
    client, headers = _login(app)
    result = _build(client, headers, target="Gatecrest HQ", host="10.10.10.53", preset="7d")
    cov = result["coverage"]
    assert cov["complete"] is False
    assert cov["reason"] == "cap"
    assert cov["fetched"] == 20000
    assert cov["matched"] > cov["fetched"]
    assert cov["through"] is not None
    assert result["bucket_seconds"] == 3 * 3600


def test_branch_camera_shows_denied_internet_traffic(app, no_network, inline_jobs):  # noqa: F811
    client, headers = _login(app, "demo-analyst")
    result = _build(
        client, headers, target="Gatecrest Branches", host="10.20.2.40", direction="src"
    )
    denied_peers = {result["peers"][f[3]] for f in result["flows"] if f[2] == 1}
    assert "198.51.100.77" in denied_peers


def test_analyst_cannot_build_on_another_target(app, no_network, inline_jobs):  # noqa: F811
    client, headers = _login(app, "demo-analyst")
    resp = client.post(
        "/api/conn-timeline",
        json={"target": "Gatecrest HQ", "host": "10.10.20.50"},
        headers=headers,
    )
    assert resp.status_code == 403


def test_demo_log_search_count_offset_and_delete(demo_on, no_network):  # noqa: F811
    client = FAZClient(host=HQ, token="demo")
    end = datetime.datetime.now(datetime.timezone.utc)
    start = end - datetime.timedelta(hours=1)
    local_start, local_end = client.local_time_range(
        start.strftime("%Y-%m-%dT%H:%M:%SZ"), end.strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    tid = client.submit_log_search(
        "traffic",
        "All_FortiGate",
        "(srcip==10.10.10.53 or dstip==10.10.10.53)",
        local_start,
        local_end,
        time_order="asc",
    )
    count = client.get_log_search_count(tid)
    assert count["progress-percent"] == 100
    matched = count["matched-logs"]
    assert matched > 1000
    first = client.fetch_log_search(tid, offset=0, limit=500)
    later = client.fetch_log_search(tid, offset=1000, limit=500)
    assert len(first["data"]) == 500
    assert len(later["data"]) == min(500, matched - 1000)  # paging past the submit limit
    assert first["total-count"] == matched
    assert int(first["data"][0]["itime_t"]) <= int(later["data"][0]["itime_t"])  # oldest first
    client.delete_log_search(tid)


def test_featured_hosts_use_private_or_documentation_addresses():
    allowed = [
        ipaddress.ip_network(n)
        for n in ("10.0.0.0/8", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
    ]
    sites = {HQ, BRANCHES}
    for host in FEATURED_HOSTS:
        assert host.site in sites
        assert any(ipaddress.ip_address(host.ip) in n for n in allowed)
        end = datetime.datetime.now(datetime.timezone.utc)
        rows = demo_faz.generate_logs(
            host.site,
            "traffic",
            "All_FortiGate",
            demo_faz.compile_filter(f"(srcip=={host.ip} or dstip=={host.ip})"),
            end - datetime.timedelta(hours=4),
            end,
            2000,
        )
        assert rows, host.ip
        for row in rows:
            for key in ("srcip", "dstip"):
                ip = ipaddress.ip_address(row[key])
                assert any(ip in n for n in allowed), (host.ip, key, row[key])


def test_demo_fortianalyzer_lists_its_adom(app, no_network):  # noqa: F811
    client, _ = _login(app)
    body = client.get("/api/conn-timeline/adoms?target=Gatecrest HQ").get_json()
    assert body["default"] in [a["name"] for a in body["adoms"]]
