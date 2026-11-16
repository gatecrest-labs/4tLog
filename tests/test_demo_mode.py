"""Demo mode (DEMO_MODE=true): synthetic FortiAnalyzer, seeded data, writes off,
and no way to reach a real FortiAnalyzer."""

import datetime
import ipaddress
import json
import os

import pytest
import requests

from app import demo, demo_faz
from app.config import Config
from app.demo_faz import DemoFAZ, compile_filter, generate_logs, is_demo_host
from app.faz_client import FAZClient, FAZError

HQ = "faz-hq.demo.invalid"
BRANCHES = "faz-branches.demo.invalid"
DR = "faz-dr.demo.invalid"
SEED_FILES = (
    "users.json",
    "groups.json",
    "faz_targets.json",
    "app_settings.json",
    "api_tokens.json",
)


def _set_demo_mode(monkeypatch, value: bool) -> None:
    """Set DEMO_MODE on every Config class in play: tests/test_config.py reloads
    app.config, so modules imported earlier can hold an older Config class."""
    import app as app_pkg
    import app.config
    import app.faz_health_cache

    configs = (app.config.Config, app.faz_health_cache.Config, app_pkg.Config, Config)
    for cfg in {id(c): c for c in configs}.values():
        monkeypatch.setattr(cfg, "DEMO_MODE", value)


@pytest.fixture
def demo_on(monkeypatch, tmp_path):
    """Demo mode switched on, stores pointed at the seeds, caches/history isolated."""
    import app.faz_health_cache as health
    import app.log_stats_cache as log_stats
    import app.log_stats_history as log_hist
    import app.sdwan_cache as sdwan
    import app.threat_stats_cache as threats
    import app.threat_stats_history as threat_hist

    _set_demo_mode(monkeypatch, True)
    demo.activate(monkeypatch.setattr)
    monkeypatch.setattr(health, "_cache", {})
    monkeypatch.setattr(sdwan, "_cache", dict(sdwan._EMPTY_CACHE))
    monkeypatch.setattr(threats, "_cache", dict(threats._EMPTY_CACHE))
    monkeypatch.setattr(
        log_stats,
        "_cache",
        {"logging_devices": [], "silent_devices": [], "silent_details": [], "collected_at": None},
    )
    monkeypatch.setattr(log_hist, "DB_PATH", tmp_path / "logstats.db")
    monkeypatch.setattr(threat_hist, "DB_PATH", tmp_path / "logstats.db")
    monkeypatch.setattr("time.sleep", lambda *_: None)


@pytest.fixture
def no_network(monkeypatch):
    """Fail the test if anything tries a real HTTP request or SNMP query."""

    def refuse(*_a, **_k):
        raise AssertionError("demo mode made a real network call")

    monkeypatch.setattr(requests.Session, "post", refuse)
    monkeypatch.setattr(requests.Session, "request", refuse)
    monkeypatch.setattr("app.faz_health_cache._snmp_get", refuse)


@pytest.fixture
def app(demo_on):
    os.environ.setdefault("SECRET_KEY", "test-secret")
    from app import create_app

    return create_app()


def _login(app, username="demo-admin"):
    client = app.test_client()
    client.get("/login")
    with client.session_transaction() as sess:
        csrf = sess["_csrf_token"]
    resp = client.post(
        "/login",
        data={"username": username, "password": demo.DEMO_PASSWORD, "csrf_token": csrf},
    )
    assert resp.status_code == 302, resp.data
    client.get("/")  # the login cleared the session; this re-issues the CSRF token
    with client.session_transaction() as sess:
        return client, {"X-CSRF-Token": sess["_csrf_token"]}


def _seed_bytes():
    return {name: (demo.DEMO_DATA_DIR / name).read_bytes() for name in SEED_FILES}


# ── Refusing real FortiAnalyzers ─────────────────────────────────────────────


@pytest.mark.parametrize("host", ["192.0.2.10", "faz.example.com", "faz.demo.invalid.example.com"])
def test_demo_mode_refuses_a_real_target(demo_on, no_network, host):
    with pytest.raises(FAZError, match="Demo mode: refusing to contact"):
        FAZClient(host=host, token="real-token")


def test_real_target_on_the_dashboard_shows_the_refusal_not_a_connection(demo_on, no_network):
    from app.faz_health_cache import _poll_target

    entry = _poll_target({"label": "Prod", "host": "10.1.2.3", "token": "t"})
    assert entry["status"] == "offline"
    assert "Demo mode: refusing to contact" in entry["error"]


def test_real_target_in_log_search_is_refused(app, no_network, monkeypatch):
    import app.routes.log_search_routes as routes

    real = {"label": "Prod", "host": "10.1.2.3", "adom": "root", "token": "t"}
    monkeypatch.setattr(routes, "get_target", lambda label: real)
    client, headers = _login(app)
    resp = client.get("/api/log-search/devices?target=Prod")
    assert resp.status_code == 502
    assert "Demo mode: refusing to contact" in resp.get_json()["error"]


def test_demo_hosts_never_resolve():
    assert is_demo_host(HQ) and is_demo_host("FAZ-HQ.DEMO.INVALID")
    assert not is_demo_host("faz-hq.demo.invalid.evil.example")
    assert not is_demo_host("")
    # .invalid is reserved (RFC 2606): even a code path that skipped the
    # demo transport could not reach a real host by these names.
    assert all(t["host"].endswith(".invalid") for t in _seed_targets())


def test_recorder_is_never_armed_in_demo_mode(demo_on, monkeypatch, tmp_path):
    out = tmp_path / "capture.json"
    monkeypatch.setenv("FAZ_RECORD_FILE", str(out))
    client = FAZClient(host=HQ, token="demo")
    client.get_sys_status()
    assert client._recorder is None
    assert not out.exists()


def test_outside_demo_mode_real_hosts_are_untouched(monkeypatch):
    _set_demo_mode(monkeypatch, False)
    client = FAZClient(host="192.0.2.10", token="t")
    assert client._post.__self__ is client  # the real transport, not DemoFAZ


# ── Seeds ────────────────────────────────────────────────────────────────────


def _seed_targets():
    return json.loads((demo.DEMO_DATA_DIR / "faz_targets.json").read_text())


def test_activate_points_every_store_at_the_seeds(demo_on):
    from app import api_tokens, app_settings, auth, faz_targets, groups

    assert auth.USERS_FILE == demo.DEMO_DATA_DIR / "users.json"
    assert groups.GROUPS_FILE == demo.DEMO_DATA_DIR / "groups.json"
    assert faz_targets.FAZ_TARGETS_FILE == demo.DEMO_DATA_DIR / "faz_targets.json"
    assert app_settings._SETTINGS_PATH == demo.DEMO_DATA_DIR / "app_settings.json"
    assert api_tokens._TOKENS_PATH == demo.DEMO_DATA_DIR / "api_tokens.json"


def test_activate_refuses_a_seed_with_a_real_host(monkeypatch, tmp_path):
    (tmp_path / "faz_targets.json").write_text(
        json.dumps([{"label": "x", "host": "10.0.0.1", "adom": "root", "token": "t"}])
    )
    monkeypatch.setattr(demo, "DEMO_DATA_DIR", tmp_path)
    with pytest.raises(RuntimeError, match="non-demo"):
        demo.activate(monkeypatch.setattr)


def test_seed_users_sign_in_with_the_published_demo_password(demo_on):
    from app.auth import authenticate

    for username, role in demo.DEMO_USERS:
        assert authenticate(username, demo.DEMO_PASSWORD) == (role, [])
    assert authenticate("demo-admin", "wrong") is None


def test_external_api_is_off_in_the_demo(demo_on):
    from app.app_settings import get_setting

    assert get_setting("external_api_enabled") is False


# ── Writes disabled ──────────────────────────────────────────────────────────

WRITES = [
    ("post", "/admin/api/faz-targets", {"label": "x", "host": "10.0.0.1"}),
    ("put", "/admin/api/faz-targets/Gatecrest%20HQ", {"host": "10.0.0.1"}),
    ("delete", "/admin/api/faz-targets/Gatecrest%20HQ", None),
    ("post", "/admin/api/groups", {"name": "g"}),
    ("put", "/admin/api/groups/branch-analysts", {"members": []}),
    ("delete", "/admin/api/groups/branch-analysts", None),
    ("put", "/admin/api/settings", {"external_api_enabled": True}),
    ("post", "/admin/api/tokens", {"name": "t"}),
    ("delete", "/admin/api/tokens/abc", None),
    ("post", "/admin/api/logs/level", {"level": "DEBUG"}),
    ("delete", "/admin/api/logs", None),
]


@pytest.mark.parametrize("method,path,body", WRITES)
def test_admin_writes_are_refused_and_seeds_unchanged(app, method, path, body):
    before = _seed_bytes()
    client, headers = _login(app)
    resp = getattr(client, method)(path, json=body, headers=headers)
    assert resp.status_code == 403
    assert resp.get_json() == {"error": demo.BLOCKED_MESSAGE}
    assert _seed_bytes() == before


def test_4tsuite_group_push_is_refused(app):
    resp = app.test_client().post("/4tsuite/groups", json={})
    assert resp.status_code == 403


def test_read_only_self_test_still_runs(app, no_network):
    client, headers = _login(app)
    resp = client.post("/admin/api/faz-selftest", json={"label": "Gatecrest HQ"}, headers=headers)
    assert resp.status_code == 200
    report = resp.get_json()
    assert report["summary"] == {"ok": 18, "denied": 0, "error": 0, "skipped": 0}
    assert report["faz_version"] == "7.6.4"


def test_blocked_write_rules():
    assert demo.blocked_write("POST", "/admin/api/groups", "admin.api_groups_create")
    assert not demo.blocked_write("POST", "/admin/api/faz-selftest", "admin.api_faz_selftest")
    assert not demo.blocked_write("GET", "/admin/api/groups", "admin.api_groups_list")
    assert not demo.blocked_write("POST", "/api/log-search", "log_search.api_search")
    assert not demo.blocked_write("POST", "/login", "auth.login")


# ── UI ───────────────────────────────────────────────────────────────────────


def test_banner_and_demo_sign_ins_on_the_login_page(app):
    html = app.test_client().get("/login").get_data(as_text=True)
    assert "demo-banner" in html
    assert "demo-analyst" in html and demo.DEMO_PASSWORD in html


def test_banner_on_every_tab(app):
    client, _ = _login(app)
    for path in ("/", "/sdwan", "/log-search", "/admin/"):
        resp = client.get(path)
        assert resp.status_code == 200
        assert "demo-banner" in resp.get_data(as_text=True), path


def test_no_banner_outside_demo_mode(monkeypatch, tmp_path):
    _set_demo_mode(monkeypatch, False)
    from app import create_app

    html = create_app().test_client().get("/login").get_data(as_text=True)
    assert "demo-banner" not in html
    assert demo.DEMO_PASSWORD not in html


def test_analyst_sees_only_the_branches(app):
    client, _ = _login(app, "demo-analyst")
    labels = [t["label"] for t in client.get("/api/log-search/targets").get_json()]
    assert labels == ["Gatecrest Branches"]
    assert client.get("/admin/").status_code == 403


# ── Synthetic FortiAnalyzer through the real pollers ─────────────────────────


def test_dashboard_cards_show_three_states_without_snmp(app, no_network):
    from app.faz_health_cache import poll_all_targets

    poll_all_targets()
    client, _ = _login(app)
    cards = {c["label"]: c for c in client.get("/api/dashboard").get_json()}
    assert cards["Gatecrest HQ"]["status"] == "green"
    assert cards["Gatecrest HQ"]["version"].startswith("v7.6")
    assert cards["Gatecrest Branches"]["status"] == "yellow"  # CPU above CPU_WARN
    assert cards["Gatecrest Branches"]["version"].startswith("v7.4")
    assert cards["Gatecrest DR"]["status"] == "offline"
    assert cards["Gatecrest DR"]["error"] == "Connection refused"


def test_sdwan_lists_the_degraded_link_first(demo_on, no_network):
    from app.sdwan_cache import get_cached, poll_all_targets

    poll_all_targets()
    targets = {t["label"]: t for t in get_cached()["targets"]}
    branches = targets["Gatecrest Branches"]
    assert branches["state"] == "ok"
    worst = branches["interfaces"][0]
    assert (worst["device"], worst["interface"], worst["sla_status"]) == (
        "GC-BR-EAST",
        "wan2",
        "fail",
    )
    assert worst["latency"]["latest"] > 100
    assert all(v["status"] == "ok" for v in branches["views"].values())
    assert targets["Gatecrest DR"]["state"] == "error"
    assert "GC-BR-WEST" not in {i["device"] for i in branches["interfaces"]}  # silent device


def test_threat_and_log_stats_polls(demo_on, no_network):
    from app import log_stats_cache, threat_stats_cache

    threat_stats_cache.poll_all_targets()
    stats = threat_stats_cache.get_cached()
    assert stats["alerts_unacked_total"] == 111
    assert stats["ips_detections_24h"] > 0 and 80 < stats["ips_blocked_pct"] < 100
    assert stats["top_signatures"] and stats["top_source_countries"]
    assert stats["ipsec_tunnels_down"] == 1
    assert stats["failed_admin_logins_24h"] == 3

    log_stats_cache.poll_all_targets()
    silent = log_stats_cache.get_cached()["silent_details"]
    assert [d["devname"] for d in silent] == ["GC-BR-WEST"]


# ── Log search ───────────────────────────────────────────────────────────────


def _window(hours=1):
    end = datetime.datetime.now(datetime.timezone.utc)
    return end - datetime.timedelta(hours=hours), end


def test_log_search_route_applies_filters(app, no_network):
    client, headers = _login(app)
    start, end = _window(4)
    resp = client.post(
        "/api/log-search",
        json={
            "target": "Gatecrest Branches",
            "source_ips": "10.20.3.0/24",
            "ports": "443",
            "logtype": "traffic",
            "device": "All_FortiGate",
            "start_time": start.isoformat(),
            "end_time": end.isoformat(),
            "extra_filters": [{"field": "action", "op": "!=", "value": "deny"}],
        },
        headers=headers,
    )
    assert resp.status_code == 200
    rows = resp.get_json()["rows"]
    assert rows
    for row in rows:
        assert ipaddress.ip_address(row["srcip"]) in ipaddress.ip_network("10.20.3.0/24")
        assert row["dstport"] == "443" and row["action"] != "deny"
        assert row["devname"] == "GC-BR-EAST"


def test_generated_logs_are_stable_newest_first_and_inside_the_window():
    start, end = _window(2)
    match_all = compile_filter("")
    first = generate_logs(HQ, "traffic", "All_FortiGate", match_all, start, end, 200)
    again = generate_logs(HQ, "traffic", "All_FortiGate", match_all, start, end, 200)
    assert first == again and len(first) == 200
    stamps = [int(r["itime_t"]) for r in first]
    assert stamps == sorted(stamps, reverse=True)
    assert all(start.timestamp() - 1 <= s <= end.timestamp() for s in stamps)


def test_device_scope_and_unknown_logtypes():
    start, end = _window(2)
    rows = generate_logs(
        BRANCHES, "traffic", "FGT60F0000000201", compile_filter(""), start, end, 50
    )
    assert rows and {r["devname"] for r in rows} == {"GC-BR-NORTH"}
    assert (
        generate_logs(BRANCHES, "virus", "All_FortiGate", compile_filter(""), start, end, 50) == []
    )


FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "faz_8.0.2", "exchanges.json")


def test_traffic_rows_use_fields_from_the_recorded_fixture():
    # Every key a demo traffic row has is one a real FortiAnalyzer used: either
    # in its traffic field list (the demo serves that list verbatim) or on the
    # recorded log-search row.
    seeded = json.loads((demo.DEMO_DATA_DIR / "logfields.json").read_text())["traffic"]
    fields = {f["name"] for f in seeded}
    with open(FIXTURE) as fh:
        exchanges = json.load(fh)["exchanges"]
    recorded_rows = [
        row
        for ex in exchanges
        if "/logsearch/" in ex["request"]["params"][0]["url"]
        for row in (ex["response"].get("result") or {}).get("data") or []
    ]
    assert recorded_rows
    fields |= {k for row in recorded_rows for k in row}
    recorded_fields = next(
        ex["response"]["result"]["data"][0]["field"]
        for ex in exchanges
        if ex["request"]["params"][0]["url"].endswith("/logfields")
    )
    assert seeded == recorded_fields
    start, end = _window(1)
    rows = generate_logs(HQ, "traffic", "All_FortiGate", compile_filter(""), start, end, 50)
    unknown = {k for r in rows for k in r} - fields
    assert not unknown, unknown


def test_generated_addresses_are_private_or_documentation_ranges():
    allowed = [
        ipaddress.ip_network(n)
        for n in ("10.0.0.0/8", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
    ]
    start, end = _window(6)
    for host in (HQ, BRANCHES):
        for logtype in demo_faz.GENERATED_LOGTYPES:
            for row in generate_logs(
                host, logtype, "All_FortiGate", compile_filter(""), start, end, 300
            ):
                for key in ("srcip", "dstip"):
                    ip = ipaddress.ip_address(row[key])
                    assert any(ip in n for n in allowed), (logtype, key, row[key])


@pytest.mark.parametrize(
    "expr,row,expected",
    [
        ("srcip==10.20.1.0/24", {"srcip": "10.20.1.9"}, True),
        ("srcip==10.20.1.0/24", {"srcip": "10.20.2.9"}, False),
        ("(srcip>=10.0.0.5 and srcip<=10.0.0.9)", {"srcip": "10.0.0.7"}, True),
        ("(srcip>=10.0.0.5 and srcip<=10.0.0.9)", {"srcip": "10.0.0.10"}, False),
        (
            "(srcip==10.0.0.1 or srcip==10.0.0.2) and (dstport==443)",
            {"srcip": "10.0.0.2", "dstport": "443"},
            True,
        ),
        (
            "(srcip==10.0.0.1 or srcip==10.0.0.2) and (dstport==443)",
            {"srcip": "10.0.0.2", "dstport": "53"},
            False,
        ),
        ('(service=="HTTPS")', {"service": "https"}, True),
        ('(action!="deny")', {"action": "deny"}, False),
        ("(dstport>=1000 and dstport<=2000)", {"dstport": "999"}, False),
        ("(missing==1)", {"srcip": "10.0.0.1"}, False),
    ],
)
def test_filter_subset(expr, row, expected):
    assert compile_filter(expr)(row) is expected


def test_filter_built_by_the_client_compiles():
    from app.log_search_filters import parse_ip_entries, parse_port_entries

    expr = FAZClient.build_filter_expression(
        parse_ip_entries("10.20.0.0/16, 10.10.0.1-10.10.0.9", "srcip"),
        parse_ip_entries("203.0.113.5", "dstip"),
        parse_port_entries("443, tcp:8000-8100, DNS"),
        [{"field": "action", "op": "!=", "value": "deny"}],
    )
    predicate = compile_filter(expr)
    assert predicate(
        {
            "srcip": "10.20.9.9",
            "dstip": "203.0.113.5",
            "dstport": "8050",
            "service": "x",
            "action": "accept",
        }
    )


def test_bad_filter_is_an_invalid_params_error():
    resp = DemoFAZ(HQ).post(
        {
            "id": 1,
            "method": "add",
            "params": [{"url": "/logview/adom/root/logsearch", "filter": "srcip=="}],
        }
    )
    assert resp["error"]["code"] == -32002


def test_wrong_adom_is_no_permission():
    resp = DemoFAZ(HQ).post(
        {"id": 1, "method": "get", "params": [{"url": "/dvmdb/adom/branches/device"}]}
    )
    assert resp["error"]["code"] == -11


def test_offline_site_fails_like_an_unreachable_appliance():
    with pytest.raises(requests.exceptions.ConnectionError):
        DemoFAZ(DR).post({"id": 1, "method": "get", "params": [{"url": "/sys/status"}]})


def test_unknown_view_is_reported_like_a_missing_fortiview():
    resp = DemoFAZ(HQ).post(
        {"id": 1, "method": "add", "params": [{"url": "/fortiview/adom/root/no-such-view/run"}]}
    )
    assert resp["error"]["code"] == -32005
    assert "Cannot find FortiView" in resp["error"]["message"]


# ── Config ───────────────────────────────────────────────────────────────────


def test_demo_mode_generates_a_throwaway_secret_key(monkeypatch):
    import app.config as config

    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.setattr(config, "DEMO_MODE", True)
    key = config._require_secret_key()
    assert len(key) == 64 and key != config._require_secret_key()
    monkeypatch.setattr(config, "DEMO_MODE", False)
    with pytest.raises(RuntimeError):
        config._require_secret_key()


def test_demo_compose_stays_apart_from_the_real_stack():
    """The demo stack must not replace the real stack's image, share its
    Compose project, or publish its public-password login beyond localhost."""
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    demo = (root / "docker-compose.demo.yml").read_text()
    real = (root / "docker-compose.yml").read_text()
    lines = [line.split("#", 1)[0].strip() for line in demo.splitlines()]

    assert "name: 4tlog-demo" in lines
    demo_images = {line.split(":", 1)[1].strip() for line in lines if line.startswith("image:")}
    real_images = {
        line.split(":", 1)[1].strip()
        for line in (raw.split("#", 1)[0].strip() for raw in real.splitlines())
        if line.startswith("image:")
    }
    assert demo_images == {"4tlog:demo"}
    assert not demo_images & real_images
    ports = [line for line in lines if line.startswith('- "') and ':8100"' in line]
    assert ports and all(p.startswith('- "127.0.0.1:') for p in ports)
    assert "- DEMO_MODE=true" in lines
