import pytest


@pytest.fixture
def targets_file(tmp_path, monkeypatch):
    path = tmp_path / "faz_targets.json"
    import app.faz_targets as faz_targets_mod

    monkeypatch.setattr(faz_targets_mod, "FAZ_TARGETS_FILE", path)
    from app.faz_targets import create_target

    create_target("Primary", host="192.168.64.4", adom="root", token="tok")
    yield path


@pytest.fixture
def history_db(tmp_path, monkeypatch):
    path = tmp_path / "logstats.db"
    import app.threat_stats_history as history_mod

    monkeypatch.setattr(history_mod, "DB_PATH", path)
    history_mod.init_db()
    yield path


@pytest.fixture(autouse=True)
def clear_threat_stats_cache():
    import app.threat_stats_cache as cache_mod

    cache_mod._cache = dict(cache_mod._EMPTY_CACHE)
    yield
    cache_mod._cache = dict(cache_mod._EMPTY_CACHE)


def _stub_client(
    monkeypatch, alert_counts_by_filter, fortiview_rows_by_view, local_time_range=None
):
    def fake_get_alert_counts(self, adom, filter):
        return alert_counts_by_filter[filter]

    call_counts: dict[str, int] = {}

    def fake_run_fortiview(self, adom, view, time_range, limit=1000, filter=None, **_kw):
        entry = fortiview_rows_by_view[view]
        if entry and isinstance(entry[0], list):
            idx = call_counts.get(view, 0)
            call_counts[view] = idx + 1
            return entry[idx]
        return entry

    monkeypatch.setattr("app.faz_client.FAZClient.get_alert_counts", fake_get_alert_counts)
    monkeypatch.setattr("app.faz_client.FAZClient.run_fortiview", fake_run_fortiview)
    monkeypatch.setattr("app.faz_client.FAZClient.logout", lambda self: None)
    if local_time_range is not None:
        monkeypatch.setattr(
            "app.faz_client.FAZClient.local_time_range",
            lambda self, start_iso, end_iso: local_time_range,
        )


def test_poll_all_targets_populates_cache_and_writes_rollup(targets_file, history_db, monkeypatch):
    import app.threat_stats_cache as cache_mod
    from app.threat_stats_history import get_latest_rollup

    _stub_client(
        monkeypatch,
        alert_counts_by_filter={
            "ackflag=no": 5,
            "ackflag=no and severity=critical": 1,
            "ackflag=no and severity=high": 2,
            "ackflag=no and severity=medium": 1,
            "ackflag=no and severity=low": 1,
        },
        fortiview_rows_by_view={
            "top-type": [{"type": "IPS", "count": 100, "blockedsessions": 80}],
            "top-threats": [{"threatname": "Eicar.Test.Virus", "count": 40}],
            "top-countries": [{"srccountry": "China", "count": 60}],
            "admin-logins": [],
            "failed-authentication-attempts": [],
            "site-to-site-ipsec": [],
            "ssl-dialup-ipsec": [],
        },
    )

    cache_mod.poll_all_targets()

    cached = cache_mod.get_cached()
    assert cached["alerts_unacked_total"] == 5
    assert cached["alerts_unacked_by_severity"] == {"critical": 1, "high": 2, "medium": 1, "low": 1}
    assert cached["ips_detections_24h"] == 100
    assert cached["ips_blocked_24h"] == 80
    assert cached["ips_blocked_pct"] == 80.0
    assert cached["top_signatures"] == [{"signature": "Eicar.Test.Virus", "count": 40}]
    assert cached["top_source_countries"] == [{"country": "China", "count": 60}]
    assert cached["collected_at"] is not None

    rollup = get_latest_rollup()
    assert rollup["alerts_unacked_total"] == 5
    assert rollup["ips_blocked_pct"] == 80.0


def test_poll_all_targets_skips_target_with_threat_poll_disabled(tmp_path, monkeypatch, history_db):
    import app.faz_targets as faz_targets_mod
    import app.threat_stats_cache as cache_mod

    monkeypatch.setattr(faz_targets_mod, "FAZ_TARGETS_FILE", tmp_path / "faz_targets.json")
    from app.faz_targets import create_target

    create_target(
        "Primary", host="192.168.64.4", adom="root", token="tok", threat_poll_enabled=False
    )

    calls = []

    def fake_get_alert_counts(self, adom, filter):
        calls.append(filter)
        return 0

    monkeypatch.setattr("app.faz_client.FAZClient.get_alert_counts", fake_get_alert_counts)

    cache_mod.poll_all_targets()

    assert calls == []
    # No target polled ok -> stale-but-honest: cache left at its initial empty state.
    assert cache_mod.get_cached()["collected_at"] is None


def test_poll_all_targets_leaves_cache_unchanged_when_target_raises(
    targets_file, history_db, monkeypatch
):
    import app.threat_stats_cache as cache_mod
    from app.faz_client import FAZError

    seeded = {
        "alerts_unacked_total": 3,
        "alerts_unacked_by_severity": {"critical": 1, "high": 0, "medium": 1, "low": 1},
        "ips_detections_24h": 10,
        "ips_blocked_24h": 5,
        "ips_blocked_pct": 50.0,
        "top_signatures": [],
        "top_source_countries": [],
        "collected_at": "2026-09-10T00:00:00+00:00",
    }
    cache_mod._cache = dict(seeded)

    def fake_get_alert_counts(self, adom, filter):
        raise FAZError("boom")

    monkeypatch.setattr("app.faz_client.FAZClient.get_alert_counts", fake_get_alert_counts)
    monkeypatch.setattr("app.faz_client.FAZClient.logout", lambda self: None)

    cache_mod.poll_all_targets()  # must not raise

    assert cache_mod.get_cached() == seeded


def test_poll_all_targets_uses_local_time_range_for_fortiview(
    targets_file, history_db, monkeypatch
):
    """FortiView's time-range must go through client.local_time_range (which
    converts to the appliance's configured timezone), not a raw UTC window —
    see FAZClient.local_time_range's docstring for the live-confirmed FAZ
    behavior."""
    import app.threat_stats_cache as cache_mod

    sentinel = ("2026-09-10T03:00:00", "2026-09-11T03:00:00")
    captured_time_ranges = []

    def fake_get_alert_counts(self, adom, filter):
        return 0

    def fake_run_fortiview(self, adom, view, time_range, limit=1000, filter=None, **_kw):
        captured_time_ranges.append(time_range)
        return []

    monkeypatch.setattr("app.faz_client.FAZClient.get_alert_counts", fake_get_alert_counts)
    monkeypatch.setattr("app.faz_client.FAZClient.run_fortiview", fake_run_fortiview)
    monkeypatch.setattr("app.faz_client.FAZClient.logout", lambda self: None)
    monkeypatch.setattr(
        "app.faz_client.FAZClient.local_time_range",
        lambda self, start_iso, end_iso: sentinel,
    )
    # Deterministic regardless of wall-clock time: only one admin-logins
    # call happens (the 24h window), not a second business-hours call.
    monkeypatch.setattr("app.threat_stats_cache._business_hours_range", lambda client, now: None)

    cache_mod.poll_all_targets()

    # top-type, top-threats, top-countries, admin-logins,
    # failed-authentication-attempts, site-to-site-ipsec, ssl-dialup-ipsec
    assert captured_time_ranges == [sentinel] * 7


def test_parse_business_hours_default():
    from app.threat_stats_cache import _parse_business_hours

    start, end = _parse_business_hours()
    assert start.hour == 8 and start.minute == 0
    assert end.hour == 18 and end.minute == 0


def test_parse_business_hours_respects_config(monkeypatch):
    import app.threat_stats_cache as cache_mod
    from app.threat_stats_cache import _parse_business_hours

    # Monkeypatch the Config object threat_stats_cache actually holds a
    # reference to (via its own module-level `from app.config import
    # Config`), not whatever app.config.Config currently resolves to —
    # tests/test_config.py's importlib.reload(app.config) elsewhere in the
    # suite can leave app.config.Config pointing at a different class
    # object than the one this module imported at its own import time.
    monkeypatch.setattr(cache_mod.Config, "ADMIN_ACCESS_BUSINESS_HOURS", "09:30-17:15")
    start, end = _parse_business_hours()
    assert (start.hour, start.minute) == (9, 30)
    assert (end.hour, end.minute) == (17, 15)


def test_business_hours_range_returns_todays_window_so_far(monkeypatch):
    import datetime

    import app.threat_stats_cache as cache_mod
    from app.threat_stats_cache import _business_hours_range

    # See test_parse_business_hours_respects_config for why we monkeypatch
    # cache_mod.Config rather than app.config.Config.
    monkeypatch.setattr(cache_mod.Config, "ADMIN_ACCESS_BUSINESS_HOURS", "08:00-18:00")
    monkeypatch.setattr(cache_mod.Config, "ADMIN_ACCESS_TIMEZONE", "UTC")

    class FakeClient:
        def local_time_range(self, start_iso, end_iso):
            return (start_iso, end_iso)  # identity passthrough for this test

    now_utc = datetime.datetime(2026, 9, 11, 14, 0, 0, tzinfo=datetime.timezone.utc)
    result = _business_hours_range(FakeClient(), now_utc)
    assert result is not None
    start_iso, end_iso = result
    assert start_iso.startswith("2026-09-11T08:00:00")
    assert end_iso.startswith("2026-09-11T14:00:00")  # clamped to "now", not 18:00


def test_business_hours_range_returns_none_before_business_hours_start(monkeypatch):
    import datetime

    import app.threat_stats_cache as cache_mod
    from app.threat_stats_cache import _business_hours_range

    # See test_parse_business_hours_respects_config for why we monkeypatch
    # cache_mod.Config rather than app.config.Config.
    monkeypatch.setattr(cache_mod.Config, "ADMIN_ACCESS_BUSINESS_HOURS", "08:00-18:00")
    monkeypatch.setattr(cache_mod.Config, "ADMIN_ACCESS_TIMEZONE", "UTC")

    class FakeClient:
        def local_time_range(self, start_iso, end_iso):
            return (start_iso, end_iso)

    now_utc = datetime.datetime(2026, 9, 11, 5, 0, 0, tzinfo=datetime.timezone.utc)
    assert _business_hours_range(FakeClient(), now_utc) is None


def test_business_hours_range_returns_none_for_malformed_business_hours(monkeypatch):
    import datetime

    import app.threat_stats_cache as cache_mod
    from app.threat_stats_cache import _business_hours_range

    # See test_parse_business_hours_respects_config for why we monkeypatch
    # cache_mod.Config rather than app.config.Config.
    monkeypatch.setattr(cache_mod.Config, "ADMIN_ACCESS_BUSINESS_HOURS", "garbage")
    monkeypatch.setattr(cache_mod.Config, "ADMIN_ACCESS_TIMEZONE", "UTC")

    class FakeClient:
        def local_time_range(self, start_iso, end_iso):
            return (start_iso, end_iso)

    now_utc = datetime.datetime(2026, 9, 11, 14, 0, 0, tzinfo=datetime.timezone.utc)
    assert _business_hours_range(FakeClient(), now_utc) is None  # must not raise


def test_business_hours_range_returns_none_for_invalid_timezone(monkeypatch):
    import datetime

    import app.threat_stats_cache as cache_mod
    from app.threat_stats_cache import _business_hours_range

    # See test_parse_business_hours_respects_config for why we monkeypatch
    # cache_mod.Config rather than app.config.Config.
    monkeypatch.setattr(cache_mod.Config, "ADMIN_ACCESS_BUSINESS_HOURS", "08:00-18:00")
    monkeypatch.setattr(cache_mod.Config, "ADMIN_ACCESS_TIMEZONE", "Not/AZone")

    class FakeClient:
        def local_time_range(self, start_iso, end_iso):
            return (start_iso, end_iso)

    now_utc = datetime.datetime(2026, 9, 11, 14, 0, 0, tzinfo=datetime.timezone.utc)
    assert _business_hours_range(FakeClient(), now_utc) is None  # must not raise


def test_poll_all_targets_zero_detections_gives_zero_blocked_pct(
    targets_file, history_db, monkeypatch
):
    import app.threat_stats_cache as cache_mod

    _stub_client(
        monkeypatch,
        alert_counts_by_filter={
            "ackflag=no": 0,
            "ackflag=no and severity=critical": 0,
            "ackflag=no and severity=high": 0,
            "ackflag=no and severity=medium": 0,
            "ackflag=no and severity=low": 0,
        },
        fortiview_rows_by_view={
            "top-type": [],
            "top-threats": [],
            "top-countries": [],
            "admin-logins": [],
            "failed-authentication-attempts": [],
            "site-to-site-ipsec": [],
            "ssl-dialup-ipsec": [],
        },
    )

    cache_mod.poll_all_targets()

    cached = cache_mod.get_cached()
    assert cached["ips_blocked_pct"] == 0.0
    assert cached["collected_at"] is not None


def test_poll_all_targets_populates_admin_access_fields(targets_file, history_db, monkeypatch):
    import app.threat_stats_cache as cache_mod
    from app.threat_stats_history import get_latest_rollup

    _stub_client(
        monkeypatch,
        alert_counts_by_filter={
            "ackflag=no": 0,
            "ackflag=no and severity=critical": 0,
            "ackflag=no and severity=high": 0,
            "ackflag=no and severity=medium": 0,
            "ackflag=no and severity=low": 0,
        },
        fortiview_rows_by_view={
            "top-type": [],
            "top-threats": [],
            "top-countries": [],
            "admin-logins": [
                # Call 1: full 24h window.
                [
                    {"fortigate": "FGT-A", "f_user": "admin", "login_num": 10, "login_fail_num": 3},
                    {"fortigate": "FGT-B", "f_user": "svc", "login_num": 2, "login_fail_num": 0},
                ],
                # Call 2: business-hours-so-far window.
                [
                    {"fortigate": "FGT-A", "f_user": "admin", "login_num": 6, "login_fail_num": 1},
                ],
            ],
            "failed-authentication-attempts": [
                {"fortigate": "FGT-A", "src_ip": "203.0.113.5", "total_num": 3},
                {"fortigate": "FGT-A", "src_ip": "203.0.113.9", "total_num": 1},
            ],
            "site-to-site-ipsec": [],
            "ssl-dialup-ipsec": [],
        },
        local_time_range=("2026-09-11T08:00:00", "2026-09-11T14:00:00"),
    )

    cache_mod.poll_all_targets()

    cached = cache_mod.get_cached()
    # Sum of login_fail_num across admin-logins 24h rows.
    assert cached["failed_admin_logins_24h"] == 3
    assert cached["devices_with_failed_logins"] == 1  # only FGT-A has login_fail_num > 0
    assert cached["top_failed_sources"] == [
        {"source": "203.0.113.5", "count": 3},
        {"source": "203.0.113.9", "count": 1},
    ]
    # total login_num (24h) = 10 + 2 = 12; business-hours login_num = 6;
    # outside_hours = max(12 - 6, 0) = 6
    assert cached["admin_logins_outside_hours_24h"] == 6

    rollup = get_latest_rollup()
    assert rollup["failed_admin_logins_24h"] == 3
    assert rollup["devices_with_failed_logins"] == 1
    assert rollup["admin_logins_outside_hours_24h"] == 6


def test_poll_all_targets_admin_logins_business_hours_call_uses_different_time_range(
    targets_file, history_db, monkeypatch
):
    """The second "admin-logins" call (business-hours window) must receive a
    DIFFERENT time_range than the first "admin-logins" call (24h window) —
    otherwise business_logins == total_logins_24h always and
    admin_logins_outside_hours_24h is permanently 0."""
    import app.threat_stats_cache as cache_mod

    business_sentinel = ("2026-09-11T08:00:00", "2026-09-11T10:00:00")

    def fake_get_alert_counts(self, adom, filter):
        return 0

    admin_logins_rows_by_call = [
        [{"fortigate": "FGT-A", "f_user": "admin", "login_num": 10, "login_fail_num": 3}],
        [{"fortigate": "FGT-A", "f_user": "admin", "login_num": 4, "login_fail_num": 1}],
    ]
    admin_logins_call_count = {"n": 0}
    captured_admin_logins_time_ranges = []

    def fake_run_fortiview(self, adom, view, time_range, limit=1000, filter=None, **_kw):
        if view == "admin-logins":
            idx = admin_logins_call_count["n"]
            admin_logins_call_count["n"] = idx + 1
            captured_admin_logins_time_ranges.append(time_range)
            return admin_logins_rows_by_call[idx]
        return []

    monkeypatch.setattr("app.faz_client.FAZClient.get_alert_counts", fake_get_alert_counts)
    monkeypatch.setattr("app.faz_client.FAZClient.run_fortiview", fake_run_fortiview)
    monkeypatch.setattr("app.faz_client.FAZClient.logout", lambda self: None)
    # Identity passthrough so the 24h window and the business-hours window
    # naturally produce different strings instead of colliding on one
    # fixed sentinel tuple.
    monkeypatch.setattr(
        "app.faz_client.FAZClient.local_time_range",
        lambda self, start_iso, end_iso: (start_iso, end_iso),
    )
    monkeypatch.setattr(
        "app.threat_stats_cache._business_hours_range",
        lambda client, now: business_sentinel,
    )

    cache_mod.poll_all_targets()

    assert len(captured_admin_logins_time_ranges) == 2
    first_call_time_range, second_call_time_range = captured_admin_logins_time_ranges
    assert first_call_time_range != second_call_time_range
    assert second_call_time_range == business_sentinel

    # total login_num (24h) = 10; business-hours login_num = 4;
    # outside_hours = max(10 - 4, 0) = 6
    assert cache_mod.get_cached()["admin_logins_outside_hours_24h"] == 6


def test_poll_all_targets_admin_access_zero_when_business_hours_havent_started(
    targets_file, history_db, monkeypatch
):
    """When _business_hours_range returns None (business hours haven't
    started yet today), only ONE admin-logins call happens — all logins in
    the 24h window count as outside-hours."""
    import app.threat_stats_cache as cache_mod

    _stub_client(
        monkeypatch,
        alert_counts_by_filter={
            "ackflag=no": 0,
            "ackflag=no and severity=critical": 0,
            "ackflag=no and severity=high": 0,
            "ackflag=no and severity=medium": 0,
            "ackflag=no and severity=low": 0,
        },
        fortiview_rows_by_view={
            "top-type": [],
            "top-threats": [],
            "top-countries": [],
            "admin-logins": [
                {"fortigate": "FGT-A", "f_user": "admin", "login_num": 5, "login_fail_num": 0},
            ],
            "failed-authentication-attempts": [],
            "site-to-site-ipsec": [],
            "ssl-dialup-ipsec": [],
        },
        local_time_range=("2026-09-11T00:00:00", "2026-09-11T05:00:00"),
    )
    # Force _business_hours_range to return None regardless of wall-clock time.
    monkeypatch.setattr("app.threat_stats_cache._business_hours_range", lambda client, now: None)

    cache_mod.poll_all_targets()

    cached = cache_mod.get_cached()
    assert cached["admin_logins_outside_hours_24h"] == 5


def test_poll_all_targets_populates_vpn_fields(targets_file, history_db, monkeypatch):
    import app.threat_stats_cache as cache_mod
    from app.threat_stats_history import get_latest_rollup

    _stub_client(
        monkeypatch,
        alert_counts_by_filter={
            "ackflag=no": 0,
            "ackflag=no and severity=critical": 0,
            "ackflag=no and severity=high": 0,
            "ackflag=no and severity=medium": 0,
            "ackflag=no and severity=low": 0,
        },
        fortiview_rows_by_view={
            "top-type": [],
            "top-threats": [],
            "top-countries": [],
            "admin-logins": [],
            "failed-authentication-attempts": [],
            "site-to-site-ipsec": [
                # Tunnel A: one open session (no e_time) -> up.
                {"vpnname": "Tunnel-A", "e_time": 0, "locip": "10.0.0.1", "remip": "203.0.113.1"},
                # Tunnel B: one closed session (has e_time) -> down (seen, but not currently open).
                {
                    "vpnname": "Tunnel-B",
                    "e_time": 1757600000,
                    "locip": "10.0.0.2",
                    "remip": "203.0.113.2",
                },
                # Tunnel B again, still closed in this row too.
                {
                    "vpnname": "Tunnel-B",
                    "e_time": 1757600100,
                    "locip": "10.0.0.2",
                    "remip": "203.0.113.2",
                },
            ],
            "ssl-dialup-ipsec": [
                {"f_user": "alice", "end_time": 0, "remip": "198.51.100.1"},  # connected now
                {"f_user": "bob", "end_time": 1757600200, "remip": "198.51.100.2"},  # disconnected
            ],
        },
        local_time_range=("2026-09-10T08:00:00", "2026-09-11T08:00:00"),
    )

    cache_mod.poll_all_targets()

    cached = cache_mod.get_cached()
    assert cached["ipsec_tunnels_total"] == 2  # Tunnel-A, Tunnel-B
    assert cached["ipsec_tunnels_down"] == 1  # only Tunnel-B has no open session
    assert cached["ssl_vpn_users_now"] == 1  # only alice has an open session

    rollup = get_latest_rollup()
    assert rollup["ipsec_tunnels_total"] == 2
    assert rollup["ipsec_tunnels_down"] == 1
    assert rollup["ssl_vpn_users_now"] == 1


def test_poll_all_targets_vpn_fields_zero_when_no_sessions(targets_file, history_db, monkeypatch):
    import app.threat_stats_cache as cache_mod

    _stub_client(
        monkeypatch,
        alert_counts_by_filter={
            "ackflag=no": 0,
            "ackflag=no and severity=critical": 0,
            "ackflag=no and severity=high": 0,
            "ackflag=no and severity=medium": 0,
            "ackflag=no and severity=low": 0,
        },
        fortiview_rows_by_view={
            "top-type": [],
            "top-threats": [],
            "top-countries": [],
            "admin-logins": [],
            "failed-authentication-attempts": [],
            "site-to-site-ipsec": [],
            "ssl-dialup-ipsec": [],
        },
        local_time_range=("2026-09-10T08:00:00", "2026-09-11T08:00:00"),
    )

    cache_mod.poll_all_targets()

    cached = cache_mod.get_cached()
    assert cached["ipsec_tunnels_total"] == 0
    assert cached["ipsec_tunnels_down"] == 0
    assert cached["ssl_vpn_users_now"] == 0
