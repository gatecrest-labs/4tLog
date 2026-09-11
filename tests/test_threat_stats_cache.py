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

    def fake_run_fortiview(self, adom, view, time_range, limit=1000, filter=None, **_kw):
        return fortiview_rows_by_view[view]

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

    cache_mod.poll_all_targets()

    assert captured_time_ranges == [sentinel, sentinel, sentinel]


def test_parse_business_hours_default():
    from app.threat_stats_cache import _parse_business_hours

    start, end = _parse_business_hours()
    assert start.hour == 8 and start.minute == 0
    assert end.hour == 18 and end.minute == 0


def test_parse_business_hours_respects_config(monkeypatch):
    from app.config import Config
    from app.threat_stats_cache import _parse_business_hours

    monkeypatch.setattr(Config, "ADMIN_ACCESS_BUSINESS_HOURS", "09:30-17:15")
    start, end = _parse_business_hours()
    assert (start.hour, start.minute) == (9, 30)
    assert (end.hour, end.minute) == (17, 15)


def test_business_hours_range_returns_todays_window_so_far(monkeypatch):
    import datetime

    from app.config import Config
    from app.threat_stats_cache import _business_hours_range

    monkeypatch.setattr(Config, "ADMIN_ACCESS_BUSINESS_HOURS", "08:00-18:00")
    monkeypatch.setattr(Config, "ADMIN_ACCESS_TIMEZONE", "UTC")

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

    from app.config import Config
    from app.threat_stats_cache import _business_hours_range

    monkeypatch.setattr(Config, "ADMIN_ACCESS_BUSINESS_HOURS", "08:00-18:00")
    monkeypatch.setattr(Config, "ADMIN_ACCESS_TIMEZONE", "UTC")

    class FakeClient:
        def local_time_range(self, start_iso, end_iso):
            return (start_iso, end_iso)

    now_utc = datetime.datetime(2026, 9, 11, 5, 0, 0, tzinfo=datetime.timezone.utc)
    assert _business_hours_range(FakeClient(), now_utc) is None


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
        fortiview_rows_by_view={"top-type": [], "top-threats": [], "top-countries": []},
    )

    cache_mod.poll_all_targets()

    assert cache_mod.get_cached()["ips_blocked_pct"] == 0.0
