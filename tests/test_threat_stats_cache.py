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


def _stub_client(monkeypatch, alert_counts_by_filter, fortiview_rows_by_view):
    def fake_get_alert_counts(self, adom, filter):
        return alert_counts_by_filter[filter]

    def fake_run_fortiview(self, adom, view, time_range, limit=1000, filter=None, **_kw):
        return fortiview_rows_by_view[view]

    monkeypatch.setattr("app.faz_client.FAZClient.get_alert_counts", fake_get_alert_counts)
    monkeypatch.setattr("app.faz_client.FAZClient.run_fortiview", fake_run_fortiview)
    monkeypatch.setattr("app.faz_client.FAZClient.logout", lambda self: None)


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
