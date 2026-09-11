import pytest


@pytest.fixture
def history_db(tmp_path, monkeypatch):
    path = tmp_path / "logstats.db"
    import app.threat_stats_history as history_mod

    monkeypatch.setattr(history_mod, "DB_PATH", path)
    history_mod.init_db()
    yield path


def test_write_and_get_latest_rollup(history_db):
    from app.threat_stats_history import get_latest_rollup, write_rollup

    write_rollup(
        alerts_unacked_total=5,
        alerts_unacked_by_severity={"critical": 1, "high": 2, "medium": 1, "low": 1},
        ips_detections_24h=100,
        ips_blocked_24h=80,
        ips_blocked_pct=80.0,
        top_signatures=[{"signature": "Eicar.Test.Virus", "count": 40}],
        top_source_countries=[{"country": "China", "count": 60}],
        collected_at="2026-09-11T00:00:00+00:00",
    )
    rollup = get_latest_rollup()
    assert rollup["alerts_unacked_total"] == 5
    assert rollup["alerts_unacked_by_severity"] == {"critical": 1, "high": 2, "medium": 1, "low": 1}
    assert rollup["ips_detections_24h"] == 100
    assert rollup["ips_blocked_24h"] == 80
    assert rollup["ips_blocked_pct"] == 80.0
    assert rollup["top_signatures"] == [{"signature": "Eicar.Test.Virus", "count": 40}]
    assert rollup["top_source_countries"] == [{"country": "China", "count": 60}]
    assert rollup["collected_at"] == "2026-09-11T00:00:00+00:00"


def test_get_latest_rollup_returns_none_when_empty(history_db):
    from app.threat_stats_history import get_latest_rollup

    assert get_latest_rollup() is None


def test_get_latest_rollup_returns_most_recent_row(history_db):
    from app.threat_stats_history import get_latest_rollup, write_rollup

    write_rollup(
        alerts_unacked_total=1,
        alerts_unacked_by_severity={},
        ips_detections_24h=0,
        ips_blocked_24h=0,
        ips_blocked_pct=0.0,
        top_signatures=[],
        top_source_countries=[],
        collected_at="2026-09-10T00:00:00+00:00",
    )
    write_rollup(
        alerts_unacked_total=9,
        alerts_unacked_by_severity={},
        ips_detections_24h=0,
        ips_blocked_24h=0,
        ips_blocked_pct=0.0,
        top_signatures=[],
        top_source_countries=[],
        collected_at="2026-09-11T00:00:00+00:00",
    )
    assert get_latest_rollup()["alerts_unacked_total"] == 9


def test_prune_old_rows_removes_rows_older_than_retention(history_db):
    import datetime

    from app.threat_stats_history import get_latest_rollup, prune_old_rows, write_rollup

    old_ts = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=40)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    write_rollup(
        alerts_unacked_total=1,
        alerts_unacked_by_severity={},
        ips_detections_24h=0,
        ips_blocked_24h=0,
        ips_blocked_pct=0.0,
        top_signatures=[],
        top_source_countries=[],
        collected_at=old_ts,
    )
    prune_old_rows(retention_days=30)
    assert get_latest_rollup() is None
