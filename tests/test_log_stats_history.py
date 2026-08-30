import datetime

import pytest


@pytest.fixture
def history_db(tmp_path, monkeypatch):
    path = tmp_path / "logstats.db"
    import app.log_stats_history as history_mod

    monkeypatch.setattr(history_mod, "DB_PATH", path)
    history_mod.init_db()
    yield path


def test_get_latest_rollup_none_when_empty(history_db):
    from app.log_stats_history import get_latest_rollup

    assert get_latest_rollup() is None


def test_write_and_read_latest_rollup(history_db):
    from app.log_stats_history import get_latest_rollup, write_rollup

    write_rollup(devices_logging=10, devices_silent=1, total_lograte=42.5, collected_at="2026-08-29T09:00:00Z")
    write_rollup(devices_logging=11, devices_silent=0, total_lograte=50.0, collected_at="2026-08-29T09:05:00Z")

    latest = get_latest_rollup()
    assert latest == {
        "devices_logging": 11,
        "devices_silent": 0,
        "total_lograte": 50.0,
        "collected_at": "2026-08-29T09:05:00Z",
    }


def test_prune_old_rows_removes_rows_past_retention(history_db):
    from app.log_stats_history import get_latest_rollup, prune_old_rows, write_rollup

    old_ts = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=40)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    recent_ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    write_rollup(devices_logging=1, devices_silent=0, total_lograte=1.0, collected_at=old_ts)
    write_rollup(devices_logging=2, devices_silent=0, total_lograte=2.0, collected_at=recent_ts)

    prune_old_rows(retention_days=30)

    import sqlite3

    import app.log_stats_history as history_mod

    conn = sqlite3.connect(history_mod.DB_PATH)
    rows = conn.execute("SELECT collected_at FROM log_volume_history").fetchall()
    conn.close()
    assert rows == [(recent_ts,)]
