import datetime

import pytest


@pytest.fixture
def history_db(tmp_path, monkeypatch):
    path = tmp_path / "hostmetrics.db"
    import app.host_metrics_history as history_mod

    monkeypatch.setattr(history_mod, "DB_PATH", path)
    history_mod.init_db()
    yield path


def test_get_history_empty_when_no_rows(history_db):
    from app.host_metrics_history import get_history

    assert get_history("2020-01-01T00:00:00Z") == []


def test_write_and_read_history_in_range(history_db):
    from app.host_metrics_history import get_history, write_snapshot

    write_snapshot(
        cpu_percent=10.0, memory_percent=40.0, disk_percent=55.0,
        collected_at="2026-08-29T09:00:00Z",
    )
    write_snapshot(
        cpu_percent=12.5, memory_percent=41.0, disk_percent=55.5,
        collected_at="2026-08-29T09:05:00Z",
    )

    rows = get_history("2026-08-29T09:00:00Z")

    assert rows == [
        {"collected_at": "2026-08-29T09:00:00Z", "cpu_percent": 10.0, "memory_percent": 40.0, "disk_percent": 55.0},
        {"collected_at": "2026-08-29T09:05:00Z", "cpu_percent": 12.5, "memory_percent": 41.0, "disk_percent": 55.5},
    ]


def test_get_history_excludes_rows_before_since(history_db):
    from app.host_metrics_history import get_history, write_snapshot

    write_snapshot(
        cpu_percent=10.0, memory_percent=40.0, disk_percent=55.0,
        collected_at="2026-08-29T08:00:00Z",
    )
    write_snapshot(
        cpu_percent=12.5, memory_percent=41.0, disk_percent=55.5,
        collected_at="2026-08-29T09:05:00Z",
    )

    rows = get_history("2026-08-29T09:00:00Z")

    assert rows == [
        {"collected_at": "2026-08-29T09:05:00Z", "cpu_percent": 12.5, "memory_percent": 41.0, "disk_percent": 55.5},
    ]


def test_prune_old_rows_removes_rows_past_retention(history_db):
    from app.host_metrics_history import prune_old_rows, write_snapshot

    old_ts = (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=40)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    recent_ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    write_snapshot(cpu_percent=1.0, memory_percent=1.0, disk_percent=1.0, collected_at=old_ts)
    write_snapshot(cpu_percent=2.0, memory_percent=2.0, disk_percent=2.0, collected_at=recent_ts)

    prune_old_rows(retention_days=30)

    import sqlite3

    import app.host_metrics_history as history_mod

    conn = sqlite3.connect(history_mod.DB_PATH)
    rows = conn.execute("SELECT collected_at FROM host_metrics_history").fetchall()
    conn.close()
    assert rows == [(recent_ts,)]
