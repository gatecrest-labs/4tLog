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
        failed_admin_logins_24h=0,
        devices_with_failed_logins=0,
        top_failed_sources=[],
        admin_logins_outside_hours_24h=0,
        ipsec_tunnels_total=0,
        ipsec_tunnels_down=0,
        ssl_vpn_users_now=0,
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
        failed_admin_logins_24h=0,
        devices_with_failed_logins=0,
        top_failed_sources=[],
        admin_logins_outside_hours_24h=0,
        ipsec_tunnels_total=0,
        ipsec_tunnels_down=0,
        ssl_vpn_users_now=0,
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
        failed_admin_logins_24h=0,
        devices_with_failed_logins=0,
        top_failed_sources=[],
        admin_logins_outside_hours_24h=0,
        ipsec_tunnels_total=0,
        ipsec_tunnels_down=0,
        ssl_vpn_users_now=0,
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
        failed_admin_logins_24h=0,
        devices_with_failed_logins=0,
        top_failed_sources=[],
        admin_logins_outside_hours_24h=0,
        ipsec_tunnels_total=0,
        ipsec_tunnels_down=0,
        ssl_vpn_users_now=0,
        collected_at=old_ts,
    )
    prune_old_rows(retention_days=30)
    assert get_latest_rollup() is None


def test_write_and_get_latest_rollup_includes_admin_access_fields(history_db):
    from app.threat_stats_history import get_latest_rollup, write_rollup

    write_rollup(
        alerts_unacked_total=5,
        alerts_unacked_by_severity={"critical": 1, "high": 2, "medium": 1, "low": 1},
        ips_detections_24h=100,
        ips_blocked_24h=80,
        ips_blocked_pct=80.0,
        top_signatures=[{"signature": "Eicar.Test.Virus", "count": 40}],
        top_source_countries=[{"country": "China", "count": 60}],
        failed_admin_logins_24h=7,
        devices_with_failed_logins=2,
        top_failed_sources=[{"source": "203.0.113.5", "count": 4}],
        admin_logins_outside_hours_24h=3,
        ipsec_tunnels_total=0,
        ipsec_tunnels_down=0,
        ssl_vpn_users_now=0,
        collected_at="2026-09-11T00:00:00+00:00",
    )
    rollup = get_latest_rollup()
    assert rollup["failed_admin_logins_24h"] == 7
    assert rollup["devices_with_failed_logins"] == 2
    assert rollup["top_failed_sources"] == [{"source": "203.0.113.5", "count": 4}]
    assert rollup["admin_logins_outside_hours_24h"] == 3


def test_init_db_migrates_pre_existing_table_missing_admin_access_columns(tmp_path, monkeypatch):
    import sqlite3

    import app.threat_stats_history as history_mod

    path = tmp_path / "logstats.db"
    monkeypatch.setattr(history_mod, "DB_PATH", path)

    # Simulate a database created by the OLD (pre-this-task) 8-column schema —
    # no failed_admin_logins_24h/devices_with_failed_logins/top_failed_sources/
    # admin_logins_outside_hours_24h columns, with one existing row.
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE threat_stats_history (
            collected_at TEXT NOT NULL,
            alerts_unacked_total INTEGER NOT NULL,
            alerts_unacked_by_severity TEXT NOT NULL,
            ips_detections_24h INTEGER NOT NULL,
            ips_blocked_24h INTEGER NOT NULL,
            ips_blocked_pct REAL NOT NULL,
            top_signatures TEXT NOT NULL,
            top_source_countries TEXT NOT NULL
        )
        """
    )
    conn.execute(
        "INSERT INTO threat_stats_history VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ("2026-09-10T00:00:00+00:00", 1, "{}", 0, 0, 0.0, "[]", "[]"),
    )
    conn.commit()
    conn.close()

    history_mod.init_db()  # must not raise, must add the 4 new columns

    rollup = history_mod.get_latest_rollup()
    assert rollup["collected_at"] == "2026-09-10T00:00:00+00:00"
    assert rollup["failed_admin_logins_24h"] == 0
    assert rollup["devices_with_failed_logins"] == 0
    assert rollup["top_failed_sources"] == []
    assert rollup["admin_logins_outside_hours_24h"] == 0

    # A second init_db() call (e.g. app restart) against the now-migrated
    # table must also be a no-op, not raise "duplicate column".
    history_mod.init_db()


def test_write_and_get_latest_rollup_includes_vpn_fields(history_db):
    from app.threat_stats_history import get_latest_rollup, write_rollup

    write_rollup(
        alerts_unacked_total=5,
        alerts_unacked_by_severity={"critical": 1, "high": 2, "medium": 1, "low": 1},
        ips_detections_24h=100,
        ips_blocked_24h=80,
        ips_blocked_pct=80.0,
        top_signatures=[{"signature": "Eicar.Test.Virus", "count": 40}],
        top_source_countries=[{"country": "China", "count": 60}],
        failed_admin_logins_24h=7,
        devices_with_failed_logins=2,
        top_failed_sources=[{"source": "203.0.113.5", "count": 4}],
        admin_logins_outside_hours_24h=3,
        ipsec_tunnels_total=6,
        ipsec_tunnels_down=1,
        ssl_vpn_users_now=12,
        collected_at="2026-09-11T00:00:00+00:00",
    )
    rollup = get_latest_rollup()
    assert rollup["ipsec_tunnels_total"] == 6
    assert rollup["ipsec_tunnels_down"] == 1
    assert rollup["ssl_vpn_users_now"] == 12


def test_init_db_migrates_pre_existing_table_missing_vpn_columns(tmp_path, monkeypatch):
    import sqlite3

    import app.threat_stats_history as history_mod

    path = tmp_path / "logstats.db"
    monkeypatch.setattr(history_mod, "DB_PATH", path)

    # Simulate a database created by the admin-access-era 12-column schema —
    # no ipsec_tunnels_total/ipsec_tunnels_down/ssl_vpn_users_now columns,
    # with one existing row.
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE threat_stats_history (
            collected_at TEXT NOT NULL,
            alerts_unacked_total INTEGER NOT NULL,
            alerts_unacked_by_severity TEXT NOT NULL,
            ips_detections_24h INTEGER NOT NULL,
            ips_blocked_24h INTEGER NOT NULL,
            ips_blocked_pct REAL NOT NULL,
            top_signatures TEXT NOT NULL,
            top_source_countries TEXT NOT NULL,
            failed_admin_logins_24h INTEGER NOT NULL DEFAULT 0,
            devices_with_failed_logins INTEGER NOT NULL DEFAULT 0,
            top_failed_sources TEXT NOT NULL DEFAULT '[]',
            admin_logins_outside_hours_24h INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    conn.execute(
        "INSERT INTO threat_stats_history VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("2026-09-10T00:00:00+00:00", 1, "{}", 0, 0, 0.0, "[]", "[]", 0, 0, "[]", 0),
    )
    conn.commit()
    conn.close()

    history_mod.init_db()  # must not raise, must add the 3 new columns

    rollup = history_mod.get_latest_rollup()
    assert rollup["collected_at"] == "2026-09-10T00:00:00+00:00"
    assert rollup["ipsec_tunnels_total"] == 0
    assert rollup["ipsec_tunnels_down"] == 0
    assert rollup["ssl_vpn_users_now"] == 0

    # A second init_db() call (e.g. app restart) against the now-migrated
    # table must also be a no-op, not raise "duplicate column".
    history_mod.init_db()
