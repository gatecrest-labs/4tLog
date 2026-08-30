"""SQLite-backed history of fleet-wide log-volume rollups, one row per
log_stats_cache poll cycle. Exists so the /external/api/executive/summary
route can serve the last-known state immediately after a restart, before
the first new poll completes, instead of returning nulls for one full
poll interval. Schema mirrors 4tExecutive's metrics_db.py snapshots table.
"""

from __future__ import annotations

import contextlib
import datetime
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "logstats.db"


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(DB_PATH)


def init_db() -> None:
    with contextlib.closing(_connect()) as conn, conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS log_volume_history (
                collected_at TEXT NOT NULL,
                devices_logging INTEGER NOT NULL,
                devices_silent INTEGER NOT NULL,
                total_lograte REAL NOT NULL
            )
            """
        )


def write_rollup(
    devices_logging: int, devices_silent: int, total_lograte: float, collected_at: str
) -> None:
    with contextlib.closing(_connect()) as conn, conn:
        conn.execute(
            "INSERT INTO log_volume_history "
            "(collected_at, devices_logging, devices_silent, total_lograte) VALUES (?, ?, ?, ?)",
            (collected_at, devices_logging, devices_silent, total_lograte),
        )


def get_latest_rollup() -> dict | None:
    with contextlib.closing(_connect()) as conn, conn:
        row = conn.execute(
            "SELECT collected_at, devices_logging, devices_silent, total_lograte "
            "FROM log_volume_history ORDER BY collected_at DESC LIMIT 1"
        ).fetchone()
    if row is None:
        return None
    collected_at, devices_logging, devices_silent, total_lograte = row
    return {
        "collected_at": collected_at,
        "devices_logging": devices_logging,
        "devices_silent": devices_silent,
        "total_lograte": total_lograte,
    }


def prune_old_rows(retention_days: int = 30) -> None:
    cutoff = (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=retention_days)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    with contextlib.closing(_connect()) as conn, conn:
        conn.execute("DELETE FROM log_volume_history WHERE collected_at < ?", (cutoff,))
