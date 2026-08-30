"""SQLite-backed history of host CPU/Memory/Disk utilization, one row per
app.host_metrics_cache poll cycle. Schema/pattern mirrors
app/log_stats_history.py, extended with a range query since the Admin >
Host Metrics panel charts trends over a selectable window rather than only
ever needing the latest value.
"""

from __future__ import annotations

import contextlib
import datetime
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "hostmetrics.db"

RANGES: dict[str, datetime.timedelta] = {
    "1h": datetime.timedelta(hours=1),
    "4h": datetime.timedelta(hours=4),
    "12h": datetime.timedelta(hours=12),
    "1d": datetime.timedelta(days=1),
    "7d": datetime.timedelta(days=7),
    "14d": datetime.timedelta(days=14),
}
DEFAULT_RANGE = "1h"


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(DB_PATH)


def init_db() -> None:
    with contextlib.closing(_connect()) as conn, conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS host_metrics_history (
                collected_at TEXT NOT NULL,
                cpu_percent REAL NOT NULL,
                memory_percent REAL NOT NULL,
                disk_percent REAL NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_host_metrics_collected_at "
            "ON host_metrics_history (collected_at)"
        )


def write_snapshot(
    cpu_percent: float, memory_percent: float, disk_percent: float, collected_at: str
) -> None:
    with contextlib.closing(_connect()) as conn, conn:
        conn.execute(
            "INSERT INTO host_metrics_history "
            "(collected_at, cpu_percent, memory_percent, disk_percent) VALUES (?, ?, ?, ?)",
            (collected_at, cpu_percent, memory_percent, disk_percent),
        )


def get_history(since: str) -> list[dict]:
    with contextlib.closing(_connect()) as conn, conn:
        rows = conn.execute(
            "SELECT collected_at, cpu_percent, memory_percent, disk_percent "
            "FROM host_metrics_history WHERE collected_at >= ? ORDER BY collected_at ASC",
            (since,),
        ).fetchall()
    return [
        {
            "collected_at": collected_at,
            "cpu_percent": cpu_percent,
            "memory_percent": memory_percent,
            "disk_percent": disk_percent,
        }
        for collected_at, cpu_percent, memory_percent, disk_percent in rows
    ]


def prune_old_rows(retention_days: int = 30) -> None:
    cutoff = (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=retention_days)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    with contextlib.closing(_connect()) as conn, conn:
        conn.execute("DELETE FROM host_metrics_history WHERE collected_at < ?", (cutoff,))
