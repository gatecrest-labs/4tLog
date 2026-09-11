"""SQLite-backed history of fleet-wide threat-activity rollups, one row per
threat_stats_cache poll cycle. Lives in the same logstats.db file as
app/log_stats_history.py — a separate table, same database. Exists so
GET /external/api/executive/summary can serve the last-known "threats" state
immediately after a restart, before the first new poll completes."""

from __future__ import annotations

import contextlib
import datetime
import json
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
            CREATE TABLE IF NOT EXISTS threat_stats_history (
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


def write_rollup(
    alerts_unacked_total: int,
    alerts_unacked_by_severity: dict,
    ips_detections_24h: int,
    ips_blocked_24h: int,
    ips_blocked_pct: float,
    top_signatures: list[dict],
    top_source_countries: list[dict],
    collected_at: str,
) -> None:
    with contextlib.closing(_connect()) as conn, conn:
        conn.execute(
            "INSERT INTO threat_stats_history "
            "(collected_at, alerts_unacked_total, alerts_unacked_by_severity, "
            "ips_detections_24h, ips_blocked_24h, ips_blocked_pct, "
            "top_signatures, top_source_countries) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                collected_at,
                alerts_unacked_total,
                json.dumps(alerts_unacked_by_severity),
                ips_detections_24h,
                ips_blocked_24h,
                ips_blocked_pct,
                json.dumps(top_signatures),
                json.dumps(top_source_countries),
            ),
        )


def get_latest_rollup() -> dict | None:
    with contextlib.closing(_connect()) as conn, conn:
        row = conn.execute(
            "SELECT collected_at, alerts_unacked_total, alerts_unacked_by_severity, "
            "ips_detections_24h, ips_blocked_24h, ips_blocked_pct, "
            "top_signatures, top_source_countries "
            "FROM threat_stats_history ORDER BY collected_at DESC LIMIT 1"
        ).fetchone()
    if row is None:
        return None
    (
        collected_at,
        alerts_unacked_total,
        alerts_unacked_by_severity,
        ips_detections_24h,
        ips_blocked_24h,
        ips_blocked_pct,
        top_signatures,
        top_source_countries,
    ) = row
    return {
        "collected_at": collected_at,
        "alerts_unacked_total": alerts_unacked_total,
        "alerts_unacked_by_severity": json.loads(alerts_unacked_by_severity),
        "ips_detections_24h": ips_detections_24h,
        "ips_blocked_24h": ips_blocked_24h,
        "ips_blocked_pct": ips_blocked_pct,
        "top_signatures": json.loads(top_signatures),
        "top_source_countries": json.loads(top_source_countries),
    }


def prune_old_rows(retention_days: int = 30) -> None:
    cutoff = (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=retention_days)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    with contextlib.closing(_connect()) as conn, conn:
        conn.execute("DELETE FROM threat_stats_history WHERE collected_at < ?", (cutoff,))
