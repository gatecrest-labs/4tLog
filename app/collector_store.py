"""Shared SQLite-backed store (WAL mode) for cross-process cache
read-through.

Part of the collector/web process split: only the collector process
(`python -m app.collector`) runs BackgroundScheduler jobs and performs live
FAZ/SNMP polls. Web worker processes never poll; instead, each *_cache
module's get_cached()/get_all_cached() falls back to reading the
collector's last-written snapshot from this store when its own in-memory
cache is still empty (e.g. right after a web process starts, before it has
ever polled anything itself — which, by design, is always, once
RUN_SCHEDULERS is not "inline").

WAL (write-ahead logging) mode lets one process write while others read
concurrently without blocking — appropriate here since the collector
writes on its own poll cadence while web workers read on every request.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
from pathlib import Path

from app.config import Config

DB_PATH = Path(Config.DATA_DIR) / "collector_state.db"


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    with contextlib.closing(_connect()) as conn, conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cache_state (
                cache_key TEXT PRIMARY KEY,
                payload TEXT NOT NULL,
                collected_at TEXT
            )
            """
        )


def write_cache(cache_key: str, data: dict) -> None:
    """Upsert the latest snapshot for cache_key. Called by a *_cache
    module's poll function after every successful poll cycle so a web
    worker's read-through always sees the collector's most recent result.
    Safe to call without a prior init_db() (e.g. a brand-new data volume)."""
    init_db()
    payload = json.dumps(data)
    collected_at = data.get("collected_at")
    with contextlib.closing(_connect()) as conn, conn:
        conn.execute(
            "INSERT INTO cache_state (cache_key, payload, collected_at) VALUES (?, ?, ?) "
            "ON CONFLICT(cache_key) DO UPDATE SET "
            "payload=excluded.payload, collected_at=excluded.collected_at",
            (cache_key, payload, collected_at),
        )


def read_cache(cache_key: str) -> dict | None:
    """The most recently written snapshot for cache_key, or None if it has
    never been written (e.g. the collector process has never run)."""
    init_db()
    with contextlib.closing(_connect()) as conn, conn:
        row = conn.execute(
            "SELECT payload FROM cache_state WHERE cache_key = ?", (cache_key,)
        ).fetchone()
    if row is None:
        return None
    return json.loads(row[0])
