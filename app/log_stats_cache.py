"""Background cache for FAZ log-stats-based silent-device detection and
fleet log volume. Structured like app/faz_health_cache.py: a background
poller on its own APScheduler interval writes into a lock-guarded
in-memory dict; app/routes/external_api_routes.py reads a snapshot and
never blocks on a live poll.
"""

from __future__ import annotations

import threading

_lock = threading.RLock()
_cache: dict = {"logging_devices": [], "silent_devices": [], "collected_at": None}


def classify_devices(
    stats: list[dict], now: float, threshold_minutes: int
) -> tuple[list[dict], list[dict]]:
    """Split get_log_stats() records into (logging, silent). A device is
    silent if now - last_log_timestamp exceeds threshold_minutes, or if
    last_log_timestamp is None/0 (FAZ has never received a log from it —
    no grace period for that case)."""
    threshold_seconds = threshold_minutes * 60
    logging_devices = []
    silent_devices = []
    for dev in stats:
        ts = dev.get("last_log_timestamp")
        if ts and (now - ts) <= threshold_seconds:
            logging_devices.append(dev)
        else:
            silent_devices.append(dev)
    return logging_devices, silent_devices


def get_cached() -> dict:
    """Snapshot of the latest poll: {"logging_devices": [...], "silent_devices": [...],
    "collected_at": iso-str | None}."""
    with _lock:
        return dict(_cache)
