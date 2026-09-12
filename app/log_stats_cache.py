"""Background cache for FAZ log-stats-based silent-device detection and
fleet log volume. Structured like app/faz_health_cache.py: a background
poller on its own APScheduler interval writes into a lock-guarded
in-memory dict; app/routes/external_api_routes.py reads a snapshot and
never blocks on a live poll.

Also builds `silent_details` — a capped, ordered drill-down list for the
`devices_silent` count (see build_silent_details()) — for 4tExecutive's
"why is this count non-zero" UI.
"""

from __future__ import annotations

import datetime
import threading
import time

from app.config import Config

_lock = threading.RLock()
_cache: dict = {
    "logging_devices": [],
    "silent_devices": [],
    "silent_details": [],
    "collected_at": None,
}

SILENT_DETAILS_MAX = 50


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


def build_silent_details(silent_devices: list[dict], limit: int = SILENT_DETAILS_MAX) -> list[dict]:
    """Drill-down detail rows for the `devices_silent` count: up to `limit`
    silent devices, most-severe-first. "Never logged" (last_log_timestamp
    None or 0 — FAZ has no record of this device at all) is the most
    severe state and sorts ahead of every device with a real timestamp;
    among devices that have logged before, the oldest last_log_timestamp
    (most stale) sorts first. Ties preserve input order (Python sort is
    stable)."""

    def sort_key(dev: dict) -> tuple[int, float]:
        ts = dev.get("last_log_timestamp")
        if not ts:
            return (0, 0.0)
        return (1, ts)

    ordered = sorted(silent_devices, key=sort_key)
    details = []
    for dev in ordered[:limit]:
        ts = dev.get("last_log_timestamp")
        last_log_at = (
            datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).isoformat()
            if ts
            else None
        )
        details.append(
            {
                "devid": dev.get("devid"),
                "devname": dev.get("devname"),
                "last_log_at": last_log_at,
            }
        )
    return details


CACHE_KEY = "log_stats"


def get_cached() -> dict:
    """Snapshot of the latest poll: {"logging_devices": [...], "silent_devices": [...],
    "silent_details": [...], "collected_at": iso-str | None}.

    Read-through: if this process's in-memory cache is still at its
    startup/empty state (collected_at is None — true for every web worker
    under the collector/web split, since web workers never poll), fall
    back to the collector's last-written snapshot in app.collector_store.
    A successful fallback also repopulates the in-memory dict so
    subsequent calls in this process skip the SQLite read."""
    with _lock:
        if _cache.get("collected_at") is not None:
            return dict(_cache)

    from app import collector_store

    stored = collector_store.read_cache(CACHE_KEY)
    if stored is not None:
        with _lock:
            _cache.update(stored)
            return dict(_cache)

    with _lock:
        return dict(_cache)


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def poll_all_targets() -> None:
    import app.log_stats_history as history
    from app.app_logger import app_log
    from app.faz_client import FAZClient, FAZError, summarize_connection_error
    from app.faz_targets import list_targets

    now = time.time()
    devices_by_id: dict[str, dict] = {}
    polled_ok = False
    for target in list_targets():
        label = target.get("label")
        host = target.get("host")
        adom = target.get("adom", "root")
        if not label or not host:
            continue
        try:
            with FAZClient(
                host=host,
                token=target.get("token", ""),
                adom=adom,
                verify_ssl=Config.FAZ_VERIFY_SSL,
                timeout=Config.FAZ_REQUEST_TIMEOUT,
            ) as client:
                stats = client.get_log_stats()
        except FAZError as exc:
            app_log("WARN", "log_stats_cache", f"logstats poll failed for {label}: {exc}")
            continue
        except Exception as exc:
            app_log(
                "WARN",
                "log_stats_cache",
                f"logstats poll failed for {label} ({host}): {summarize_connection_error(exc)}",
            )
            continue
        polled_ok = True
        for dev in stats:
            devices_by_id[dev["devid"]] = dev  # last target seen for a devid wins

    if not polled_ok:
        # Every target was unreachable this cycle. Leave the cache and
        # persisted history untouched (stale-but-honest) rather than
        # overwriting with a fabricated "zero silent devices" reading that
        # would look identical to a genuinely healthy, empty fleet.
        return

    logging_devices, silent_devices = classify_devices(
        list(devices_by_id.values()), now, Config.SILENT_DEVICE_THRESHOLD_MINUTES
    )
    silent_details = build_silent_details(silent_devices)
    collected_at = _now()
    with _lock:
        _cache["logging_devices"] = logging_devices
        _cache["silent_devices"] = silent_devices
        _cache["silent_details"] = silent_details
        _cache["collected_at"] = collected_at
        snapshot = dict(_cache)

    from app import collector_store

    collector_store.write_cache(CACHE_KEY, snapshot)

    total_lograte = sum(d.get("lograte", 0.0) for d in logging_devices)
    history.init_db()
    history.write_rollup(
        devices_logging=len(logging_devices),
        devices_silent=len(silent_devices),
        total_lograte=total_lograte,
        collected_at=collected_at,
    )
    history.prune_old_rows()


def poll_now() -> None:
    """Kick off a non-blocking poll of all targets in a daemon thread."""
    t = threading.Thread(target=poll_all_targets, name="log_stats_poll_now", daemon=True)
    t.start()


def init_scheduler(app) -> None:
    """Register a recurring APScheduler job and run the first poll immediately.

    No-op if Config.LOG_STATS_POLL_DISABLED (set by tests/conftest.py)."""
    if Config.LOG_STATS_POLL_DISABLED:
        return

    from apscheduler.schedulers.background import BackgroundScheduler

    poll_now()

    scheduler = BackgroundScheduler()
    scheduler.add_job(
        func=poll_all_targets,
        trigger="interval",
        seconds=Config.LOG_STATS_POLL_INTERVAL,
        id="log_stats_poll",
        replace_existing=True,
        max_instances=1,
    )
    scheduler.start()
