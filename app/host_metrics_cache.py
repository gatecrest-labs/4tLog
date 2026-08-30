"""Background poller for host CPU/Memory/Disk utilization, persisted so the
Admin > Host Metrics panel can chart trends across restarts. Structured like
app/log_stats_cache.py: a poll function writes into
app/host_metrics_history.py's SQLite store. Unlike log_stats_cache.py there
is no in-memory `_cache` dict here — Admin's range-query API is the only
consumer, and it reads the history store directly; nothing needs an instant
in-process snapshot the way FAZ health's dashboard cards do.
"""

from __future__ import annotations

import datetime
import threading

import psutil

from app.config import Config


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def poll_host_metrics() -> None:
    import app.host_metrics_history as history
    from app.app_logger import app_log

    try:
        cpu_percent = psutil.cpu_percent()
        memory_percent = psutil.virtual_memory().percent
        disk_percent = psutil.disk_usage("/").percent
    except Exception as exc:
        app_log("WARN", "host_metrics_cache", f"psutil read failed: {exc}")
        return

    history.init_db()
    history.write_snapshot(
        cpu_percent=cpu_percent,
        memory_percent=memory_percent,
        disk_percent=disk_percent,
        collected_at=_now(),
    )
    history.prune_old_rows()


def poll_now() -> None:
    """Kick off a non-blocking poll in a daemon thread."""
    t = threading.Thread(target=poll_host_metrics, name="host_metrics_poll_now", daemon=True)
    t.start()


def init_scheduler(app) -> None:
    """Register a recurring APScheduler job and run the first poll immediately.

    No-op if Config.HOST_METRICS_POLL_DISABLED (set by tests/conftest.py) —
    keeps the test suite from starting a real background polling thread.
    """
    if Config.HOST_METRICS_POLL_DISABLED:
        return

    from apscheduler.schedulers.background import BackgroundScheduler

    poll_now()

    scheduler = BackgroundScheduler()
    scheduler.add_job(
        func=poll_host_metrics,
        trigger="interval",
        seconds=Config.HOST_METRICS_POLL_INTERVAL,
        id="host_metrics_poll",
        replace_existing=True,
        max_instances=1,
    )
    scheduler.start()
