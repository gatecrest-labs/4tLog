"""Standalone collector process — owns every BackgroundScheduler poller
(FAZ health, log stats, threat stats, host metrics) so a `gunicorn`-served
web process never has to.

Run with:

    python -m app.collector

Each poller still honors its own tests/conftest.py-only *_POLL_DISABLED
flag, same as when they were started inline from app/__init__.py. See
app/config.py's RUN_SCHEDULERS: web processes leave it at its default
("collector") and start no schedulers at all, reading poll results
through each cache module's SQLite read-through fallback
(app/collector_store.py) instead. RUN_SCHEDULERS=inline restores the
historical single-process behavior for local development, in which case
running this module too would double the poll rate — don't do both.
"""

from __future__ import annotations

import time

from app.app_logger import app_log


def start_all_schedulers() -> None:
    """Initialize every history DB and start every poller's
    BackgroundScheduler. Each init_scheduler() is itself a no-op when its
    module's *_POLL_DISABLED flag is set (see tests/conftest.py), so this
    is always safe to call, including under the test suite."""
    from app.faz_health_cache import init_scheduler as init_faz_health_scheduler
    from app.host_metrics_cache import init_scheduler as init_host_metrics_scheduler
    from app.host_metrics_history import init_db as init_host_metrics_db
    from app.log_stats_cache import init_scheduler as init_log_stats_scheduler
    from app.log_stats_history import init_db as init_log_stats_db
    from app.threat_stats_cache import init_scheduler as init_threat_stats_scheduler
    from app.threat_stats_history import init_db as init_threat_stats_db

    init_log_stats_db()
    init_threat_stats_db()
    init_host_metrics_db()

    init_faz_health_scheduler(None)
    init_log_stats_scheduler(None)
    init_threat_stats_scheduler(None)
    init_host_metrics_scheduler(None)


def main() -> None:
    app_log(
        "INFO",
        "collector",
        "Starting collector process (FAZ health/log stats/threat stats/host metrics)",
    )
    start_all_schedulers()
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        app_log("INFO", "collector", "Collector process shutting down")


if __name__ == "__main__":
    main()
