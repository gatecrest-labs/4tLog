"""Background cache for FAZ SD-WAN link health (Admin-independent "SD-WAN" tab).

Structured like app/threat_stats_cache.py: a poller on its own APScheduler
interval (owned by app/collector.py) fills a lock-guarded in-memory snapshot and
mirrors it to app.collector_store, so web workers never block on a live FAZ
call.

Per target, one FortiView run per view in ``VIEWS`` over a fixed 24h window.
Each view is isolated: a view this FortiAnalyzer release does not have is
``unsupported``, any other FortiAnalyzer error marks just that view ``error``,
and neither stops the other views or other targets. A connection-level failure
marks only that target ``error``.

Row shapes of the SD-WAN views are unconfirmed (see app/sdwan_parse.py);
``sdwan-dev-stats`` is polled but only its status and row count are kept.
"""

from __future__ import annotations

import datetime
import threading

from app.config import Config

# sdwan-intf-sla-status, sdwan-link-view and sdwan-intf-traffic-line were
# removed in FortiAnalyzer 8.0.x ("Cannot find FortiView") and are not used.
VIEWS: tuple[str, ...] = (
    "sdwan-dev-stats",
    "sdwan-intf-sla-status-line",
    "sdwan-perf-stats-line",
    "sdwan-intf-bandwidth-line",
)
_PARSED_VIEWS = frozenset(VIEWS) - {"sdwan-dev-stats"}

CACHE_KEY = "sdwan_stats"
WINDOW = datetime.timedelta(hours=24)

_lock = threading.RLock()
_EMPTY_CACHE: dict = {"targets": [], "collected_at": None}
_cache: dict = dict(_EMPTY_CACHE)


def get_cached() -> dict:
    """Latest snapshot: {"targets": [TargetEntry, ...], "collected_at": iso | None}.

    Read-through: every call compares the collector's last-written snapshot
    (app.collector_store) with this process's in-memory one and uses the
    newer (a web worker never polls, so it must keep following the collector)."""
    from app import collector_store

    with _lock:
        in_memory = dict(_cache)

    stored = collector_store.read_cache(CACHE_KEY)
    if stored is not None:
        mem_at = in_memory.get("collected_at")
        stored_at = stored.get("collected_at")
        if mem_at is None or (stored_at is not None and stored_at > mem_at):
            with _lock:
                _cache.update(stored)
                return dict(_cache)

    return in_memory


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _is_unsupported(exc) -> bool:
    return getattr(exc, "code", None) == -32005 and "Cannot find FortiView" in str(exc)


def _poll_view(client, view: str, window: tuple[str, str]) -> tuple[dict, list[dict]]:
    """Run one view. Returns (view status entry, raw rows). Raises only for
    non-FAZError (connection-level) failures."""
    from app.faz_client import FAZError

    try:
        rows = client.run_fortiview(client.adom, view, window, limit=1000)
    except FAZError as exc:
        status = "unsupported" if _is_unsupported(exc) else "error"
        return {"status": status, "rows": 0, "error": str(exc)}, []
    status = "ok" if rows else "empty"
    return {"status": status, "rows": len(rows), "error": None}, rows


def _poll_target(target: dict, now: datetime.datetime) -> dict:
    from app.faz_client import FAZClient
    from app.sdwan_parse import parse_interfaces

    label = target["label"]
    adom = target.get("adom", "root")
    entry = {
        "label": label,
        "adom": adom,
        "host": target.get("host", ""),
        "collected_at": now.isoformat(timespec="seconds"),
        "state": "no_data",
        "error": None,
        "views": {},
        "interfaces": [],
    }
    with FAZClient(
        host=target["host"],
        token=target.get("token", ""),
        adom=adom,
        verify_ssl=Config.FAZ_VERIFY_SSL,
        timeout=Config.FAZ_REQUEST_TIMEOUT,
    ) as client:
        window = client.local_time_range((now - WINDOW).isoformat(), now.isoformat())
        parse_input: dict[str, list[dict]] = {}
        for view in VIEWS:
            view_entry, rows = _poll_view(client, view, window)
            entry["views"][view] = view_entry
            if rows and view in _PARSED_VIEWS:
                parse_input[view] = rows

    entry["interfaces"] = parse_interfaces(parse_input)
    if any(v["rows"] for v in entry["views"].values()):
        entry["state"] = "ok"
    return entry


def poll_all_targets() -> None:
    from app import collector_store
    from app.app_logger import app_log
    from app.faz_client import summarize_connection_error
    from app.faz_targets import list_targets

    now = _now()
    entries: list[dict] = []
    for target in list_targets():
        label = target.get("label")
        host = target.get("host")
        if not label or not host:
            continue
        try:
            entries.append(_poll_target(target, now))
        except Exception as exc:  # connection errors, timeouts, DNS failures, etc.
            app_log("WARN", "sdwan_cache", f"SD-WAN poll failed for {label} ({host}): {exc}")
            entries.append(
                {
                    "label": label,
                    "adom": target.get("adom", "root"),
                    "host": host,
                    "collected_at": now.isoformat(timespec="seconds"),
                    "state": "error",
                    "error": summarize_connection_error(exc),
                    "views": {},
                    "interfaces": [],
                }
            )

    snapshot = {"targets": entries, "collected_at": now.isoformat(timespec="seconds")}
    with _lock:
        _cache.update(snapshot)
    collector_store.write_cache(CACHE_KEY, snapshot)


def poll_now() -> None:
    """Kick off a non-blocking poll of all targets in a daemon thread."""
    t = threading.Thread(target=poll_all_targets, name="sdwan_poll_now", daemon=True)
    t.start()


def init_scheduler(app) -> None:
    """Register a recurring APScheduler job and run the first poll immediately.

    No-op if Config.SDWAN_POLL_DISABLED (set by tests/conftest.py)."""
    if Config.SDWAN_POLL_DISABLED:
        return

    from apscheduler.schedulers.background import BackgroundScheduler

    poll_now()

    scheduler = BackgroundScheduler()
    scheduler.add_job(
        func=poll_all_targets,
        trigger="interval",
        seconds=Config.SDWAN_POLL_INTERVAL,
        id="sdwan_poll",
        replace_existing=True,
        max_instances=1,
    )
    scheduler.start()
