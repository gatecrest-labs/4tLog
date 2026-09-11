"""Background cache for FAZ threat-activity: unacknowledged alert counts by
severity, and 24h IPS detection activity (count, blocked %, top signatures,
top source countries). Structured like app/log_stats_cache.py: a background
poller on its own APScheduler interval writes into a lock-guarded in-memory
dict; app/routes/external_api_routes.py reads a snapshot and never blocks on
a live poll.

Per-target opt-out: a target with threat_poll_enabled=False (see
app/faz_targets.py) is skipped entirely for this poller, though it's still
polled by faz_health_cache/log_stats_cache as normal.
"""

from __future__ import annotations

import datetime
import threading

from app.config import Config

SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low")

_lock = threading.RLock()
_EMPTY_CACHE: dict = {
    "alerts_unacked_total": 0,
    "alerts_unacked_by_severity": {sev: 0 for sev in SEVERITIES},
    "ips_detections_24h": 0,
    "ips_blocked_24h": 0,
    "ips_blocked_pct": 0.0,
    "top_signatures": [],
    "top_source_countries": [],
    "collected_at": None,
}
_cache: dict = dict(_EMPTY_CACHE)


def get_cached() -> dict:
    with _lock:
        return dict(_cache)


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _last_24h_range(now: datetime.datetime) -> tuple[str, str]:
    """Return a UTC 24h window as offset-aware ISO8601 strings, suitable as
    input to FAZClient.local_time_range (which needs a genuine UTC offset to
    convert correctly)."""
    start = now - datetime.timedelta(hours=24)
    return start.isoformat(), now.isoformat()


def _merge_top_lists(lists: list[list[dict]], key: str, limit: int = 5) -> list[dict]:
    """Sum "count" across every target's top-N list by `key`, then return
    the fleet-wide top `limit` sorted descending. Same "one fleet across
    multiple FAZ targets" model log_stats_cache.py already uses for device
    dedup."""
    totals: dict[str, int] = {}
    for rows in lists:
        for row in rows:
            name = row.get(key, "")
            totals[name] = totals.get(name, 0) + int(row.get("count", 0) or 0)
    ranked = sorted(totals.items(), key=lambda kv: kv[1], reverse=True)
    return [{key: name, "count": count} for name, count in ranked[:limit]]


def _poll_one_target(client) -> dict:
    """Collect one target's threat stats. Raises FAZError/Exception on any
    failure — the caller decides whether to skip this target or abort."""
    alerts_unacked_total = client.get_alert_counts(client.adom, "ackflag=no")
    alerts_unacked_by_severity = {
        sev: client.get_alert_counts(client.adom, f"ackflag=no and severity={sev}")
        for sev in SEVERITIES
    }

    now = datetime.datetime.now(datetime.timezone.utc)
    utc_start, utc_end = _last_24h_range(now)
    # FortiAnalyzer interprets FortiView's time-range in the appliance's own
    # configured timezone, not UTC (see FAZClient.local_time_range's
    # docstring for the live-confirmed finding) — convert before using it,
    # same as app/routes/log_search_routes.py does for log searches.
    time_range = client.local_time_range(utc_start, utc_end)

    type_rows = client.run_fortiview(client.adom, "top-type", time_range, limit=50)
    ips_row = next((r for r in type_rows if str(r.get("type", "")).strip().lower() == "ips"), None)
    ips_detections_24h = int(ips_row.get("count", 0) or 0) if ips_row else 0
    ips_blocked_24h = int(ips_row.get("blockedsessions", 0) or 0) if ips_row else 0

    signature_rows = client.run_fortiview(
        client.adom, "top-threats", time_range, limit=5, filter="type==ips"
    )
    country_rows = client.run_fortiview(
        client.adom, "top-countries", time_range, limit=5, filter="type==ips"
    )

    return {
        "alerts_unacked_total": alerts_unacked_total,
        "alerts_unacked_by_severity": alerts_unacked_by_severity,
        "ips_detections_24h": ips_detections_24h,
        "ips_blocked_24h": ips_blocked_24h,
        "top_signatures": [
            {"signature": r.get("threatname", ""), "count": int(r.get("count", 0) or 0)}
            for r in signature_rows
        ],
        "top_source_countries": [
            {"country": r.get("srccountry", ""), "count": int(r.get("count", 0) or 0)}
            for r in country_rows
        ],
    }


def poll_all_targets() -> None:
    import app.threat_stats_history as history
    from app.app_logger import app_log
    from app.faz_client import FAZClient, FAZError, summarize_connection_error
    from app.faz_targets import list_targets

    results: list[dict] = []
    polled_ok = False
    for target in list_targets():
        label = target.get("label")
        host = target.get("host")
        adom = target.get("adom", "root")
        if not label or not host or not target.get("threat_poll_enabled", True):
            continue
        try:
            with FAZClient(
                host=host,
                token=target.get("token", ""),
                adom=adom,
                verify_ssl=Config.FAZ_VERIFY_SSL,
                timeout=Config.FAZ_REQUEST_TIMEOUT,
            ) as client:
                results.append(_poll_one_target(client))
        except FAZError as exc:
            app_log("WARN", "threat_stats_cache", f"threat-stats poll failed for {label}: {exc}")
            continue
        except Exception as exc:
            app_log(
                "WARN",
                "threat_stats_cache",
                f"threat-stats poll failed for {label} ({host}): {summarize_connection_error(exc)}",
            )
            continue
        polled_ok = True

    if not polled_ok:
        # Every enabled target was unreachable (or none are enabled) this
        # cycle. Leave the cache and persisted history untouched
        # (stale-but-honest) rather than overwriting with a fabricated
        # "zero threats" reading.
        return

    alerts_unacked_total = sum(r["alerts_unacked_total"] for r in results)
    alerts_unacked_by_severity = {
        sev: sum(r["alerts_unacked_by_severity"][sev] for r in results) for sev in SEVERITIES
    }
    ips_detections_24h = sum(r["ips_detections_24h"] for r in results)
    ips_blocked_24h = sum(r["ips_blocked_24h"] for r in results)
    ips_blocked_pct = (
        round(ips_blocked_24h / ips_detections_24h * 100, 1) if ips_detections_24h else 0.0
    )
    top_signatures = _merge_top_lists([r["top_signatures"] for r in results], "signature")
    top_source_countries = _merge_top_lists([r["top_source_countries"] for r in results], "country")

    collected_at = _now()
    with _lock:
        _cache["alerts_unacked_total"] = alerts_unacked_total
        _cache["alerts_unacked_by_severity"] = alerts_unacked_by_severity
        _cache["ips_detections_24h"] = ips_detections_24h
        _cache["ips_blocked_24h"] = ips_blocked_24h
        _cache["ips_blocked_pct"] = ips_blocked_pct
        _cache["top_signatures"] = top_signatures
        _cache["top_source_countries"] = top_source_countries
        _cache["collected_at"] = collected_at

    history.init_db()
    history.write_rollup(
        alerts_unacked_total=alerts_unacked_total,
        alerts_unacked_by_severity=alerts_unacked_by_severity,
        ips_detections_24h=ips_detections_24h,
        ips_blocked_24h=ips_blocked_24h,
        ips_blocked_pct=ips_blocked_pct,
        top_signatures=top_signatures,
        top_source_countries=top_source_countries,
        failed_admin_logins_24h=0,
        devices_with_failed_logins=0,
        top_failed_sources=[],
        admin_logins_outside_hours_24h=0,
        collected_at=collected_at,
    )
    history.prune_old_rows()


def poll_now() -> None:
    """Kick off a non-blocking poll of all targets in a daemon thread."""
    t = threading.Thread(target=poll_all_targets, name="threat_stats_poll_now", daemon=True)
    t.start()


def init_scheduler(app) -> None:
    """Register a recurring APScheduler job and run the first poll immediately.

    No-op if Config.THREAT_STATS_POLL_DISABLED (set by tests/conftest.py)."""
    if Config.THREAT_STATS_POLL_DISABLED:
        return

    from apscheduler.schedulers.background import BackgroundScheduler

    poll_now()

    scheduler = BackgroundScheduler()
    scheduler.add_job(
        func=poll_all_targets,
        trigger="interval",
        seconds=Config.THREAT_STATS_POLL_INTERVAL,
        id="threat_stats_poll",
        replace_existing=True,
        max_instances=1,
    )
    scheduler.start()
