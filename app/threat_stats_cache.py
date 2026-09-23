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
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

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
    "failed_admin_logins_24h": 0,
    "devices_with_failed_logins": 0,
    "top_failed_sources": [],
    "admin_logins_outside_hours_24h": 0,
    "ipsec_tunnels_total": 0,
    "ipsec_tunnels_down": 0,
    "ssl_vpn_users_now": 0,
    "collected_at": None,
}
_cache: dict = dict(_EMPTY_CACHE)


CACHE_KEY = "threat_stats"


def get_cached() -> dict:
    """Read-through: falls back to app.collector_store's last-written
    snapshot when this process's in-memory cache is still empty (see
    app/log_stats_cache.py::get_cached() for the identical pattern)."""
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


def _last_24h_range(now: datetime.datetime) -> tuple[str, str]:
    """Return a UTC 24h window as offset-aware ISO8601 strings, suitable as
    input to FAZClient.local_time_range (which needs a genuine UTC offset to
    convert correctly)."""
    start = now - datetime.timedelta(hours=24)
    return start.isoformat(), now.isoformat()


def _parse_business_hours() -> tuple[datetime.time, datetime.time]:
    """Parse Config.ADMIN_ACCESS_BUSINESS_HOURS ("HH:MM-HH:MM") into
    (start, end) datetime.time objects."""
    start_str, _, end_str = Config.ADMIN_ACCESS_BUSINESS_HOURS.partition("-")
    start_h, start_m = (int(x) for x in start_str.split(":"))
    end_h, end_m = (int(x) for x in end_str.split(":"))
    return datetime.time(start_h, start_m), datetime.time(end_h, end_m)


def _business_hours_range(client, now_utc: datetime.datetime) -> tuple[str, str] | None:
    """Today's business-hours window "so far" (per Config.ADMIN_ACCESS_TIMEZONE
    and Config.ADMIN_ACCESS_BUSINESS_HOURS), converted to the FAZ appliance's
    local time via client.local_time_range, as (start, end) strings suitable
    for run_fortiview's time_range. Returns None if business hours haven't
    started yet today in ADMIN_ACCESS_TIMEZONE (nothing to count).

    Known limitation: only considers TODAY's business window intersected
    with "now", not a rolling 24h lookback — if the poll runs shortly after
    local midnight, yesterday's business window (which may still partly
    fall within the trailing 24h admin-logins query) is not counted as
    "business hours", so admin_logins_outside_hours_24h can be a slight
    overestimate in the few hours after midnight. Acceptable for an
    informational executive-summary metric; not exact-audit-grade.

    Returns None (same as the "business hours haven't started yet" case)
    if Config.ADMIN_ACCESS_BUSINESS_HOURS is malformed or
    Config.ADMIN_ACCESS_TIMEZONE is not a valid IANA zone name, so a
    single bad env var degrades this metric instead of taking down the
    whole per-target poll (see app_log call below).
    """
    try:
        start_time, end_time = _parse_business_hours()
        tz = ZoneInfo(Config.ADMIN_ACCESS_TIMEZONE)
    except (ValueError, ZoneInfoNotFoundError) as exc:
        from app.app_logger import app_log

        app_log(
            "WARN",
            "threat_stats_cache",
            "Invalid ADMIN_ACCESS_BUSINESS_HOURS/ADMIN_ACCESS_TIMEZONE config "
            f"({Config.ADMIN_ACCESS_BUSINESS_HOURS!r} / {Config.ADMIN_ACCESS_TIMEZONE!r}): {exc}",
        )
        return None
    now_local = now_utc.astimezone(tz)
    business_start_local = now_local.replace(
        hour=start_time.hour, minute=start_time.minute, second=0, microsecond=0
    )
    business_end_local = now_local.replace(
        hour=end_time.hour, minute=end_time.minute, second=0, microsecond=0
    )
    business_end_local = min(business_end_local, now_local)
    if business_start_local >= business_end_local:
        return None
    business_start_utc = business_start_local.astimezone(datetime.timezone.utc)
    business_end_utc = business_end_local.astimezone(datetime.timezone.utc)
    return client.local_time_range(business_start_utc.isoformat(), business_end_utc.isoformat())


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


def _poll_one_target(client, now: datetime.datetime) -> dict:
    """Collect one target's threat stats. Raises FAZError/Exception on any
    failure — the caller decides whether to skip this target or abort."""
    alerts_unacked_total = client.get_alert_counts(client.adom, "ackflag=no")
    alerts_unacked_by_severity = {
        sev: client.get_alert_counts(client.adom, f"ackflag=no and severity={sev}")
        for sev in SEVERITIES
    }

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

    # NOTE: "failed-authentication-attempts" (used below for
    # top_failed_sources) covers ALL failed authentication FAZ tracks
    # (VPN, wireless captive portal, admin login, etc. — see the vendored
    # spec's filterable fields "vpntunnel"/"xauthuser"/"ssid"/"stamac"),
    # not admin-logins specifically. It is NOT scoped to admin access the
    # way failed_admin_logins_24h (from the separate "admin-logins" view)
    # is. A future task could scope it down with a logintype/ui filter
    # once field values are confirmed live.

    # Admin access anomalies (P13): row field names ("fortigate", "f_user",
    # "login_num", "login_fail_num" for admin-logins; "fortigate", "src_ip",
    # "total_num" for failed-authentication-attempts) trace to the vendored
    # spec's Filterable/Sortable-field appendix table (see this plan's
    # Global Constraints) — not yet confirmed live against real hardware.
    admin_logins_24h_rows = client.run_fortiview(
        client.adom, "admin-logins", time_range, limit=1000
    )
    failed_auth_rows = client.run_fortiview(
        client.adom, "failed-authentication-attempts", time_range, limit=1000
    )

    failed_admin_logins_24h = sum(
        int(r.get("login_fail_num", 0) or 0) for r in admin_logins_24h_rows
    )
    total_logins_24h = sum(int(r.get("login_num", 0) or 0) for r in admin_logins_24h_rows)
    devices_with_failed_login_names = {
        r.get("fortigate", "")
        for r in admin_logins_24h_rows
        if int(r.get("login_fail_num", 0) or 0) > 0
    }
    devices_with_failed_login_names.discard("")

    business_range = _business_hours_range(client, now)
    if business_range is not None:
        business_rows = client.run_fortiview(
            client.adom, "admin-logins", business_range, limit=1000
        )
        business_logins = sum(int(r.get("login_num", 0) or 0) for r in business_rows)
    else:
        business_logins = 0
    admin_logins_outside_hours_24h = max(total_logins_24h - business_logins, 0)

    # VPN coverage (P14): FortiView has no live "tunnel status" field —
    # site-to-site-ipsec/ssl-dialup-ipsec are session-log views, so
    # liveness is inferred from the trailing 24h window: a tunnel/user is
    # "up"/"connected now" if at least one logged session has no end
    # timestamp (e_time/end_time falsy means still open); a tunnel is
    # "down" if it was seen at all in the last 24h but every session for
    # it has since closed. Same "recent log presence = liveness"
    # philosophy as log_stats_cache.py's silent-device detection — an
    # approximation, not a live device-config query.
    #
    # UNVALIDATED against live FortiAnalyzer hardware: both the presence
    # of e_time/end_time as a per-row field, and whether these views
    # return raw per-session rows at all (as opposed to aggregated
    # per-tunnel summary rows), trace only to the vendored spec's
    # Filterable/Sortable-field appendix table. That evidence is weaker
    # for e_time (site-to-site-ipsec) than for end_time
    # (ssl-dialup-ipsec): e_time appears only in site-to-site-ipsec's
    # FILTERABLE list — alongside s_time/timescale/min_duration/
    # max_duration, a vocabulary that reads like query-window bounds, not
    # row columns — and never in its sortable/row-column list, whereas
    # end_time IS in ssl-dialup-ipsec's sortable list. Two silent, opposite
    # failure modes are possible if this assumption is wrong: if e_time
    # isn't actually returned per-row, every tunnel looks "up" forever and
    # ipsec_tunnels_down reads permanently 0 (a false-green on a metric
    # that drives a 4tExecutive RAG threshold); if the view instead
    # returns aggregated per-tunnel summary rows (its sortable fields
    # bandwidth/duration/traffic_in/traffic_out suggest aggregation, not
    # raw sessions) rather than raw sessions, an end timestamp could be
    # populated on nearly every row and ipsec_tunnels_down could read
    # permanently equal to ipsec_tunnels_total (a false-red). Confirm
    # live before trusting this metric operationally.
    #
    # Tunnel identity is keyed on (dvid, name) rather than name alone:
    # both views' vendored-spec filterable field lists include dvid
    # (device ID), which is used here to disambiguate tunnels that share
    # a name across different FortiGate devices (a common deployment
    # pattern, e.g. many branches all naming their tunnel to headquarters
    # "to-HQ"). If dvid isn't actually present in the live row shape,
    # row.get("dvid", "") returns "" for every row and this degrades
    # gracefully back to today's name-only grouping — no regression.
    site_to_site_rows = client.run_fortiview(
        client.adom, "site-to-site-ipsec", time_range, limit=1000
    )
    ssl_dialup_rows = client.run_fortiview(client.adom, "ssl-dialup-ipsec", time_range, limit=1000)

    from app.app_logger import app_log

    if len(site_to_site_rows) >= 1000:
        app_log(
            "WARN",
            "threat_stats_cache",
            f"site-to-site-ipsec FortiView returned {len(site_to_site_rows)} rows "
            "(>= limit=1000) — results may be truncated, which can silently skew "
            "ipsec_tunnels_down",
        )
    if len(ssl_dialup_rows) >= 1000:
        app_log(
            "WARN",
            "threat_stats_cache",
            f"ssl-dialup-ipsec FortiView returned {len(ssl_dialup_rows)} rows "
            "(>= limit=1000) — results may be truncated, which can silently skew "
            "ssl_vpn_users_now",
        )

    tunnel_up: dict[tuple[str, str], bool] = {}
    for row in site_to_site_rows:
        name = row.get("vpnname") or row.get("tunnelid") or ""
        if not name:
            continue
        dvid = row.get("dvid", "")
        key = (dvid, name)
        is_open = not row.get("e_time")
        tunnel_up[key] = tunnel_up.get(key, False) or is_open

    ssl_users_now_names = {
        (row.get("dvid", ""), row.get("f_user", ""))
        for row in ssl_dialup_rows
        if not row.get("end_time") and row.get("f_user")
    }

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
        "failed_admin_logins_24h": failed_admin_logins_24h,
        "devices_with_failed_login_names": devices_with_failed_login_names,
        "top_failed_sources": [
            {"source": r.get("src_ip", ""), "count": int(r.get("total_num", 0) or 0)}
            for r in failed_auth_rows
        ],
        "admin_logins_outside_hours_24h": admin_logins_outside_hours_24h,
        "ipsec_tunnel_names": set(tunnel_up.keys()),
        "ipsec_tunnel_up_names": {name for name, up in tunnel_up.items() if up},
        "ssl_vpn_users_now_names": ssl_users_now_names,
    }


def poll_all_targets() -> None:
    import app.threat_stats_history as history
    from app.app_logger import app_log
    from app.faz_client import FAZClient, FAZError, summarize_connection_error
    from app.faz_targets import list_targets

    now = datetime.datetime.now(datetime.timezone.utc)
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
                results.append(_poll_one_target(client, now))
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

    failed_admin_logins_24h = sum(r["failed_admin_logins_24h"] for r in results)
    admin_logins_outside_hours_24h = sum(r["admin_logins_outside_hours_24h"] for r in results)
    devices_with_failed_logins = (
        len(set().union(*(r["devices_with_failed_login_names"] for r in results))) if results else 0
    )
    top_failed_sources = _merge_top_lists([r["top_failed_sources"] for r in results], "source")

    all_tunnel_names: set = (
        set().union(*(r["ipsec_tunnel_names"] for r in results)) if results else set()
    )
    all_up_tunnel_names: set = (
        set().union(*(r["ipsec_tunnel_up_names"] for r in results)) if results else set()
    )
    ipsec_tunnels_total = len(all_tunnel_names)
    ipsec_tunnels_down = len(all_tunnel_names - all_up_tunnel_names)
    ssl_vpn_users_now = (
        len(set().union(*(r["ssl_vpn_users_now_names"] for r in results))) if results else 0
    )

    collected_at = _now()
    with _lock:
        _cache["alerts_unacked_total"] = alerts_unacked_total
        _cache["alerts_unacked_by_severity"] = alerts_unacked_by_severity
        _cache["ips_detections_24h"] = ips_detections_24h
        _cache["ips_blocked_24h"] = ips_blocked_24h
        _cache["ips_blocked_pct"] = ips_blocked_pct
        _cache["top_signatures"] = top_signatures
        _cache["top_source_countries"] = top_source_countries
        _cache["failed_admin_logins_24h"] = failed_admin_logins_24h
        _cache["devices_with_failed_logins"] = devices_with_failed_logins
        _cache["top_failed_sources"] = top_failed_sources
        _cache["admin_logins_outside_hours_24h"] = admin_logins_outside_hours_24h
        _cache["ipsec_tunnels_total"] = ipsec_tunnels_total
        _cache["ipsec_tunnels_down"] = ipsec_tunnels_down
        _cache["ssl_vpn_users_now"] = ssl_vpn_users_now
        _cache["collected_at"] = collected_at
        snapshot = dict(_cache)

    from app import collector_store

    collector_store.write_cache(CACHE_KEY, snapshot)

    history.init_db()
    history.write_rollup(
        alerts_unacked_total=alerts_unacked_total,
        alerts_unacked_by_severity=alerts_unacked_by_severity,
        ips_detections_24h=ips_detections_24h,
        ips_blocked_24h=ips_blocked_24h,
        ips_blocked_pct=ips_blocked_pct,
        top_signatures=top_signatures,
        top_source_countries=top_source_countries,
        failed_admin_logins_24h=failed_admin_logins_24h,
        devices_with_failed_logins=devices_with_failed_logins,
        top_failed_sources=top_failed_sources,
        admin_logins_outside_hours_24h=admin_logins_outside_hours_24h,
        ipsec_tunnels_total=ipsec_tunnels_total,
        ipsec_tunnels_down=ipsec_tunnels_down,
        ssl_vpn_users_now=ssl_vpn_users_now,
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
