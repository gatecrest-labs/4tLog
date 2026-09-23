"""External API — bearer-token-authenticated read-only endpoints for
4tExecutive. No browser session required.

Authentication: Authorization: Bearer <token> (see app/api_tokens.py).
Feature gate: app.app_settings.get_setting("external_api_enabled") — when
disabled, every route returns 503.

Endpoints:
  GET /external/api/executive/summary   Fleet-wide metrics for 4tExecutive
"""

from __future__ import annotations

import re

from flask import Blueprint, jsonify, request

from app.api_tokens import validate_token
from app.app_logger import app_log
from app.app_settings import get_setting

bp = Blueprint("external_api", __name__, url_prefix="/external/api")

_DISK_USAGE_RE = re.compile(r"Free\s+([\d.]+)\s*\w+,\s*Total\s+([\d.]+)\s*\w+")


def _feature_enabled() -> bool:
    return get_setting("external_api_enabled", False)


def _authenticate():
    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        return None
    return validate_token(auth[7:].strip())


def _gate():
    if not _feature_enabled():
        return jsonify({"error": "External API is disabled"}), 503
    if _authenticate() is None:
        app_log(
            "WARN",
            "external_api",
            "Unauthorized executive/summary request",
            remote=request.remote_addr,
        )
        return jsonify({"error": "Unauthorized — valid Bearer token required"}), 401
    return None


def _validate_log_usage_request(data: dict) -> tuple[dict | None, str | None]:
    """Validate and normalize a /external/api/log-usage request body.

    Returns (normalized_request, None) on success, or (None, error_message)
    on the first validation failure. Rejects out-of-range `days` rather
    than clamping it -- this endpoint is a contract boundary; the caller
    owns its own input hygiene."""
    adom = str(data.get("adom") or "").strip()
    if not adom:
        return None, "adom is required"

    devices = data.get("devices")
    if (
        not isinstance(devices, list)
        or not devices
        or not all(isinstance(d, str) and d.strip() for d in devices)
    ):
        return None, "devices must be a non-empty list of strings"

    policyid = data.get("policyid")
    if not isinstance(policyid, int) or isinstance(policyid, bool) or policyid <= 0:
        return None, "policyid must be a positive integer"

    days = data.get("days")
    if not isinstance(days, int) or isinstance(days, bool) or not (1 <= days <= 60):
        return None, "days must be an integer between 1 and 60"

    return {
        "adom": adom,
        "devices": [d.strip() for d in devices],
        "policyid": policyid,
        "days": days,
    }, None


def _parse_disk_used_pct(disk_used: str | None) -> float | None:
    """ "Free 40GB, Total 100GB" -> 60.0 (used percent). None if unparseable."""
    if not disk_used:
        return None
    match = _DISK_USAGE_RE.search(disk_used)
    if not match:
        return None
    free, total = float(match.group(1)), float(match.group(2))
    if total <= 0:
        return None
    return round((total - free) / total * 100, 1)


def _normalize_str(value) -> str | None:
    """faz_health_cache uses the sentinel string "n/a" for a field that
    couldn't be read from the target; normalize it to None here so
    consumers (4tExecutive) see the same "no data" shape this repo's
    sibling, 4thealth-plus, uses for its own "infra" key."""
    if value in (None, "n/a"):
        return None
    return value


def _build_infra_list(targets: list[dict]) -> list[dict]:
    """Per-target FortiAnalyzer management-plane health, in the same shape
    as 4thealth-plus's "infra" executive-summary key (see that repo's
    app/executive_summary_cache.py) so 4tExecutive can merge infra health
    from every source into one list. Sourced entirely from
    faz_health_cache's existing poll cache — no extra network calls.
    Never includes "host" (an IP) or any credential field."""
    return [
        {
            "role": "fortianalyzer",
            "label": t.get("label", ""),
            "hostname": _normalize_str(t.get("hostname")),
            "version": _normalize_str(t.get("version")),
            "cpu": t.get("cpu"),
            "mem": t.get("mem"),
            "disk_used_pct": _parse_disk_used_pct(t.get("disk_used")),
            "ha_role": _normalize_str(t.get("ha_role")),
            "status": t.get("status"),
            "last_updated": t.get("last_updated"),
        }
        for t in targets
    ]


def _build_threats(cache: dict, rollup: dict | None) -> dict:
    """Threat activity summary, preferring cache over history rollup.
    Follows the same cache-first/history-fallback pattern as log stats."""
    source = cache if cache.get("collected_at") is not None else (rollup or {})
    return {
        "alerts_unacked_total": source.get("alerts_unacked_total", 0),
        "alerts_unacked_by_severity": source.get(
            "alerts_unacked_by_severity", {"critical": 0, "high": 0, "medium": 0, "low": 0}
        ),
        "ips_detections_24h": source.get("ips_detections_24h", 0),
        "ips_blocked_pct": source.get("ips_blocked_pct", 0.0),
        "top_signatures": source.get("top_signatures", []),
        "top_source_countries": source.get("top_source_countries", []),
        "collected_at": source.get("collected_at"),
    }


def _build_admin_access(cache: dict, rollup: dict | None) -> dict:
    """Admin access anomalies summary, preferring cache over history rollup.
    Follows the same cache-first/history-fallback pattern as log stats."""
    from app.config import Config

    source = cache if cache.get("collected_at") is not None else (rollup or {})
    return {
        "failed_admin_logins_24h": source.get("failed_admin_logins_24h", 0),
        "devices_with_failed_logins": source.get("devices_with_failed_logins", 0),
        "top_failed_sources": source.get("top_failed_sources", []),
        "admin_logins_outside_hours_24h": source.get("admin_logins_outside_hours_24h", 0),
        "business_hours": f"{Config.ADMIN_ACCESS_BUSINESS_HOURS} {Config.ADMIN_ACCESS_TIMEZONE}",
        "collected_at": source.get("collected_at"),
    }


def _build_vpn(cache: dict, rollup: dict | None) -> dict:
    """VPN tunnel/SSL-VPN-user coverage summary, preferring cache over
    history rollup. Follows the same cache-first/history-fallback pattern
    as threats/admin_access.

    Liveness here is inferred from log presence, not a live status query:
    a session whose close event was never logged (e.g. a device reboot or
    a logging gap) keeps a no-end-timestamp row in the 24h window and
    counts as "up"/"connected now" for the full 24h even if the tunnel or
    user actually disconnected hours ago — ssl_vpn_users_now in
    particular reads like an instantaneous gauge but is really "distinct
    users with an unterminated session logged in the last 24h."
    """
    source = cache if cache.get("collected_at") is not None else (rollup or {})
    return {
        "ipsec_tunnels_total": source.get("ipsec_tunnels_total", 0),
        "ipsec_tunnels_down": source.get("ipsec_tunnels_down", 0),
        "ssl_vpn_users_now": source.get("ssl_vpn_users_now", 0),
        "collected_at": source.get("collected_at"),
    }


@bp.route("/executive/summary")
def executive_summary():
    gate_error = _gate()
    if gate_error is not None:
        return gate_error

    from app import faz_health_cache, log_stats_cache, threat_stats_cache
    from app.config import Config
    from app.log_stats_history import get_latest_rollup
    from app.threat_stats_history import get_latest_rollup as get_latest_threat_rollup

    targets = faz_health_cache.get_all_cached()
    faz_targets_total = len(targets)
    faz_targets_healthy = sum(1 for t in targets if t.get("status") in ("green", "yellow"))
    disk_pcts = [
        pct for t in targets if (pct := _parse_disk_used_pct(t.get("disk_used"))) is not None
    ]
    faz_disk_used_pct = max(disk_pcts) if disk_pcts else None

    log_cache = log_stats_cache.get_cached()
    if log_cache.get("collected_at") is not None:
        devices_logging = len(log_cache["logging_devices"])
        devices_silent = len(log_cache["silent_devices"])
        log_volume_events_per_sec = sum(d.get("lograte", 0.0) for d in log_cache["logging_devices"])
        log_stats_collected_at = log_cache["collected_at"]
    else:
        rollup = get_latest_rollup()
        if rollup is not None:
            devices_logging = rollup["devices_logging"]
            devices_silent = rollup["devices_silent"]
            log_volume_events_per_sec = rollup["total_lograte"]
            log_stats_collected_at = rollup["collected_at"]
        else:
            devices_logging = 0
            devices_silent = 0
            log_volume_events_per_sec = 0.0
            log_stats_collected_at = None

    threat_cache = threat_stats_cache.get_cached()
    threat_rollup = (
        None if threat_cache.get("collected_at") is not None else get_latest_threat_rollup()
    )
    threats = _build_threats(threat_cache, threat_rollup)
    admin_access = _build_admin_access(threat_cache, threat_rollup)
    vpn = _build_vpn(threat_cache, threat_rollup)

    return jsonify(
        {
            "schema_version": 1,
            "faz_targets_total": faz_targets_total,
            "faz_targets_healthy": faz_targets_healthy,
            "faz_disk_used_pct": faz_disk_used_pct,
            "devices_logging": devices_logging,
            "devices_silent": devices_silent,
            "silent_device_threshold_minutes": Config.SILENT_DEVICE_THRESHOLD_MINUTES,
            "log_volume_events_per_sec": log_volume_events_per_sec,
            "log_stats_collected_at": log_stats_collected_at,
            "infra": _build_infra_list(targets),
            "threats": threats,
            "admin_access": admin_access,
            "vpn": vpn,
        }
    )
