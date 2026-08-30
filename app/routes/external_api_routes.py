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
            "WARNING",
            "external_api",
            "Unauthorized executive/summary request",
            remote=request.remote_addr,
        )
        return jsonify({"error": "Unauthorized — valid Bearer token required"}), 401
    return None


def _parse_disk_used_pct(disk_used: str | None) -> float | None:
    """"Free 40GB, Total 100GB" -> 60.0 (used percent). None if unparseable."""
    if not disk_used:
        return None
    match = _DISK_USAGE_RE.search(disk_used)
    if not match:
        return None
    free, total = float(match.group(1)), float(match.group(2))
    if total <= 0:
        return None
    return round((total - free) / total * 100, 1)


@bp.route("/executive/summary")
def executive_summary():
    gate_error = _gate()
    if gate_error is not None:
        return gate_error

    from app import faz_health_cache, log_stats_cache
    from app.config import Config
    from app.log_stats_history import get_latest_rollup

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
        log_volume_events_per_sec = sum(
            d.get("lograte", 0.0) for d in log_cache["logging_devices"]
        )
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
        }
    )
