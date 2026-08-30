"""Admin-only routes.

Page:  GET  /admin

Groups API (JSON):
  GET    /admin/api/groups
  POST   /admin/api/groups           {"name": str, "members": [...], "allowed_tabs": [...],
                                      "adom_restrict": bool, "allowed_adoms": [...]}
  PUT    /admin/api/groups/<name>    {"members": [...], "allowed_tabs": [...],
                                      "adom_restrict": bool, "allowed_adoms": [...]}
  DELETE /admin/api/groups/<name>
  GET    /admin/api/users            list of {username, role} for member picker

FAZ Targets API (JSON):
  GET    /admin/api/faz-targets
  POST   /admin/api/faz-targets           {"label": str, "host": str, "adom": str, "token": str,
                                           ...snmp overrides}
  PUT    /admin/api/faz-targets/<label>   {"host": str, "adom": str, "token": str,
                                           ...snmp overrides}
  DELETE /admin/api/faz-targets/<label>

Tab registry:
  GET    /admin/api/tabs             known tab keys + display names

Logs API (JSON):
  GET    /admin/api/logs?level=INFO&component=auth&limit=500
  POST   /admin/api/logs/level       {"level": "DEBUG"}
  DELETE /admin/api/logs             clears the buffer

Host Metrics API (JSON):
  GET    /admin/api/host-metrics?range=1h   {"cpu": [...], "mem": [...], "disk": [...]}
"""

import datetime

from flask import Blueprint, jsonify, render_template, request, session

from app import registry
from app.app_logger import (
    app_log,
    clear_log_entries,
    get_log_entries,
    get_log_level,
    get_log_levels,
    set_log_level,
)
from app.auth import list_users
from app.decorators import admin_required as _admin_required
from app.faz_targets import create_target, delete_target, get_target, list_targets, update_target
from app.groups import create_group, delete_group, get_group, list_groups, update_group

bp = Blueprint("admin", __name__, url_prefix="/admin")

registry.register("admin", "Admin", "admin.admin_page")

_SNMP_OVERRIDE_FIELDS = (
    "snmp_user",
    "snmp_auth_key",
    "snmp_priv_key",
    "snmp_auth_protocol",
    "snmp_priv_protocol",
)


def _mask_target(target: dict | None) -> dict | None:
    """Strip the raw bearer token from a target dict before it goes out over
    the API. Replaced with a boolean `token_set` flag — the Admin UI has no
    functional need to redisplay a live FortiAnalyzer credential, and doing
    so puts it in the DOM, dev tools, and potentially browser
    history/autofill for no benefit."""
    if target is None:
        return None
    masked = dict(target)
    masked["token_set"] = bool(masked.get("token"))
    masked.pop("token", None)
    return masked


@bp.route("/")
@_admin_required
def admin_page():
    app_log("DEBUG", "admin", "Admin page accessed", username=session["user"])
    return render_template("admin.html", user=session["user"])


# ── Groups API ────────────────────────────────────────────────────────────────


@bp.route("/api/groups")
@_admin_required
def api_groups_list():
    return jsonify(list_groups())


@bp.route("/api/groups", methods=["POST"])
@_admin_required
def api_groups_create():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400
    members = data.get("members", [])
    ad_groups = data.get("ad_groups", [])
    allowed_tabs = data.get("allowed_tabs", [])
    adom_restrict = bool(data.get("adom_restrict", False))
    allowed_adoms = data.get("allowed_adoms", [])
    try:
        ok = create_group(name, members, ad_groups, allowed_tabs, adom_restrict, allowed_adoms)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    if not ok:
        return jsonify({"error": f"Group '{name}' already exists"}), 409
    app_log("INFO", "admin", "Group created", by=session["user"], group=name)
    return jsonify(get_group(name)), 201


@bp.route("/api/groups/<name>", methods=["PUT"])
@_admin_required
def api_groups_update(name: str):
    data = request.get_json(silent=True) or {}
    existing = get_group(name)
    if existing is None:
        return jsonify({"error": f"Group '{name}' not found"}), 404
    # Any field not present in the incoming body keeps its current value —
    # the Phase 1 admin UI only sends `members`/`allowed_tabs`, and without
    # this it would silently wipe ad_groups/adom_restrict/allowed_adoms on
    # every save.
    members = data.get("members", existing["members"])
    ad_groups = data.get("ad_groups", existing["ad_groups"])
    allowed_tabs = data.get("allowed_tabs", existing["allowed_tabs"])
    adom_restrict = bool(data.get("adom_restrict", existing["adom_restrict"]))
    allowed_adoms = data.get("allowed_adoms", existing["allowed_adoms"])
    if not update_group(
        name, members, allowed_tabs, adom_restrict, allowed_adoms, ad_groups=ad_groups
    ):
        return jsonify({"error": f"Group '{name}' not found"}), 404
    app_log("INFO", "admin", "Group updated", by=session["user"], group=name)
    return jsonify(get_group(name))


@bp.route("/api/groups/<name>", methods=["DELETE"])
@_admin_required
def api_groups_delete(name: str):
    if not delete_group(name):
        return jsonify({"error": f"Group '{name}' not found"}), 404
    app_log("INFO", "admin", "Group deleted", by=session["user"], group=name)
    return jsonify({"deleted": name})


# ── FAZ Targets API ────────────────────────────────────────────────────────────


@bp.route("/api/faz-targets")
@_admin_required
def api_faz_targets_list():
    return jsonify([_mask_target(t) for t in list_targets()])


@bp.route("/api/faz-targets", methods=["POST"])
@_admin_required
def api_faz_targets_create():
    data = request.get_json(silent=True) or {}
    label = (data.get("label") or "").strip()
    if not label:
        return jsonify({"error": "label is required"}), 400
    host = data.get("host", "")
    adom = data.get("adom", "root")
    token = data.get("token", "")
    snmp_overrides = {k: data[k] for k in _SNMP_OVERRIDE_FIELDS if data.get(k)}
    ok = create_target(label, host, adom, token, snmp_overrides)
    if not ok:
        return jsonify({"error": f"Target '{label}' already exists"}), 409
    app_log("INFO", "admin", "FAZ target created", by=session["user"], target=label)
    return jsonify(_mask_target(get_target(label))), 201


@bp.route("/api/faz-targets/<label>", methods=["PUT"])
@_admin_required
def api_faz_targets_update(label: str):
    data = request.get_json(silent=True) or {}
    host = data.get("host", "")
    adom = data.get("adom", "root")
    # A blank/omitted token means "keep the existing one" — the edit modal
    # leaves the token input blank on open (see admin.js) rather than
    # redisplaying the stored credential, so update_target() preserves the
    # prior token whenever this is empty.
    token = data.get("token", "")
    snmp_overrides = {k: data[k] for k in _SNMP_OVERRIDE_FIELDS if data.get(k)}
    ok = update_target(label, host, adom, token, snmp_overrides)
    if not ok:
        return jsonify({"error": f"Target '{label}' not found"}), 404
    app_log("INFO", "admin", "FAZ target updated", by=session["user"], target=label)
    return jsonify(_mask_target(get_target(label)))


@bp.route("/api/faz-targets/<label>", methods=["DELETE"])
@_admin_required
def api_faz_targets_delete(label: str):
    if not delete_target(label):
        return jsonify({"error": f"Target '{label}' not found"}), 404
    app_log("INFO", "admin", "FAZ target deleted", by=session["user"], target=label)
    return jsonify({"deleted": label})


# ── Users API (for member picker) ─────────────────────────────────────────────


@bp.route("/api/users")
@_admin_required
def api_users_list():
    return jsonify(list_users())


# ── Tabs registry ─────────────────────────────────────────────────────────────


@bp.route("/api/tabs")
@_admin_required
def api_tabs_list():
    # "admin" access is role-based (the user's `role` field), not a
    # tab-permission grantable via the group editor, so it's excluded here.
    return jsonify(
        [{"key": k, "name": v} for k, v in registry.known_tabs().items() if k != "admin"]
    )


# ── Logs API ──────────────────────────────────────────────────────────────────


@bp.route("/api/logs")
@_admin_required
def api_logs_get():
    level = request.args.get("level") or None
    component = request.args.get("component") or None
    try:
        limit = int(request.args.get("limit", 500))
    except ValueError:
        limit = 500
    entries = get_log_entries(level=level, component=component, limit=limit)
    return jsonify(
        {
            "current_level": get_log_level(),
            "levels": get_log_levels(),
            "count": len(entries),
            "entries": entries,
        }
    )


@bp.route("/api/logs/level", methods=["POST"])
@_admin_required
def api_logs_set_level():
    data = request.get_json(silent=True) or {}
    level = (data.get("level") or "").upper()
    try:
        set_log_level(level)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    app_log("INFO", "admin", "Log level changed", by=session["user"], new_level=level)
    return jsonify({"current_level": get_log_level()})


@bp.route("/api/logs", methods=["DELETE"])
@_admin_required
def api_logs_clear():
    clear_log_entries()
    app_log("INFO", "admin", "Log buffer cleared", by=session["user"])
    return jsonify({"cleared": True})


# ── Host Metrics API ──────────────────────────────────────────────────────────


def _downsample_rows(rows: list[dict], max_points: int = 150) -> list[dict]:
    n = len(rows)
    if n <= max_points:
        return rows
    step = n / max_points
    return [rows[int(i * step)] for i in range(max_points)]


@bp.route("/api/host-metrics")
@_admin_required
def api_host_metrics():
    import app.host_metrics_history as history

    range_key = request.args.get("range", history.DEFAULT_RANGE)
    if range_key not in history.RANGES:
        range_key = history.DEFAULT_RANGE

    since_dt = datetime.datetime.now(datetime.timezone.utc) - history.RANGES[range_key]
    since = since_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    rows = history.get_history(since)
    rows = _downsample_rows(rows)

    result = {"cpu": [], "mem": [], "disk": []}
    for row in rows:
        ts = int(datetime.datetime.fromisoformat(row["collected_at"]).timestamp())
        result["cpu"].append({"ts": ts, "v": row["cpu_percent"]})
        result["mem"].append({"ts": ts, "v": row["memory_percent"]})
        result["disk"].append({"ts": ts, "v": row["disk_percent"]})
    return jsonify(result)
