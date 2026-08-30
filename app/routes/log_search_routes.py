"""Log Search routes.

Page:  GET  /log-search

API (JSON):
  GET  /api/log-search/targets           allowed-ADOM-filtered target list
  GET  /api/log-search/fields?target=&logtype=   field names for the advanced-filter picker
  GET  /api/log-search/devices?target=   managed-device list for the device picker
  POST /api/log-search                   run a search, return matching rows
"""

from flask import Blueprint, jsonify, render_template, request, session

from app import registry
from app.app_logger import app_log
from app.config import Config
from app.decorators import check_adom_access, tab_required
from app.faz_client import FAZClient, FAZError, FAZSearchTimeout, summarize_connection_error
from app.faz_targets import get_target, list_targets
from app.groups import get_allowed_adoms
from app.log_search_filters import FilterValidationError, parse_ip_entries, parse_port_entries

bp = Blueprint("log_search", __name__)

registry.register("log_search", "Log Search", "log_search.index")


def _client_for(target: dict) -> FAZClient:
    return FAZClient(
        host=target["host"],
        token=target.get("token", ""),
        adom=target.get("adom", "root"),
        verify_ssl=Config.FAZ_VERIFY_SSL,
        timeout=Config.FAZ_REQUEST_TIMEOUT,
    )


@bp.route("/log-search")
@tab_required("log_search")
def index():
    return render_template("log_search.html", user=session["user"])


@bp.route("/api/log-search/targets")
@tab_required("log_search")
def api_targets():
    ad_groups = session.get("ad_groups", [])
    allowed = get_allowed_adoms(session["user"], ad_groups=ad_groups, role=session.get("role"))
    targets = list_targets()
    if allowed is not None:
        targets = [t for t in targets if t.get("label") in allowed]
    return jsonify(
        [{"label": t["label"], "host": t["host"], "adom": t.get("adom", "root")} for t in targets]
    )


@bp.route("/api/log-search/fields")
@tab_required("log_search")
def api_fields():
    target_label = request.args.get("target", "")
    err = check_adom_access(target_label)
    if err is not None:
        return err
    target = get_target(target_label)
    if target is None:
        return jsonify({"error": f"Target '{target_label}' not found"}), 404
    logtype = request.args.get("logtype", "traffic")
    try:
        with _client_for(target) as client:
            fields = client.get_log_fields(logtype)
    except FAZError as exc:
        return jsonify({"error": str(exc)}), 502
    except Exception as exc:
        return jsonify({"error": summarize_connection_error(exc)}), 502
    return jsonify(fields)


@bp.route("/api/log-search/devices")
@tab_required("log_search")
def api_devices():
    target_label = request.args.get("target", "")
    err = check_adom_access(target_label)
    if err is not None:
        return err
    target = get_target(target_label)
    if target is None:
        return jsonify({"error": f"Target '{target_label}' not found"}), 404
    try:
        with _client_for(target) as client:
            devices = client.get_devices()
    except FAZError as exc:
        return jsonify({"error": str(exc)}), 502
    except Exception as exc:
        return jsonify({"error": summarize_connection_error(exc)}), 502
    return jsonify(devices)


@bp.route("/api/log-search", methods=["POST"])
@tab_required("log_search")
def api_search():
    data = request.get_json(silent=True) or {}
    target_label = data.get("target", "")
    user = session["user"]
    err = check_adom_access(target_label)
    if err is not None:
        app_log(
            "WARN",
            "log_search",
            "Search denied: ADOM access not permitted",
            by=user,
            target=target_label,
        )
        return err
    target = get_target(target_label)
    if target is None:
        app_log(
            "WARN",
            "log_search",
            "Search failed: target not found",
            by=user,
            target=target_label,
        )
        return jsonify({"error": f"Target '{target_label}' not found"}), 404

    source_raw = data.get("source_ips", "") or ""
    dest_raw = data.get("destination_ips", "") or ""

    start_time = data.get("start_time", "")
    end_time = data.get("end_time", "")
    if not start_time or not end_time:
        app_log(
            "WARN",
            "log_search",
            "Search rejected: missing start_time/end_time",
            by=user,
            target=target_label,
        )
        return jsonify({"error": "start_time and end_time are required"}), 400

    try:
        source_clauses = parse_ip_entries(source_raw, "srcip") if source_raw.strip() else []
        dest_clauses = parse_ip_entries(dest_raw, "dstip") if dest_raw.strip() else []
        port_clauses = parse_port_entries(data.get("ports", "") or "")
    except FilterValidationError as exc:
        app_log(
            "WARN",
            "log_search",
            "Search rejected: invalid filter input",
            by=user,
            target=target_label,
            error=str(exc),
        )
        return jsonify({"error": str(exc)}), 400

    # ANY/ALL (or a blank box) means "no filter on this field" — parse_ip_entries
    # already drops those entries, so checking the resulting clause lists (not
    # the raw strings) is what actually enforces "no ANY/ANY searches".
    if not source_clauses and not dest_clauses:
        app_log(
            "WARN",
            "log_search",
            "Search rejected: no source or destination IP",
            by=user,
            target=target_label,
        )
        return jsonify({"error": "At least one of source or destination IP is required"}), 400

    try:
        filter_expression = FAZClient.build_filter_expression(
            source_clauses, dest_clauses, port_clauses, data.get("extra_filters") or []
        )
    except FilterValidationError as exc:
        app_log(
            "WARN",
            "log_search",
            "Search rejected: invalid filter input",
            by=user,
            target=target_label,
            error=str(exc),
        )
        return jsonify({"error": str(exc)}), 400

    local_start = local_end = None
    try:
        with _client_for(target) as client:
            local_start, local_end = client.local_time_range(start_time, end_time)
            result = client.search_logs(
                logtype=data.get("logtype", "traffic"),
                device=data.get("device", "All_FortiGate"),
                filter_expression=filter_expression,
                start_time=local_start,
                end_time=local_end,
                limit=Config.LOG_SEARCH_MAX_RESULTS,
                poll_interval=Config.LOG_SEARCH_POLL_INTERVAL,
                timeout=Config.LOG_SEARCH_TIMEOUT,
            )
    except FAZSearchTimeout as exc:
        app_log(
            "WARN",
            "log_search",
            "Search timed out",
            by=user,
            target=target_label,
            filter_expression=filter_expression,
            error=str(exc),
            appliance_local=f"{local_start}..{local_end}",
        )
        return jsonify(
            {"error": "Search is taking too long — narrow the time range or add more filters."}
        ), 504
    except FAZError as exc:
        app_log(
            "WARN",
            "log_search",
            "Search failed: FortiAnalyzer error",
            by=user,
            target=target_label,
            filter_expression=filter_expression,
            error=str(exc),
            appliance_local=f"{local_start}..{local_end}",
        )
        return jsonify({"error": str(exc)}), 502
    except Exception as exc:
        app_log(
            "WARN",
            "log_search",
            "Search failed: connection error",
            by=user,
            target=target_label,
            filter_expression=filter_expression,
            error=summarize_connection_error(exc),
            appliance_local=f"{local_start}..{local_end}",
        )
        return jsonify({"error": summarize_connection_error(exc)}), 502

    app_log(
        "INFO",
        "log_search",
        "Search completed",
        by=user,
        target=target_label,
        filter_expression=filter_expression,
        rows=len(result.get("rows", [])),
        requested_utc=f"{start_time}..{end_time}",
        appliance_local=f"{local_start}..{local_end}",
    )
    return jsonify(result)
