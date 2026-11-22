"""Connection Timeline routes.

Page:  GET  /conn-timeline

API (JSON):
  GET    /api/conn-timeline/targets            allowed-ADOM-filtered target list
  GET    /api/conn-timeline/devices?target=    managed-device list for the device picker
  POST   /api/conn-timeline                    start a build, returns {job_id} (202)
  GET    /api/conn-timeline/<job_id>           progress, then the result
  DELETE /api/conn-timeline/<job_id>           cancel a running build

Read-only towards FortiAnalyzer: log search submit, fetch, count and delete
(of the search task only). Every build is written to the app log under the
``conn_timeline`` component: who looked at which host, when, and how much of
the traffic the picture covers.
"""

from __future__ import annotations

import datetime
import time

from flask import Blueprint, jsonify, render_template, request, session

from app import registry
from app.adom import AdomError, parse_adom, with_adom
from app.app_logger import app_log
from app.config import Config
from app.conn_timeline import (
    DIRECTIONS,
    Timeline,
    TimelineInputError,
    build_filter,
    parse_device,
    parse_host,
    parse_window,
)
from app.conn_timeline_job import STORE, JobLimitError, collect
from app.decorators import check_adom_access, tab_required
from app.faz_client import FAZClient, FAZError, summarize_connection_error
from app.faz_targets import get_target, list_targets
from app.groups import get_allowed_adoms

bp = Blueprint("conn_timeline", __name__)

registry.register("conn_timeline", "Connection Timeline", "conn_timeline.index")

COMPONENT = "conn_timeline"


def _client_for(target: dict) -> FAZClient:
    return FAZClient(
        host=target["host"],
        token=target.get("token", ""),
        adom=target.get("adom", "root"),
        verify_ssl=Config.FAZ_VERIFY_SSL,
        timeout=Config.FAZ_REQUEST_TIMEOUT,
    )


def _iso(dt: datetime.datetime) -> str:
    return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _allowed_targets() -> list[dict]:
    ad_groups = session.get("ad_groups", [])
    allowed = get_allowed_adoms(session["user"], ad_groups=ad_groups, role=session.get("role"))
    targets = list_targets()
    if allowed is not None:
        targets = [t for t in targets if t.get("label") in allowed]
    return targets


def _demo_hosts(targets: list[dict]) -> list[dict]:
    """In demo mode, the featured demo hosts on targets this user can see."""
    if not Config.DEMO_MODE:
        return []
    from app.demo_faz import FEATURED_HOSTS

    by_host = {t["host"]: t["label"] for t in targets}
    return [
        {"ip": h.ip, "target": by_host[h.site], "description": h.description}
        for h in FEATURED_HOSTS
        if h.site in by_host
    ]


@bp.route("/conn-timeline")
@tab_required("conn_timeline")
def index():
    return render_template(
        "conn_timeline.html",
        user=session["user"],
        default_preset=Config.CONN_TIMELINE_DEFAULT_WINDOW,
        max_window_hours=Config.CONN_TIMELINE_MAX_WINDOW_HOURS,
        max_rows=Config.CONN_TIMELINE_MAX_ROWS,
        demo_hosts=_demo_hosts(_allowed_targets()),
    )


@bp.route("/api/conn-timeline/targets")
@tab_required("conn_timeline")
def api_targets():
    return jsonify(
        [
            {"label": t["label"], "host": t["host"], "adom": t.get("adom", "root")}
            for t in _allowed_targets()
        ]
    )


@bp.route("/api/conn-timeline/adoms")
@tab_required("conn_timeline")
def api_adoms():
    target_label = request.args.get("target", "")
    err = check_adom_access(target_label)
    if err is not None:
        return err
    target = get_target(target_label)
    if target is None:
        return jsonify({"error": f"Target '{target_label}' not found"}), 404
    try:
        with _client_for(target) as client:
            adoms = client.get_adoms()
    except FAZError as exc:
        return jsonify({"error": str(exc)}), 502
    except Exception as exc:
        return jsonify({"error": summarize_connection_error(exc)}), 502
    return jsonify({"default": target.get("adom", "root"), "adoms": adoms})


@bp.route("/api/conn-timeline/devices")
@tab_required("conn_timeline")
def api_devices():
    target_label = request.args.get("target", "")
    err = check_adom_access(target_label)
    if err is not None:
        return err
    target = get_target(target_label)
    if target is None:
        return jsonify({"error": f"Target '{target_label}' not found"}), 404
    try:
        target = with_adom(target, parse_adom(request.args.get("adom"), target))
    except AdomError as exc:
        return jsonify({"error": str(exc)}), 400
    try:
        with _client_for(target) as client:
            devices = client.get_devices()
    except FAZError as exc:
        return jsonify({"error": str(exc)}), 502
    except Exception as exc:
        return jsonify({"error": summarize_connection_error(exc)}), 502
    return jsonify(devices)


def _decorate(timeline: Timeline, spec: dict, coverage: dict) -> dict:
    result = timeline.to_dict()
    result.update(
        {
            "target": spec["target"],
            "adom": spec["adom"],
            "host": spec["host"],
            "direction": spec["direction"],
            "direction_label": DIRECTIONS[spec["direction"]],
            "device": spec["device"],
            "verdict_filter": spec["verdict"],
            "preset": spec["preset"],
            "coverage": coverage,
        }
    )
    return result


def _run_build(job, target: dict, spec: dict) -> None:
    """The background half of a build: page the logs, roll them up, audit."""
    user = job.user
    deadline_at = time.monotonic() + Config.CONN_TIMELINE_DEADLINE_SECS
    timeline = Timeline(spec["host"], spec["direction"], spec["start"], spec["end"])
    audit = {
        "by": user,
        "target": spec["target"],
        "adom": target["adom"],
        "host": spec["host"],
        "direction": spec["direction"],
        "device": spec["device"],
        "filter_expression": spec["filter"],
        "requested_utc": f"{_iso(spec['start'])}..{_iso(spec['end'])}",
    }

    def snapshot() -> None:
        # Called by collect() with the timeline locked: what has arrived so far.
        progress = job.progress
        job.set_partial(
            _decorate(
                timeline,
                spec,
                {
                    "complete": False,
                    "reason": "running",
                    "fetched": progress.get("fetched", 0),
                    "matched": progress.get("matched"),
                    "matched_final": progress.get("matched_final", False),
                    "gaps": [],
                    "through": None,
                },
            )
        )

    try:
        with _client_for(target) as client:
            local_start, local_end = client.local_time_range(_iso(spec["start"]), _iso(spec["end"]))
            audit["appliance_local"] = f"{local_start}..{local_end}"
            coverage = collect(
                client,
                timeline,
                device=spec["device"],
                filter_expression=spec["filter"],
                start=spec["start"],
                end=spec["end"],
                max_rows=Config.CONN_TIMELINE_MAX_ROWS,
                page_size=Config.CONN_TIMELINE_PAGE_SIZE,
                deadline_at=deadline_at,
                poll_interval=Config.LOG_SEARCH_POLL_INTERVAL,
                on_progress=job.update,
                is_cancelled=job.is_cancelled,
                workers=max(1, Config.CONN_TIMELINE_WORKERS),
                client_factory=lambda: _client_for(target),
                on_snapshot=snapshot,
            )
    except FAZError as exc:
        job.finish("failed", error=str(exc))
        app_log("WARN", COMPONENT, "Timeline failed: FortiAnalyzer error", error=str(exc), **audit)
        return
    except Exception as exc:
        message = summarize_connection_error(exc)
        job.finish("failed", error=message)
        app_log("WARN", COMPONENT, "Timeline failed: connection error", error=message, **audit)
        return

    result = _decorate(timeline, spec, coverage)
    audit.update(matched=coverage["matched"], fetched=coverage["fetched"])
    reason = coverage["reason"]
    if reason == "cancelled":
        job.finish("cancelled", result=result)
        app_log("INFO", COMPONENT, "Timeline cancelled", **audit)
    elif reason == "deadline":
        job.finish("done", result=result)
        app_log("WARN", COMPONENT, "Timeline timed out (partial result)", **audit)
    elif reason:
        job.finish("done", result=result)
        app_log("INFO", COMPONENT, "Timeline truncated", reason=reason, **audit)
    else:
        job.finish("done", result=result)
        app_log("INFO", COMPONENT, "Timeline completed", **audit)


@bp.route("/api/conn-timeline", methods=["POST"])
@tab_required("conn_timeline")
def api_build():
    from app import conn_timeline_job

    data = request.get_json(silent=True) or {}
    user = session["user"]
    target_label = str(data.get("target", ""))
    err = check_adom_access(target_label)
    if err is not None:
        app_log(
            "WARN",
            COMPONENT,
            "Timeline denied: ADOM access not permitted",
            by=user,
            target=target_label,
        )
        return err
    target = get_target(target_label)
    if target is None:
        app_log(
            "WARN", COMPONENT, "Timeline failed: target not found", by=user, target=target_label
        )
        return jsonify({"error": f"Target '{target_label}' not found"}), 404

    try:
        adom = parse_adom(data.get("adom"), target)
        target = with_adom(target, adom)
        host = parse_host(data.get("host"))
        direction = str(data.get("direction") or "either")
        verdict_filter = str(data.get("verdict") or "all")
        device = parse_device(data.get("device"))
        start, end, preset = parse_window(
            data, Config.CONN_TIMELINE_MAX_WINDOW_HOURS, Config.CONN_TIMELINE_DEFAULT_WINDOW
        )
        filter_expression = build_filter(host, direction, verdict_filter)
    except (TimelineInputError, AdomError) as exc:
        app_log(
            "WARN",
            COMPONENT,
            "Timeline rejected: invalid input",
            by=user,
            target=target_label,
            error=str(exc),
        )
        return jsonify({"error": str(exc)}), 400

    spec = {
        "target": target_label,
        "adom": adom,
        "host": str(host),
        "direction": direction,
        "verdict": verdict_filter,
        "device": device,
        "start": start,
        "end": end,
        "preset": preset,
        "filter": filter_expression,
    }
    try:
        job = STORE.create(
            user,
            {k: (_iso(v) if isinstance(v, datetime.datetime) else v) for k, v in spec.items()},
            max_running=Config.CONN_TIMELINE_MAX_JOBS,
            max_per_user=Config.CONN_TIMELINE_MAX_JOBS_PER_USER,
            lifetime=Config.CONN_TIMELINE_JOB_LIFETIME_SECS,
        )
    except JobLimitError as exc:
        app_log("WARN", COMPONENT, "Timeline refused: build limit", by=user, error=str(exc))
        return jsonify({"error": str(exc)}), 429

    app_log(
        "INFO",
        COMPONENT,
        "Timeline started",
        by=user,
        target=target_label,
        adom=adom,
        host=spec["host"],
        direction=direction,
        device=device,
        filter_expression=filter_expression,
        requested_utc=f"{_iso(start)}..{_iso(end)}",
    )
    conn_timeline_job.spawn(lambda: _run_build(job, target, spec))
    return jsonify({"job_id": job.id, "status": job.status}), 202


@bp.route("/api/conn-timeline/<job_id>")
@tab_required("conn_timeline")
def api_job(job_id):
    job = STORE.get(job_id, session["user"], Config.CONN_TIMELINE_JOB_LIFETIME_SECS)
    if job is None:
        return jsonify({"error": "Timeline not found or expired"}), 404
    return jsonify(job.to_dict())


@bp.route("/api/conn-timeline/<job_id>", methods=["DELETE"])
@tab_required("conn_timeline")
def api_cancel(job_id):
    job = STORE.get(job_id, session["user"], Config.CONN_TIMELINE_JOB_LIFETIME_SECS)
    if job is None:
        return jsonify({"error": "Timeline not found or expired"}), 404
    job.cancel()
    return jsonify({"id": job.id, "status": job.status})
