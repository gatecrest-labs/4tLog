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
import threading
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
from app.conn_timeline_job import STORE, JobLimitError, collect, continue_collect
from app.conn_timeline_summary import SECTIONS, summarize
from app.decorators import check_adom_access, tab_required
from app.faz_client import FAZClient, FAZError, summarize_connection_error
from app.faz_targets import get_target, list_targets
from app.groups import get_allowed_adoms

bp = Blueprint("conn_timeline", __name__)

registry.register("conn_timeline", "Connection Timeline", "conn_timeline.index")

COMPONENT = "conn_timeline"
_CONTINUE_LOCK = threading.Lock()
_SUMMARY_LOCK = threading.Lock()
_summaries_running = 0


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


def _run_build(job, target: dict, spec: dict, resume_from: dict | None = None) -> None:
    """The background half of a build: page the logs, roll them up, audit.

    With ``resume_from`` (the state a partial build left on its job) it reads only
    what that build did not reach, into the same timeline."""
    user = job.user
    budget = Config.CONN_TIMELINE_DEADLINE_SECS
    if resume_from is None:
        timeline = Timeline(spec["host"], spec["direction"], spec["start"], spec["end"])
    else:
        timeline = resume_from["timeline"]
        prior = resume_from["prior"]
        left = max((prior["matched"] or 0) - prior["fetched"], 0)
        per_1k, cap = (
            Config.CONN_TIMELINE_DEADLINE_SECS_PER_1K,
            Config.CONN_TIMELINE_DEADLINE_MAX_SECS,
        )
        budget = max(budget, min(cap, per_1k * left / 1000))
    deadline_at = time.monotonic() + budget
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
    if resume_from is not None:
        audit["continued"] = True

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
                    # a continued build's counts are the whole timeline's, not this stretch's
                    "fetched": timeline.rows if resume_from else progress.get("fetched", 0),
                    "matched": (
                        resume_from["prior"]["matched"] if resume_from else progress.get("matched")
                    ),
                    "matched_final": (
                        resume_from["prior"]["matched_final"]
                        if resume_from
                        else progress.get("matched_final", False)
                    ),
                    "gaps": [],
                    "through": None,
                },
            )
        )

    try:
        with _client_for(target) as client:
            local_start, local_end = client.local_time_range(_iso(spec["start"]), _iso(spec["end"]))
            audit["appliance_local"] = f"{local_start}..{local_end}"
            common = {
                "device": spec["device"],
                "filter_expression": spec["filter"],
                "max_rows": Config.CONN_TIMELINE_MAX_ROWS,
                "page_size": Config.CONN_TIMELINE_PAGE_SIZE,
                "deadline_at": deadline_at,
                "deadline_per_1k": Config.CONN_TIMELINE_DEADLINE_SECS_PER_1K or None,
                "deadline_max": Config.CONN_TIMELINE_DEADLINE_MAX_SECS,
                "poll_interval": Config.LOG_SEARCH_POLL_INTERVAL,
                "on_progress": job.update,
                "is_cancelled": job.is_cancelled,
                "workers": max(1, Config.CONN_TIMELINE_WORKERS),
                "client_factory": lambda: _client_for(target),
                "on_snapshot": snapshot,
            }
            if resume_from is None:
                coverage = collect(client, timeline, start=spec["start"], end=spec["end"], **common)
            else:
                coverage = continue_collect(
                    client, timeline, resume_from["resume"], resume_from["prior"], **common
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

    resume = coverage.pop("_resume", [])
    burst = coverage.pop("_burst", [])
    coverage["resumable"] = bool(resume)
    if resume:  # what Continue needs; the timeline stays in memory only while it can be used
        job.resume_state = {
            "timeline": timeline,
            "resume": resume,
            "spec": spec,
            "target": target,
            "prior": {
                "matched": coverage["matched"],
                "matched_final": coverage["matched_final"],
                "fetched": coverage["fetched"],
                "searches": coverage["searches"],
                "burst": burst,
            },
        }
    result = _decorate(timeline, spec, coverage)
    audit.update(
        matched=coverage["matched"],
        fetched=coverage["fetched"],
        diagnostics=coverage.get("diagnostics"),
    )
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


@bp.route("/api/conn-timeline/summary", methods=["POST"])
@tab_required("conn_timeline")
def api_summary():
    """One section of the Quick summary: what FortiView says about one IP, in seconds.

    Stateless: the page asks for each section separately and shows them as they arrive."""
    global _summaries_running
    data = request.get_json(silent=True) or {}
    user = session["user"]
    target_label = str(data.get("target", ""))
    err = check_adom_access(target_label)
    if err is not None:
        app_log(
            "WARN",
            COMPONENT,
            "Summary denied: ADOM access not permitted",
            by=user,
            target=target_label,
        )
        return err
    target = get_target(target_label)
    if target is None:
        return jsonify({"error": f"Target '{target_label}' not found"}), 404
    try:
        adom = parse_adom(data.get("adom"), target)
        target = with_adom(target, adom)
        host = parse_host(data.get("host"))
        direction = str(data.get("direction") or "either")
        if direction not in DIRECTIONS:
            raise TimelineInputError(f"Unknown direction '{direction}'")
        device = parse_device(data.get("device"))
        start, end, _preset = parse_window(
            data, Config.CONN_TIMELINE_MAX_WINDOW_HOURS, Config.CONN_TIMELINE_DEFAULT_WINDOW
        )
        section = str(data.get("section") or "")
        if section not in SECTIONS:
            raise TimelineInputError(f"Unknown summary section '{section}'")
    except (TimelineInputError, AdomError) as exc:
        return jsonify({"error": str(exc)}), 400

    with _SUMMARY_LOCK:
        if _summaries_running >= Config.CONN_TIMELINE_SUMMARY_MAX_CONCURRENT:
            return jsonify({"error": "Too many summaries are running. Try again shortly."}), 429
        _summaries_running += 1
    began = time.monotonic()
    try:
        with _client_for(target) as client:
            time_range = client.local_time_range(_iso(start), _iso(end))
            result = summarize(
                client, section, str(host), direction, time_range, [{"devid": device}]
            )
    except FAZError as exc:
        app_log(
            "WARN",
            COMPONENT,
            "Summary failed: FortiAnalyzer error",
            by=user,
            section=section,
            error=str(exc),
        )
        return jsonify({"error": str(exc)}), 502
    except Exception as exc:
        message = summarize_connection_error(exc)
        app_log(
            "WARN",
            COMPONENT,
            "Summary failed: connection error",
            by=user,
            section=section,
            error=message,
        )
        return jsonify({"error": message}), 502
    finally:
        with _SUMMARY_LOCK:
            _summaries_running -= 1
    seconds = round(time.monotonic() - began, 1)
    app_log(
        "INFO",
        COMPONENT,
        "Timeline summary",
        by=user,
        target=target_label,
        adom=adom,
        host=str(host),
        direction=direction,
        section=section,
        seconds=seconds,
    )
    return jsonify({**result, "section": section, "units": "sessions", "seconds": seconds})


@bp.route("/api/conn-timeline/<job_id>/continue", methods=["POST"])
@tab_required("conn_timeline")
def api_continue(job_id):
    """Read what a partial build did not reach, into the same timeline, as a new job."""
    from app import conn_timeline_job

    user = session["user"]
    old = STORE.get(job_id, user, Config.CONN_TIMELINE_JOB_LIFETIME_SECS)
    if old is None:
        return jsonify({"error": "Timeline not found or expired"}), 404
    with _CONTINUE_LOCK:
        state, old.resume_state = old.resume_state, None  # one Continue per partial build
    if old.running or state is None:
        return jsonify({"error": "There is nothing left to continue on this timeline"}), 409
    spec = state["spec"]
    err = check_adom_access(spec["target"])
    if err is not None:
        old.resume_state = state
        return err
    try:
        job = STORE.create(
            user,
            old.request,
            max_running=Config.CONN_TIMELINE_MAX_JOBS,
            max_per_user=Config.CONN_TIMELINE_MAX_JOBS_PER_USER,
            lifetime=Config.CONN_TIMELINE_JOB_LIFETIME_SECS,
        )
    except JobLimitError as exc:
        old.resume_state = state
        app_log("WARN", COMPONENT, "Timeline refused: build limit", by=user, error=str(exc))
        return jsonify({"error": str(exc)}), 429
    app_log(
        "INFO",
        COMPONENT,
        "Timeline continuing",
        by=user,
        target=spec["target"],
        host=spec["host"],
        stretches=len(state["resume"]),
        fetched=state["prior"]["fetched"],
        matched=state["prior"]["matched"],
    )
    conn_timeline_job.spawn(lambda: _run_build(job, state["target"], spec, resume_from=state))
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
