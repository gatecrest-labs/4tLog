"""Security helpers for CSRF and safe API error responses."""

from __future__ import annotations

import hmac
import secrets
import uuid

from flask import jsonify, request, session

from app.app_logger import app_log


def ensure_csrf_token() -> str:
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def validate_csrf_request() -> bool:
    expected = session.get("_csrf_token", "")
    if not expected:
        return False
    provided = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token") or ""
    return hmac.compare_digest(expected, provided)


SESSION_LOST_MESSAGE = "Your session expired or was replaced. Please log in again."


def csrf_error_response():
    if request.path.startswith("/api/") or request.path.startswith("/admin/api/"):
        if "login_at" not in session:
            # The page was loaded under a session that is gone (expired, or its cookie
            # replaced, e.g. by another app on the same host name): the token it sent can
            # never match the new empty session, and "CSRF failed" would send the user
            # hunting for the wrong problem.
            return jsonify({"error": SESSION_LOST_MESSAGE}), 401
        return jsonify({"error": "CSRF validation failed"}), 400
    return "CSRF validation failed", 400


def _error_id() -> str:
    return uuid.uuid4().hex[:12]


def internal_api_error(component: str, exc: Exception, status: int = 500):
    eid = _error_id()
    app_log(
        "ERROR",
        component,
        "Internal API error",
        error_id=eid,
        exc_type=type(exc).__name__,
        exc=str(exc),
        path=request.path,
        method=request.method,
    )
    return jsonify({"error": "Internal server error", "error_id": eid}), status


def upstream_api_error(component: str, exc: Exception):
    eid = _error_id()
    app_log(
        "WARN",
        component,
        "Upstream request failed",
        error_id=eid,
        exc_type=type(exc).__name__,
        exc=str(exc),
        path=request.path,
        method=request.method,
    )
    return jsonify({"error": "Upstream request failed", "error_id": eid}), 502
