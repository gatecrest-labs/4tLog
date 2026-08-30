"""Shared route decorators — import these instead of redefining in every blueprint."""

from __future__ import annotations

import time as _time
from functools import wraps

from flask import abort, current_app, jsonify, redirect, request, url_for
from flask import session as flask_session


def _is_api_path(path: str) -> bool:
    return path.startswith("/api/") or path.startswith("/admin/api/")


def _revalidate_session() -> "tuple | None":
    """Re-check that the session is still valid on every request."""
    login_at = flask_session.get("login_at")
    if login_at is None:
        flask_session.clear()
        return redirect(url_for("auth.login")), 302

    lifetime = current_app.config.get("SESSION_ABSOLUTE_LIFETIME", 36000)
    if _time.time() - login_at > lifetime:
        flask_session.clear()
        if _is_api_path(request.path):
            return jsonify({"error": "Session expired"}), 401
        return redirect(url_for("auth.login")), 302

    username = flask_session.get("user", "")
    if username:
        from app.auth import _load_users
        from app.groups import get_allowed_tabs

        users = _load_users()
        entry = users.get(username)
        ad_groups = flask_session.get("ad_groups", [])
        if entry is None:
            # A local-auth user whose entry has disappeared from users.json
            # (e.g. deleted by an admin) must always lose their session,
            # regardless of whether `role` happens to still be set. Only
            # non-local auth sources (future RADIUS/AD) may fall back to
            # session-cached role data when there's no local entry to check.
            if flask_session.get("auth_source") == "local" or not flask_session.get("role"):
                flask_session.clear()
                if _is_api_path(request.path):
                    return jsonify({"error": "Not authenticated"}), 401
                return redirect(url_for("auth.login")), 302
        else:
            flask_session["role"] = entry.get("role", "viewer")
        flask_session["allowed_tabs"] = list(
            get_allowed_tabs(username, ad_groups=ad_groups, role=flask_session.get("role"))
        )

    return None


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in flask_session:
            if _is_api_path(request.path):
                return jsonify({"error": "Not authenticated"}), 401
            return redirect(url_for("auth.login", next=request.path))
        err = _revalidate_session()
        if err is not None:
            return err
        return f(*args, **kwargs)

    return decorated


def tab_required(tab_key: str):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "user" not in flask_session:
                if _is_api_path(request.path):
                    return jsonify({"error": "Not authenticated"}), 401
                return redirect(url_for("auth.login", next=request.path))
            err = _revalidate_session()
            if err is not None:
                return err
            if flask_session.get("role") != "admin" and tab_key not in set(
                flask_session.get("allowed_tabs", [])
            ):
                if _is_api_path(request.path):
                    return jsonify({"error": "Access denied"}), 403
                abort(403)
            return f(*args, **kwargs)

        return decorated

    return decorator


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in flask_session:
            if _is_api_path(request.path):
                return jsonify({"error": "Not authenticated"}), 401
            return redirect(url_for("auth.login", next=request.path))
        err = _revalidate_session()
        if err is not None:
            return err
        if flask_session.get("role") != "admin":
            if _is_api_path(request.path):
                return jsonify({"error": "Admin role required"}), 403
            abort(403)
        return f(*args, **kwargs)

    return decorated


def check_adom_access(adom: str) -> "tuple | None":
    """Return a 403 JSON response tuple if the current user cannot access ``adom``.

    Called by Dashboard routes (Phase 2) and the Log Search fields/devices/
    search routes (Phase 3, app/routes/log_search_routes.py).
    """
    if flask_session.get("role") == "admin":
        return None
    from app.groups import user_can_access_adom

    ad_groups = flask_session.get("ad_groups", [])
    if not user_can_access_adom(flask_session.get("user", ""), adom, ad_groups=ad_groups):
        return jsonify({"error": f"Access to ADOM '{adom}' is not permitted for your account"}), 403
    return None
