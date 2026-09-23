from flask import Flask, jsonify, request, session
from werkzeug.exceptions import RequestEntityTooLarge

from app.config import Config
from app.security import csrf_error_response, ensure_csrf_token, validate_csrf_request

# Blueprint modules to import — each one calls registry.register() at import
# time.  To add a new module, append its dotted path here and nothing else.
_BLUEPRINT_MODULES: list[str] = [
    "app.routes.auth_routes",
    "app.routes.dashboard_routes",
    "app.routes.log_search_routes",
    "app.routes.admin_routes",
    "app.routes.external_api_routes",
]


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.from_object(Config)

    @app.before_request
    def _security_filters():
        ensure_csrf_token()
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            if request.endpoint == "static":
                return None
            if request.path.startswith("/external/api/"):
                # Bearer-token authenticated, no browser session/CSRF token exists.
                return None
            if not validate_csrf_request():
                return csrf_error_response()
        return None

    @app.after_request
    def _set_security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self' data:; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'"
        )
        forwarded_proto = request.headers.get("X-Forwarded-Proto", "")
        if request.is_secure or forwarded_proto.lower() == "https":
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return resp

    @app.errorhandler(RequestEntityTooLarge)
    def _file_too_large(_exc):
        if request.path.startswith("/api/") or request.path.startswith("/admin/api/"):
            return jsonify({"error": "Uploaded file is too large"}), 413
        return "Uploaded file is too large", 413

    import importlib

    for module_path in _BLUEPRINT_MODULES:
        mod = importlib.import_module(module_path)
        if hasattr(mod, "bp"):
            app.register_blueprint(mod.bp)

    from app import groups, registry

    groups.KNOWN_TABS = registry.known_tabs()

    @app.context_processor
    def inject_session_globals():
        role = session.get("role", "viewer")
        if role == "admin":
            allowed = set(registry.known_tabs().keys())
        else:
            allowed = set(session.get("allowed_tabs", []))
        return {
            "current_role": role,
            "allowed_tabs": allowed,
            "nav_registry": registry.get_registry(),
            "csrf_token": ensure_csrf_token(),
        }

    # DB tables must exist regardless of which process polls into them — a
    # web worker reads them (via each cache's SQLite read-through
    # fallback, or history rollups) even when it never runs a scheduler
    # itself.
    from app.host_metrics_history import init_db as init_host_metrics_db
    from app.log_stats_history import init_db as init_log_stats_db
    from app.threat_stats_history import init_db as init_threat_stats_db

    init_log_stats_db()
    init_threat_stats_db()
    init_host_metrics_db()

    # RUN_SCHEDULERS=inline reproduces the historical single-process
    # behavior for local development. Otherwise (the default), this
    # process starts no BackgroundScheduler jobs at all — a separate
    # `python -m app.collector` process owns every poller instead. See
    # app/collector.py and app/collector_store.py.
    if Config.RUN_SCHEDULERS == "inline":
        if not app.config.get("_FAZ_HEALTH_STARTED"):
            app.config["_FAZ_HEALTH_STARTED"] = True
            from app.faz_health_cache import init_scheduler as init_faz_health_scheduler

            init_faz_health_scheduler(app)

        if not app.config.get("_LOG_STATS_STARTED"):
            app.config["_LOG_STATS_STARTED"] = True
            from app.log_stats_cache import init_scheduler as init_log_stats_scheduler

            init_log_stats_scheduler(app)

        if not app.config.get("_THREAT_STATS_STARTED"):
            app.config["_THREAT_STATS_STARTED"] = True
            from app.threat_stats_cache import init_scheduler as init_threat_stats_scheduler

            init_threat_stats_scheduler(app)

        if not app.config.get("_HOST_METRICS_STARTED"):
            app.config["_HOST_METRICS_STARTED"] = True
            from app.host_metrics_cache import init_scheduler as init_host_metrics_scheduler

            init_host_metrics_scheduler(app)

    return app
