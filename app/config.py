"""Application configuration loaded from environment / .env file."""

import os
import secrets
import sys
from pathlib import Path

from dotenv import load_dotenv

if os.environ.get("APP_LOAD_DOTENV", "true").lower() == "true":
    load_dotenv()


_ROOT = Path(__file__).resolve().parent.parent

# Demo mode (app/demo.py): synthetic FortiAnalyzer data, seeded users and
# targets, writes disabled. Never contacts a real FortiAnalyzer.
DEMO_MODE = os.environ.get("DEMO_MODE", "false").lower() == "true"


def _require_secret_key() -> str:
    val = os.environ.get("SECRET_KEY", "")
    if not val or val == "change-me-in-production":
        if DEMO_MODE:
            # A throwaway key: demo sessions end when the process restarts.
            print("[config] DEMO_MODE: SECRET_KEY not set, using a random one", file=sys.stderr)
            return secrets.token_hex(32)
        raise RuntimeError(
            "SECRET_KEY is not set or is the insecure default. "
            "Generate one with: uv run python manage_users.py secret"
        )
    return val


class Config:
    DEMO_MODE = DEMO_MODE
    SECRET_KEY = _require_secret_key()
    # Browser cookies are scoped by domain+path, not by port (RFC 6265).
    # Without a unique name here, this collides with any other Flask app's
    # default "session" cookie served from localhost at a different port
    # (e.g. 4thealth-plus, 4tExecutive) -- whichever app's response the
    # browser processes last silently overwrites the others' session
    # cookie, causing intermittent 401s and CSRF failures that have
    # nothing to do with this app's own auth logic.
    SESSION_COOKIE_NAME = "4tlog_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    _ssl_active = os.path.exists(os.environ.get("SSL_CERT", "certs/cert.pem")) and os.path.exists(
        os.environ.get("SSL_KEY", "certs/key.pem")
    )
    SESSION_COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "auto").lower() == "true" or (
        os.environ.get("COOKIE_SECURE", "auto").lower() == "auto" and _ssl_active
    )
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour
    SESSION_ABSOLUTE_LIFETIME = int(
        os.environ.get("SESSION_ABSOLUTE_LIFETIME", str(10 * 3600))
    )  # 10 h
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", str(4 * 1024 * 1024)))

    # Collector/web process split (app/collector.py, app/collector_store.py).
    # DATA_DIR is where every SQLite file (logstats.db, hostmetrics.db,
    # collector_state.db) lives — default matches where they've always
    # lived (the repo root), overridable so docker-compose can point both
    # the "web" and "collector" services at one shared volume.
    # Demo mode keeps its SQLite files apart from a real deployment's.
    DATA_DIR = os.environ.get("DATA_DIR") or str(_ROOT / ".demo-data" if DEMO_MODE else _ROOT)

    # "inline" reproduces the historical single-process behavior (this app
    # starts and owns every BackgroundScheduler poller itself) — useful for
    # local development. Any other value (the default, "collector") means
    # this process starts no schedulers; a separate `python -m
    # app.collector` process owns them instead, and this process reads
    # poll results via each cache module's SQLite read-through fallback.
    # Demo mode defaults to "inline" so a single process is the whole demo.
    RUN_SCHEDULERS = os.environ.get("RUN_SCHEDULERS", "inline" if DEMO_MODE else "collector")

    # FortiAnalyzer client (app/faz_client.py)
    FAZ_VERIFY_SSL = os.environ.get("FAZ_VERIFY_SSL", "false").lower() == "true"
    FAZ_REQUEST_TIMEOUT = int(os.environ.get("FAZ_REQUEST_TIMEOUT", "30"))

    # SNMPv3 health polling (app/faz_health_cache.py)
    SNMP_ENABLED = os.environ.get("SNMP_ENABLED", "false").lower() == "true"
    SNMP_PORT = int(os.environ.get("SNMP_PORT", "161"))
    SNMP_TIMEOUT = int(os.environ.get("SNMP_TIMEOUT", "5"))
    SNMP_RETRIES = int(os.environ.get("SNMP_RETRIES", "1"))
    SNMP_POLL_INTERVAL = int(os.environ.get("SNMP_POLL_INTERVAL", "60"))
    SNMP_USER = os.environ.get("SNMP_USER", "")
    SNMP_AUTH_PROTOCOL = os.environ.get("SNMP_AUTH_PROTOCOL", "SHA")
    SNMP_AUTH_KEY = os.environ.get("SNMP_AUTH_KEY", "")
    SNMP_PRIV_PROTOCOL = os.environ.get("SNMP_PRIV_PROTOCOL", "AES")
    SNMP_PRIV_KEY = os.environ.get("SNMP_PRIV_KEY", "")

    # Three-tier health thresholds (percent), same convention as 4thealth
    CPU_WARN = float(os.environ.get("CPU_WARN", "70"))
    CPU_CRIT = float(os.environ.get("CPU_CRIT", "90"))
    MEM_WARN = float(os.environ.get("MEM_WARN", "70"))
    MEM_CRIT = float(os.environ.get("MEM_CRIT", "90"))

    # Log Search tab (app/faz_client.py's search_logs(), app/log_search_filters.py)
    LOG_SEARCH_MAX_RESULTS = int(os.environ.get("LOG_SEARCH_MAX_RESULTS", "1000"))
    LOG_SEARCH_POLL_INTERVAL = float(os.environ.get("LOG_SEARCH_POLL_INTERVAL", "2.0"))
    LOG_SEARCH_TIMEOUT = float(os.environ.get("LOG_SEARCH_TIMEOUT", "60.0"))

    # Connection Timeline tab (app/conn_timeline.py, app/conn_timeline_job.py).
    # Window: 1 hour by default, 7 days at most. A build rolls up at most
    # MAX_ROWS raw logs (fetched PAGE_SIZE at a time, the spec's maximum per
    # fetch) and stops at DEADLINE_SECS, under gunicorn's 120s timeout, marking
    # what it has as partial. At most MAX_JOBS builds run app-wide, and
    # MAX_JOBS_PER_USER per user; results are dropped JOB_LIFETIME_SECS after
    # a build ends.
    CONN_TIMELINE_DEFAULT_WINDOW = os.environ.get("CONN_TIMELINE_DEFAULT_WINDOW", "1h")
    CONN_TIMELINE_MAX_WINDOW_HOURS = float(os.environ.get("CONN_TIMELINE_MAX_WINDOW_HOURS", "168"))
    CONN_TIMELINE_MAX_ROWS = int(os.environ.get("CONN_TIMELINE_MAX_ROWS", "100000"))
    CONN_TIMELINE_PAGE_SIZE = int(os.environ.get("CONN_TIMELINE_PAGE_SIZE", "1000"))
    CONN_TIMELINE_DEADLINE_SECS = float(os.environ.get("CONN_TIMELINE_DEADLINE_SECS", "120"))
    # Once a build knows how many logs matched, its time limit grows to this many
    # seconds per 1,000 of them (never below DEADLINE_SECS, never above
    # DEADLINE_MAX_SECS), so a window of 100,000 logs is not cut off at the time that
    # suits a small one. 0 turns the growth off.
    CONN_TIMELINE_DEADLINE_SECS_PER_1K = float(
        os.environ.get("CONN_TIMELINE_DEADLINE_SECS_PER_1K", "10")
    )
    CONN_TIMELINE_DEADLINE_MAX_SECS = float(
        os.environ.get("CONN_TIMELINE_DEADLINE_MAX_SECS", "1200")
    )
    # Time slices of one build searched at once. Each uses its own FortiAnalyzer
    # connection, so mind the appliance's limit on concurrent log searches
    # (1 = the old one-search-at-a-time behaviour).
    CONN_TIMELINE_WORKERS = int(os.environ.get("CONN_TIMELINE_WORKERS", "4"))
    # Quick summary (FortiView) requests running at once, app-wide: each is a few FortiView
    # runs on the FortiAnalyzer, and a page asks for its four sections together.
    CONN_TIMELINE_SUMMARY_MAX_CONCURRENT = int(
        os.environ.get("CONN_TIMELINE_SUMMARY_MAX_CONCURRENT", "8")
    )
    CONN_TIMELINE_MAX_JOBS = int(os.environ.get("CONN_TIMELINE_MAX_JOBS", "2"))
    CONN_TIMELINE_MAX_JOBS_PER_USER = int(os.environ.get("CONN_TIMELINE_MAX_JOBS_PER_USER", "1"))
    CONN_TIMELINE_JOB_LIFETIME_SECS = float(
        os.environ.get("CONN_TIMELINE_JOB_LIFETIME_SECS", "600")
    )

    # Log stats polling (app/log_stats_cache.py) — silent-device detection
    # and log volume, independent cadence from the SNMP health poll since
    # logstats is a cheap JSON-RPC call with no SNMP round-trip.
    SILENT_DEVICE_THRESHOLD_MINUTES = int(os.environ.get("SILENT_DEVICE_THRESHOLD_MINUTES", "60"))
    LOG_STATS_POLL_INTERVAL = int(os.environ.get("LOG_STATS_POLL_INTERVAL", "300"))

    # Set by tests/conftest.py to skip starting the background log-stats
    # poller (real network calls) during the test suite.
    LOG_STATS_POLL_DISABLED = os.environ.get("LOG_STATS_POLL_DISABLED", "false").lower() == "true"

    # Threat activity polling (app/threat_stats_cache.py) — unacked alert
    # counts and 24h IPS detection activity, independent cadence since it's
    # a heavier FortiView run/poll call rather than a single cheap query.
    THREAT_STATS_POLL_INTERVAL = int(os.environ.get("THREAT_STATS_POLL_INTERVAL", "900"))

    # Set by tests/conftest.py to skip starting the background threat-stats
    # poller (real network calls) during the test suite.
    THREAT_STATS_POLL_DISABLED = (
        os.environ.get("THREAT_STATS_POLL_DISABLED", "false").lower() == "true"
    )

    # SD-WAN link health polling (app/sdwan_cache.py) — FortiView SD-WAN views
    # over a fixed 24h window.
    SDWAN_POLL_INTERVAL = int(os.environ.get("SDWAN_POLL_INTERVAL", "300"))

    # Set by tests/conftest.py to skip starting the background SD-WAN
    # poller (real network calls) during the test suite.
    SDWAN_POLL_DISABLED = os.environ.get("SDWAN_POLL_DISABLED", "false").lower() == "true"

    # Set by tests/conftest.py to skip starting the background health
    # poller (real network/SNMP calls) during the test suite.
    FAZ_HEALTH_POLL_DISABLED = os.environ.get("FAZ_HEALTH_POLL_DISABLED", "false").lower() == "true"

    # Host CPU/Memory/Disk polling (app/host_metrics_cache.py) — local
    # psutil reads, independent cadence from the FAZ-facing pollers since
    # there's no network round-trip to amortize.
    HOST_METRICS_POLL_INTERVAL = int(os.environ.get("HOST_METRICS_POLL_INTERVAL", "60"))

    # Set by tests/conftest.py to skip starting the background host-metrics
    # poller during the test suite.
    HOST_METRICS_POLL_DISABLED = (
        os.environ.get("HOST_METRICS_POLL_DISABLED", "false").lower() == "true"
    )

    # Business-hours window for the admin-access anomaly detector
    # (app/threat_stats_cache.py) — "outside hours" admin logins are
    # flagged relative to this window. Format: "HH:MM-HH:MM" in
    # ADMIN_ACCESS_TIMEZONE (an IANA zone name).
    ADMIN_ACCESS_BUSINESS_HOURS = os.environ.get("ADMIN_ACCESS_BUSINESS_HOURS", "08:00-18:00")
    ADMIN_ACCESS_TIMEZONE = os.environ.get("ADMIN_ACCESS_TIMEZONE", "America/Chicago")
