"""Application configuration loaded from environment / .env file."""

import os

from dotenv import load_dotenv

if os.environ.get("APP_LOAD_DOTENV", "true").lower() == "true":
    load_dotenv()


def _require_secret_key() -> str:
    val = os.environ.get("SECRET_KEY", "")
    if not val or val == "change-me-in-production":
        raise RuntimeError(
            "SECRET_KEY is not set or is the insecure default. "
            "Generate one with: uv run python manage_users.py secret"
        )
    return val


class Config:
    SECRET_KEY = _require_secret_key()
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
