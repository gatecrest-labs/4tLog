import importlib
import os

import app.config  # noqa: F401 - pre-cache module in sys.modules for test isolation


def test_config_requires_secret_key(monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    import app.config as config_mod

    with __import__("pytest").raises(RuntimeError):
        importlib.reload(config_mod)
    # restore for subsequent tests in the same process
    os.environ["SECRET_KEY"] = "test-secret-key-for-ci"
    importlib.reload(config_mod)


def test_config_loads_defaults(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "a-real-secret")
    import app.config as config_mod

    importlib.reload(config_mod)
    assert config_mod.Config.SECRET_KEY == "a-real-secret"
    assert config_mod.Config.SESSION_COOKIE_HTTPONLY is True
    assert config_mod.Config.PERMANENT_SESSION_LIFETIME == 3600


def test_session_cookie_name_is_app_specific(monkeypatch):
    """Must not be Flask's default "session" -- browser cookies are scoped
    by domain+path, not port, so a default name collides with any other
    local Flask app (e.g. 4thealth-plus) served from localhost at a
    different port, silently clobbering each other's session cookie."""
    monkeypatch.setenv("SECRET_KEY", "a-real-secret")
    import app.config as config_mod

    importlib.reload(config_mod)
    assert config_mod.Config.SESSION_COOKIE_NAME == "4tlog_session"


def test_log_search_defaults(monkeypatch):
    monkeypatch.delenv("LOG_SEARCH_MAX_RESULTS", raising=False)
    monkeypatch.delenv("LOG_SEARCH_POLL_INTERVAL", raising=False)
    monkeypatch.delenv("LOG_SEARCH_TIMEOUT", raising=False)
    import app.config as config_mod

    importlib.reload(config_mod)
    assert config_mod.Config.LOG_SEARCH_MAX_RESULTS == 1000
    assert config_mod.Config.LOG_SEARCH_POLL_INTERVAL == 2.0
    assert config_mod.Config.LOG_SEARCH_TIMEOUT == 60.0
