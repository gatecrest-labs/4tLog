import pytest


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setattr("app.api_tokens._TOKENS_PATH", tmp_path / "api_tokens.json")
    monkeypatch.setattr("app.app_settings._SETTINGS_PATH", tmp_path / "app_settings.json")
    monkeypatch.setattr("app.faz_targets.FAZ_TARGETS_FILE", tmp_path / "faz_targets.json")
    import app.log_stats_history as history_mod

    monkeypatch.setattr(history_mod, "DB_PATH", tmp_path / "logstats.db")
    history_mod.init_db()

    from app import create_app

    return create_app()


@pytest.fixture
def client(app):
    return app.test_client()


def _enable_and_token():
    from app.api_tokens import create_token
    from app.app_settings import set_setting

    set_setting("external_api_enabled", True)
    raw, _ = create_token("test")
    return raw


def test_returns_503_when_disabled(client):
    resp = client.get("/external/api/executive/summary")
    assert resp.status_code == 503


def test_returns_401_when_no_token(client):
    from app.app_settings import set_setting

    set_setting("external_api_enabled", True)
    resp = client.get("/external/api/executive/summary")
    assert resp.status_code == 401


def test_returns_401_when_invalid_token(client):
    from app.app_settings import set_setting

    set_setting("external_api_enabled", True)
    resp = client.get("/external/api/executive/summary", headers={"Authorization": "Bearer wrong"})
    assert resp.status_code == 401


def test_401_logs_unauthorized_attempt(client):
    from app.app_logger import clear_log_entries, get_log_entries, set_log_level
    from app.app_settings import set_setting

    set_setting("external_api_enabled", True)
    clear_log_entries()
    set_log_level("TRACE")

    resp = client.get("/external/api/executive/summary", headers={"Authorization": "Bearer wrong"})
    assert resp.status_code == 401

    entries = get_log_entries(component="external_api")
    assert len(entries) == 1
    assert "Unauthorized" in entries[0]["message"]


def test_happy_path_shape(client, monkeypatch):
    raw = _enable_and_token()

    import app.faz_health_cache as health_mod
    import app.log_stats_cache as logstats_mod

    monkeypatch.setattr(
        health_mod,
        "get_all_cached",
        lambda: [
            {"label": "Primary", "status": "green", "disk_used": "Free 40GB, Total 100GB"},
            {"label": "Secondary", "status": "red", "disk_used": "Free 5GB, Total 100GB"},
        ],
    )
    monkeypatch.setattr(
        logstats_mod,
        "get_cached",
        lambda: {
            "logging_devices": [{"devid": "A", "lograte": 5.0}, {"devid": "B", "lograte": 3.0}],
            "silent_devices": [{"devid": "C", "lograte": 0.0}],
            "collected_at": "2026-08-29T18:00:00Z",
        },
    )

    resp = client.get("/external/api/executive/summary", headers={"Authorization": f"Bearer {raw}"})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["schema_version"] == 1
    assert body["faz_targets_total"] == 2
    assert body["faz_targets_healthy"] == 1
    assert body["faz_disk_used_pct"] == 95.0
    assert body["devices_logging"] == 2
    assert body["devices_silent"] == 1
    assert body["silent_device_threshold_minutes"] == 60
    assert body["log_volume_events_per_sec"] == 8.0
    assert body["log_stats_collected_at"] == "2026-08-29T18:00:00Z"


def test_falls_back_to_persisted_rollup_when_cache_empty(client, monkeypatch):
    raw = _enable_and_token()

    import app.faz_health_cache as health_mod
    import app.log_stats_cache as logstats_mod
    from app.log_stats_history import write_rollup

    monkeypatch.setattr(health_mod, "get_all_cached", lambda: [])
    monkeypatch.setattr(
        logstats_mod,
        "get_cached",
        lambda: {"logging_devices": [], "silent_devices": [], "collected_at": None},
    )
    write_rollup(
        devices_logging=7, devices_silent=1, total_lograte=12.5, collected_at="2026-08-29T17:00:00Z"
    )

    resp = client.get("/external/api/executive/summary", headers={"Authorization": f"Bearer {raw}"})
    body = resp.get_json()
    assert body["devices_logging"] == 7
    assert body["devices_silent"] == 1
    assert body["log_volume_events_per_sec"] == 12.5
    assert body["log_stats_collected_at"] == "2026-08-29T17:00:00Z"
