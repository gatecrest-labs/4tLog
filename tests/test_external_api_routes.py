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
    assert body["schema_version"] == 2
    assert body["faz_targets_total"] == 2
    assert body["faz_targets_healthy"] == 1
    assert body["faz_disk_used_pct"] == 95.0
    assert body["devices_logging"] == 2
    assert body["devices_silent"] == 1
    assert body["silent_device_threshold_minutes"] == 60
    assert body["log_volume_events_per_sec"] == 8.0
    assert body["log_stats_collected_at"] == "2026-08-29T18:00:00Z"


def test_devices_silent_details_from_cache(client, monkeypatch):
    raw = _enable_and_token()

    import app.faz_health_cache as health_mod
    import app.log_stats_cache as logstats_mod

    monkeypatch.setattr(health_mod, "get_all_cached", lambda: [])
    monkeypatch.setattr(
        logstats_mod,
        "get_cached",
        lambda: {
            "logging_devices": [],
            "silent_devices": [{"devid": "C", "devname": "c", "lograte": 0.0}],
            "silent_details": [{"devid": "C", "devname": "c", "last_log_at": None}],
            "collected_at": "2026-08-29T18:00:00Z",
        },
    )

    resp = client.get("/external/api/executive/summary", headers={"Authorization": f"Bearer {raw}"})
    body = resp.get_json()
    assert body["devices_silent_details"] == [{"devid": "C", "devname": "c", "last_log_at": None}]


def test_devices_silent_details_empty_when_falling_back_to_rollup(client, monkeypatch):
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
    assert resp.get_json()["devices_silent_details"] == []


def test_freshness_key_reflects_each_source_collected_at(client, monkeypatch):
    raw = _enable_and_token()

    import app.faz_health_cache as health_mod
    import app.log_stats_cache as logstats_mod
    import app.threat_stats_cache as threat_mod

    monkeypatch.setattr(
        health_mod,
        "get_all_cached",
        lambda: [
            {"label": "Primary", "status": "green", "last_updated": "2026-09-12T01:00:00+00:00"},
            {"label": "Secondary", "status": "green", "last_updated": "2026-09-12T02:00:00+00:00"},
        ],
    )
    monkeypatch.setattr(
        logstats_mod,
        "get_cached",
        lambda: {
            "logging_devices": [],
            "silent_devices": [],
            "silent_details": [],
            "collected_at": "2026-09-12T03:00:00+00:00",
        },
    )
    monkeypatch.setattr(
        threat_mod,
        "get_cached",
        lambda: {"collected_at": "2026-09-12T04:00:00+00:00"},
    )

    resp = client.get("/external/api/executive/summary", headers={"Authorization": f"Bearer {raw}"})
    freshness = resp.get_json()["freshness"]
    assert freshness["faz_health"] == "2026-09-12T02:00:00+00:00"
    assert freshness["log_stats"] == "2026-09-12T03:00:00+00:00"
    assert freshness["threats"] == "2026-09-12T04:00:00+00:00"


def test_freshness_key_none_when_never_polled(client, monkeypatch):
    raw = _enable_and_token()

    import app.faz_health_cache as health_mod
    import app.log_stats_cache as logstats_mod
    import app.threat_stats_cache as threat_mod
    import app.threat_stats_history as threat_history_mod

    monkeypatch.setattr(health_mod, "get_all_cached", lambda: [])
    monkeypatch.setattr(
        logstats_mod,
        "get_cached",
        lambda: {"logging_devices": [], "silent_devices": [], "collected_at": None},
    )
    monkeypatch.setattr(threat_mod, "get_cached", lambda: {"collected_at": None})
    monkeypatch.setattr(threat_history_mod, "get_latest_rollup", lambda: None)

    resp = client.get("/external/api/executive/summary", headers={"Authorization": f"Bearer {raw}"})
    freshness = resp.get_json()["freshness"]
    assert freshness == {"faz_health": None, "log_stats": None, "threats": None}


def test_infra_key_shape_and_no_host_or_credentials(client, monkeypatch):
    raw = _enable_and_token()

    import app.faz_health_cache as health_mod
    import app.log_stats_cache as logstats_mod

    monkeypatch.setattr(
        health_mod,
        "get_all_cached",
        lambda: [
            {
                "label": "Primary",
                "host": "10.0.0.5",
                "token": "secret",
                "status": "green",
                "hostname": "faz1.local",
                "version": "v7.4.5",
                "ha_role": "master",
                "cpu": 12.0,
                "mem": 30.0,
                "disk_used": "Free 40GB, Total 100GB",
                "last_updated": "2026-09-10T00:00:00Z",
            }
        ],
    )
    monkeypatch.setattr(
        logstats_mod,
        "get_cached",
        lambda: {"logging_devices": [], "silent_devices": [], "collected_at": None},
    )

    resp = client.get("/external/api/executive/summary", headers={"Authorization": f"Bearer {raw}"})
    body = resp.get_json()

    assert body["infra"] == [
        {
            "role": "fortianalyzer",
            "label": "Primary",
            "hostname": "faz1.local",
            "version": "v7.4.5",
            "cpu": 12.0,
            "mem": 30.0,
            "disk_used_pct": 60.0,
            "ha_role": "master",
            "status": "green",
            "last_updated": "2026-09-10T00:00:00Z",
        }
    ]
    assert "host" not in body["infra"][0]
    assert "token" not in body["infra"][0]


def test_infra_normalizes_na_sentinel_to_none(client, monkeypatch):
    raw = _enable_and_token()

    import app.faz_health_cache as health_mod
    import app.log_stats_cache as logstats_mod

    monkeypatch.setattr(
        health_mod,
        "get_all_cached",
        lambda: [
            {
                "label": "Primary",
                "status": "gray",
                "hostname": "n/a",
                "version": "n/a",
                "ha_role": "n/a",
                "cpu": None,
                "mem": None,
                "disk_used": "n/a",
                "last_updated": None,
            }
        ],
    )
    monkeypatch.setattr(
        logstats_mod,
        "get_cached",
        lambda: {"logging_devices": [], "silent_devices": [], "collected_at": None},
    )

    resp = client.get("/external/api/executive/summary", headers={"Authorization": f"Bearer {raw}"})
    infra = resp.get_json()["infra"][0]

    assert infra["hostname"] is None
    assert infra["version"] is None
    assert infra["ha_role"] is None
    assert infra["disk_used_pct"] is None


def test_infra_empty_list_when_no_targets(client, monkeypatch):
    raw = _enable_and_token()

    import app.faz_health_cache as health_mod
    import app.log_stats_cache as logstats_mod

    monkeypatch.setattr(health_mod, "get_all_cached", lambda: [])
    monkeypatch.setattr(
        logstats_mod,
        "get_cached",
        lambda: {"logging_devices": [], "silent_devices": [], "collected_at": None},
    )

    resp = client.get("/external/api/executive/summary", headers={"Authorization": f"Bearer {raw}"})
    assert resp.get_json()["infra"] == []


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


def test_threats_key_shape_from_cache(client, monkeypatch):
    raw = _enable_and_token()

    import app.faz_health_cache as health_mod
    import app.log_stats_cache as logstats_mod
    import app.threat_stats_cache as threat_mod

    monkeypatch.setattr(health_mod, "get_all_cached", lambda: [])
    monkeypatch.setattr(
        logstats_mod,
        "get_cached",
        lambda: {"logging_devices": [], "silent_devices": [], "collected_at": None},
    )
    monkeypatch.setattr(
        threat_mod,
        "get_cached",
        lambda: {
            "alerts_unacked_total": 5,
            "alerts_unacked_by_severity": {"critical": 1, "high": 2, "medium": 1, "low": 1},
            "ips_detections_24h": 100,
            "ips_blocked_24h": 80,
            "ips_blocked_pct": 80.0,
            "top_signatures": [{"signature": "Eicar.Test.Virus", "count": 40}],
            "top_source_countries": [{"country": "China", "count": 60}],
            "collected_at": "2026-09-11T00:00:00+00:00",
        },
    )

    resp = client.get("/external/api/executive/summary", headers={"Authorization": f"Bearer {raw}"})
    assert resp.status_code == 200
    threats = resp.get_json()["threats"]
    assert threats["alerts_unacked_total"] == 5
    expected_severity = {"critical": 1, "high": 2, "medium": 1, "low": 1}
    assert threats["alerts_unacked_by_severity"] == expected_severity
    assert threats["ips_detections_24h"] == 100
    assert threats["ips_blocked_pct"] == 80.0
    assert threats["top_signatures"] == [{"signature": "Eicar.Test.Virus", "count": 40}]
    assert threats["top_source_countries"] == [{"country": "China", "count": 60}]
    assert threats["collected_at"] == "2026-09-11T00:00:00+00:00"


def test_threats_key_falls_back_to_history_when_cache_empty(client, monkeypatch):
    raw = _enable_and_token()

    import app.faz_health_cache as health_mod
    import app.log_stats_cache as logstats_mod
    import app.threat_stats_cache as threat_mod
    import app.threat_stats_history as threat_history_mod

    monkeypatch.setattr(health_mod, "get_all_cached", lambda: [])
    monkeypatch.setattr(
        logstats_mod,
        "get_cached",
        lambda: {"logging_devices": [], "silent_devices": [], "collected_at": None},
    )
    monkeypatch.setattr(threat_mod, "get_cached", lambda: {"collected_at": None})
    monkeypatch.setattr(
        threat_history_mod,
        "get_latest_rollup",
        lambda: {
            "alerts_unacked_total": 2,
            "alerts_unacked_by_severity": {"critical": 0, "high": 0, "medium": 1, "low": 1},
            "ips_detections_24h": 10,
            "ips_blocked_24h": 5,
            "ips_blocked_pct": 50.0,
            "top_signatures": [],
            "top_source_countries": [],
            "collected_at": "2026-09-10T00:00:00+00:00",
        },
    )

    resp = client.get("/external/api/executive/summary", headers={"Authorization": f"Bearer {raw}"})
    threats = resp.get_json()["threats"]
    assert threats["alerts_unacked_total"] == 2
    assert threats["collected_at"] == "2026-09-10T00:00:00+00:00"


def test_threats_key_all_zero_when_no_cache_and_no_history(client, monkeypatch):
    raw = _enable_and_token()

    import app.faz_health_cache as health_mod
    import app.log_stats_cache as logstats_mod
    import app.threat_stats_cache as threat_mod
    import app.threat_stats_history as threat_history_mod

    monkeypatch.setattr(health_mod, "get_all_cached", lambda: [])
    monkeypatch.setattr(
        logstats_mod,
        "get_cached",
        lambda: {"logging_devices": [], "silent_devices": [], "collected_at": None},
    )
    monkeypatch.setattr(threat_mod, "get_cached", lambda: {"collected_at": None})
    monkeypatch.setattr(threat_history_mod, "get_latest_rollup", lambda: None)

    resp = client.get("/external/api/executive/summary", headers={"Authorization": f"Bearer {raw}"})
    threats = resp.get_json()["threats"]
    assert threats["alerts_unacked_total"] == 0
    expected_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    assert threats["alerts_unacked_by_severity"] == expected_severity
    assert threats["ips_detections_24h"] == 0
    assert threats["ips_blocked_pct"] == 0.0
    assert threats["top_signatures"] == []
    assert threats["top_source_countries"] == []
    assert threats["collected_at"] is None


def test_admin_access_key_shape_from_cache(client, monkeypatch):
    raw = _enable_and_token()

    import app.faz_health_cache as health_mod
    import app.log_stats_cache as logstats_mod
    import app.threat_stats_cache as threat_mod

    monkeypatch.setattr(health_mod, "get_all_cached", lambda: [])
    monkeypatch.setattr(
        logstats_mod,
        "get_cached",
        lambda: {"logging_devices": [], "silent_devices": [], "collected_at": None},
    )
    monkeypatch.setattr(
        threat_mod,
        "get_cached",
        lambda: {
            "alerts_unacked_total": 0,
            "alerts_unacked_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "ips_detections_24h": 0,
            "ips_blocked_24h": 0,
            "ips_blocked_pct": 0.0,
            "top_signatures": [],
            "top_source_countries": [],
            "failed_admin_logins_24h": 4,
            "devices_with_failed_logins": 1,
            "top_failed_sources": [{"source": "203.0.113.5", "count": 4}],
            "admin_logins_outside_hours_24h": 2,
            "collected_at": "2026-09-11T12:00:00+00:00",
        },
    )

    resp = client.get("/external/api/executive/summary", headers={"Authorization": f"Bearer {raw}"})
    assert resp.status_code == 200
    admin_access = resp.get_json()["admin_access"]
    assert admin_access["failed_admin_logins_24h"] == 4
    assert admin_access["devices_with_failed_logins"] == 1
    assert admin_access["top_failed_sources"] == [{"source": "203.0.113.5", "count": 4}]
    assert admin_access["admin_logins_outside_hours_24h"] == 2
    assert admin_access["business_hours"] == "08:00-18:00 America/Chicago"
    assert admin_access["collected_at"] == "2026-09-11T12:00:00+00:00"


def test_admin_access_business_hours_reflects_config_override(client, monkeypatch):
    raw = _enable_and_token()

    import app.faz_health_cache as health_mod
    import app.log_stats_cache as logstats_mod
    import app.threat_stats_cache as threat_mod
    from app.config import Config

    monkeypatch.setattr(Config, "ADMIN_ACCESS_BUSINESS_HOURS", "09:00-17:00")
    monkeypatch.setattr(Config, "ADMIN_ACCESS_TIMEZONE", "UTC")
    monkeypatch.setattr(health_mod, "get_all_cached", lambda: [])
    monkeypatch.setattr(
        logstats_mod,
        "get_cached",
        lambda: {"logging_devices": [], "silent_devices": [], "collected_at": None},
    )
    monkeypatch.setattr(threat_mod, "get_cached", lambda: {"collected_at": None})

    resp = client.get("/external/api/executive/summary", headers={"Authorization": f"Bearer {raw}"})
    assert resp.get_json()["admin_access"]["business_hours"] == "09:00-17:00 UTC"


def test_admin_access_all_zero_when_no_cache_and_no_history(client, monkeypatch):
    raw = _enable_and_token()

    import app.faz_health_cache as health_mod
    import app.log_stats_cache as logstats_mod
    import app.threat_stats_cache as threat_mod
    import app.threat_stats_history as threat_history_mod

    monkeypatch.setattr(health_mod, "get_all_cached", lambda: [])
    monkeypatch.setattr(
        logstats_mod,
        "get_cached",
        lambda: {"logging_devices": [], "silent_devices": [], "collected_at": None},
    )
    monkeypatch.setattr(threat_mod, "get_cached", lambda: {"collected_at": None})
    monkeypatch.setattr(threat_history_mod, "get_latest_rollup", lambda: None)

    resp = client.get("/external/api/executive/summary", headers={"Authorization": f"Bearer {raw}"})
    admin_access = resp.get_json()["admin_access"]
    assert admin_access["failed_admin_logins_24h"] == 0
    assert admin_access["devices_with_failed_logins"] == 0
    assert admin_access["top_failed_sources"] == []
    assert admin_access["admin_logins_outside_hours_24h"] == 0
    assert admin_access["collected_at"] is None


def test_vpn_key_shape_from_cache(client, monkeypatch):
    raw = _enable_and_token()

    import app.faz_health_cache as health_mod
    import app.log_stats_cache as logstats_mod
    import app.threat_stats_cache as threat_mod

    monkeypatch.setattr(health_mod, "get_all_cached", lambda: [])
    monkeypatch.setattr(
        logstats_mod,
        "get_cached",
        lambda: {"logging_devices": [], "silent_devices": [], "collected_at": None},
    )
    monkeypatch.setattr(
        threat_mod,
        "get_cached",
        lambda: {
            "alerts_unacked_total": 0,
            "alerts_unacked_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "ips_detections_24h": 0,
            "ips_blocked_24h": 0,
            "ips_blocked_pct": 0.0,
            "top_signatures": [],
            "top_source_countries": [],
            "failed_admin_logins_24h": 0,
            "devices_with_failed_logins": 0,
            "top_failed_sources": [],
            "admin_logins_outside_hours_24h": 0,
            "ipsec_tunnels_total": 6,
            "ipsec_tunnels_down": 1,
            "ssl_vpn_users_now": 12,
            "collected_at": "2026-09-11T12:00:00+00:00",
        },
    )

    resp = client.get("/external/api/executive/summary", headers={"Authorization": f"Bearer {raw}"})
    assert resp.status_code == 200
    vpn = resp.get_json()["vpn"]
    assert vpn["ipsec_tunnels_total"] == 6
    assert vpn["ipsec_tunnels_down"] == 1
    assert vpn["ssl_vpn_users_now"] == 12
    assert vpn["collected_at"] == "2026-09-11T12:00:00+00:00"


def test_vpn_key_all_zero_when_no_cache_and_no_history(client, monkeypatch):
    raw = _enable_and_token()

    import app.faz_health_cache as health_mod
    import app.log_stats_cache as logstats_mod
    import app.threat_stats_cache as threat_mod
    import app.threat_stats_history as threat_history_mod

    monkeypatch.setattr(health_mod, "get_all_cached", lambda: [])
    monkeypatch.setattr(
        logstats_mod,
        "get_cached",
        lambda: {"logging_devices": [], "silent_devices": [], "collected_at": None},
    )
    monkeypatch.setattr(threat_mod, "get_cached", lambda: {"collected_at": None})
    monkeypatch.setattr(threat_history_mod, "get_latest_rollup", lambda: None)

    resp = client.get("/external/api/executive/summary", headers={"Authorization": f"Bearer {raw}"})
    vpn = resp.get_json()["vpn"]
    assert vpn["ipsec_tunnels_total"] == 0
    assert vpn["ipsec_tunnels_down"] == 0
    assert vpn["ssl_vpn_users_now"] == 0
    assert vpn["collected_at"] is None
