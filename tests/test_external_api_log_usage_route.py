import json

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


def _post(client, token, payload):
    return client.post(
        "/external/api/log-usage",
        data=json.dumps(payload),
        content_type="application/json",
        headers={"Authorization": f"Bearer {token}"} if token else {},
    )


def test_returns_503_when_disabled(client):
    resp = _post(client, "no-token", {"adom": "A", "devices": ["FW1"], "policyid": 1, "days": 1})
    assert resp.status_code == 503


def test_returns_401_when_no_token(client):
    from app.app_settings import set_setting

    set_setting("external_api_enabled", True)
    resp = client.post(
        "/external/api/log-usage",
        data=json.dumps({"adom": "A", "devices": ["FW1"], "policyid": 1, "days": 1}),
        content_type="application/json",
    )
    assert resp.status_code == 401


def test_returns_400_on_invalid_body(client):
    token = _enable_and_token()
    resp = _post(client, token, {"adom": "A"})
    assert resp.status_code == 400
    assert "error" in resp.get_json()


def test_returns_404_when_no_faz_target(client):
    token = _enable_and_token()
    resp = _post(client, token, {"adom": "Nonexistent", "devices": ["FW1"], "policyid": 1, "days": 1})
    assert resp.status_code == 404


def test_happy_path_end_to_end(client, monkeypatch):
    from app.faz_targets import create_target

    token = _enable_and_token()
    create_target(label="Primary", host="1.2.3.4", adom="Enterprise Services", token="faztoken")

    import app.routes.external_api_routes as route_mod

    class FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def get_devices(self):
            return [{"devid": "SN001", "name": "FW-DC-01", "platform": "x"}]

        def local_time_range(self, start, end):
            return start, end

        def search_logs(self, **kwargs):
            return {
                "rows": [{"srcip": "10.1.1.5", "dstip": "10.2.2.10", "dstport": 443}],
                "fields": [],
                "truncated": False,
            }

    monkeypatch.setattr(route_mod, "FAZClient", lambda **kwargs: FakeClient())

    resp = _post(client, token, {
        "adom": "Enterprise Services", "devices": ["FW-DC-01"], "policyid": 123, "days": 30,
    })
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["srcips"] == ["10.1.1.5"]
    assert data["dstips"] == ["10.2.2.10"]
    assert data["dstports"] == [443]
    assert data["devices_queried"] == ["FW-DC-01"]
    assert data["policyid"] == 123
