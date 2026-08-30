import os

import pytest


@pytest.fixture
def app(tmp_path, monkeypatch):
    os.environ.setdefault("SECRET_KEY", "test-secret")
    import app.auth as auth_mod
    import app.faz_targets as faz_targets_mod
    import app.groups as groups_mod

    monkeypatch.setattr(auth_mod, "USERS_FILE", tmp_path / "users.json")
    monkeypatch.setattr(groups_mod, "GROUPS_FILE", tmp_path / "groups.json")
    monkeypatch.setattr(faz_targets_mod, "FAZ_TARGETS_FILE", tmp_path / "faz_targets.json")

    auth_mod.add_user("alice", "Str0ng!Passw0rd", role="viewer")
    groups_mod.create_group("g1", members=["alice"], allowed_tabs=["log_search"])
    faz_targets_mod.create_target("Primary", host="192.168.64.4", adom="root", token="tok")
    faz_targets_mod.create_target("Secondary", host="192.168.64.5", adom="root", token="tok2")

    from app import create_app

    return create_app()


@pytest.fixture
def client(app):
    return app.test_client()


def _login(client, username="alice", password="Str0ng!Passw0rd"):
    client.get("/login")
    with client.session_transaction() as sess:
        csrf = sess.get("_csrf_token", "")
    client.post("/login", data={"username": username, "password": password, "csrf_token": csrf})


def _csrf(client):
    # login() calls session.clear(), so the pre-login CSRF token doesn't
    # survive into the authenticated session. A request must happen
    # post-login to let before_request's ensure_csrf_token() establish a
    # fresh one before we can read it.
    client.get("/api/log-search/targets")
    with client.session_transaction() as sess:
        return sess.get("_csrf_token", "")


def test_targets_requires_login(client):
    resp = client.get("/api/log-search/targets")
    assert resp.status_code == 401


def test_targets_lists_all_when_unrestricted(client):
    _login(client)
    resp = client.get("/api/log-search/targets")
    assert resp.status_code == 200
    labels = [t["label"] for t in resp.get_json()]
    assert labels == ["Primary", "Secondary"]


def test_targets_filters_by_group_restriction(client, app):
    import app.groups as groups_mod

    groups_mod.update_group(
        "g1",
        members=["alice"],
        allowed_tabs=["log_search"],
        adom_restrict=True,
        allowed_adoms=["Primary"],
    )
    _login(client)
    resp = client.get("/api/log-search/targets")
    labels = [t["label"] for t in resp.get_json()]
    assert labels == ["Primary"]


def test_search_rejects_both_ips_blank(client):
    _login(client)
    csrf = _csrf(client)
    resp = client.post(
        "/api/log-search",
        json={
            "target": "Primary",
            "logtype": "traffic",
            "device": "All_FortiGate",
            "start_time": "2026-07-25T00:00:00",
            "end_time": "2026-07-25T23:59:59",
            "source_ips": "",
            "destination_ips": "",
            "ports": "",
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 400
    assert "source or destination" in resp.get_json()["error"]


def test_search_rejects_both_ips_any(client):
    _login(client)
    csrf = _csrf(client)
    resp = client.post(
        "/api/log-search",
        json={
            "target": "Primary",
            "logtype": "traffic",
            "device": "All_FortiGate",
            "start_time": "2026-07-25T00:00:00",
            "end_time": "2026-07-25T23:59:59",
            "source_ips": "ANY",
            "destination_ips": "ALL",
            "ports": "",
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 400
    assert "source or destination" in resp.get_json()["error"]


def test_search_allows_one_side_any(client, monkeypatch):
    def fake_search_logs(self, **kwargs):
        assert kwargs["filter_expression"] == "(dstip==8.8.8.8)"
        return {"rows": [], "fields": [], "truncated": False}

    monkeypatch.setattr("app.faz_client.FAZClient.preflight", lambda self: True)
    monkeypatch.setattr("app.faz_client.FAZClient.local_time_range", lambda self, s, e: (s, e))
    monkeypatch.setattr("app.faz_client.FAZClient.search_logs", fake_search_logs)
    monkeypatch.setattr("app.faz_client.FAZClient.logout", lambda self: None)

    _login(client)
    csrf = _csrf(client)
    resp = client.post(
        "/api/log-search",
        json={
            "target": "Primary",
            "logtype": "traffic",
            "device": "All_FortiGate",
            "start_time": "2026-07-25T00:00:00",
            "end_time": "2026-07-25T23:59:59",
            "source_ips": "ANY",
            "destination_ips": "8.8.8.8",
            "ports": "",
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 200


def test_search_rejects_invalid_ip(client):
    _login(client)
    csrf = _csrf(client)
    resp = client.post(
        "/api/log-search",
        json={
            "target": "Primary",
            "logtype": "traffic",
            "device": "All_FortiGate",
            "start_time": "2026-07-25T00:00:00",
            "end_time": "2026-07-25T23:59:59",
            "source_ips": "not-an-ip",
            "destination_ips": "",
            "ports": "",
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 400
    assert "not-an-ip" in resp.get_json()["error"]


def test_search_rejects_disallowed_target(client, app):
    import app.groups as groups_mod

    groups_mod.update_group(
        "g1",
        members=["alice"],
        allowed_tabs=["log_search"],
        adom_restrict=True,
        allowed_adoms=["Secondary"],
    )
    _login(client)
    csrf = _csrf(client)
    resp = client.post(
        "/api/log-search",
        json={
            "target": "Primary",
            "logtype": "traffic",
            "device": "All_FortiGate",
            "start_time": "2026-07-25T00:00:00",
            "end_time": "2026-07-25T23:59:59",
            "source_ips": "10.1.1.5",
            "destination_ips": "",
            "ports": "",
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 403


def test_search_happy_path(client, monkeypatch):
    def fake_search_logs(self, **kwargs):
        assert kwargs["filter_expression"] == "(srcip==10.1.1.5)"
        return {"rows": [{"srcip": "10.1.1.5"}], "fields": ["srcip"], "truncated": False}

    monkeypatch.setattr("app.faz_client.FAZClient.preflight", lambda self: True)
    monkeypatch.setattr("app.faz_client.FAZClient.local_time_range", lambda self, s, e: (s, e))
    monkeypatch.setattr("app.faz_client.FAZClient.search_logs", fake_search_logs)
    monkeypatch.setattr("app.faz_client.FAZClient.logout", lambda self: None)

    from app.app_logger import get_log_entries

    _login(client)
    csrf = _csrf(client)
    resp = client.post(
        "/api/log-search",
        json={
            "target": "Primary",
            "logtype": "traffic",
            "device": "All_FortiGate",
            "start_time": "2026-07-25T00:00:00",
            "end_time": "2026-07-25T23:59:59",
            "source_ips": "10.1.1.5",
            "destination_ips": "",
            "ports": "",
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["rows"] == [{"srcip": "10.1.1.5"}]
    assert body["truncated"] is False

    entries = get_log_entries(component="log_search")
    assert any(
        e["level"] == "INFO" and e["message"] == "Search completed" and e["extra"]["rows"] == 1
        for e in entries
    )


def test_search_rejects_extra_filter_injection(client):
    _login(client)
    csrf = _csrf(client)
    resp = client.post(
        "/api/log-search",
        json={
            "target": "Primary",
            "logtype": "traffic",
            "device": "All_FortiGate",
            "start_time": "2026-07-25T00:00:00",
            "end_time": "2026-07-25T23:59:59",
            "source_ips": "10.1.1.5",
            "destination_ips": "",
            "ports": "",
            "extra_filters": [
                {"field": "srcip", "op": "==", "value": '0.0.0.0" or dstip>="0.0.0.0'}
            ],
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 400
    assert "quote" in resp.get_json()["error"]


def test_search_returns_502_on_faz_error(client, monkeypatch):
    from app.faz_client import FAZError

    def raising_search_logs(self, **kwargs):
        raise FAZError("No permission for the resource")

    monkeypatch.setattr("app.faz_client.FAZClient.local_time_range", lambda self, s, e: (s, e))
    monkeypatch.setattr("app.faz_client.FAZClient.search_logs", raising_search_logs)
    monkeypatch.setattr("app.faz_client.FAZClient.logout", lambda self: None)

    _login(client)
    csrf = _csrf(client)
    resp = client.post(
        "/api/log-search",
        json={
            "target": "Primary",
            "logtype": "traffic",
            "device": "All_FortiGate",
            "start_time": "2026-07-25T00:00:00",
            "end_time": "2026-07-25T23:59:59",
            "source_ips": "10.1.1.5",
            "destination_ips": "",
            "ports": "",
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 502
    assert "No permission" in resp.get_json()["error"]


def test_search_returns_504_on_timeout(client, monkeypatch):
    from app.faz_client import FAZSearchTimeout

    def raising_search_logs(self, **kwargs):
        raise FAZSearchTimeout("did not complete")

    monkeypatch.setattr("app.faz_client.FAZClient.local_time_range", lambda self, s, e: (s, e))
    monkeypatch.setattr("app.faz_client.FAZClient.search_logs", raising_search_logs)
    monkeypatch.setattr("app.faz_client.FAZClient.logout", lambda self: None)

    _login(client)
    csrf = _csrf(client)
    resp = client.post(
        "/api/log-search",
        json={
            "target": "Primary",
            "logtype": "traffic",
            "device": "All_FortiGate",
            "start_time": "2026-07-25T00:00:00",
            "end_time": "2026-07-25T23:59:59",
            "source_ips": "10.1.1.5",
            "destination_ips": "",
            "ports": "",
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 504
    assert "narrow" in resp.get_json()["error"].lower()


def test_fields_endpoint(client, monkeypatch):
    monkeypatch.setattr(
        "app.faz_client.FAZClient.get_log_fields",
        lambda self, logtype="traffic", devtype="FortiGate": [{"name": "srcip"}],
    )
    monkeypatch.setattr("app.faz_client.FAZClient.logout", lambda self: None)

    _login(client)
    resp = client.get("/api/log-search/fields?target=Primary&logtype=traffic")
    assert resp.status_code == 200
    assert resp.get_json() == [{"name": "srcip"}]


def test_devices_endpoint(client, monkeypatch):
    monkeypatch.setattr(
        "app.faz_client.FAZClient.get_devices",
        lambda self: [
            {"devid": "FWF71GTK25000691", "name": "FortiWiFi-71G", "platform": "FortiWiFi-71G"}
        ],
    )
    monkeypatch.setattr("app.faz_client.FAZClient.logout", lambda self: None)

    _login(client)
    resp = client.get("/api/log-search/devices?target=Primary")
    assert resp.status_code == 200
    assert resp.get_json() == [
        {"devid": "FWF71GTK25000691", "name": "FortiWiFi-71G", "platform": "FortiWiFi-71G"}
    ]


def test_devices_endpoint_rejects_disallowed_target(client, app):
    import app.groups as groups_mod

    groups_mod.update_group(
        "g1",
        members=["alice"],
        allowed_tabs=["log_search"],
        adom_restrict=True,
        allowed_adoms=["Secondary"],
    )
    _login(client)
    resp = client.get("/api/log-search/devices?target=Primary")
    assert resp.status_code == 403
