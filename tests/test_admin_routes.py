import os

import pytest


@pytest.fixture
def app(tmp_path, monkeypatch):
    os.environ.setdefault("SECRET_KEY", "test-secret")
    import app.auth as auth_mod
    import app.groups as groups_mod

    monkeypatch.setattr(auth_mod, "USERS_FILE", tmp_path / "users.json")
    monkeypatch.setattr(groups_mod, "GROUPS_FILE", tmp_path / "groups.json")
    auth_mod.add_user("admin1", "Str0ng!Passw0rd", role="admin")
    auth_mod.add_user("viewer1", "Str0ng!Passw0rd", role="viewer")

    from app import create_app

    return create_app()


@pytest.fixture
def client(app):
    return app.test_client()


def _login(client, username, password="Str0ng!Passw0rd"):
    client.get("/login")
    with client.session_transaction() as sess:
        csrf = sess.get("_csrf_token", "")
    client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": csrf},
    )


def _csrf(client):
    # login() now calls session.clear() (finding #14 fix), so the
    # pre-login CSRF token no longer survives into the authenticated
    # session. A request must happen post-login to let before_request's
    # ensure_csrf_token() establish a fresh one before we can read it.
    client.get("/admin/api/tabs")
    with client.session_transaction() as sess:
        return sess.get("_csrf_token", "")


def test_admin_page_blocked_for_viewer(client):
    _login(client, "viewer1")
    resp = client.get("/admin/")
    assert resp.status_code == 403


def test_admin_page_reachable_for_admin(client):
    _login(client, "admin1")
    resp = client.get("/admin/")
    assert resp.status_code == 200


def test_admin_users_list(client):
    _login(client, "admin1")
    resp = client.get("/admin/api/users")
    assert resp.status_code == 200
    usernames = {u["username"] for u in resp.get_json()}
    assert usernames == {"admin1", "viewer1"}


def test_admin_tabs_list_includes_registered_tabs(client):
    _login(client, "admin1")
    resp = client.get("/admin/api/tabs")
    keys = {t["key"] for t in resp.get_json()}
    assert {"dashboard", "log_search"} <= keys


def test_admin_tabs_list_excludes_admin_tab(client):
    # "admin" access is role-based, not tab-permission-based, so it must
    # never be offered as a grantable tab in the group editor.
    _login(client, "admin1")
    resp = client.get("/admin/api/tabs")
    keys = {t["key"] for t in resp.get_json()}
    assert "admin" not in keys


def test_admin_group_crud(client):
    _login(client, "admin1")
    csrf = _csrf(client)
    resp = client.post(
        "/admin/api/groups",
        json={"name": "noc", "members": ["viewer1"], "allowed_tabs": ["dashboard"]},
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 201
    resp = client.get("/admin/api/groups")
    assert [g["name"] for g in resp.get_json()] == ["noc"]

    resp = client.put(
        "/admin/api/groups/noc",
        json={"members": ["viewer1"], "allowed_tabs": ["dashboard", "log_search"]},
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 200
    assert set(resp.get_json()["allowed_tabs"]) == {"dashboard", "log_search"}

    resp = client.delete("/admin/api/groups/noc", headers={"X-CSRF-Token": csrf})
    assert resp.status_code == 200
    assert client.get("/admin/api/groups").get_json() == []


def test_admin_group_update_preserves_unset_fields(client):
    # The Phase 1 admin UI only sends members/allowed_tabs in its PUT body.
    # Fields set via direct API use (adom_restrict/allowed_adoms/ad_groups)
    # must survive a UI-driven edit rather than being silently wiped.
    _login(client, "admin1")
    csrf = _csrf(client)
    resp = client.post(
        "/admin/api/groups",
        json={
            "name": "restricted",
            "members": ["viewer1"],
            "allowed_tabs": ["dashboard"],
            "adom_restrict": True,
            "allowed_adoms": ["adom1"],
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 201

    resp = client.put(
        "/admin/api/groups/restricted",
        json={"members": ["viewer1"], "allowed_tabs": ["dashboard", "log_search"]},
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["adom_restrict"] is True
    assert body["allowed_adoms"] == ["adom1"]
    assert set(body["allowed_tabs"]) == {"dashboard", "log_search"}


def test_admin_logs_endpoints(client):
    _login(client, "admin1")
    csrf = _csrf(client)
    resp = client.get("/admin/api/logs")
    assert resp.status_code == 200
    body = resp.get_json()
    assert "entries" in body and "current_level" in body

    resp = client.post(
        "/admin/api/logs/level",
        json={"level": "DEBUG"},
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 200
    assert resp.get_json()["current_level"] == "DEBUG"

    resp = client.delete("/admin/api/logs", headers={"X-CSRF-Token": csrf})
    assert resp.status_code == 200


def test_admin_api_blocked_without_csrf(client):
    _login(client, "admin1")
    resp = client.post("/admin/api/groups", json={"name": "x", "allowed_tabs": []})
    assert resp.status_code == 400


@pytest.fixture
def faz_targets_file(tmp_path, monkeypatch):
    path = tmp_path / "faz_targets.json"
    import app.faz_targets as faz_targets_mod

    monkeypatch.setattr(faz_targets_mod, "FAZ_TARGETS_FILE", path)
    yield path


def test_faz_targets_blocked_for_viewer(client, faz_targets_file):
    _login(client, "viewer1")
    resp = client.get("/admin/api/faz-targets")
    assert resp.status_code == 403


def test_faz_targets_crud_for_admin(client, faz_targets_file):
    _login(client, "admin1")
    csrf = _csrf(client)

    resp = client.get("/admin/api/faz-targets")
    assert resp.status_code == 200
    assert resp.get_json() == []

    resp = client.post(
        "/admin/api/faz-targets",
        json={"label": "Primary", "host": "192.168.64.4", "adom": "root", "token": "abc"},
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 201
    assert resp.get_json()["label"] == "Primary"

    resp = client.post(
        "/admin/api/faz-targets",
        json={"label": "Primary", "host": "10.0.0.9"},
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 409

    resp = client.put(
        "/admin/api/faz-targets/Primary",
        json={"host": "10.0.0.9", "adom": "lab", "token": "xyz"},
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 200
    assert resp.get_json()["host"] == "10.0.0.9"

    resp = client.delete("/admin/api/faz-targets/Primary", headers={"X-CSRF-Token": csrf})
    assert resp.status_code == 200

    resp = client.get("/admin/api/faz-targets")
    assert resp.get_json() == []


def test_faz_targets_missing_label_rejected(client, faz_targets_file):
    _login(client, "admin1")
    csrf = _csrf(client)
    resp = client.post(
        "/admin/api/faz-targets",
        json={"host": "192.168.64.4"},
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 400


def test_faz_targets_responses_do_not_leak_raw_token(client, faz_targets_file):
    # List/create/update responses must not include a usable raw token —
    # only a token_set boolean. Putting a live FAZ credential in API
    # responses (and thus the DOM/dev-tools) has no functional benefit.
    _login(client, "admin1")
    csrf = _csrf(client)

    resp = client.post(
        "/admin/api/faz-targets",
        json={"label": "Primary", "host": "192.168.64.4", "adom": "root", "token": "supersecret"},
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 201
    body = resp.get_json()
    assert "token" not in body
    assert body["token_set"] is True

    resp = client.get("/admin/api/faz-targets")
    assert resp.status_code == 200
    for t in resp.get_json():
        assert "token" not in t

    resp = client.put(
        "/admin/api/faz-targets/Primary",
        json={"host": "10.0.0.9", "adom": "lab"},
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert "token" not in body
    assert body["token_set"] is True


def test_host_metrics_api_blocked_for_viewer(client):
    _login(client, "viewer1")
    resp = client.get("/admin/api/host-metrics")
    assert resp.status_code == 403


def test_host_metrics_api_returns_shape(client, tmp_path, monkeypatch):
    import datetime

    import app.host_metrics_history as history_mod

    monkeypatch.setattr(history_mod, "DB_PATH", tmp_path / "hostmetrics.db")
    history_mod.init_db()
    # A relative-to-now timestamp, not a fixed literal — the endpoint under
    # test filters by "since = now - range", so a hardcoded past date would
    # silently fall outside the window once real time moves past it (see
    # this plan's Global Constraints section).
    recent_ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    history_mod.write_snapshot(
        cpu_percent=12.5, memory_percent=40.0, disk_percent=55.0, collected_at=recent_ts,
    )
    expected_epoch = int(datetime.datetime.fromisoformat(recent_ts).timestamp())

    _login(client, "admin1")
    resp = client.get("/admin/api/host-metrics?range=1d")

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["cpu"] == [{"ts": expected_epoch, "v": 12.5}]
    assert body["mem"] == [{"ts": expected_epoch, "v": 40.0}]
    assert body["disk"] == [{"ts": expected_epoch, "v": 55.0}]


def test_host_metrics_api_defaults_invalid_range(client, tmp_path, monkeypatch):
    import datetime

    import app.host_metrics_history as history_mod

    monkeypatch.setattr(history_mod, "DB_PATH", tmp_path / "hostmetrics.db")
    history_mod.init_db()
    recent_ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    history_mod.write_snapshot(
        cpu_percent=5.0, memory_percent=10.0, disk_percent=15.0, collected_at=recent_ts,
    )

    _login(client, "admin1")
    resp = client.get("/admin/api/host-metrics?range=not-a-real-range")

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["cpu"] == [{"ts": int(datetime.datetime.fromisoformat(recent_ts).timestamp()), "v": 5.0}]


def test_faz_targets_update_without_token_preserves_existing_token(client, faz_targets_file):
    # The edit modal leaves the token field blank; omitting it from the PUT
    # body must not clobber the previously stored token.
    from app.faz_targets import get_target

    _login(client, "admin1")
    csrf = _csrf(client)

    client.post(
        "/admin/api/faz-targets",
        json={"label": "Primary", "host": "192.168.64.4", "adom": "root", "token": "supersecret"},
        headers={"X-CSRF-Token": csrf},
    )

    resp = client.put(
        "/admin/api/faz-targets/Primary",
        json={"host": "10.0.0.9", "adom": "root"},
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 200

    t = get_target("Primary")
    assert t["host"] == "10.0.0.9"
    assert t["token"] == "supersecret"


def test_faz_targets_update_missing_returns_404(client, faz_targets_file):
    _login(client, "admin1")
    csrf = _csrf(client)
    resp = client.put(
        "/admin/api/faz-targets/Ghost",
        json={"host": "10.0.0.9", "adom": "root", "token": "x"},
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 404
