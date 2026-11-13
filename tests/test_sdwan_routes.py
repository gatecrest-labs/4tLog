import os

import pytest

TARGETS = [
    {"label": "A", "adom": "root", "host": "h1", "state": "ok", "interfaces": []},
    {"label": "B", "adom": "root", "host": "h2", "state": "no_data", "interfaces": []},
]


@pytest.fixture
def app(tmp_path, monkeypatch):
    os.environ.setdefault("SECRET_KEY", "test-secret")
    import app.auth as auth_mod
    import app.groups as groups_mod

    monkeypatch.setattr(auth_mod, "USERS_FILE", tmp_path / "users.json")
    monkeypatch.setattr(groups_mod, "GROUPS_FILE", tmp_path / "groups.json")
    auth_mod.add_user("alice", "Str0ng!Passw0rd", role="viewer")
    auth_mod.add_user("bob", "Str0ng!Passw0rd", role="viewer")
    auth_mod.add_user("root", "Str0ng!Passw0rd", role="admin")
    groups_mod.create_group("sd", members=["alice"], allowed_tabs=["dashboard", "sdwan"])
    groups_mod.create_group("nosd", members=["bob"], allowed_tabs=["dashboard"])

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


def _stub_cache(monkeypatch, targets=TARGETS, collected_at="2026-11-13T10:00:00+00:00"):
    monkeypatch.setattr(
        "app.routes.sdwan_routes.get_cached",
        lambda: {"targets": list(targets), "collected_at": collected_at},
    )


def test_sdwan_requires_login(client):
    for path in ("/sdwan", "/api/sdwan"):
        resp = client.get(path)
        assert resp.status_code in (302, 401)


def test_sdwan_blocked_without_tab_permission(client):
    _login(client, "bob")
    assert client.get("/sdwan").status_code == 403
    resp = client.get("/api/sdwan")
    assert resp.status_code == 403
    assert resp.get_json() == {"error": "Access denied"}


def test_api_returns_cached_targets_for_admin(client, monkeypatch):
    _stub_cache(monkeypatch)
    _login(client, "root")

    resp = client.get("/api/sdwan")

    assert resp.status_code == 200
    body = resp.get_json()
    assert [t["label"] for t in body["targets"]] == ["A", "B"]
    assert body["collected_at"] == "2026-11-13T10:00:00+00:00"
    assert body["poll_interval"] == 300  # lets the page judge staleness


def test_api_filters_targets_by_allowed_adoms(client, monkeypatch):
    _stub_cache(monkeypatch)
    monkeypatch.setattr("app.routes.sdwan_routes.get_allowed_adoms", lambda *a, **k: {"A"})
    _login(client)

    body = client.get("/api/sdwan").get_json()

    assert [t["label"] for t in body["targets"]] == ["A"]


def test_api_empty_cache_returns_empty_targets_list(client, monkeypatch):
    monkeypatch.setattr(
        "app.routes.sdwan_routes.get_cached", lambda: {"targets": [], "collected_at": None}
    )
    _login(client)

    assert client.get("/api/sdwan").get_json() == {
        "targets": [],
        "collected_at": None,
        "poll_interval": 300,
    }


def test_nav_shows_sd_wan_tab_for_permitted_user(client):
    _login(client)

    resp = client.get("/sdwan")

    assert resp.status_code == 200
    assert b"SD-WAN" in resp.data


def test_nav_hides_sd_wan_tab_without_permission(client):
    _login(client, "bob")

    resp = client.get("/")

    assert resp.status_code == 200
    assert b"/sdwan" not in resp.data


def test_sdwan_page_has_root_and_script(client):
    _login(client)

    html = client.get("/sdwan").get_data(as_text=True)

    assert 'id="sdwanRoot"' in html
    assert "js/sdwan.js" in html
