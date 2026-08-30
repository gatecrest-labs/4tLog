import os

import pytest


@pytest.fixture
def app(tmp_path, monkeypatch):
    os.environ.setdefault("SECRET_KEY", "test-secret")
    import app.auth as auth_mod
    import app.groups as groups_mod

    monkeypatch.setattr(auth_mod, "USERS_FILE", tmp_path / "users.json")
    monkeypatch.setattr(groups_mod, "GROUPS_FILE", tmp_path / "groups.json")
    auth_mod.add_user("alice", "Str0ng!Passw0rd", role="admin")

    from app import create_app

    return create_app()


@pytest.fixture
def client(app):
    return app.test_client()


def test_login_page_reachable(client):
    resp = client.get("/login")
    assert resp.status_code == 200
    assert b"Password" in resp.data


def test_unauthenticated_root_has_no_crash(client):
    resp = client.get("/nonexistent")
    assert resp.status_code == 404


def _csrf(client):
    client.get("/login")
    with client.session_transaction() as sess:
        return sess.get("_csrf_token", "")


def test_login_with_wrong_password_returns_401(client):
    csrf = _csrf(client)
    resp = client.post(
        "/login", data={"username": "alice", "password": "wrong", "csrf_token": csrf}
    )
    assert resp.status_code == 401


def test_login_success_sets_session(client):
    csrf = _csrf(client)
    resp = client.post(
        "/login",
        data={"username": "alice", "password": "Str0ng!Passw0rd", "csrf_token": csrf},
    )
    assert resp.status_code in (302, 200)
    with client.session_transaction() as sess:
        assert sess["user"] == "alice"
        assert sess["role"] == "admin"


def test_logout_clears_session(client):
    csrf = _csrf(client)
    client.post(
        "/login",
        data={"username": "alice", "password": "Str0ng!Passw0rd", "csrf_token": csrf},
    )
    # login() now calls session.clear() (finding #14 fix), so the pre-login
    # CSRF token doesn't survive into the authenticated session — a request
    # must happen first to let before_request's ensure_csrf_token()
    # establish a fresh one.
    client.get("/")
    with client.session_transaction() as sess:
        assert sess["user"] == "alice"  # confirm login actually succeeded this time
        logout_csrf = sess.get("_csrf_token", "")
    resp = client.post("/logout", headers={"X-CSRF-Token": logout_csrf})
    assert resp.status_code == 302
    with client.session_transaction() as sess:
        assert "user" not in sess
