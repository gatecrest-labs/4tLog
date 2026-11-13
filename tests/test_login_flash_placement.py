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


def _csrf(client):
    client.get("/login")
    with client.session_transaction() as sess:
        return sess.get("_csrf_token", "")


def test_flash_message_renders_inside_the_login_card_not_above_it(client):
    csrf = _csrf(client)
    response = client.post(
        "/login",
        data={"username": "alice", "password": "wrong", "csrf_token": csrf},
    )

    html = response.data.decode()
    assert response.status_code == 401
    card_start = html.index('<div class="login-card">')
    flash_pos = html.index('class="alert alert-danger"')
    card_end = html.index("</form>", card_start)  # form is always after the flash, inside the card
    assert card_start < flash_pos < card_end


def test_login_page_with_no_flash_has_no_alert_div(client):
    response = client.get("/login")

    assert response.status_code == 200
    assert b'class="alert' not in response.data
