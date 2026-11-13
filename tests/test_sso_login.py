import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _keypair():
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def _mint(priv_pem, *, audience="4tlog", issuer="4tsuite", sub="alice"):
    now = int(time.time())
    claims = {
        "sub": sub,
        "aud": audience,
        "iss": issuer,
        "iat": now,
        "nbf": now,
        "exp": now + 300,
    }
    return jwt.encode(claims, priv_pem, algorithm="EdDSA")


@pytest.fixture
def app(tmp_path, monkeypatch):
    import app.groups as groups_mod
    import app.sso_verify as sso_mod

    monkeypatch.setattr(groups_mod, "GROUPS_FILE", tmp_path / "groups.json")
    priv_pem, pub_pem = _keypair()
    key_path = tmp_path / "sso_public_key.pem"
    key_path.write_bytes(pub_pem)
    monkeypatch.setattr(sso_mod, "PUBLIC_KEY_PATH", key_path)

    groups_mod.create_group("operators", members=["alice"], allowed_tabs=["dashboard"])

    from app import create_app

    app = create_app()
    app.config["_TEST_PRIV_KEY"] = priv_pem
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def test_sso_login_with_valid_token_establishes_session(app, client):
    token = _mint(app.config["_TEST_PRIV_KEY"], sub="alice")
    response = client.get(f"/sso/login?token={token}", follow_redirects=False)
    assert response.status_code == 302
    with client.session_transaction() as sess:
        assert sess["user"] == "alice"
        assert sess["role"] == "sso"
        assert "dashboard" in sess["allowed_tabs"]


def test_sso_login_with_invalid_token_returns_403(client):
    response = client.get("/sso/login?token=not-a-real-token")
    assert response.status_code == 403


def test_sso_login_with_wrong_audience_returns_403(app, client):
    token = _mint(app.config["_TEST_PRIV_KEY"], audience="4texecutive", sub="alice")
    response = client.get("/sso/login?token={0}".format(token))
    assert response.status_code == 403


def test_sso_login_does_not_establish_a_session_on_failure(client):
    client.get("/sso/login?token=garbage")
    with client.session_transaction() as sess:
        assert "user" not in sess


def test_sso_session_survives_a_second_authenticated_request(app, client):
    """Regression test: a session for a username absent from users.json is
    cleared on the next request unless session["role"] is truthy. A
    session["role"] = None mistake passes the initial redirect and only
    fails on this second request."""
    token = _mint(app.config["_TEST_PRIV_KEY"], sub="alice")
    client.get(f"/sso/login?token={token}")

    response = client.get("/")

    assert response.status_code == 200
    with client.session_transaction() as sess:
        assert sess.get("user") == "alice"


def test_zero_grant_sso_user_sees_banner_in_an_authenticated_shell(app, client):
    """Reference behavior the other sub-apps match: authenticated, nothing granted."""
    token = _mint(app.config["_TEST_PRIV_KEY"], sub="mallory")  # in no group
    response = client.get(f"/sso/login?token={token}", follow_redirects=True)
    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "Your account has no tabs assigned. Contact an administrator." in body
    assert "mallory" in body  # username shown in the nav
    assert "/logout" in body  # working logout form


def _login_sso(app, client, sub="alice"):
    client.get(f"/sso/login?token={_mint(app.config['_TEST_PRIV_KEY'], sub=sub)}")


def test_sso_login_records_login_time(app, client):
    _login_sso(app, client)
    with client.session_transaction() as sess:
        assert isinstance(sess["sso_login_at"], float)


def test_revoked_sso_session_is_cleared_and_redirected(app, client):
    state = {"valid": True}
    app.extensions["tsuite_session_checker"] = lambda u, t: state["valid"]
    _login_sso(app, client)
    assert client.get("/", follow_redirects=False).status_code == 200
    state["valid"] = False
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]
    with client.session_transaction() as sess:
        assert "user" not in sess


def test_revoked_sso_session_gets_401_json_on_api_paths(app, client):
    app.extensions["tsuite_session_checker"] = lambda u, t: False
    _login_sso(app, client)
    response = client.get("/api/log-search/targets")
    assert response.status_code == 401
    assert response.get_json()["error"] == "Not authenticated"


def test_local_session_is_never_checked(app, client):
    def explode(username, login_at):
        raise AssertionError("checker must not run for local sessions")

    app.extensions["tsuite_session_checker"] = explode
    with client.session_transaction() as sess:
        sess["user"] = "alice"
        sess["role"] = "sso"  # no sso_login_at: not an SSO-established session
        sess["login_at"] = int(time.time())
    assert client.get("/", follow_redirects=False).status_code != 500


def test_no_checker_leaves_sso_sessions_alone(app, client):
    app.extensions["tsuite_session_checker"] = None
    _login_sso(app, client)
    assert client.get("/", follow_redirects=False).status_code == 200


def _csrf(client):
    client.get("/login")
    with client.session_transaction() as sess:
        return sess.get("_csrf_token", "")


def _local_login(client, password="Str0ng!Passw0rd"):
    return client.post(
        "/login",
        data={"username": "bob", "password": password, "csrf_token": _csrf(client)},
    )


@pytest.fixture
def local_user(tmp_path, monkeypatch):
    import app.auth as auth_mod

    monkeypatch.setattr(auth_mod, "USERS_FILE", tmp_path / "users.json")
    auth_mod.add_user("bob", "Str0ng!Passw0rd", role="admin")


def test_stale_sso_marker_does_not_survive_logout_and_local_login(app, client, local_user):
    """Regression guard: a local session must never inherit sso_login_at."""
    _login_sso(app, client)
    client.get("/")  # before_request mints a CSRF token for the fresh session
    with client.session_transaction() as sess:
        assert "sso_login_at" in sess
        csrf = sess["_csrf_token"]
    client.post("/logout", data={"csrf_token": csrf})
    with client.session_transaction() as sess:
        assert "sso_login_at" not in sess

    def explode(username, login_at):
        raise AssertionError("checker must not run for local sessions")

    app.extensions["tsuite_session_checker"] = explode
    _local_login(client)
    with client.session_transaction() as sess:
        assert sess["user"] == "bob"
        assert "sso_login_at" not in sess
    assert client.get("/", follow_redirects=False).status_code != 500


def test_local_login_over_a_live_sso_session_drops_the_sso_marker(app, client, local_user):
    _login_sso(app, client)
    app.extensions["tsuite_session_checker"] = lambda u, t: (_ for _ in ()).throw(
        AssertionError("checker must not run for local sessions")
    )
    _local_login(client)
    with client.session_transaction() as sess:
        assert sess["user"] == "bob"
        assert "sso_login_at" not in sess
    assert client.get("/", follow_redirects=False).status_code != 500
