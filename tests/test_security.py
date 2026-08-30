import pytest
from flask import Flask

from app.security import ensure_csrf_token, validate_csrf_request


@pytest.fixture
def app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test"
    return app


def test_ensure_csrf_token_persists_in_session(app):
    with app.test_request_context("/"):
        token1 = ensure_csrf_token()
        token2 = ensure_csrf_token()
        assert token1 == token2
        assert len(token1) > 20


def test_validate_csrf_request_accepts_matching_header(app):
    with app.test_request_context("/", headers={}, method="POST"):
        token = ensure_csrf_token()
    with app.test_request_context("/", method="POST", headers={"X-CSRF-Token": token}):
        from flask import session

        session["_csrf_token"] = token
        assert validate_csrf_request() is True


def test_validate_csrf_request_rejects_missing_token(app):
    with app.test_request_context("/", method="POST"):
        assert validate_csrf_request() is False
