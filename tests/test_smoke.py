"""Smoke tests — verify the app can be imported and instantiated."""

import os

import pytest


@pytest.fixture
def app():
    os.environ.setdefault("SECRET_KEY", "test-secret")
    from app import create_app

    return create_app()


@pytest.fixture
def client(app):
    return app.test_client()


def test_app_creates(app):
    assert app is not None


def test_security_headers_present(client):
    resp = client.get("/nonexistent-path")
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"
