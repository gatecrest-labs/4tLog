"""Tests for POST /admin/api/faz-selftest and the Admin panel markup."""

import os
from unittest.mock import patch

import pytest

from tests.test_admin_routes import _csrf, _login


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


TARGETS = [
    {"label": "Primary", "host": "10.0.0.1", "adom": "root", "token": "tok1"},
    {"label": "Second", "host": "10.0.0.2", "adom": "lab", "token": "tok2"},
]
REPORT = {
    "faz_version": "8.0.2",
    "train": "8.0",
    "sample": {},
    "summary": {"ok": 1, "denied": 0, "error": 0, "skipped": 0},
    "checks": [],
}


def _post(client, body=None):
    csrf = _csrf(client)
    return client.post("/admin/api/faz-selftest", json=body or {}, headers={"X-CSRF-Token": csrf})


def test_admin_gets_report_for_first_target_by_default(client):
    _login(client, "admin1")
    with (
        patch("app.routes.admin_routes.list_targets", return_value=TARGETS),
        patch("app.faz_selftest.run_selftest", return_value=REPORT) as run,
        patch("app.faz_client.FAZClient") as fc,
    ):
        resp = _post(client)
    assert resp.status_code == 200
    assert resp.get_json()["faz_version"] == "8.0.2"
    run.assert_called_once()
    assert fc.call_args.kwargs["host"] == "10.0.0.1"
    assert fc.call_args.kwargs["adom"] == "root"
    fc.return_value.__enter__.assert_called_once()


def test_label_selects_the_target(client):
    _login(client, "admin1")
    with (
        patch("app.routes.admin_routes.list_targets", return_value=TARGETS),
        patch("app.routes.admin_routes.get_target", return_value=TARGETS[1]),
        patch("app.faz_selftest.run_selftest", return_value=REPORT),
        patch("app.faz_client.FAZClient") as fc,
    ):
        resp = _post(client, {"label": "Second"})
    assert resp.status_code == 200
    assert fc.call_args.kwargs["host"] == "10.0.0.2"


def test_unknown_label_is_404(client):
    _login(client, "admin1")
    with (
        patch("app.routes.admin_routes.list_targets", return_value=TARGETS),
        patch("app.routes.admin_routes.get_target", return_value=None),
    ):
        resp = _post(client, {"label": "nope"})
    assert resp.status_code == 404


def test_no_targets_is_404(client):
    _login(client, "admin1")
    with patch("app.routes.admin_routes.list_targets", return_value=[]):
        resp = _post(client)
    assert resp.status_code == 404


def test_viewer_is_forbidden(client):
    _login(client, "viewer1")
    resp = client.post("/admin/api/faz-selftest", json={}, headers={"X-CSRF-Token": _csrf(client)})
    assert resp.status_code == 403


def test_get_not_allowed(client):
    _login(client, "admin1")
    assert client.get("/admin/api/faz-selftest").status_code == 405


def test_unreachable_faz_is_502_json_and_never_leaks_the_token(client):
    _login(client, "admin1")
    with (
        patch("app.routes.admin_routes.list_targets", return_value=TARGETS),
        patch("app.faz_client.FAZClient", side_effect=RuntimeError("no route")),
    ):
        resp = _post(client)
    assert resp.status_code == 502
    assert "no route" in resp.get_json()["error"]
    assert "tok1" not in resp.get_data(as_text=True)


def test_admin_page_has_the_self_test_panel(client):
    _login(client, "admin1")
    html = client.get("/admin/").get_data(as_text=True)
    assert 'data-panel="panel-faz-selftest"' in html
    assert 'id="panel-faz-selftest"' in html
    assert 'id="btnFazSelftest"' in html
    assert 'id="fazSelftestResult"' in html


def test_self_test_is_not_run_on_page_load():
    js = open("app/static/js/admin.js").read()
    assert js.count("/admin/api/faz-selftest") == 1
    # only inside the click handler, never from the tab switcher
    tab_switch = js[js.index("Admin sub-tab switching") : js.index("// ── API Self-Test")]
    assert "selftest" not in tab_switch.lower()


@pytest.mark.parametrize("cls", ["st-ok", "st-denied", "st-error", "st-skipped"])
def test_status_styles_exist(cls):
    assert f".{cls}" in open("app/static/css/style.css").read()
