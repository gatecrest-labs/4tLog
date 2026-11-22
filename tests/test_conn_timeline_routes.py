"""Connection Timeline routes: tab and ADOM gates, validation, jobs, audit."""

import datetime
import os

import pytest

from tests.test_conn_timeline_job import FakeFAZ, _rows


class _CtxFAZ(FakeFAZ):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


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
    auth_mod.add_user("bob", "Str0ng!Passw0rd", role="viewer")
    auth_mod.add_user("carol", "Str0ng!Passw0rd", role="viewer")
    groups_mod.create_group(
        "g1", members=["alice", "bob"], allowed_tabs=["conn_timeline"], adom_restrict=False
    )
    groups_mod.create_group(
        "g2",
        members=["carol"],
        allowed_tabs=["conn_timeline"],
        adom_restrict=True,
        allowed_adoms=["Secondary"],
    )
    faz_targets_mod.create_target("Primary", host="192.168.64.4", adom="root", token="tok")
    faz_targets_mod.create_target("Secondary", host="192.168.64.5", adom="root", token="tok2")

    from app import create_app

    return create_app()


@pytest.fixture
def faz(monkeypatch):
    """Builds run inline against a fake FortiAnalyzer holding 1,234 rows."""
    import app.conn_timeline_job as job_mod
    import app.routes.conn_timeline_routes as routes

    now = datetime.datetime.now(datetime.timezone.utc)
    fake = _CtxFAZ(_rows(1234, start=now - datetime.timedelta(minutes=50)))
    job_mod.STORE.clear()
    monkeypatch.setattr(job_mod, "spawn", lambda target: target())
    monkeypatch.setattr(routes, "_client_for", lambda target: fake)
    yield fake
    job_mod.STORE.clear()


def _login(app, username="alice"):
    client = app.test_client()
    client.get("/login")
    with client.session_transaction() as sess:
        csrf = sess.get("_csrf_token", "")
    client.post(
        "/login", data={"username": username, "password": "Str0ng!Passw0rd", "csrf_token": csrf}
    )
    client.get("/api/conn-timeline/targets")
    with client.session_transaction() as sess:
        return client, {"X-CSRF-Token": sess.get("_csrf_token", "")}


def _start(client, headers, **payload):
    body = {"target": "Primary", "host": "10.10.10.53"}
    body.update(payload)
    return client.post("/api/conn-timeline", json=body, headers=headers)


def test_requires_login(app):
    assert app.test_client().get("/api/conn-timeline/targets").status_code == 401


def test_page_needs_the_tab(app):
    import app.groups as groups_mod

    groups_mod.update_group("g1", members=["alice", "bob"], allowed_tabs=["log_search"])
    client, _ = _login(app)
    assert client.get("/conn-timeline").status_code in (302, 403)


def test_page_renders_with_the_one_hour_default(app):
    client, _ = _login(app)
    resp = client.get("/conn-timeline")
    assert resp.status_code == 200
    assert b'data-default-preset="1h"' in resp.data
    assert b"Connection Timeline" in resp.data


def test_targets_follow_the_adom_restriction(app):
    client, _ = _login(app, "carol")
    labels = [t["label"] for t in client.get("/api/conn-timeline/targets").get_json()]
    assert labels == ["Secondary"]


def test_restricted_user_cannot_build_on_another_target(app, faz):
    client, headers = _login(app, "carol")
    resp = _start(client, headers, target="Primary")
    assert resp.status_code == 403
    assert faz.tasks == {}


def test_build_defaults_to_one_hour_and_returns_the_result(app, faz):
    from app.app_logger import clear_log_entries, get_log_entries

    clear_log_entries()
    client, headers = _login(app)
    resp = _start(client, headers)
    assert resp.status_code == 202
    job_id = resp.get_json()["job_id"]
    job = client.get(f"/api/conn-timeline/{job_id}").get_json()
    assert job["status"] == "done"
    result = job["result"]
    assert result["preset"] == "1h" and result["bucket_seconds"] == 60
    assert result["host"] == "10.10.10.53" and result["direction"] == "either"
    assert result["coverage"]["complete"] is True
    assert result["coverage"]["matched"] == result["coverage"]["fetched"] == 1234
    assert faz.deleted == list(faz.tasks)

    messages = [e["message"] for e in get_log_entries(component="conn_timeline")]
    assert messages == ["Timeline started", "Timeline completed"]
    done = get_log_entries(component="conn_timeline")[-1]["extra"]
    assert done["by"] == "alice" and done["host"] == "10.10.10.53"
    assert done["matched"] == 1234


def test_truncated_build_is_audited(app, faz, monkeypatch):
    from app.app_logger import clear_log_entries, get_log_entries
    import app.routes.conn_timeline_routes as routes

    # tests/test_config.py reloads app.config: patch the class the routes use.
    monkeypatch.setattr(routes.Config, "CONN_TIMELINE_MAX_ROWS", 500)
    clear_log_entries()
    client, headers = _login(app)
    job_id = _start(client, headers).get_json()["job_id"]
    result = client.get(f"/api/conn-timeline/{job_id}").get_json()["result"]
    assert result["coverage"]["reason"] == "cap"
    last = get_log_entries(component="conn_timeline")[-1]
    assert last["message"] == "Timeline truncated" and last["extra"]["reason"] == "cap"


@pytest.mark.parametrize(
    "payload,message",
    [
        ({"host": "web01.example.com"}, "Enter an IP address"),
        ({"host": "10.1.1.0/24"}, "Enter an IP address"),
        (
            {"start_time": "2026-11-01T00:00:00Z", "end_time": "2026-11-09T00:00:00Z"},
            "at most 7 days",
        ),
        ({"direction": "sideways"}, "Unknown direction"),
        ({"verdict": "maybe"}, "Unknown verdict"),
        ({"preset": "30d"}, "Unknown time preset"),
    ],
)
def test_invalid_input_is_refused(app, faz, payload, message):
    client, headers = _login(app)
    resp = _start(client, headers, **payload)
    assert resp.status_code == 400
    assert message in resp.get_json()["error"]
    assert faz.tasks == {}


def test_unknown_target_is_404(app, faz):
    client, headers = _login(app)
    assert _start(client, headers, target="Nowhere").status_code in (403, 404)


def test_another_users_job_is_not_found(app, faz):
    alice, alice_headers = _login(app, "alice")
    job_id = _start(alice, alice_headers).get_json()["job_id"]
    bob, bob_headers = _login(app, "bob")
    assert bob.get(f"/api/conn-timeline/{job_id}").status_code == 404
    assert bob.delete(f"/api/conn-timeline/{job_id}", headers=bob_headers).status_code == 404
    assert alice.get(f"/api/conn-timeline/{job_id}").status_code == 200


def test_one_build_per_user_at_a_time(app, faz, monkeypatch):
    import app.conn_timeline_job as job_mod

    monkeypatch.setattr(job_mod, "spawn", lambda target: None)  # leave it running
    client, headers = _login(app)
    first = _start(client, headers)
    assert first.status_code == 202
    second = _start(client, headers)
    assert second.status_code == 429
    assert "already have a timeline" in second.get_json()["error"]
    job_id = first.get_json()["job_id"]
    resp = client.delete(f"/api/conn-timeline/{job_id}", headers=headers)
    assert resp.status_code == 200


def test_faz_error_fails_the_job_and_is_audited(app, faz):
    from app.app_logger import get_log_entries
    from app.faz_client import FAZError

    def broken(*a, **k):
        raise FAZError("logview failed")

    faz.submit_log_search = broken
    client, headers = _login(app)
    job_id = _start(client, headers).get_json()["job_id"]
    job = client.get(f"/api/conn-timeline/{job_id}").get_json()
    assert job["status"] == "failed" and "logview failed" in job["error"]
    last = get_log_entries(component="conn_timeline")[-1]
    assert last["message"] == "Timeline failed: FortiAnalyzer error"


def test_post_needs_csrf(app, faz):
    client, _ = _login(app)
    resp = client.post("/api/conn-timeline", json={"target": "Primary", "host": "10.1.1.5"})
    assert resp.status_code in (400, 403)
