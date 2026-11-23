"""Connection Timeline routes: tab and ADOM gates, validation, jobs, audit."""

import datetime
import os

import pytest

from tests.test_conn_timeline_job import FakeFAZ, _rows


class _CtxFAZ(FakeFAZ):
    adom = "root"

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.fv_calls = []  # one dict per FortiView run
        self.fv_errors = {}  # view -> exception to raise

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run_fortiview_page(self, adom, view, time_range, *, filter=None, devices=None, **kw):
        from app.faz_client import FAZError  # noqa: F401  (tests raise it via fv_errors)

        self.fv_calls.append(
            {"view": view, "filter": filter, "devices": devices, "time_range": time_range}
        )
        if view in self.fv_errors:
            raise self.fv_errors[view]
        rows = {
            "top-destinations": [
                {"dstip": "192.0.2.1", "session_pass": "7", "session_block": "1", "sessions": "8"}
            ],
        }.get(view, [])
        return rows, len(rows)


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
    import app.routes.conn_timeline_routes as routes
    from app.app_logger import clear_log_entries, get_log_entries

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


def test_build_uses_and_audits_the_chosen_adom(app, faz, monkeypatch):
    import app.routes.conn_timeline_routes as routes
    from app.app_logger import clear_log_entries, get_log_entries

    used = []
    monkeypatch.setattr(routes, "_client_for", lambda target: used.append(target["adom"]) or faz)
    clear_log_entries()
    client, headers = _login(app)
    resp = _start(client, headers, adom="Branches")
    assert resp.status_code == 202
    job = client.get(f"/api/conn-timeline/{resp.get_json()['job_id']}").get_json()
    assert job["result"]["adom"] == "Branches"
    assert set(used) == {"Branches"}
    assert any(
        e["extra"].get("adom") == "Branches" for e in get_log_entries(component="conn_timeline")
    )


def test_build_defaults_to_the_targets_adom_and_rejects_a_bad_one(app, faz):
    client, headers = _login(app)
    resp = _start(client, headers)
    job = client.get(f"/api/conn-timeline/{resp.get_json()['job_id']}").get_json()
    assert job["result"]["adom"] == "root"
    assert _start(client, headers, adom="../x").status_code == 400


def test_adoms_endpoint_for_the_timeline(app, monkeypatch):
    monkeypatch.setattr(
        "app.faz_client.FAZClient.get_adoms", lambda self: [{"name": "root", "desc": ""}]
    )
    monkeypatch.setattr("app.faz_client.FAZClient.logout", lambda self: None)
    client, _ = _login(app)
    body = client.get("/api/conn-timeline/adoms?target=Primary").get_json()
    assert body == {"default": "root", "adoms": [{"name": "root", "desc": ""}]}


def test_a_lost_session_says_so_instead_of_csrf_failed(app):
    """A page loaded under a session that has since been replaced (another app on the
    same host name sharing the cookie name) must be told to log in again."""
    client, headers = _login(app)
    with client.session_transaction() as sess:
        sess.clear()  # what a replaced or expired session cookie looks like
    resp = client.post(
        "/api/conn-timeline", json={"target": "Primary", "host": "10.1.1.1"}, headers=headers
    )
    assert resp.status_code == 401
    assert "log in again" in resp.get_json()["error"]


def _partial_job(client, headers, monkeypatch, rows=500):
    import app.routes.conn_timeline_routes as routes

    monkeypatch.setattr(routes.Config, "CONN_TIMELINE_MAX_ROWS", rows)
    job_id = _start(client, headers).get_json()["job_id"]
    job = client.get(f"/api/conn-timeline/{job_id}").get_json()
    assert job["result"]["coverage"]["complete"] is False
    return job_id, job


def test_a_partial_build_can_be_continued_into_a_complete_one(app, faz, monkeypatch):
    import app.routes.conn_timeline_routes as routes
    from app.app_logger import clear_log_entries, get_log_entries

    clear_log_entries()
    client, headers = _login(app)
    job_id, job = _partial_job(client, headers, monkeypatch)
    cov = job["result"]["coverage"]
    assert cov["resumable"] is True and cov["fetched"] == 500
    assert not any(k.startswith("_") for k in cov)  # nothing private reaches the page

    monkeypatch.setattr(routes.Config, "CONN_TIMELINE_MAX_ROWS", 100000)
    resp = client.post(f"/api/conn-timeline/{job_id}/continue", headers=headers)
    assert resp.status_code == 202
    new_id = resp.get_json()["job_id"]
    assert new_id != job_id
    done = client.get(f"/api/conn-timeline/{new_id}").get_json()
    assert done["status"] == "done"
    cov2 = done["result"]["coverage"]
    assert cov2["complete"] is True and cov2["resumable"] is False
    assert cov2["fetched"] == cov2["matched"] == 1234
    assert sum(f[-1] for f in done["result"]["flows"]) == 1234  # no row counted twice
    assert faz.deleted == list(faz.tasks)
    messages = [e["message"] for e in get_log_entries(component="conn_timeline")]
    assert "Timeline continuing" in messages and messages[-1] == "Timeline completed"


def test_a_build_can_only_be_continued_once(app, faz, monkeypatch):
    client, headers = _login(app)
    job_id, _ = _partial_job(client, headers, monkeypatch)
    assert client.post(f"/api/conn-timeline/{job_id}/continue", headers=headers).status_code == 202
    again = client.post(f"/api/conn-timeline/{job_id}/continue", headers=headers)
    assert again.status_code == 409


def test_a_complete_build_has_nothing_to_continue(app, faz):
    client, headers = _login(app)
    job_id = _start(client, headers).get_json()["job_id"]
    resp = client.post(f"/api/conn-timeline/{job_id}/continue", headers=headers)
    assert resp.status_code == 409


def test_another_user_cannot_continue_a_build(app, faz, monkeypatch):
    client, headers = _login(app, "alice")
    job_id, _ = _partial_job(client, headers, monkeypatch)
    other, other_headers = _login(app, "bob")
    resp = other.post(f"/api/conn-timeline/{job_id}/continue", headers=other_headers)
    assert resp.status_code == 404


def test_continue_needs_csrf(app, faz, monkeypatch):
    client, headers = _login(app)
    job_id, _ = _partial_job(client, headers, monkeypatch)
    assert client.post(f"/api/conn-timeline/{job_id}/continue").status_code in (400, 403)


# ── Quick summary endpoint ───────────────────────────────────────────────────


def _summary(client, headers, **payload):
    body = {"target": "Primary", "host": "10.10.10.53", "section": "peers"}
    body.update(payload)
    return client.post("/api/conn-timeline/summary", json=body, headers=headers)


def test_summary_returns_a_section_with_units_and_seconds(app, faz):
    client, headers = _login(app)
    resp = _summary(client, headers)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["section"] == "peers" and body["units"] == "sessions"
    assert isinstance(body["seconds"], (int, float))
    assert body["rows"][0]["peer"] == "192.0.2.1" and body["rows"][0]["sessions"] == 8


def test_summary_defaults_to_either_direction_all_firewalls_and_one_hour(app, faz):
    client, headers = _login(app)
    _summary(client, headers)
    assert {c["filter"] for c in faz.fv_calls} == {"srcip==10.10.10.53", "dstip==10.10.10.53"}
    assert all(c["devices"] == [{"devid": "All_FortiGate"}] for c in faz.fv_calls)
    start, end = faz.fv_calls[0]["time_range"]
    delta = datetime.datetime.fromisoformat(end) - datetime.datetime.fromisoformat(start)
    assert delta == datetime.timedelta(hours=1)


def test_summary_passes_the_chosen_firewall_and_direction(app, faz):
    client, headers = _login(app)
    _summary(client, headers, direction="src", device="FGT0000000001", section="policies")
    assert [(c["view"], c["filter"]) for c in faz.fv_calls] == [
        ("policy-hits", "srcip==10.10.10.53")
    ]
    assert faz.fv_calls[0]["devices"] == [{"devid": "FGT0000000001"}]


@pytest.mark.parametrize(
    "payload,message",
    [
        ({"section": "ports"}, "section"),
        ({"host": "web01.example.com"}, "Enter an IP address"),
        ({"direction": "sideways"}, "Unknown direction"),
        ({"preset": "30d"}, "Unknown time preset"),
    ],
)
def test_summary_rejects_an_unknown_section_and_bad_input(app, faz, payload, message):
    client, headers = _login(app)
    resp = _summary(client, headers, **payload)
    assert resp.status_code == 400 and message in resp.get_json()["error"]
    assert faz.fv_calls == []


def test_summary_unknown_target_is_404(app, faz):
    client, headers = _login(app)
    assert _summary(client, headers, target="Nope").status_code == 404


def test_summary_for_an_unavailable_view_is_a_200_with_unavailable(app, faz):
    from app.faz_client import FAZError

    faz.fv_errors["top-applications"] = FAZError("Cannot find FortiView 'top-applications'")
    client, headers = _login(app)
    resp = _summary(client, headers, section="applications")
    assert resp.status_code == 200 and "unavailable" in resp.get_json()
    assert _summary(client, headers, section="peers").get_json()["rows"]  # others unaffected


def test_summary_faz_error_is_a_502(app, faz):
    from app.faz_client import FAZError

    faz.fv_errors["policy-hits"] = FAZError("Internal error")
    client, headers = _login(app)
    resp = _summary(client, headers, section="policies")
    assert resp.status_code == 502 and "Internal error" in resp.get_json()["error"]


def test_restricted_user_cannot_summarize_another_target(app, faz):
    client, headers = _login(app, "carol")
    assert _summary(client, headers, target="Primary").status_code == 403
    assert faz.fv_calls == []


def test_summary_needs_csrf(app, faz):
    client, _ = _login(app)
    resp = client.post(
        "/api/conn-timeline/summary",
        json={"target": "Primary", "host": "10.1.1.5", "section": "peers"},
    )
    assert resp.status_code in (400, 403)


def test_summary_is_audited(app, faz):
    from app.app_logger import clear_log_entries, get_log_entries

    clear_log_entries()
    client, headers = _login(app)
    _summary(client, headers, section="countries")
    entry = get_log_entries(component="conn_timeline")[-1]
    assert entry["message"] == "Timeline summary"
    assert entry["extra"]["by"] == "alice" and entry["extra"]["section"] == "countries"
    assert entry["extra"]["host"] == "10.10.10.53" and "seconds" in entry["extra"]


def test_summary_is_refused_over_the_concurrency_limit(app, faz, monkeypatch):
    import app.routes.conn_timeline_routes as routes

    monkeypatch.setattr(routes.Config, "CONN_TIMELINE_SUMMARY_MAX_CONCURRENT", 0)
    client, headers = _login(app)
    resp = _summary(client, headers)
    assert resp.status_code == 429 and faz.fv_calls == []
