import pytest


@pytest.fixture
def history_db(tmp_path, monkeypatch):
    path = tmp_path / "hostmetrics.db"
    import app.host_metrics_history as history_mod

    monkeypatch.setattr(history_mod, "DB_PATH", path)
    history_mod.init_db()
    yield path


def test_poll_host_metrics_writes_snapshot(history_db, monkeypatch):
    import psutil

    import app.host_metrics_cache as cache_mod
    from app.host_metrics_history import get_history

    monkeypatch.setattr(psutil, "cpu_percent", lambda: 12.5)
    monkeypatch.setattr(
        psutil, "virtual_memory", lambda: type("_VM", (), {"percent": 40.0})()
    )
    monkeypatch.setattr(
        psutil, "disk_usage", lambda path: type("_DU", (), {"percent": 55.0})()
    )

    cache_mod.poll_host_metrics()

    rows = get_history("1970-01-01T00:00:00Z")
    assert len(rows) == 1
    assert rows[0]["cpu_percent"] == 12.5
    assert rows[0]["memory_percent"] == 40.0
    assert rows[0]["disk_percent"] == 55.0


def test_poll_host_metrics_handles_psutil_failure(history_db, monkeypatch):
    import psutil

    import app.host_metrics_cache as cache_mod
    from app.host_metrics_history import get_history

    def _raise():
        raise RuntimeError("psutil boom")

    monkeypatch.setattr(psutil, "cpu_percent", _raise)

    cache_mod.poll_host_metrics()  # should not raise

    assert get_history("1970-01-01T00:00:00Z") == []


def test_init_scheduler_noop_when_disabled(monkeypatch):
    import app.host_metrics_cache as cache_mod
    from app.config import Config

    monkeypatch.setattr(Config, "HOST_METRICS_POLL_DISABLED", True)
    calls = []
    monkeypatch.setattr(cache_mod, "poll_now", lambda: calls.append("called"))

    cache_mod.init_scheduler(app=None)

    assert calls == []
