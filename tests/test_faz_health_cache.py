import pytest


@pytest.fixture(autouse=True)
def clear_faz_health_cache():
    """Clear the faz_health_cache module-level cache before each test in this file."""
    try:
        import app.faz_health_cache as cache_mod

        cache_mod._cache.clear()
    except ImportError:
        pass
    yield
    # Also clear after test to be safe
    try:
        import app.faz_health_cache as cache_mod

        cache_mod._cache.clear()
    except ImportError:
        pass


@pytest.fixture
def targets_file(tmp_path, monkeypatch):
    path = tmp_path / "faz_targets.json"
    import app.faz_targets as faz_targets_mod

    monkeypatch.setattr(faz_targets_mod, "FAZ_TARGETS_FILE", path)
    from app.faz_targets import create_target

    create_target("Primary", host="192.168.64.4", adom="root", token="tok")
    yield path


def test_classify_status_green_when_below_thresholds():
    from app.faz_health_cache import _classify_status

    assert _classify_status(cpu=10, mem=20) == "green"


def test_classify_status_yellow_at_warn_threshold():
    from app.faz_health_cache import _classify_status

    assert _classify_status(cpu=75, mem=10) == "yellow"


def test_classify_status_red_at_crit_threshold():
    from app.faz_health_cache import _classify_status

    assert _classify_status(cpu=10, mem=95) == "red"


def test_classify_status_green_when_no_snmp_data():
    from app.faz_health_cache import _classify_status

    assert _classify_status(cpu=None, mem=None) == "green"


def test_poll_all_targets_populates_cache_on_success(targets_file, monkeypatch):
    import app.faz_health_cache as cache_mod
    from app.config import Config

    monkeypatch.setattr(Config, "SNMP_ENABLED", False)

    def fake_get_sys_status(self):
        return {
            "Hostname": "FAZ-TEST",
            "Version": "v7.6.7",
            "Serial Number": "SN1",
            "Disk Usage": "Free 100GB, Total 200GB",
        }

    def fake_preflight(self):
        return True

    monkeypatch.setattr("app.faz_client.FAZClient.get_sys_status", fake_get_sys_status)
    monkeypatch.setattr("app.faz_client.FAZClient.preflight", fake_preflight)
    monkeypatch.setattr("app.faz_client.FAZClient.logout", lambda self: None)

    cache_mod.poll_all_targets()
    entry = cache_mod.get_cached("Primary")
    assert entry is not None
    assert entry["status"] == "green"
    assert entry["hostname"] == "FAZ-TEST"
    assert entry["serial"] == "SN1"
    assert entry["disk_used"] == "Free 100GB, Total 200GB"
    assert entry["error"] is None


def test_poll_all_targets_marks_offline_on_connection_failure(targets_file, monkeypatch):
    import app.faz_health_cache as cache_mod
    from app.faz_client import FAZError

    def raising_preflight(self):
        raise FAZError("No permission for the resource")

    monkeypatch.setattr("app.faz_client.FAZClient.preflight", raising_preflight)
    monkeypatch.setattr("app.faz_client.FAZClient.logout", lambda self: None)

    cache_mod.poll_all_targets()
    entry = cache_mod.get_cached("Primary")
    assert entry["status"] == "offline"
    assert "No permission" in entry["error"]


def test_poll_all_targets_summarizes_raw_network_error(targets_file, monkeypatch):
    # Raw requests/urllib3 exception text (connection pool internals, retry
    # counts, etc.) must not leak to the Dashboard card verbatim.
    import requests

    import app.faz_health_cache as cache_mod

    def raising_preflight(self):
        raise requests.exceptions.ConnectionError(
            "HTTPSConnectionPool(host='192.168.64.4', port=443): Max retries exceeded "
            "with url: /jsonrpc (Caused by NewConnectionError("
            "\"HTTPSConnection(host='192.168.64.4', port=443): Failed to establish a "
            'new connection: [Errno 111] Connection refused"))'
        )

    monkeypatch.setattr("app.faz_client.FAZClient.preflight", raising_preflight)
    monkeypatch.setattr("app.faz_client.FAZClient.logout", lambda self: None)

    cache_mod.poll_all_targets()
    entry = cache_mod.get_cached("Primary")
    assert entry["status"] == "offline"
    assert entry["error"] == "Connection refused"


def test_poll_all_targets_logs_failure_at_a_real_level(targets_file, monkeypatch):
    # Regression test: app_log("WARNING", ...) is silently dropped by
    # app_logger's _LEVEL_RANK (which only recognizes WARN, not WARNING),
    # since an unrecognized level ranks as low as TRACE and falls below the
    # default INFO filter. Confirm the poll-failure log entry survives a
    # WARN-level filter, i.e. it was logged at a level app_logger actually
    # recognizes.
    from app.app_logger import clear_log_entries, get_log_entries

    clear_log_entries()

    def raising_preflight(self):
        raise ConnectionError("boom")

    monkeypatch.setattr("app.faz_client.FAZClient.preflight", raising_preflight)
    monkeypatch.setattr("app.faz_client.FAZClient.logout", lambda self: None)

    import app.faz_health_cache as cache_mod

    cache_mod.poll_all_targets()

    entries = get_log_entries(level="WARN", component="faz_health_cache")
    assert any("Poll failed" in e["message"] for e in entries)


def test_poll_all_targets_survives_malformed_target(targets_file, monkeypatch):
    # A malformed entry (e.g. missing "host") must not abort the whole poll
    # cycle and leave every OTHER valid target frozen at its last cache
    # state — it should be recorded as offline and polling should continue.
    import app.faz_health_cache as cache_mod
    import app.faz_targets as faz_targets_mod
    from app.config import Config

    targets = faz_targets_mod._load()
    targets.append({"label": "Broken"})  # no "host" key
    faz_targets_mod._save(targets)

    monkeypatch.setattr(Config, "SNMP_ENABLED", False)

    def fake_get_sys_status(self):
        return {
            "Hostname": "FAZ-TEST",
            "Version": "v7.6.7",
            "Serial Number": "SN1",
        }

    def fake_preflight(self):
        return True

    monkeypatch.setattr("app.faz_client.FAZClient.get_sys_status", fake_get_sys_status)
    monkeypatch.setattr("app.faz_client.FAZClient.preflight", fake_preflight)
    monkeypatch.setattr("app.faz_client.FAZClient.logout", lambda self: None)

    cache_mod.poll_all_targets()

    primary = cache_mod.get_cached("Primary")
    assert primary is not None
    assert primary["status"] == "green"

    broken = cache_mod.get_cached("Broken")
    assert broken is not None
    assert broken["status"] == "offline"
    assert "Malformed target entry" in broken["error"]


def test_get_all_cached_returns_uncached_targets_as_pending(targets_file):
    import app.faz_health_cache as cache_mod

    entries = cache_mod.get_all_cached()
    assert len(entries) == 1
    assert entries[0]["label"] == "Primary"
    assert entries[0]["status"] == "gray"


def test_poll_all_targets_writes_snapshot_to_collector_store(targets_file, monkeypatch):
    import app.faz_health_cache as cache_mod
    from app import collector_store

    def fake_poll_target(target):
        return {"label": target["label"], "status": "green", "last_updated": "t1"}

    monkeypatch.setattr(cache_mod, "_poll_target", fake_poll_target)

    cache_mod.poll_all_targets()

    stored = collector_store.read_cache(cache_mod.CACHE_KEY)
    assert stored == {"Primary": {"label": "Primary", "status": "green", "last_updated": "t1"}}


def test_get_all_cached_reads_through_to_collector_store_when_in_memory_empty(
    targets_file,
):
    """Simulates a web worker (empty in-memory cache) reading data a
    separate collector process already wrote to SQLite."""
    import app.faz_health_cache as cache_mod
    from app import collector_store

    collector_store.write_cache(
        cache_mod.CACHE_KEY,
        {"Primary": {"label": "Primary", "status": "green", "last_updated": "t1"}},
    )
    assert cache_mod._cache == {}  # this "process" has never polled

    entries = cache_mod.get_all_cached()

    assert len(entries) == 1
    assert entries[0]["status"] == "green"
    # Read-through also repopulates the in-memory dict.
    assert cache_mod._cache.get("Primary", {}).get("status") == "green"
