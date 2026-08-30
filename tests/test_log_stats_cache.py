import pytest


@pytest.fixture
def targets_file(tmp_path, monkeypatch):
    path = tmp_path / "faz_targets.json"
    import app.faz_targets as faz_targets_mod

    monkeypatch.setattr(faz_targets_mod, "FAZ_TARGETS_FILE", path)
    from app.faz_targets import create_target

    create_target("Primary", host="192.168.64.4", adom="root", token="tok")
    yield path


@pytest.fixture
def history_db(tmp_path, monkeypatch):
    path = tmp_path / "logstats.db"
    import app.log_stats_history as history_mod

    monkeypatch.setattr(history_mod, "DB_PATH", path)
    history_mod.init_db()
    yield path


@pytest.fixture(autouse=True)
def clear_log_stats_cache():
    import app.log_stats_cache as cache_mod

    cache_mod._cache = {"logging_devices": [], "silent_devices": [], "collected_at": None}
    yield
    cache_mod._cache = {"logging_devices": [], "silent_devices": [], "collected_at": None}


def test_poll_all_targets_populates_cache_and_writes_rollup(
    targets_file, history_db, monkeypatch
):
    import app.log_stats_cache as cache_mod
    from app.log_stats_history import get_latest_rollup

    def fake_get_log_stats(self, adom=None):
        return [
            {
                "devid": "A",
                "devname": "a",
                "last_log_timestamp": int(__import__("time").time()),
                "lograte": 4.0,
            },
            {"devid": "B", "devname": "b", "last_log_timestamp": 1, "lograte": 0.0},
        ]

    monkeypatch.setattr("app.faz_client.FAZClient.get_log_stats", fake_get_log_stats)
    monkeypatch.setattr("app.faz_client.FAZClient.logout", lambda self: None)

    cache_mod.poll_all_targets()

    cached = cache_mod.get_cached()
    assert [d["devid"] for d in cached["logging_devices"]] == ["A"]
    assert [d["devid"] for d in cached["silent_devices"]] == ["B"]
    assert cached["collected_at"] is not None

    rollup = get_latest_rollup()
    assert rollup["devices_logging"] == 1
    assert rollup["devices_silent"] == 1
    assert rollup["total_lograte"] == 4.0


def test_poll_all_targets_skips_unreachable_target_without_aborting(
    targets_file, history_db, monkeypatch
):
    import app.log_stats_cache as cache_mod
    from app.faz_client import FAZError

    def fake_get_log_stats(self, adom=None):
        raise FAZError("boom")

    monkeypatch.setattr("app.faz_client.FAZClient.get_log_stats", fake_get_log_stats)
    monkeypatch.setattr("app.faz_client.FAZClient.logout", lambda self: None)

    cache_mod.poll_all_targets()  # must not raise

    cached = cache_mod.get_cached()
    assert cached["logging_devices"] == []
    assert cached["silent_devices"] == []


def test_poll_all_targets_dedupes_devices_seen_across_multiple_targets(
    tmp_path, monkeypatch, history_db
):
    import app.faz_targets as faz_targets_mod
    import app.log_stats_cache as cache_mod

    monkeypatch.setattr(faz_targets_mod, "FAZ_TARGETS_FILE", tmp_path / "faz_targets.json")
    from app.faz_targets import create_target

    create_target("Primary", host="192.168.64.4", adom="root", token="tok")
    create_target("Secondary", host="192.168.64.5", adom="root", token="tok2")

    now = int(__import__("time").time())

    def fake_get_log_stats(self, adom=None):
        # Same devid ("SHARED") visible from both targets; last poll wins.
        return [{"devid": "SHARED", "devname": "shared", "last_log_timestamp": now, "lograte": 1.0}]

    monkeypatch.setattr("app.faz_client.FAZClient.get_log_stats", fake_get_log_stats)
    monkeypatch.setattr("app.faz_client.FAZClient.logout", lambda self: None)

    cache_mod.poll_all_targets()

    cached = cache_mod.get_cached()
    assert len(cached["logging_devices"]) == 1
    assert cached["logging_devices"][0]["devid"] == "SHARED"


def test_classify_devices_splits_logging_and_silent():
    from app.log_stats_cache import classify_devices

    now = 10_000.0
    stats = [
        # 100s ago: logging
        {"devid": "A", "devname": "a", "last_log_timestamp": 9_900, "lograte": 1.0},
        # ~66min ago: silent
        {"devid": "B", "devname": "b", "last_log_timestamp": 6_000, "lograte": 0.0},
    ]
    logging_devices, silent_devices = classify_devices(stats, now, threshold_minutes=60)
    assert [d["devid"] for d in logging_devices] == ["A"]
    assert [d["devid"] for d in silent_devices] == ["B"]


def test_classify_devices_at_exact_threshold_boundary_is_not_silent():
    from app.log_stats_cache import classify_devices

    now = 10_000.0
    stats = [{"devid": "A", "devname": "a", "last_log_timestamp": now - 60 * 60, "lograte": 0.0}]
    logging_devices, silent_devices = classify_devices(stats, now, threshold_minutes=60)
    assert [d["devid"] for d in logging_devices] == ["A"]
    assert silent_devices == []


def test_classify_devices_none_timestamp_is_silent_no_grace_period():
    from app.log_stats_cache import classify_devices

    now = 10_000.0
    stats = [{"devid": "A", "devname": "a", "last_log_timestamp": None, "lograte": 0.0}]
    logging_devices, silent_devices = classify_devices(stats, now, threshold_minutes=60)
    assert logging_devices == []
    assert [d["devid"] for d in silent_devices] == ["A"]
