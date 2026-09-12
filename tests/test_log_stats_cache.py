import time

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


def _empty_cache():
    return {
        "logging_devices": [],
        "silent_devices": [],
        "silent_details": [],
        "collected_at": None,
    }


@pytest.fixture(autouse=True)
def clear_log_stats_cache():
    import app.log_stats_cache as cache_mod

    cache_mod._cache = _empty_cache()
    yield
    cache_mod._cache = _empty_cache()


def test_poll_all_targets_populates_cache_and_writes_rollup(targets_file, history_db, monkeypatch):
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
    assert [d["devid"] for d in cached["silent_details"]] == ["B"]
    assert cached["silent_details"][0]["devname"] == "b"
    assert cached["silent_details"][0]["last_log_at"] is not None
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


def test_poll_all_targets_leaves_cache_unchanged_when_every_target_unreachable(
    targets_file, history_db, monkeypatch
):
    import app.log_stats_cache as cache_mod
    from app.faz_client import FAZError

    seeded = {
        "logging_devices": [{"devid": "X", "devname": "x", "lograte": 2.0}],
        "silent_devices": [{"devid": "Y", "devname": "y", "lograte": 0.0}],
        "silent_details": [{"devid": "Y", "devname": "y", "last_log_at": None}],
        "collected_at": "2026-08-29T12:00:00+00:00",
    }
    cache_mod._cache = dict(seeded)

    def fake_get_log_stats(self, adom=None):
        raise FAZError("boom")

    monkeypatch.setattr("app.faz_client.FAZClient.get_log_stats", fake_get_log_stats)
    monkeypatch.setattr("app.faz_client.FAZClient.logout", lambda self: None)

    cache_mod.poll_all_targets()  # must not raise

    assert cache_mod.get_cached() == seeded


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


def test_poll_all_targets_writes_snapshot_to_collector_store(
    targets_file, history_db, monkeypatch
):
    import app.log_stats_cache as cache_mod
    from app import collector_store

    def fake_get_log_stats(self, adom=None):
        return [
            {
                "devid": "A",
                "devname": "a",
                "last_log_timestamp": int(time.time()),
                "lograte": 4.0,
            }
        ]

    monkeypatch.setattr("app.faz_client.FAZClient.get_log_stats", fake_get_log_stats)
    monkeypatch.setattr("app.faz_client.FAZClient.logout", lambda self: None)

    cache_mod.poll_all_targets()

    stored = collector_store.read_cache(cache_mod.CACHE_KEY)
    assert stored is not None
    assert [d["devid"] for d in stored["logging_devices"]] == ["A"]
    assert stored["collected_at"] == cache_mod.get_cached()["collected_at"]


def test_get_cached_reads_through_to_collector_store_when_in_memory_empty():
    """Simulates a web worker (empty in-memory cache) reading data a
    separate collector process already wrote to SQLite."""
    import app.log_stats_cache as cache_mod
    from app import collector_store

    persisted = {
        "logging_devices": [{"devid": "A", "devname": "a", "lograte": 1.0}],
        "silent_devices": [],
        "silent_details": [],
        "collected_at": "2026-09-12T00:00:00+00:00",
    }
    collector_store.write_cache(cache_mod.CACHE_KEY, persisted)
    assert cache_mod._cache["collected_at"] is None  # this "process" has never polled

    cached = cache_mod.get_cached()

    assert cached == persisted
    # Read-through also repopulates the in-memory dict.
    assert cache_mod._cache["collected_at"] == "2026-09-12T00:00:00+00:00"


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


def test_build_silent_details_orders_most_stale_first():
    from app.log_stats_cache import build_silent_details

    silent_devices = [
        {"devid": "A", "devname": "a", "last_log_timestamp": 5_000},
        {"devid": "B", "devname": "b", "last_log_timestamp": 1_000},
        {"devid": "C", "devname": "c", "last_log_timestamp": 3_000},
    ]
    details = build_silent_details(silent_devices)
    assert [d["devid"] for d in details] == ["B", "C", "A"]


def test_build_silent_details_never_logged_sorts_before_any_timestamp():
    from app.log_stats_cache import build_silent_details

    silent_devices = [
        {"devid": "A", "devname": "a", "last_log_timestamp": 1},
        {"devid": "B", "devname": "b", "last_log_timestamp": None},
        {"devid": "C", "devname": "c", "last_log_timestamp": 0},
    ]
    details = build_silent_details(silent_devices)
    # Never-logged (None/0) devices are most severe: they sort first,
    # order between themselves is stable (input order preserved).
    assert [d["devid"] for d in details] == ["B", "C", "A"]


def test_build_silent_details_last_log_at_is_iso8601_or_null():
    from app.log_stats_cache import build_silent_details

    silent_devices = [
        {"devid": "A", "devname": "a", "last_log_timestamp": 1_700_000_000},
        {"devid": "B", "devname": "b", "last_log_timestamp": None},
    ]
    details = build_silent_details(silent_devices)
    by_id = {d["devid"]: d for d in details}
    assert by_id["A"]["last_log_at"] == "2023-11-14T22:13:20+00:00"
    assert by_id["B"]["last_log_at"] is None
    assert set(by_id["A"].keys()) == {"devid", "devname", "last_log_at"}


def test_build_silent_details_caps_at_50():
    from app.log_stats_cache import build_silent_details

    silent_devices = [
        {"devid": str(i), "devname": f"dev{i}", "last_log_timestamp": i}
        for i in range(75)
    ]
    details = build_silent_details(silent_devices)
    assert len(details) == 50
    # Most-stale-first: lowest timestamps (0..49) survive the cap.
    assert [d["devid"] for d in details] == [str(i) for i in range(50)]
