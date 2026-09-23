import pytest


@pytest.fixture
def store_db(tmp_path, monkeypatch):
    path = tmp_path / "collector_state.db"
    import app.collector_store as store_mod

    monkeypatch.setattr(store_mod, "DB_PATH", path)
    store_mod.init_db()
    yield path


def test_read_cache_returns_none_for_missing_key(store_db):
    from app.collector_store import read_cache

    assert read_cache("nope") is None


def test_write_then_read_round_trips(store_db):
    from app.collector_store import read_cache, write_cache

    data = {"foo": "bar", "count": 3, "collected_at": "2026-09-12T00:00:00+00:00"}
    write_cache("log_stats", data)

    assert read_cache("log_stats") == data


def test_write_upserts_existing_key(store_db):
    from app.collector_store import read_cache, write_cache

    write_cache("log_stats", {"count": 1, "collected_at": "t1"})
    write_cache("log_stats", {"count": 2, "collected_at": "t2"})

    assert read_cache("log_stats") == {"count": 2, "collected_at": "t2"}


def test_different_keys_are_independent(store_db):
    from app.collector_store import read_cache, write_cache

    write_cache("log_stats", {"count": 1})
    write_cache("threat_stats", {"count": 99})

    assert read_cache("log_stats") == {"count": 1}
    assert read_cache("threat_stats") == {"count": 99}


def test_wal_mode_is_active(store_db):
    import sqlite3

    from app.collector_store import write_cache

    write_cache("log_stats", {"count": 1})
    conn = sqlite3.connect(store_db)
    mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    conn.close()
    assert mode.lower() == "wal"


def test_write_cache_creates_table_if_missing(tmp_path, monkeypatch):
    # No init_db() call — write_cache must be safe to call on a brand-new
    # (or never-initialized) DB file, since a web worker might call
    # read_cache() before any collector process has ever run.
    path = tmp_path / "fresh.db"
    import app.collector_store as store_mod

    monkeypatch.setattr(store_mod, "DB_PATH", path)

    from app.collector_store import read_cache, write_cache

    assert read_cache("log_stats") is None
    write_cache("log_stats", {"count": 5})
    assert read_cache("log_stats") == {"count": 5}
