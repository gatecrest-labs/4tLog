"""Tests for app.sdwan_cache.

Rows returned by the faked FortiView runs are SYNTHETIC (built from the 7.6.7
spec's field names); real SD-WAN row shapes are unconfirmed.
"""

import pytest
import requests

PERF = "sdwan-perf-stats-line"
SLA = "sdwan-intf-sla-status-line"
BW = "sdwan-intf-bandwidth-line"
DEV = "sdwan-dev-stats"

SENTINEL_RANGE = ("2026-11-12T03:00:00", "2026-11-13T03:00:00")


@pytest.fixture
def targets_file(tmp_path, monkeypatch):
    path = tmp_path / "faz_targets.json"
    import app.faz_targets as faz_targets_mod

    monkeypatch.setattr(faz_targets_mod, "FAZ_TARGETS_FILE", path)
    from app.faz_targets import create_target

    create_target("Primary", host="192.168.64.4", adom="root", token="tok")
    yield path


@pytest.fixture(autouse=True)
def clear_sdwan_cache():
    import app.sdwan_cache as cache_mod

    cache_mod._cache = dict(cache_mod._EMPTY_CACHE)
    yield
    cache_mod._cache = dict(cache_mod._EMPTY_CACHE)


def _perf_rows():
    return [
        {"dvid": "FGT-A", "interface": "wan1", "time": "t1", "latency": 20, "packetloss": 0},
        {"dvid": "FGT-A", "interface": "wan1", "time": "t2", "latency": 40, "packetloss": 1},
    ]


def _stub(monkeypatch, run_fortiview):
    monkeypatch.setattr("app.faz_client.FAZClient.run_fortiview", run_fortiview)
    monkeypatch.setattr("app.faz_client.FAZClient.logout", lambda self: None)
    monkeypatch.setattr(
        "app.faz_client.FAZClient.local_time_range",
        lambda self, start_iso, end_iso: SENTINEL_RANGE,
    )


def test_views_are_the_four_supported_ones():
    import app.sdwan_cache as cache_mod

    assert cache_mod.VIEWS == (DEV, SLA, PERF, BW)


def test_poll_populates_snapshot_and_writes_collector_store(targets_file, monkeypatch):
    import app.sdwan_cache as cache_mod
    from app import collector_store

    def fake(self, adom, view, time_range, limit=1000, **_kw):
        return _perf_rows() if view == PERF else []

    _stub(monkeypatch, fake)

    cache_mod.poll_all_targets()

    snap = cache_mod.get_cached()
    assert snap["collected_at"] is not None
    (target,) = snap["targets"]
    assert target["label"] == "Primary"
    assert target["state"] == "ok"
    assert target["views"][PERF] == {"status": "ok", "rows": 2, "error": None}
    assert target["views"][SLA]["status"] == "empty"
    assert target["interfaces"][0]["interface"] == "wan1"
    assert collector_store.read_cache(cache_mod.CACHE_KEY) == snap


def test_all_views_empty_is_no_data_state(targets_file, monkeypatch):
    import app.sdwan_cache as cache_mod

    _stub(monkeypatch, lambda self, adom, view, time_range, limit=1000, **_kw: [])

    cache_mod.poll_all_targets()

    (target,) = cache_mod.get_cached()["targets"]
    assert target["state"] == "no_data"
    assert target["interfaces"] == []


def test_unsupported_view_does_not_abort_the_others(targets_file, monkeypatch):
    import app.sdwan_cache as cache_mod
    from app.faz_client import FAZError

    called = []

    def fake(self, adom, view, time_range, limit=1000, **_kw):
        called.append(view)
        if view == SLA:
            raise FAZError("Cannot find FortiView 'x'", code=-32005)
        return _perf_rows() if view == PERF else []

    _stub(monkeypatch, fake)

    cache_mod.poll_all_targets()

    assert sorted(called) == sorted(cache_mod.VIEWS)
    (target,) = cache_mod.get_cached()["targets"]
    assert target["views"][SLA]["status"] == "unsupported"
    assert target["views"][PERF]["status"] == "ok"
    assert target["state"] == "ok"
    assert target["interfaces"]


def test_other_fazerror_marks_only_that_view_error(targets_file, monkeypatch):
    import app.sdwan_cache as cache_mod
    from app.faz_client import FAZError

    def fake(self, adom, view, time_range, limit=1000, **_kw):
        if view == BW:
            raise FAZError("boom", code=-32603)
        return _perf_rows() if view == PERF else []

    _stub(monkeypatch, fake)

    cache_mod.poll_all_targets()

    (target,) = cache_mod.get_cached()["targets"]
    assert target["views"][BW]["status"] == "error"
    assert "boom" in target["views"][BW]["error"]
    assert target["views"][PERF]["status"] == "ok"
    assert target["state"] == "ok"


def test_unreachable_target_is_error_state_and_others_still_polled(targets_file, monkeypatch):
    import app.sdwan_cache as cache_mod
    from app.faz_targets import create_target

    create_target("Second", host="192.168.64.5", adom="root", token="tok2")

    def fake(self, adom, view, time_range, limit=1000, **_kw):
        if self.host == "192.168.64.4":
            raise requests.exceptions.ConnectionError("no route")
        return _perf_rows() if view == PERF else []

    _stub(monkeypatch, fake)

    cache_mod.poll_all_targets()

    by_label = {t["label"]: t for t in cache_mod.get_cached()["targets"]}
    assert by_label["Primary"]["state"] == "error"
    assert by_label["Primary"]["error"]
    assert by_label["Primary"]["interfaces"] == []
    assert by_label["Second"]["state"] == "ok"


def test_uses_local_time_range_for_every_view(targets_file, monkeypatch):
    import app.sdwan_cache as cache_mod

    ranges = []

    def fake(self, adom, view, time_range, limit=1000, **_kw):
        ranges.append(time_range)
        return []

    _stub(monkeypatch, fake)

    cache_mod.poll_all_targets()

    assert ranges == [SENTINEL_RANGE] * len(cache_mod.VIEWS)


def test_get_cached_picks_up_newer_collector_snapshot_after_first_read():
    import app.sdwan_cache as cache_mod
    from app import collector_store

    collector_store.write_cache(
        cache_mod.CACHE_KEY, {"targets": [], "collected_at": "2026-11-13T17:00:00+00:00"}
    )
    assert cache_mod.get_cached()["collected_at"] == "2026-11-13T17:00:00+00:00"

    collector_store.write_cache(
        cache_mod.CACHE_KEY, {"targets": [], "collected_at": "2026-11-13T17:05:00+00:00"}
    )

    assert cache_mod.get_cached()["collected_at"] == "2026-11-13T17:05:00+00:00"


def test_get_cached_keeps_in_memory_snapshot_newer_than_stored():
    import app.sdwan_cache as cache_mod
    from app import collector_store

    cache_mod._cache.update({"targets": [], "collected_at": "2026-11-13T18:00:00+00:00"})
    collector_store.write_cache(
        cache_mod.CACHE_KEY, {"targets": [], "collected_at": "2026-11-13T17:00:00+00:00"}
    )

    assert cache_mod.get_cached()["collected_at"] == "2026-11-13T18:00:00+00:00"
