def test_start_all_schedulers_calls_every_init_scheduler_once(monkeypatch):
    """All four *_POLL_DISABLED flags are set true by tests/conftest.py, so
    each real init_scheduler() is already a no-op — but start_all_schedulers()
    must still call every one of them (each module's own DISABLED guard is
    what keeps the test suite safe, not app.collector skipping any of them)."""
    import app.collector as collector_mod

    calls = []

    def make_recorder(name):
        def _recorder(app):
            calls.append(name)

        return _recorder

    monkeypatch.setattr(
        "app.faz_health_cache.init_scheduler", make_recorder("faz_health")
    )
    monkeypatch.setattr(
        "app.log_stats_cache.init_scheduler", make_recorder("log_stats")
    )
    monkeypatch.setattr(
        "app.threat_stats_cache.init_scheduler", make_recorder("threat_stats")
    )
    monkeypatch.setattr(
        "app.host_metrics_cache.init_scheduler", make_recorder("host_metrics")
    )

    collector_mod.start_all_schedulers()

    assert sorted(calls) == ["faz_health", "host_metrics", "log_stats", "threat_stats"]


def test_start_all_schedulers_is_safe_with_every_poller_disabled(monkeypatch):
    """With every *_POLL_DISABLED flag set (as tests/conftest.py does),
    start_all_schedulers() must not raise and must not start any real
    scheduler or background thread."""
    import app.collector as collector_mod

    collector_mod.start_all_schedulers()  # must not raise
