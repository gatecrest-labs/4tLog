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
