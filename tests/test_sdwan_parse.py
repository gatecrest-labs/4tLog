"""Tests for app.sdwan_parse.

Every row below is SYNTHETIC: built from the field names in the vendored 7.6.7
FortiView spec (api-info/), not from a real capture. The lab FortiAnalyzer has no
SD-WAN data, so real row keys and units are unconfirmed; revisit these tests when a
real capture exists.
"""

from app.sdwan_parse import MAX_SERIES_POINTS, parse_interfaces

PERF = "sdwan-perf-stats-line"
SLA = "sdwan-intf-sla-status-line"
BW = "sdwan-intf-bandwidth-line"


def _perf(t, latency=None, jitter=None, loss=None, dvid="FGT-A", intf="wan1"):
    row = {"dvid": dvid, "interface": intf, "time": t}
    if latency is not None:
        row["latency"] = latency
    if jitter is not None:
        row["jitter"] = jitter
    if loss is not None:
        row["packetloss"] = loss
    return row


def test_perf_rows_become_stats_per_device_interface():
    rows = [
        _perf("2026-11-13 10:00", latency=20, jitter=2, loss=0),
        _perf("2026-11-13 11:00", latency=40, jitter=4, loss=1),
    ]

    result = parse_interfaces({PERF: rows})

    assert len(result) == 1
    entry = result[0]
    assert (entry["device"], entry["interface"]) == ("FGT-A", "wan1")
    assert entry["latency"] == {"latest": 40.0, "min": 20.0, "avg": 30.0, "max": 40.0}
    assert entry["series"]["latency"] == [["2026-11-13 10:00", 20.0], ["2026-11-13 11:00", 40.0]]


def test_rows_missing_interface_or_time_are_dropped():
    rows = [
        {"dvid": "FGT-A", "time": "2026-11-13 10:00", "latency": 20},  # no interface
        {"dvid": "FGT-A", "interface": "wan1", "latency": 20},  # no time
        _perf("2026-11-13 10:00", latency=30),
    ]

    result = parse_interfaces({PERF: rows})

    assert len(result) == 1
    assert result[0]["latency"]["latest"] == 30.0


def test_non_numeric_values_are_ignored_not_zeroed():
    rows = [_perf("2026-11-13 10:00", latency="n/a", jitter=3)]

    entry = parse_interfaces({PERF: rows})[0]

    assert entry["latency"] is None
    assert entry["series"]["latency"] == []
    assert entry["jitter"]["latest"] == 3.0


def test_unknown_keys_only_returns_empty_list():
    assert parse_interfaces({PERF: [{"foo": 1, "bar": "x"}]}) == []
    assert parse_interfaces({}) == []


def test_key_lookup_is_case_insensitive_and_accepts_aliases():
    rows = [{"devid": "FGT-B", "Interface": "wan2", "Time": "t1", "Latency": 7}]

    entry = parse_interfaces({PERF: rows})[0]

    assert (entry["device"], entry["interface"]) == ("FGT-B", "wan2")
    assert entry["latency"]["latest"] == 7.0


def test_sla_status_from_latest_sla_available():
    sla_rows = [
        {"dvid": "FGT-A", "interface": "wan1", "time": "t1", "sla_available": 1},
        {"dvid": "FGT-A", "interface": "wan1", "time": "t2", "sla_available": 0},
    ]

    entry = parse_interfaces({SLA: sla_rows})[0]

    assert entry["sla_status"] == "fail"
    assert entry["sla_met_pct"] == 50.0


def test_sla_status_is_none_without_sla_rows():
    entry = parse_interfaces({PERF: [_perf("t1", latency=5)]})[0]

    assert entry["sla_status"] is None
    assert entry["sla_met_pct"] is None


def test_sla_values_already_percent_are_not_rescaled():
    sla_rows = [
        {"dvid": "FGT-A", "interface": "wan1", "time": "t1", "sla_available": 100},
        {"dvid": "FGT-A", "interface": "wan1", "time": "t2", "sla_available": 90},
    ]

    entry = parse_interfaces({SLA: sla_rows})[0]

    assert entry["sla_met_pct"] == 95.0


def test_bandwidth_rows_fill_in_out_stats():
    rows = [
        {"dvid": "FGT-A", "interface": "wan1", "time": "t1", "inbandwidth": 10, "outbandwidth": 4},
    ]

    entry = parse_interfaces({BW: rows})[0]

    assert entry["in_bw"]["latest"] == 10.0
    assert entry["out_bw"]["latest"] == 4.0


def test_series_is_downsampled_to_max_points_and_stays_ordered():
    rows = [_perf(f"2026-11-13 {i // 60:02d}:{i % 60:02d}", latency=i) for i in range(200)]

    entry = parse_interfaces({PERF: rows})[0]

    series = entry["series"]["latency"]
    assert len(series) == MAX_SERIES_POINTS
    times = [t for t, _ in series]
    assert times == sorted(times)


def test_entries_sorted_worst_first():
    sla = [
        {"dvid": "A", "interface": "good", "time": "t1", "sla_available": 1},
        {"dvid": "A", "interface": "bad", "time": "t1", "sla_available": 0},
    ]
    perf = [
        _perf("t1", latency=10, loss=0, dvid="A", intf="good"),
        _perf("t1", latency=5, loss=0, dvid="A", intf="bad"),
        _perf("t1", latency=50, loss=2, dvid="A", intf="lossy"),
        _perf("t1", latency=90, loss=0, dvid="A", intf="slow"),
    ]
    bare = {"dvid": "A", "interface": "nostats", "time": "t1"}

    result = parse_interfaces({SLA: sla, PERF: perf + [bare]})

    order = [e["interface"] for e in result]
    assert order[0] == "bad"  # SLA fail first
    assert order.index("lossy") < order.index("slow") < order.index("good")
    assert order[-1] == "nostats"  # no stats last
