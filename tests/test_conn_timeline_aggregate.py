"""Connection Timeline: input rules and the roll-up of raw rows into flows."""

import datetime

import pytest

from app.conn_timeline import (
    ALLOWED,
    DENIED,
    OTHER,
    Timeline,
    TimelineInputError,
    bucket_seconds,
    build_filter,
    parse_device,
    parse_host,
    parse_window,
    policy_label,
    port_label,
    row_key,
    row_timestamp,
    verdict,
)

UTC = datetime.timezone.utc
NOW = datetime.datetime(2026, 11, 22, 12, 0, tzinfo=UTC)
START = NOW - datetime.timedelta(hours=1)


def _row(ts_offset, **fields):
    row = {
        "itime_t": str(int(START.timestamp()) + ts_offset),
        "devname": "GC-HQ-CORE",
        "devid": "FGVM01",
        "vd": "root",
        "srcip": "10.10.20.50",
        "dstip": "10.10.30.10",
        "dstport": "22",
        "proto": "6",
        "service": "SSH",
        "action": "accept",
        "policyid": "30",
        "policyname": "Jump-to-Servers",
    }
    row.update(fields)
    return row


# ── Inputs ───────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("raw", ["10.1.1.5", " 2001:db8::5 "])
def test_parse_host_takes_one_address(raw):
    assert str(parse_host(raw)) == raw.strip()


@pytest.mark.parametrize("raw", ["", None, "web01.example.com", "10.1.1.0/24", "10.1.1.1-10.1.1.9"])
def test_parse_host_refuses_names_and_ranges(raw):
    with pytest.raises(TimelineInputError, match="Enter an IP address"):
        parse_host(raw)


def test_parse_device_defaults_and_refuses_junk():
    assert parse_device(None) == "All_FortiGate"
    assert parse_device("FGVM01") == "FGVM01"
    with pytest.raises(TimelineInputError):
        parse_device('x" or 1==1')


def test_window_defaults_to_one_hour():
    start, end, preset = parse_window({}, 168, "1h", now=NOW)
    assert preset == "1h"
    assert end == NOW and end - start == datetime.timedelta(hours=1)


def test_window_allows_seven_days_and_no_more():
    start, end, preset = parse_window({"preset": "7d"}, 168, "1h", now=NOW)
    assert end - start == datetime.timedelta(days=7)
    custom = {"start_time": "2026-11-10T00:00:00Z", "end_time": "2026-11-17T00:00:00Z"}
    start, end, preset = parse_window(custom, 168, "1h", now=NOW)
    assert preset is None and end - start == datetime.timedelta(days=7)
    too_long = {"start_time": "2026-11-10T00:00:00Z", "end_time": "2026-11-17T00:00:02Z"}
    with pytest.raises(TimelineInputError, match="at most 7 days"):
        parse_window(too_long, 168, "1h", now=NOW)


@pytest.mark.parametrize(
    "data,message",
    [
        ({"preset": "30d"}, "Unknown time preset"),
        ({"start_time": "2026-11-10T00:00:00Z"}, "both a start and an end"),
        ({"start_time": "2026-11-10T01:00:00Z", "end_time": "2026-11-10T00:00:00Z"}, "after"),
        ({"start_time": "yesterday", "end_time": "today"}, "Invalid time"),
    ],
)
def test_window_errors(data, message):
    with pytest.raises(TimelineInputError, match=message):
        parse_window(data, 168, "1h", now=NOW)


def test_build_filter_by_direction_and_verdict():
    assert build_filter("10.1.1.5", "src") == "(srcip==10.1.1.5)"
    assert build_filter("10.1.1.5", "dst") == "(dstip==10.1.1.5)"
    assert build_filter("10.1.1.5", "either") == "(srcip==10.1.1.5 or dstip==10.1.1.5)"
    denied = build_filter("10.1.1.5", "src", "denied")
    assert denied == "(srcip==10.1.1.5) and (action==block or action==deny or action==dropped)"
    assert "action==accept" in build_filter("10.1.1.5", "src", "allowed")
    with pytest.raises(TimelineInputError):
        build_filter("10.1.1.5", "sideways")
    with pytest.raises(TimelineInputError):
        build_filter("10.1.1.5", "src", "maybe")


# ── Buckets, verdicts, labels ────────────────────────────────────────────────


@pytest.mark.parametrize(
    "window,step",
    [(15 * 60, 15), (3600, 60), (4 * 3600, 300), (24 * 3600, 1800), (7 * 86400, 10800)],
)
def test_bucket_sizes_keep_about_sixty_columns(window, step):
    assert bucket_seconds(window) == step
    assert window / step <= 60


@pytest.mark.parametrize(
    "action,expected",
    [
        ("accept", ALLOWED),
        ("close", ALLOWED),
        ("server-rst", ALLOWED),
        ("DENY", DENIED),
        ("ip-conn", OTHER),  # "Connection Failed": allowed by policy, never established
        ("dropped", DENIED),
        ("something-new", OTHER),
        (None, OTHER),
    ],
)
def test_verdicts(action, expected):
    assert verdict(action) == expected


def test_labels():
    assert port_label("443", "6", "HTTPS") == "443/tcp"
    assert port_label("0", "1", "PING") == "icmp"
    assert port_label("", "", "GRE") == "GRE"
    assert policy_label("0", "") == "Implicit deny"
    assert policy_label("12", "Cameras-to-NVR") == "12 · Cameras-to-NVR"
    assert policy_label("12", "") == "Policy 12"


def test_row_time_and_identity():
    assert row_timestamp({"itime_t": "1795351441"}) == 1795351441
    assert row_timestamp({"itime": "1795351441"}) == 1795351441
    assert row_timestamp({"eventtime": "1795351441123456789"}) == 1795351441
    assert row_timestamp({"itime": "2026-11-22 12:00:00"}) is None
    assert row_key({"id": "7"}) == ("id", "7")
    assert row_key({"eventtime": "1", "devid": "A"}) != row_key({"eventtime": "1", "devid": "B"})


# ── Roll-up ──────────────────────────────────────────────────────────────────


def test_flows_count_by_lane_bucket_verdict_peer_port_policy():
    t = Timeline("10.10.20.50", "either", START, NOW)
    t.add(_row(5))
    t.add(_row(30))  # same minute, same everything: one flow, count 2
    t.add(_row(70, action="deny", policyid="0", policyname=""))
    out = t.to_dict()
    assert out["bucket_seconds"] == 60 and out["buckets"] == 60
    assert out["rows"] == 3
    assert out["peers"] == ["10.10.30.10"]
    assert out["ports"][0]["label"] == "22/tcp" and out["ports"][0]["proto"] == "tcp"
    assert [p["label"] for p in out["policies"]] == ["30 · Jump-to-Servers", "Implicit deny"]
    assert out["flows"] == [[0, 0, ALLOWED, 0, 0, 0, 2], [0, 1, DENIED, 0, 0, 1, 1]]


def test_peer_is_the_other_side_in_either_direction():
    t = Timeline("10.10.20.50", "either", START, NOW)
    t.add(_row(1))  # host is source
    t.add(_row(2, srcip="10.10.30.11", dstip="10.10.20.50"))  # host is destination
    t.add(_row(3, srcip="10.9.9.9", dstip="10.8.8.8"))  # neither side: counted apart
    out = t.to_dict()
    assert out["peers"] == ["10.10.30.10", "10.10.30.11"]
    assert out["unmatched_rows"] == 1


def test_fixed_direction_peer_and_untimed_rows():
    t = Timeline("10.10.20.50", "dst", START, NOW)
    t.add(_row(1, srcip="203.0.113.9", dstip="10.10.20.50"))
    t.add({"srcip": "203.0.113.9", "dstip": "10.10.20.50"})  # no timestamp
    out = t.to_dict()
    assert out["peers"] == ["203.0.113.9"]
    assert out["untimed_rows"] == 1 and out["rows"] == 2


def test_rows_outside_the_window_land_in_the_edge_buckets():
    t = Timeline("10.10.20.50", "src", START, NOW)
    t.add(_row(-500))
    t.add(_row(10_000))
    buckets = {f[1] for f in t.to_dict()["flows"]}
    assert buckets == {0, 59}


def test_lanes_split_by_vdom_and_sort_by_first_seen():
    t = Timeline("10.10.20.50", "src", START, NOW)
    t.add(_row(300, devname="GC-HQ-EDGE", devid="FGVM02", vd="root"))
    t.add(_row(100, vd="root"))
    t.add(_row(200, vd="dmz"))
    lanes = t.to_dict()["lanes"]
    assert [lane["label"] for lane in lanes] == [
        "GC-HQ-CORE [root]",
        "GC-HQ-CORE [dmz]",
        "GC-HQ-EDGE",
    ]
    assert lanes[2]["devid"] == "FGVM02"


def test_policy_lane_index_follows_the_sorted_lanes():
    t = Timeline("10.10.20.50", "src", START, NOW)
    t.add(_row(300, devname="LATE", policyid="5", policyname="Late-Policy"))
    t.add(_row(100, devname="EARLY", policyid="6", policyname="Early-Policy"))
    out = t.to_dict()
    by_name = {p["policyname"]: p["lane"] for p in out["policies"]}
    assert out["lanes"][by_name["Early-Policy"]]["devname"] == "EARLY"
    assert out["lanes"][by_name["Late-Policy"]]["devname"] == "LATE"
    for flow in out["flows"]:
        assert out["policies"][flow[5]]["lane"] == flow[0]


def test_paths_record_role_firewall_port_and_exact_first_and_last_seen():
    host = "10.10.20.50"
    t = Timeline(host, "either", START, NOW)
    t.add(_row(10))
    t.add(_row(40))
    t.add(_row(30, srcip="10.10.1.9", dstip=host, dstport="3389", service="RDP"))
    out = t.to_dict()
    assert out["path_fields"] == [
        "peer", "role", "lane", "port", "bucket", "count", "first_ts", "last_ts",
        "allowed", "denied", "other",
    ]  # fmt: skip
    base = int(START.timestamp())
    peers = out["peers"]
    ssh = [p for p in out["paths"] if p[0] == peers.index("10.10.30.10")]
    rdp = [p for p in out["paths"] if p[0] == peers.index("10.10.1.9")]
    assert ssh == [[peers.index("10.10.30.10"), 0, 0, 0, 0, 2, base + 10, base + 40, 2, 0, 0]]
    assert [p[1] for p in rdp] == [1]  # host was the destination


def test_a_failed_connection_is_neither_allowed_nor_denied():
    """FortiGate logs ``action=ip-conn`` with ``msg=Connection Failed`` and zero bytes for a
    connection a policy allowed that never completed: counted as other, not as a deny."""
    t = Timeline("10.10.20.50", "src", START, NOW)
    t.add(_row(5))
    t.add(_row(6, action="ip-conn"))
    t.add(_row(7, action="deny"))
    counts = {"allowed": 0, "denied": 0, "other": 0}
    for flow in t.to_dict()["flows"]:
        counts[("allowed", "denied", "other")[flow[2]]] += flow[-1]
    assert counts == {"allowed": 1, "denied": 1, "other": 1}


def test_paths_split_each_firewall_and_interval_by_verdict():
    t = Timeline("10.10.20.50", "src", START, NOW)
    for offset, action in ((10, "accept"), (11, "accept"), (12, "deny"), (13, "ip-conn")):
        t.add(_row(offset, action=action))
    (path,) = t.to_dict()["paths"]
    assert path[5:] == [4, path[6], path[7], 2, 1, 1]  # count, first, last, allowed, denied, other
    assert path[5] == path[8] + path[9] + path[10]
