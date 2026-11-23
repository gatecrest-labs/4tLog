"""Connection Timeline quick summary: FortiView rows for one IP, merged into sections."""

import pytest

import app.conn_timeline_summary as summary
from app.conn_timeline_summary import SECTIONS, role_filter, roles, summarize
from app.faz_client import FAZError

HOST = "10.1.1.2"
TR = ("2026-11-23T10:00:00", "2026-11-23T11:00:00")
SRC, DST = f"srcip=={HOST}", f"dstip=={HOST}"


class FakeClient:
    """FortiView as measured: string values, ``limit``/``offset`` paging, a total."""

    adom = "root"

    def __init__(self, data=None, totals=None, errors=None):
        self.data = data or {}  # (view, filter) -> full list of rows
        self.totals = totals or {}  # (view, filter) -> reported total-count-all
        self.errors = errors or {}  # view -> exception to raise
        self.calls = []

    def run_fortiview_page(self, adom, view, time_range, *, filter=None, devices=None, **kw):
        limit, offset = kw.get("limit", 1000), kw.get("offset", 0)
        self.calls.append(
            {"view": view, "filter": filter, "offset": offset, "limit": limit, "devices": devices}
        )
        if view in self.errors:
            raise self.errors[view]
        rows = self.data.get((view, filter), [])
        total = self.totals.get((view, filter), len(rows))
        return rows[offset : offset + limit], total


def _dest(ip, ok, blocked=0):
    return {
        "dstip": ip,
        "session_pass": str(ok),
        "session_block": str(blocked),
        "sessions": str(ok + blocked),
    }


def _src(ip, ok, blocked=0):
    return {
        "srcip": ip,
        "session_pass": str(ok),
        "session_block": str(blocked),
        "sessions": str(ok + blocked),
    }


def test_roles_and_filters():
    assert (
        roles("either") == ("src", "dst") and roles("src") == ("src",) and roles("dst") == ("dst",)
    )
    assert role_filter(HOST, "src") == SRC and role_filter(HOST, "dst") == DST
    assert role_filter("2001:db8::1", "dst") == "dstip==2001:db8::1"


def test_either_direction_merges_a_peer_seen_in_both_roles():
    client = FakeClient(
        {
            ("top-destinations", SRC): [_dest("192.0.2.1", 10, 2), _dest("192.0.2.9", 1)],
            ("top-sources", DST): [_src("192.0.2.1", 5)],
        }
    )
    out = summarize(client, "peers", HOST, "either", TR, None)
    top = out["rows"][0]
    assert top == {
        "peer": "192.0.2.1",
        "allowed": 15,
        "denied": 2,
        "sessions": 17,
        "roles": ["src", "dst"],
    }
    assert [r["peer"] for r in out["rows"]] == ["192.0.2.1", "192.0.2.9"]
    assert out["total"] == 2 and out["truncated"] is False


def test_direction_src_runs_only_the_destination_report():
    client = FakeClient({("top-destinations", SRC): [_dest("192.0.2.1", 3)]})
    summarize(client, "peers", HOST, "src", TR, None)
    assert [(c["view"], c["filter"]) for c in client.calls] == [("top-destinations", SRC)]


def test_peers_are_paged_with_offset_until_the_total(monkeypatch):
    monkeypatch.setattr(summary, "PEER_CAP", 5000)
    rows = [_dest(f"198.51.100.{i % 250}.{i // 250}", 1) for i in range(1057)]
    client = FakeClient({("top-destinations", SRC): rows})
    out = summarize(client, "peers", HOST, "src", TR, None)
    assert [c["offset"] for c in client.calls] == [0, 1000]
    assert (
        out["total"] == 1057 and out["truncated"] is False and len(out["rows"]) == summary.PEER_ROWS
    )


def test_more_peers_than_the_cap_are_flagged_truncated(monkeypatch):
    monkeypatch.setattr(summary, "PEER_CAP", 3)
    rows = [_dest(f"192.0.2.{i}", 10 - i) for i in range(10)]
    client = FakeClient({("top-destinations", SRC): rows}, totals={("top-destinations", SRC): 10})
    out = summarize(client, "peers", HOST, "src", TR, None)
    assert out["truncated"] is True and out["total"] == 3  # peers read
    assert out["reported_total"] == 10  # what FortiAnalyzer says there are
    assert client.calls[0]["limit"] == 3  # never asks for more than the cap


def test_reaching_the_cap_without_a_reported_total_is_still_truncated(monkeypatch):
    monkeypatch.setattr(summary, "PEER_CAP", 3)
    rows = [_dest(f"192.0.2.{i}", 10 - i) for i in range(10)]
    client = FakeClient({("top-destinations", SRC): rows}, totals={("top-destinations", SRC): None})
    out = summarize(client, "peers", HOST, "src", TR, None)
    assert out["truncated"] is True and out["reported_total"] == 3


def test_reported_total_is_the_larger_role_total_and_never_below_the_peers_read():
    rows = [_dest("192.0.2.1", 1)]
    client = FakeClient(
        {("top-destinations", SRC): rows, ("top-sources", DST): [_src("192.0.2.2", 1)]},
        totals={("top-destinations", SRC): 1, ("top-sources", DST): 1},
    )
    out = summarize(client, "peers", HOST, "either", TR, None)
    assert out["total"] == 2 and out["reported_total"] == 2 and out["truncated"] is False


def test_a_host_with_no_sessions_gives_empty_sections():
    client = FakeClient()
    for section in SECTIONS:
        out = summarize(client, section, HOST, "either", TR, None)
        assert out["rows"] == [] and "unavailable" not in out, section
    out = summarize(client, "policies", HOST, "either", TR, None)
    assert out["totals"] == {"allowed": 0, "denied": 0} and out["firewalls"] == []


def test_policies_give_totals_and_per_firewall_totals():
    pol = lambda fw, pid, name, ok, bl: {  # noqa: E731
        "fortigate": fw,
        "agg_policyid": pid,
        "policy": name,
        "counts": str(ok + bl),
        "count_pass": str(ok),
        "count_block": str(bl),
    }
    client = FakeClient(
        {
            ("policy-hits", SRC): [
                pol("FW-A", "2", "Wifi", 100, 1),
                pol("FW-B", "2", "Wifi", 20, 0),
            ],
            ("policy-hits", DST): [pol("FW-A", "2", "Wifi", 4, 0), pol("FW-A", "9", "Mgmt", 0, 3)],
        }
    )
    out = summarize(client, "policies", HOST, "either", TR, None)
    wifi_a = next(r for r in out["rows"] if r["firewall"] == "FW-A" and r["policy_id"] == "2")
    assert wifi_a == {
        "firewall": "FW-A",
        "policy_id": "2",
        "policy": "Wifi",
        "allowed": 104,
        "denied": 1,
        "hits": 105,
    }
    assert [r["hits"] for r in out["rows"]] == sorted(
        (r["hits"] for r in out["rows"]), reverse=True
    )
    assert out["totals"] == {"allowed": 124, "denied": 4}
    assert out["firewalls"] == [
        {"firewall": "FW-A", "allowed": 104, "denied": 4},
        {"firewall": "FW-B", "allowed": 20, "denied": 0},
    ]


def test_applications_and_countries_use_the_confirmed_field_names():
    client = FakeClient(
        {
            ("top-applications", SRC): [
                {
                    "app_group": "Microsoft.Teams",
                    "appcat": "Collaboration",
                    "sessions": "36",
                    "session_pass": "36",
                    "session_block": "0",
                }
            ],
            ("top-countries", SRC): [
                {"dstcountry": "Japan", "sessions": "5", "session_pass": "5", "session_block": "0"}
            ],
            ("top-countries", DST): [
                {"srccountry": "Japan", "sessions": "2", "session_pass": "1", "session_block": "1"}
            ],
        }
    )
    apps = summarize(client, "applications", HOST, "src", TR, None)
    assert apps["rows"] == [
        {
            "app": "Microsoft.Teams",
            "category": "Collaboration",
            "allowed": 36,
            "denied": 0,
            "sessions": 36,
        }
    ]
    countries = summarize(client, "countries", HOST, "either", TR, None)
    assert countries["rows"] == [{"country": "Japan", "allowed": 6, "denied": 1, "sessions": 7}]


@pytest.mark.parametrize(
    "message",
    ["Cannot find FortiView 'top-applications'", "Invalid params: filter 'srcip' not supported."],
)
def test_a_missing_view_or_unsupported_filter_makes_only_that_section_unavailable(message):
    client = FakeClient(
        {("top-destinations", SRC): [_dest("192.0.2.1", 1)]},
        errors={"top-applications": FAZError(message)},
    )
    apps = summarize(client, "applications", HOST, "src", TR, None)
    assert "unavailable" in apps and "rows" not in apps
    assert summarize(client, "peers", HOST, "src", TR, None)["rows"][0]["peer"] == "192.0.2.1"


def test_other_faz_errors_propagate():
    client = FakeClient(errors={"policy-hits": FAZError("Internal error")})
    with pytest.raises(FAZError, match="Internal error"):
        summarize(client, "policies", HOST, "src", TR, None)


def test_unknown_section_is_refused():
    with pytest.raises(ValueError):
        summarize(FakeClient(), "ports", HOST, "src", TR, None)


def test_devices_are_passed_through():
    client = FakeClient()
    devices = [{"devid": "FGT0000000001"}]
    summarize(client, "policies", HOST, "src", TR, devices)
    assert client.calls[0]["devices"] == devices
