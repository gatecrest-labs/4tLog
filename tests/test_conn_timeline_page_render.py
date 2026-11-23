"""Render tests for app/static/js/conn_timeline.js, run through Node.

The result comes from the real :class:`app.conn_timeline.Timeline`, so the
contract between the roll-up and the page is pinned here, along with escaping
of FortiAnalyzer strings, the partial-coverage banner, peer/port filtering and
the Log Search drill-down links. Skipped if node is not installed.
"""

import datetime
import json
import shutil
import subprocess
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from app.conn_timeline import Timeline

ROOT = Path(__file__).resolve().parent.parent
HARNESS = ROOT / "tests" / "js" / "render_conn_timeline.js"
SCRIPT = ROOT / "app" / "static" / "js" / "conn_timeline.js"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")

EVIL = "<img src=x onerror=alert(1)>"
UTC = datetime.timezone.utc
END = datetime.datetime(2026, 11, 22, 12, 0, tzinfo=UTC)
START = END - datetime.timedelta(hours=1)
HOST = "10.10.20.50"


def _row(offset, **kw):
    row = {
        "itime_t": str(int(START.timestamp()) + offset),
        "devname": "GC-HQ-CORE",
        "devid": "FGVM01",
        "vd": "root",
        "srcip": HOST,
        "dstip": "10.10.30.10",
        "dstport": "22",
        "proto": "6",
        "service": "SSH",
        "action": "accept",
        "policyid": "30",
        "policyname": "Jump-to-Servers",
    }
    row.update(kw)
    return row


def _result(rows, direction="either", coverage=None):
    t = Timeline(HOST, direction, START, END)
    for r in rows:
        t.add(r)
    out = t.to_dict()
    out.update(
        {
            "target": "Gatecrest HQ",
            "host": HOST,
            "direction": direction,
            "direction_label": "either direction",
            "device": "All_FortiGate",
            "verdict_filter": "all",
            "preset": "1h",
            "coverage": coverage
            or {
                "matched": len(rows),
                "matched_final": True,
                "fetched": len(rows),
                "complete": True,
                "reason": None,
                "through": None,
                "searches": 1,
            },
        }
    )
    return out


def _render(cases):
    proc = subprocess.run(
        ["node", str(HARNESS), str(SCRIPT)],
        input=json.dumps(cases),
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(proc.stdout)


ROWS = [
    _row(5),
    _row(10),
    _row(65, action="deny", dstip="10.10.30.11", dstport="445", service="SMB", policyid="0"),
    _row(66, action="deny", dstip="10.10.30.12", dstport="445", service="SMB", policyid="0"),
    _row(70, srcip="10.10.1.9", dstip=HOST, dstport="3389", service="RDP"),
    _row(120, devname="GC-HQ-EDGE", devid="FGVM02", action="ip-conn", policyid="0"),
]


def test_totals_lanes_and_top_lists():
    out = _render([{"name": "all", "result": _result(ROWS)}])["all"]
    assert out["totals"] == {"allowed": 3, "denied": 2, "other": 1, "total": 6}  # ip-conn is other
    assert out["lanesShown"] == [0, 1]
    assert out["maxCell"] == 3  # minute two on the core: 2 denied SMB + 1 RDP
    assert out["peers"][0]["ip"] == "10.10.30.10"
    assert {p["label"] for p in out["ports"]} == {"22/tcp", "445/tcp", "3389/tcp"}
    assert any(p["label"] == "Implicit deny" for p in out["policies"])
    assert "GC-HQ-EDGE" in out["chart"] and "ct-denied" in out["chart"]
    assert "Complete: built from all 6 matched log(s)." in out["coverage"]
    assert "10.10.20.50" in out["header"] and "last 1h" in out["header"]


def test_peer_filter_narrows_everything_but_the_peer_list():
    result = _result(ROWS)
    smb_peer = result["peers"].index("10.10.30.11")
    out = _render([{"name": "f", "result": result, "filter": {"peer": smb_peer, "port": None}}])[
        "f"
    ]
    assert out["totals"]["total"] == 1 and out["totals"]["denied"] == 1
    assert len(out["peers"]) == len(result["peers"])  # other peers stay clickable
    assert "10.10.30.11" in out["filter"] and "Show everything" in out["filter"]
    assert "ct-active" in out["peersTable"]


def test_partial_coverage_banner_and_greyed_time():
    coverage = {
        "matched": 54321,
        "matched_final": True,
        "fetched": 20000,
        "complete": False,
        "reason": "cap",
        "through": "2026-11-22T11:30:00Z",
        "searches": 20,
    }
    out = _render([{"name": "p", "result": _result(ROWS, coverage=coverage)}])["p"]
    assert "Partial: built from 20,000 of 54,321 matched log(s)" in out["coverage"]
    assert "the row cap" in out["coverage"]
    assert "ct-not-fetched" in out["chart"]


def test_strings_from_fortianalyzer_are_escaped():
    rows = [
        _row(5, devname=EVIL, policyname=EVIL, service=EVIL, dstport="0", proto="47"),
        _row(6, devname=EVIL, dstip=EVIL, dstport=EVIL, proto="6"),
    ]
    out = _render([{"name": "e", "result": _result(rows), "selected": {"lane": 0, "bucket": 0}}])[
        "e"
    ]
    for part in ("chart", "policiesTable", "portsTable", "peersTable", "detail"):
        assert "<img" not in out[part], part
    assert "&lt;img" in out["policiesTable"]


def test_empty_result_says_so():
    out = _render([{"name": "z", "result": _result([])}])["z"]
    assert "No matching traffic logs" in out["chart"]


def test_many_lanes_collapse_to_the_busiest_forty():
    rows = [_row(i, devname=f"FW-{i:02d}", devid=f"FG{i:02d}") for i in range(45)]
    rows += [_row(50, devname="FW-44", devid="FG44")]
    cases = [
        {"name": "few", "result": _result(rows)},
        {"name": "all", "result": _result(rows), "showAll": True},
    ]
    out = _render(cases)
    assert len(out["few"]["lanesShown"]) == 40 and "Show all" in out["few"]["chart"]
    assert len(out["all"]["lanesShown"]) == 45


def _links(out):
    return [parse_qs(urlparse(link["href"]).query) for link in out["links"]]


def test_drill_down_links_open_log_search_on_the_slice():
    result = _result(ROWS)
    out = _render(
        [
            {
                "name": "d",
                "result": result,
                "selected": {"lane": 0, "bucket": 1, "verdict": "denied"},
            }
        ]
    )["d"]
    assert "Allowed 1 · Denied 2" not in out["detail"]  # verdict narrows the slice
    assert "Denied 2" in out["detail"]
    assert [link["label"] for link in out["links"]] == [
        "Open in Log Search (as source)",
        "Open in Log Search (as destination)",
    ]
    src, dst = _links(out)
    assert src["src"] == [HOST] and "dst" not in src
    assert dst["dst"] == [HOST] and "src" not in dst
    for q in (src, dst):
        assert q["target"] == ["Gatecrest HQ"]
        assert q["device"] == ["FGVM01"]
        assert q["start"] == ["2026-11-22T11:01:00.000Z"]
        assert q["end"] == ["2026-11-22T11:02:00.000Z"]
        assert q["filter"] == ["action==deny"]
        assert q["run"] == ["1"]


def test_allowed_link_excludes_every_deny_action_and_carries_the_filters():
    result = _result(ROWS, direction="src")
    peer = result["peers"].index("10.10.30.10")
    port = [p["label"] for p in result["ports"]].index("22/tcp")
    out = _render(
        [
            {
                "name": "a",
                "result": result,
                "filter": {"peer": peer, "port": port},
                "selected": {"lane": 0, "bucket": 0, "verdict": "allowed"},
            }
        ]
    )["a"]
    (q,) = _links(out)
    assert q["src"] == [HOST] and q["dst"] == ["10.10.30.10"]
    assert q["ports"] == ["tcp:22"]
    assert sorted(q["filter"]) == [
        "action!=block",
        "action!=deny",
        "action!=dropped",
        "action!=ip-conn",
    ]


def _peer_case(result, peer_ip, port_label=None):
    peer = result["peers"].index(peer_ip)
    flt = {"peer": peer, "port": None}
    if port_label:
        flt["port"] = [p["label"] for p in result["ports"]].index(port_label)
    return {"name": "p", "result": result, "filter": flt}


def test_no_picture_until_a_peer_is_selected():
    out = _render([{"name": "p", "result": _result(ROWS)}])["p"]
    assert out["peerPath"] == ""


def test_peer_picture_shows_ips_firewalls_ports_and_duration():
    result = _result(ROWS)
    out = _render([_peer_case(result, "10.10.30.10")])["p"]["peerPath"]
    assert f"{HOST} → 10.10.30.10" in out
    assert "GC-HQ-CORE" in out
    assert "22/tcp" in out and "SSH" in out
    assert "First seen" in out and "last seen" in out
    assert 'class="ct-path-graph"' in out


def test_peer_picture_separates_the_two_directions():
    result = _result(ROWS)  # RDP row: 10.10.1.9 -> HOST
    out = _render([_peer_case(result, "10.10.1.9")])["p"]["peerPath"]
    assert f"10.10.1.9 → {HOST}" in out
    assert "3389/tcp" in out
    assert f"{HOST} → 10.10.1.9" not in out


def test_details_link_opens_log_search_in_a_new_window():
    result = _result(ROWS)
    out = _render([_peer_case(result, "10.10.30.10", "22/tcp")])["p"]["peerPath"]
    assert 'target="_blank"' in out and 'rel="noopener"' in out
    href = out.split('class="btn btn-sm btn-secondary ct-details" href="')[1].split('"')[0]
    href = href.replace("&amp;", "&")
    q = parse_qs(urlparse(href).query)
    assert urlparse(href).path == "/log-search"
    assert q["src"] == [HOST] and q["dst"] == ["10.10.30.10"]
    assert q["device"] == ["FGVM01"] and q["ports"] == ["tcp:22"] and q["run"] == ["1"]
    assert q["start"] == ["2026-11-22T11:00:00.000Z"] and q["end"] == ["2026-11-22T12:00:00.000Z"]


def test_peer_picture_escapes_untrusted_strings():
    result = _result([_row(5, devname=EVIL, dstip="10.9.9.9")])
    out = _render([_peer_case(result, "10.9.9.9")])["p"]["peerPath"]
    assert "<img" not in out and "&lt;img" in out


def test_gaps_from_a_parallel_build_are_each_greyed_out():
    coverage = {
        "matched": 900,
        "matched_final": False,
        "fetched": 500,
        "complete": False,
        "reason": "deadline",
        "gaps": [
            ["2026-11-22T11:10:00Z", "2026-11-22T11:20:00Z"],
            ["2026-11-22T11:40:00Z", "2026-11-22T12:00:00Z"],
        ],
        "through": "2026-11-22T11:10:00Z",
        "searches": 9,
    }
    out = _render([{"name": "g", "result": _result(ROWS, coverage=coverage)}])["g"]
    assert out["chart"].count('class="ct-not-fetched"') == 2
    assert "of 900+ matched" in out["coverage"]


def test_running_build_shows_a_still_fetching_banner_and_no_grey():
    coverage = {
        "matched": 5000,
        "matched_final": False,
        "fetched": 1200,
        "complete": False,
        "reason": "running",
        "gaps": [],
        "through": None,
    }
    out = _render([{"name": "r", "result": _result(ROWS, coverage=coverage)}])["r"]
    assert "Still fetching: 1,200 of 5,000+ matched" in out["coverage"]
    assert "ct-not-fetched" not in out["chart"]


def _partial(**extra):
    return {
        "matched": 54321,
        "matched_final": True,
        "fetched": 20000,
        "complete": False,
        "reason": "cap",
        "through": "2026-11-22T11:30:00Z",
        "searches": 20,
        **extra,
    }


def test_a_resumable_partial_result_offers_continue():
    out = _render([{"name": "r", "result": _result(ROWS, coverage=_partial(resumable=True))}])["r"]
    assert 'id="ctContinue"' in out["coverage"] and "reads only what is missing" in out["coverage"]


def test_continue_is_not_offered_when_there_is_nothing_to_continue():
    cases = {
        "not_resumable": _partial(resumable=False),
        "unmarked": _partial(),
        "complete": {**_partial(resumable=True), "complete": True, "reason": None},
    }
    out = _render([{"name": n, "result": _result(ROWS, coverage=c)} for n, c in cases.items()])
    for name in cases:
        assert "ctContinue" not in out[name]["coverage"], name


def test_a_burst_reason_is_worded_for_the_user():
    cov = _partial(reason="burst", resumable=False)
    out = _render([{"name": "b", "result": _result(ROWS, coverage=cov)}])["b"]
    assert "burst of logs in one second" in out["coverage"]


# ── Quick summary panel ──────────────────────────────────────────────────────


def _ok(data):
    return {"status": "ok", "data": data}


PEERS = _ok(
    {
        "rows": [
            {"peer": "192.0.2.1", "allowed": 7, "denied": 1, "sessions": 8, "roles": ["src"]},
            {"peer": "192.0.2.9", "allowed": 2, "denied": 0, "sessions": 2, "roles": ["src"]},
        ],
        "total": 2,
        "truncated": False,
    }
)
POLICIES = _ok(
    {
        "rows": [
            {
                "firewall": "FW-A",
                "policy_id": "2",
                "policy": "Wifi",
                "allowed": 9,
                "denied": 1,
                "hits": 10,
            }
        ],
        "totals": {"allowed": 9, "denied": 1},
        "firewalls": [{"firewall": "FW-A", "allowed": 9, "denied": 1}],
    }
)
APPS = _ok(
    {
        "rows": [
            {
                "app": "Microsoft.Teams",
                "category": "Collaboration",
                "allowed": 36,
                "denied": 0,
                "sessions": 36,
            }
        ]
    }
)
COUNTRIES = _ok({"rows": [{"country": "Japan", "allowed": 5, "denied": 0, "sessions": 5}]})


def _panel(**sections):
    state = {"host": HOST, "direction": "either", "sections": sections}
    return _render([{"name": "s", "summary": state}])["s"]["summary"]


def test_summary_renders_totals_and_tables():
    html = _panel(peers=PEERS, policies=POLICIES, applications=APPS, countries=COUNTRIES)
    for text in ("192.0.2.1", "Wifi", "FW-A", "Microsoft.Teams", "Collaboration", "Japan"):
        assert text in html, text
    assert "Allowed" in html and "Denied" in html
    assert ">9<" in html and ">1<" in html  # the allowed and denied totals


def test_summary_states_loading_unavailable_and_error():
    html = _panel(
        peers={"status": "loading"},
        policies={"status": "unavailable", "message": "Cannot find FortiView"},
        applications={"status": "error", "message": "FortiAnalyzer said no"},
        countries=COUNTRIES,
    )
    assert "Loading" in html
    assert "Not available on this FortiAnalyzer" in html
    assert "FortiAnalyzer said no" in html and "Japan" in html


def test_summary_says_when_peers_are_cut_off():
    cut = _ok({**PEERS["data"], "total": 5, "truncated": False})
    assert "Showing the top 2 of 5 peers" in _panel(peers=cut)
    more = _ok({**PEERS["data"], "total": 2000, "reported_total": 5000, "truncated": True})
    assert "at least 5,000 peers" in _panel(peers=more)  # the FortiAnalyzer's own total
    assert "Showing the top" not in _panel(peers=PEERS)


def test_summary_says_when_a_section_has_no_sessions():
    empty = _ok({"rows": [], "total": 0, "truncated": False})
    assert "No sessions in this window" in _panel(peers=empty)


def test_summary_escapes_strings_from_fortianalyzer():
    evil_peers = _ok(
        {
            "rows": [{"peer": EVIL, "allowed": 1, "denied": 0, "sessions": 1, "roles": []}],
            "total": 1,
            "truncated": False,
        }
    )
    evil_pol = _ok(
        {
            "rows": [
                {
                    "firewall": EVIL,
                    "policy_id": EVIL,
                    "policy": EVIL,
                    "allowed": 1,
                    "denied": 0,
                    "hits": 1,
                }
            ],
            "totals": {"allowed": 1, "denied": 0},
            "firewalls": [{"firewall": EVIL, "allowed": 1, "denied": 0}],
        }
    )
    evil_apps = _ok(
        {"rows": [{"app": EVIL, "category": EVIL, "allowed": 1, "denied": 0, "sessions": 1}]}
    )
    evil_countries = _ok({"rows": [{"country": EVIL, "allowed": 1, "denied": 0, "sessions": 1}]})
    html = _panel(
        peers=evil_peers, policies=evil_pol, applications=evil_apps, countries=evil_countries
    )
    assert "<img" not in html and "&lt;img" in html
    error = _panel(peers={"status": "error", "message": EVIL})
    assert "<img" not in error


def test_summary_always_states_its_unit():
    for html in (_panel(), _panel(peers=PEERS), _panel(peers={"status": "loading"})):
        assert "sessions" in html.lower() and "not logs" in html.lower()


def test_partial_banner_points_at_the_summary():
    out = _render([{"name": "p", "result": _result(ROWS, coverage=_partial())}])["p"]
    assert "Quick summary" in out["coverage"]
    done = _render([{"name": "c", "result": _result(ROWS)}])["c"]
    assert "Quick summary" not in done["coverage"]


def test_loader_keeps_three_requests_in_flight():
    out = _render([{"name": "l", "loader": "concurrency"}])["l"]
    assert out["firstWave"] == ["peers", "policies", "applications"]
    assert out["afterOne"] == [
        "peers",
        "policies",
        "applications",
        "countries",
    ]  # one finished, next starts


def test_loader_reports_each_outcome_per_section():
    out = _render([{"name": "o", "loader": "outcomes"}])["o"]
    assert out["last"]["statuses"] == {
        "peers": "ok",
        "policies": "unavailable",
        "applications": "error",
        "countries": "loading",
    }


def test_loader_ignores_answers_from_an_older_run():
    out = _render([{"name": "s", "loader": "stale"}])["s"]
    assert out["updatesAfterOldAnswers"] == 0
    assert out["tags"][-1] == "two"


def test_loader_stop_ignores_late_answers():
    out = _render([{"name": "s", "loader": "stop"}])["s"]
    assert out["updatesAfterStop"] == 0


def test_starting_a_new_build_clears_the_panel_and_drops_the_old_answers():
    out = _render([{"name": "r", "loader": "reset"}])["r"]
    assert out["hidden"] is True and out["html"] == ""
    assert out["updatesAfterReset"] == 0


# ── A failed connection is "other", and every verdict shows where counts are listed ──


def test_tables_show_an_other_column_only_when_something_is_other():
    with_other = _render([{"name": "o", "result": _result(ROWS)}])["o"]
    for table in ("peersTable", "portsTable", "policiesTable"):
        assert "<th>Other</th>" in with_other[table], table
    without = _render([{"name": "n", "result": _result(ROWS[:5])}])["n"]
    for table in ("peersTable", "portsTable", "policiesTable"):
        assert "<th>Other</th>" not in without[table], table


FAILED = [
    _row(5, dstip="10.9.9.9"),
    _row(6, dstip="10.9.9.9", action="deny"),
    _row(7, dstip="10.9.9.9", action="ip-conn"),
]


def test_peer_path_splits_each_firewall_by_verdict():
    out = _render([_peer_case(_result(FAILED), "10.9.9.9")])["p"]["peerPath"]
    assert "<th>Allowed</th><th>Denied</th><th>Other</th>" in out
    assert (
        '<td>GC-HQ-CORE</td><td class="ct-num">1</td><td class="ct-num ct-num-denied">1</td>'
        '<td class="ct-num">1</td>' in out
    )


def test_peer_path_graph_draws_denied_and_other_beside_allowed():
    out = _render([_peer_case(_result(FAILED), "10.9.9.9")])["p"]["peerPath"]
    graph = out.split('class="ct-path-graph"')[1]
    assert "ct-allowed" in graph and "ct-denied" in graph and "ct-other" in graph
    plain = _render([_peer_case(_result([_row(5, dstip="10.9.9.9")]), "10.9.9.9")])["p"]["peerPath"]
    plain_graph = plain.split('class="ct-path-graph"')[1]
    assert "ct-denied" not in plain_graph and "<th>Denied</th>" in plain
    assert "<th>Other</th>" not in plain


def test_allowed_details_link_still_leaves_out_failed_connections():
    result = _result(FAILED)
    out = _render(
        [
            {
                "name": "a",
                "result": result,
                "selected": {"lane": 0, "bucket": 0, "verdict": "allowed"},
            }
        ]
    )["a"]
    links = _links(out)
    assert links and all("action!=ip-conn" in q["filter"] for q in links)  # not allowed, so out
