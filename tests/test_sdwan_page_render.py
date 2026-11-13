"""Render tests for app/static/js/sdwan.js, run through Node with a stub DOM.

The page is built from untrusted FortiAnalyzer strings, so escaping and the
distinct empty/error/unrecognised states are pinned here. Skipped if node is
not installed.
"""

import datetime
import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
HARNESS = ROOT / "tests" / "js" / "render_sdwan.js"
SCRIPT = ROOT / "app" / "static" / "js" / "sdwan.js"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")

EVIL = "<img src=x onerror=alert(1)>"


def _now(minutes_ago=0):
    t = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=minutes_ago)
    return t.isoformat(timespec="seconds")


def _target(**kw):
    base = {
        "label": "T",
        "adom": "root",
        "host": "h",
        "collected_at": _now(),
        "state": "no_data",
        "error": None,
        "views": {},
        "interfaces": [],
    }
    base.update(kw)
    return base


def _stat(v):
    return {"latest": v, "min": v, "avg": v, "max": v}


def _iface(**kw):
    base = {
        "device": "FGT-A",
        "interface": "wan1",
        "check": None,
        "sla_status": "ok",
        "sla_met_pct": 100.0,
        "latency": _stat(10),
        "jitter": _stat(1),
        "packetloss": _stat(0),
        "in_bw": _stat(5),
        "out_bw": _stat(2),
        "series": {"latency": [["t1", 10], ["t2", 12]]},
    }
    base.update(kw)
    return base


def _render(**cases):
    payload = [
        {"name": n, "target": c[0], "pollInterval": c[1] if len(c) > 1 else 300}
        for n, c in cases.items()
    ]
    proc = subprocess.run(
        ["node", str(HARNESS), str(SCRIPT)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def test_every_untrusted_string_is_html_escaped():
    target = _target(
        label=EVIL,
        host=EVIL,
        adom=EVIL,
        state="ok",
        views={EVIL: {"status": EVIL, "rows": 1, "error": None, "truncated": False}},
        interfaces=[_iface(device=EVIL, interface=EVIL, check=EVIL)],
    )
    err = _target(state="error", error=EVIL)

    out = _render(ok=(target,), err=(err,))

    for html in out.values():
        assert "<img" not in html
        assert "&lt;img" in html


def test_no_data_state_shows_enable_logging_copy_and_never_looks_healthy():
    html = _render(nd=(_target(state="no_data"),))["nd"]

    assert "No SD-WAN data from this FortiAnalyzer in the last 24h" in html
    assert "sdwan-ok" not in html


def test_error_state_shows_the_error_not_the_enable_logging_copy():
    html = _render(e=(_target(state="error", error="sdwan-perf-stats-line: No permission"),))["e"]

    assert "No permission" in html
    assert "SLA logging must be enabled" not in html


def test_unrecognized_state_says_rows_could_not_be_interpreted():
    views = {"sdwan-perf-stats-line": {"status": "ok", "rows": 7, "error": None}}

    html = _render(u=(_target(state="unrecognized", views=views),))["u"]

    assert "could not interpret" in html
    assert "7 rows" in html
    assert "SLA logging must be enabled" not in html


def test_truncated_view_is_marked():
    views = {"sdwan-perf-stats-line": {"status": "ok", "rows": 1000, "truncated": True}}
    t = _target(state="ok", views=views, interfaces=[_iface()])

    assert "truncated" in _render(x=(t,))["x"]


def test_missing_stats_render_as_dash_never_zero():
    t = _target(
        state="ok",
        interfaces=[_iface(sla_status=None, latency=None, jitter=None, packetloss=None)],
    )

    html = _render(x=(t,))["x"]

    assert "—" in html
    assert "0 ms" not in html


def test_check_name_is_shown_next_to_the_interface():
    t = _target(state="ok", interfaces=[_iface(check="Default_Google")])

    assert "Default_Google" in _render(x=(t,))["x"]


def test_collection_time_and_age_are_shown():
    html = _render(x=(_target(collected_at=_now(2)),))["x"]

    assert "Collected" in html
    assert "2m ago" in html


def test_staleness_follows_the_poll_interval():
    t = _target(collected_at=_now(20))

    out = _render(default=(t, 300), slow=(t, 1800))

    assert "(stale)" in out["default"]  # 20 min > 3 x 5 min
    assert "(stale)" not in out["slow"]  # 20 min < 3 x 30 min
