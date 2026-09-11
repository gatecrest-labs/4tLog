# Threat Activity Collector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a third background collector to 4tlog — unacknowledged FortiAnalyzer alerts by severity and 24h IPS detection activity (count, blocked %, top signatures, top source countries) — exposed under a new `"threats"` key in `GET /external/api/executive/summary`, matching the existing `log_stats_cache.py` collector pattern exactly.

**Architecture:** Two new low-level `FAZClient` methods (`get_alert_counts`, `run_fortiview`) confirmed against the vendored Swagger specs in `api-info/`. A new lock-guarded in-memory cache (`app/threat_stats_cache.py`) polled on its own APScheduler interval, per FAZ target, with a `threat_poll_enabled` opt-out per target. A new SQLite table in the existing `logstats.db` (`app/threat_stats_history.py`) persists one rollup row per poll cycle so a restart doesn't blank the executive-summary payload for a full poll interval. `external_api_routes.py` reads cache-first, history-fallback, exactly like it already does for `log_stats_cache`/`log_stats_history`.

**Tech Stack:** Flask, APScheduler (`BackgroundScheduler`), `requests`, `sqlite3` (stdlib), pytest + `monkeypatch`.

**Spec:** `~/Downloads/4texecutive2.md` §6, Prompt W3-1 (Wave 3 / P12) — this plan implements the 4tlog half only (steps 1–6). The 4tExecutive-side consumption (extractors, Logging & Visibility card, scorecard-header strip, RAG rule) is **out of scope** for this plan — it's a separate repo/session per the source doc.

## Global Constraints

- Follow `app/log_stats_cache.py`'s structure exactly: lock-guarded in-memory dict, APScheduler interval job, `poll_now()` for an immediate first poll, stale-but-honest on total poll failure (leave cache/history untouched, never fabricate a healthy-looking zero reading).
- Never hit the lab FAZ appliance from tests — every test mocks `FAZClient` methods or the HTTP `_post`, following `tests/test_faz_client.py` / `tests/test_log_stats_cache.py`.
- Request shapes must trace to `api-info/FortiAnalyzer 7.6.7 FortiAnalyzer Modules eventmgmt.json` and `...fortiview.json`. Where the vendored spec doesn't document a response shape (both `eventmgmt.alerts.count.get.resp` and the exact FortiView row columns are unconfirmed against live hardware), pick the most reasonable shape, implement it, and flag it in a docstring comment the same way `FAZClient.get_sys_status()` already does — this is established practice in this repo (see the `4tlog-phase2-status` precedent: ship a best-guess field mapping now, live-validate later, small follow-up fix if wrong).
- New Config knobs follow the existing naming/env convention: `THREAT_STATS_POLL_INTERVAL` (default `900`), `THREAT_STATS_POLL_DISABLED` (test-only kill switch, mirrors `LOG_STATS_POLL_DISABLED`).
- `schema_version` in the executive-summary payload stays `1` — the 2026-09-10 `"infra"` addition was additive with no version bump; `"threats"` follows the same precedent.

---

### Task 1: `FAZClient.get_alert_counts` and `FAZClient.run_fortiview`

**Files:**
- Modify: `app/faz_client.py`
- Test: `tests/test_faz_client.py`

**Interfaces:**
- Produces:
  - `FAZClient.get_alert_counts(self, adom: str, filter: str) -> int` — POSTs `{"url": f"/eventmgmt/adom/{adom}/alerts/count", "apiver": 3, "filter": filter}`, method `"get"`. Response shape is undocumented in the vendored spec (`eventmgmt.alerts.count.get.resp` is `null`); parse defensively: `result.get("data")` may be a list of one dict (`[{"count": N}]`), a bare dict (`{"count": N}`), or a bare number — return `0` if none of those shapes match.
  - `FAZClient.run_fortiview(self, adom: str, view: str, time_range: tuple[str, str], limit: int = 1000, filter: str | None = None, poll_interval: float = 2.0, timeout: float = 60.0) -> list[dict]` — submits to `/fortiview/adom/{adom}/{view}/run` (method `"add"`), gets back `{"tid": ...}`, then polls `/fortiview/adom/{adom}/{view}/run/{tid}` (method `"get"`) until `percentage >= 100` or `timeout` elapses (raises `FAZError` on timeout, mirroring `FAZSearchTimeout`'s message shape but reusing plain `FAZError` since this isn't the Log Search path). Returns `result["data"]` (list of row dicts) once complete.

- [ ] **Step 1: Write failing tests for `get_alert_counts`**

```python
def test_get_alert_counts_parses_list_shape(monkeypatch):
    client, calls = _client(
        monkeypatch,
        [{"jsonrpc": "2.0", "id": 1, "result": [{"data": [{"count": 7}]}]}],
    )
    assert client.get_alert_counts("root", "ackflag=no") == 7
    assert calls[0]["json"]["params"][0]["url"] == "/eventmgmt/adom/root/alerts/count"
    assert calls[0]["json"]["params"][0]["filter"] == "ackflag=no"


def test_get_alert_counts_parses_bare_dict_shape(monkeypatch):
    client, _ = _client(
        monkeypatch,
        [{"jsonrpc": "2.0", "id": 1, "result": [{"data": {"count": 3}}]}],
    )
    assert client.get_alert_counts("root", "ackflag=no and severity=critical") == 3


def test_get_alert_counts_returns_zero_on_unrecognized_shape(monkeypatch):
    client, _ = _client(
        monkeypatch,
        [{"jsonrpc": "2.0", "id": 1, "result": [{"data": []}]}],
    )
    assert client.get_alert_counts("root", "ackflag=no") == 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_faz_client.py -k get_alert_counts -v`
Expected: FAIL with `AttributeError: 'FAZClient' object has no attribute 'get_alert_counts'`

- [ ] **Step 3: Implement `get_alert_counts`**

Add to `app/faz_client.py`, after `get_sys_status`:

```python
    def get_alert_counts(self, adom: str, filter: str) -> int:
        """Unacknowledged/severity-filtered alert count from
        /eventmgmt/adom/<adom>/alerts/count. Confirmed against the vendored
        spec (api-info/.../eventmgmt.json, eventmgmt.alerts.count.get.req)
        for the request shape; the response is NOT documented there
        (eventmgmt.alerts.count.get.resp is null) and has not been
        confirmed live. Parsed defensively: result["data"] may come back as
        a one-item list ([{"count": N}]), a bare dict ({"count": N}), or a
        bare number — anything else is treated as zero rather than raising,
        since a count endpoint should never abort a poll cycle."""
        body = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "get",
            "params": [
                {
                    "url": f"/eventmgmt/adom/{adom}/alerts/count",
                    "apiver": 3,
                    "filter": filter,
                }
            ],
            "session": None,
        }
        result = self._unwrap_result(self._post(body))
        data = result.get("data")
        if isinstance(data, list):
            data = data[0] if data else {}
        if isinstance(data, dict):
            return int(data.get("count", 0) or 0)
        if isinstance(data, (int, float)):
            return int(data)
        return 0
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_faz_client.py -k get_alert_counts -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add app/faz_client.py tests/test_faz_client.py
git commit -m "feat: add FAZClient.get_alert_counts for unacked-alert queries"
```

- [ ] **Step 6: Write failing tests for `run_fortiview`**

```python
def test_run_fortiview_submits_and_polls_to_completion(monkeypatch):
    client, calls = _client(
        monkeypatch,
        [
            {"jsonrpc": "2.0", "id": 1, "result": {"tid": 42}},
            {
                "jsonrpc": "2.0",
                "id": 2,
                "result": {"percentage": 40, "data": [], "status": {"code": 0, "message": "OK"}},
            },
            {
                "jsonrpc": "2.0",
                "id": 3,
                "result": {
                    "percentage": 100,
                    "data": [{"threatname": "Eicar.Test.Virus", "count": 12}],
                    "status": {"code": 0, "message": "OK"},
                },
            },
        ],
    )
    monkeypatch.setattr("time.sleep", lambda *_: None)
    rows = client.run_fortiview(
        "root", "top-threats", ("2026-09-10T00:00:00+00:00", "2026-09-11T00:00:00+00:00"), limit=5
    )
    assert rows == [{"threatname": "Eicar.Test.Virus", "count": 12}]
    assert calls[0]["json"]["params"][0]["url"] == "/fortiview/adom/root/top-threats/run"
    assert calls[0]["json"]["method"] == "add"
    assert calls[0]["json"]["params"][0]["limit"] == 5
    assert calls[1]["json"]["params"][0]["url"] == "/fortiview/adom/root/top-threats/run/42"
    assert calls[1]["json"]["method"] == "get"


def test_run_fortiview_passes_filter_when_given(monkeypatch):
    client, calls = _client(
        monkeypatch,
        [
            {"jsonrpc": "2.0", "id": 1, "result": {"tid": 1}},
            {
                "jsonrpc": "2.0",
                "id": 2,
                "result": {"percentage": 100, "data": [], "status": {"code": 0, "message": "OK"}},
            },
        ],
    )
    client.run_fortiview(
        "root",
        "top-type",
        ("2026-09-10T00:00:00+00:00", "2026-09-11T00:00:00+00:00"),
        filter="type==ips",
    )
    assert calls[0]["json"]["params"][0]["filter"] == "type==ips"


def test_run_fortiview_raises_on_timeout(monkeypatch):
    from app.faz_client import FAZError

    client, _ = _client(
        monkeypatch,
        [
            {"jsonrpc": "2.0", "id": 1, "result": {"tid": 1}},
            {
                "jsonrpc": "2.0",
                "id": 2,
                "result": {"percentage": 50, "data": [], "status": {"code": 0, "message": "OK"}},
            },
        ]
        * 5,
    )
    monkeypatch.setattr("time.sleep", lambda *_: None)
    now = [0.0]
    monkeypatch.setattr("time.monotonic", lambda: now.__setitem__(0, now[0] + 10) or now[0])
    with pytest.raises(FAZError, match="did not complete"):
        client.run_fortiview(
            "root",
            "top-threats",
            ("2026-09-10T00:00:00+00:00", "2026-09-11T00:00:00+00:00"),
            timeout=5.0,
        )
```

- [ ] **Step 7: Run tests to verify they fail**

Run: `uv run pytest tests/test_faz_client.py -k run_fortiview -v`
Expected: FAIL with `AttributeError: 'FAZClient' object has no attribute 'run_fortiview'`

- [ ] **Step 8: Implement `run_fortiview`**

Add to `app/faz_client.py`, after `get_alert_counts`:

```python
    def run_fortiview(
        self,
        adom: str,
        view: str,
        time_range: tuple[str, str],
        limit: int = 1000,
        filter: str | None = None,
        poll_interval: float = 2.0,
        timeout: float = 60.0,
    ) -> list[dict]:
        """Run a FortiView report and poll it to completion, returning its
        result rows. Request/poll shape confirmed against the vendored spec
        (api-info/.../fortiview.json: fortiview.view-name.run.add.{req,resp},
        fortiview.view-name.run.tid.get.{req,resp}) — the exact column names
        inside each returned row are NOT documented there (they vary by
        view/report-by and the spec's row schema is a generic
        {"field","value"} placeholder) and have not been confirmed live;
        callers must treat row keys defensively. Same submit->poll->fetch
        shape as search_logs(), ported to FortiView's /run and /run/<tid>
        resources instead of /logsearch."""
        start, end = time_range
        submit_body = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "add",
            "params": [
                {
                    "url": f"/fortiview/adom/{adom}/{view}/run",
                    "apiver": 3,
                    "time-range": {"start": start, "end": end},
                    "limit": limit,
                    **({"filter": filter} if filter else {}),
                }
            ],
            "session": None,
        }
        submit_result = self._unwrap_result(self._post(submit_body))
        tid = submit_result.get("tid")
        if tid is None:
            raise FAZError(f"FortiView run submit returned no task ID: {submit_result!r}")

        fetch_url = f"/fortiview/adom/{adom}/{view}/run/{tid}"
        deadline = time.monotonic() + timeout
        last_result: dict = {}
        while True:
            if time.monotonic() >= deadline:
                raise FAZError(
                    f"FortiView '{view}' run did not complete within {timeout}s "
                    f"(last percentage={last_result.get('percentage', 0)})"
                )
            fetch_body = {
                "jsonrpc": "2.0",
                "id": self._next_id(),
                "method": "get",
                "params": [{"url": fetch_url, "apiver": 3, "limit": limit, "offset": 0}],
                "session": None,
            }
            last_result = self._unwrap_result(self._post(fetch_body))
            if last_result.get("percentage", 0) >= 100:
                break
            time.sleep(poll_interval)

        return last_result.get("data", [])
```

- [ ] **Step 9: Run tests to verify they pass**

Run: `uv run pytest tests/test_faz_client.py -v`
Expected: PASS (all tests in the file, including the new ones)

- [ ] **Step 10: Commit**

```bash
git add app/faz_client.py tests/test_faz_client.py
git commit -m "feat: add FAZClient.run_fortiview for the FortiView run/poll pattern"
```

---

### Task 2: `app/threat_stats_history.py`

**Files:**
- Create: `app/threat_stats_history.py`
- Test: `tests/test_threat_stats_history.py`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `init_db() -> None`
  - `write_rollup(alerts_unacked_total: int, alerts_unacked_by_severity: dict, ips_detections_24h: int, ips_blocked_24h: int, ips_blocked_pct: float, top_signatures: list[dict], top_source_countries: list[dict], collected_at: str) -> None`
  - `get_latest_rollup() -> dict | None` — same keys as the `write_rollup` params (minus nothing; includes `collected_at`).
  - `prune_old_rows(retention_days: int = 30) -> None`
  - Table `threat_stats_history` lives in the **same** `logstats.db` file as `log_stats_history.py` (`app/threat_stats_history.py`'s `DB_PATH` points at the identical path) — the two modules' tables coexist in one file, matching the "Persisted rollups in logstats.db" requirement literally.

- [ ] **Step 1: Write failing tests**

```python
import pytest


@pytest.fixture
def history_db(tmp_path, monkeypatch):
    path = tmp_path / "logstats.db"
    import app.threat_stats_history as history_mod

    monkeypatch.setattr(history_mod, "DB_PATH", path)
    history_mod.init_db()
    yield path


def test_write_and_get_latest_rollup(history_db):
    from app.threat_stats_history import get_latest_rollup, write_rollup

    write_rollup(
        alerts_unacked_total=5,
        alerts_unacked_by_severity={"critical": 1, "high": 2, "medium": 1, "low": 1},
        ips_detections_24h=100,
        ips_blocked_24h=80,
        ips_blocked_pct=80.0,
        top_signatures=[{"signature": "Eicar.Test.Virus", "count": 40}],
        top_source_countries=[{"country": "China", "count": 60}],
        collected_at="2026-09-11T00:00:00+00:00",
    )
    rollup = get_latest_rollup()
    assert rollup["alerts_unacked_total"] == 5
    assert rollup["alerts_unacked_by_severity"] == {"critical": 1, "high": 2, "medium": 1, "low": 1}
    assert rollup["ips_detections_24h"] == 100
    assert rollup["ips_blocked_24h"] == 80
    assert rollup["ips_blocked_pct"] == 80.0
    assert rollup["top_signatures"] == [{"signature": "Eicar.Test.Virus", "count": 40}]
    assert rollup["top_source_countries"] == [{"country": "China", "count": 60}]
    assert rollup["collected_at"] == "2026-09-11T00:00:00+00:00"


def test_get_latest_rollup_returns_none_when_empty(history_db):
    from app.threat_stats_history import get_latest_rollup

    assert get_latest_rollup() is None


def test_get_latest_rollup_returns_most_recent_row(history_db):
    from app.threat_stats_history import get_latest_rollup, write_rollup

    write_rollup(
        alerts_unacked_total=1,
        alerts_unacked_by_severity={},
        ips_detections_24h=0,
        ips_blocked_24h=0,
        ips_blocked_pct=0.0,
        top_signatures=[],
        top_source_countries=[],
        collected_at="2026-09-10T00:00:00+00:00",
    )
    write_rollup(
        alerts_unacked_total=9,
        alerts_unacked_by_severity={},
        ips_detections_24h=0,
        ips_blocked_24h=0,
        ips_blocked_pct=0.0,
        top_signatures=[],
        top_source_countries=[],
        collected_at="2026-09-11T00:00:00+00:00",
    )
    assert get_latest_rollup()["alerts_unacked_total"] == 9


def test_prune_old_rows_removes_rows_older_than_retention(history_db):
    import datetime

    from app.threat_stats_history import get_latest_rollup, prune_old_rows, write_rollup

    old_ts = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=40)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    write_rollup(
        alerts_unacked_total=1,
        alerts_unacked_by_severity={},
        ips_detections_24h=0,
        ips_blocked_24h=0,
        ips_blocked_pct=0.0,
        top_signatures=[],
        top_source_countries=[],
        collected_at=old_ts,
    )
    prune_old_rows(retention_days=30)
    assert get_latest_rollup() is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_threat_stats_history.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.threat_stats_history'`

- [ ] **Step 3: Implement `app/threat_stats_history.py`**

```python
"""SQLite-backed history of fleet-wide threat-activity rollups, one row per
threat_stats_cache poll cycle. Lives in the same logstats.db file as
app/log_stats_history.py — a separate table, same database. Exists so
GET /external/api/executive/summary can serve the last-known "threats" state
immediately after a restart, before the first new poll completes."""

from __future__ import annotations

import contextlib
import datetime
import json
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "logstats.db"


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(DB_PATH)


def init_db() -> None:
    with contextlib.closing(_connect()) as conn, conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS threat_stats_history (
                collected_at TEXT NOT NULL,
                alerts_unacked_total INTEGER NOT NULL,
                alerts_unacked_by_severity TEXT NOT NULL,
                ips_detections_24h INTEGER NOT NULL,
                ips_blocked_24h INTEGER NOT NULL,
                ips_blocked_pct REAL NOT NULL,
                top_signatures TEXT NOT NULL,
                top_source_countries TEXT NOT NULL
            )
            """
        )


def write_rollup(
    alerts_unacked_total: int,
    alerts_unacked_by_severity: dict,
    ips_detections_24h: int,
    ips_blocked_24h: int,
    ips_blocked_pct: float,
    top_signatures: list[dict],
    top_source_countries: list[dict],
    collected_at: str,
) -> None:
    with contextlib.closing(_connect()) as conn, conn:
        conn.execute(
            "INSERT INTO threat_stats_history "
            "(collected_at, alerts_unacked_total, alerts_unacked_by_severity, "
            "ips_detections_24h, ips_blocked_24h, ips_blocked_pct, "
            "top_signatures, top_source_countries) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                collected_at,
                alerts_unacked_total,
                json.dumps(alerts_unacked_by_severity),
                ips_detections_24h,
                ips_blocked_24h,
                ips_blocked_pct,
                json.dumps(top_signatures),
                json.dumps(top_source_countries),
            ),
        )


def get_latest_rollup() -> dict | None:
    with contextlib.closing(_connect()) as conn, conn:
        row = conn.execute(
            "SELECT collected_at, alerts_unacked_total, alerts_unacked_by_severity, "
            "ips_detections_24h, ips_blocked_24h, ips_blocked_pct, "
            "top_signatures, top_source_countries "
            "FROM threat_stats_history ORDER BY collected_at DESC LIMIT 1"
        ).fetchone()
    if row is None:
        return None
    (
        collected_at,
        alerts_unacked_total,
        alerts_unacked_by_severity,
        ips_detections_24h,
        ips_blocked_24h,
        ips_blocked_pct,
        top_signatures,
        top_source_countries,
    ) = row
    return {
        "collected_at": collected_at,
        "alerts_unacked_total": alerts_unacked_total,
        "alerts_unacked_by_severity": json.loads(alerts_unacked_by_severity),
        "ips_detections_24h": ips_detections_24h,
        "ips_blocked_24h": ips_blocked_24h,
        "ips_blocked_pct": ips_blocked_pct,
        "top_signatures": json.loads(top_signatures),
        "top_source_countries": json.loads(top_source_countries),
    }


def prune_old_rows(retention_days: int = 30) -> None:
    cutoff = (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=retention_days)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    with contextlib.closing(_connect()) as conn, conn:
        conn.execute("DELETE FROM threat_stats_history WHERE collected_at < ?", (cutoff,))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_threat_stats_history.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add app/threat_stats_history.py tests/test_threat_stats_history.py
git commit -m "feat: add threat_stats_history rollup persistence in logstats.db"
```

---

### Task 3: `app/faz_targets.py` gains `threat_poll_enabled`

**Files:**
- Modify: `app/faz_targets.py`
- Test: `tests/test_faz_targets.py`

**Interfaces:**
- Produces: `create_target(label, host, adom="root", token="", snmp_overrides=None, threat_poll_enabled=True) -> bool` and `update_target(label, host, adom, token, snmp_overrides=None, threat_poll_enabled=True) -> bool` now also write a `"threat_poll_enabled"` bool field into each target entry. `get_target`/`list_targets` return it as part of the raw dict; entries written before this change (missing the key) must be read as enabled — callers use `target.get("threat_poll_enabled", True)`, not a stored default, so no migration of `faz_targets.json` is needed.

- [ ] **Step 1: Write failing tests**

```python
def test_create_target_defaults_threat_poll_enabled_true(targets_file):
    from app.faz_targets import create_target, get_target

    create_target("Primary", host="192.168.64.4")
    assert get_target("Primary")["threat_poll_enabled"] is True


def test_create_target_threat_poll_enabled_false(targets_file):
    from app.faz_targets import create_target, get_target

    create_target("Primary", host="192.168.64.4", threat_poll_enabled=False)
    assert get_target("Primary")["threat_poll_enabled"] is False


def test_update_target_changes_threat_poll_enabled(targets_file):
    from app.faz_targets import create_target, get_target, update_target

    create_target("Primary", host="192.168.64.4")
    update_target("Primary", host="192.168.64.4", adom="root", token="", threat_poll_enabled=False)
    assert get_target("Primary")["threat_poll_enabled"] is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_faz_targets.py -k threat_poll_enabled -v`
Expected: FAIL with `KeyError: 'threat_poll_enabled'`

- [ ] **Step 3: Implement**

In `app/faz_targets.py`, update `_build_entry`, `create_target`, `update_target`:

```python
def _build_entry(
    label: str, host: str, adom: str, token: str, snmp_overrides: dict | None, threat_poll_enabled: bool
) -> dict:
    entry = {
        "label": label,
        "host": host,
        "adom": adom,
        "token": token,
        "threat_poll_enabled": threat_poll_enabled,
    }
    for key, value in (snmp_overrides or {}).items():
        if key in _SNMP_FIELDS and value:
            entry[key] = value
    return entry


def create_target(
    label: str,
    host: str,
    adom: str = "root",
    token: str = "",
    snmp_overrides: dict | None = None,
    threat_poll_enabled: bool = True,
) -> bool:
    """Returns False if a target with this label already exists."""
    label = label.strip()
    if not label:
        raise ValueError("Target label cannot be empty.")
    with _lock:
        targets = _load()
        if any(t.get("label") == label for t in targets):
            return False
        targets.append(_build_entry(label, host, adom, token, snmp_overrides, threat_poll_enabled))
        _save(targets)
    return True


def update_target(
    label: str,
    host: str,
    adom: str,
    token: str,
    snmp_overrides: dict | None = None,
    threat_poll_enabled: bool = True,
) -> bool:
    """Returns False if no target with this label exists.

    Fields the caller doesn't explicitly provide are preserved from the
    existing stored entry ... [existing docstring content unchanged]
    """
    with _lock:
        targets = _load()
        for i, t in enumerate(targets):
            if t.get("label") == label:
                effective_token = token if token else t.get("token", "")
                merged_overrides = {key: t[key] for key in _SNMP_FIELDS if key in t}
                merged_overrides.update(snmp_overrides or {})
                targets[i] = _build_entry(
                    label, host, adom, effective_token, merged_overrides, threat_poll_enabled
                )
                _save(targets)
                return True
    return False
```

Keep the rest of the file (`_load`, `_save`, `list_targets`, `get_target`, `delete_target`) unchanged.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_faz_targets.py -v`
Expected: PASS (all tests in the file, including the 3 new ones)

- [ ] **Step 5: Commit**

```bash
git add app/faz_targets.py tests/test_faz_targets.py
git commit -m "feat: add threat_poll_enabled flag to FAZ targets"
```

---

### Task 4: `app/threat_stats_cache.py` poller + Config + scheduler wiring

**Files:**
- Create: `app/threat_stats_cache.py`
- Modify: `app/config.py`
- Modify: `app/__init__.py`
- Modify: `tests/conftest.py`
- Test: `tests/test_threat_stats_cache.py`

**Interfaces:**
- Consumes: `FAZClient.get_alert_counts`/`run_fortiview` (Task 1), `app.threat_stats_history.init_db/write_rollup/prune_old_rows` (Task 2), `app.faz_targets.list_targets` (Task 3, each target dict now carries `threat_poll_enabled`).
- Produces:
  - `SEVERITIES = ("critical", "high", "medium", "low")` module constant.
  - `get_cached() -> dict` — `{"alerts_unacked_total": int, "alerts_unacked_by_severity": {sev: int, ...}, "ips_detections_24h": int, "ips_blocked_24h": int, "ips_blocked_pct": float, "top_signatures": [{"signature": str, "count": int}], "top_source_countries": [{"country": str, "count": int}], "collected_at": str | None}`.
  - `poll_all_targets() -> None`
  - `poll_now() -> None`
  - `init_scheduler(app) -> None`

- [ ] **Step 1: Add Config knobs**

In `app/config.py`, after the `LOG_STATS_POLL_DISABLED` block:

```python
    # Threat activity polling (app/threat_stats_cache.py) — unacked alert
    # counts and 24h IPS detection activity, independent cadence since it's
    # a heavier FortiView run/poll call rather than a single cheap query.
    THREAT_STATS_POLL_INTERVAL = int(os.environ.get("THREAT_STATS_POLL_INTERVAL", "900"))

    # Set by tests/conftest.py to skip starting the background threat-stats
    # poller (real network calls) during the test suite.
    THREAT_STATS_POLL_DISABLED = (
        os.environ.get("THREAT_STATS_POLL_DISABLED", "false").lower() == "true"
    )
```

- [ ] **Step 2: Add the conftest kill switch**

In `tests/conftest.py`, add alongside the other `POLL_DISABLED` defaults:

```python
os.environ.setdefault("THREAT_STATS_POLL_DISABLED", "true")
```

- [ ] **Step 3: Write failing tests for the poller**

```python
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
    import app.threat_stats_history as history_mod

    monkeypatch.setattr(history_mod, "DB_PATH", path)
    history_mod.init_db()
    yield path


@pytest.fixture(autouse=True)
def clear_threat_stats_cache():
    import app.threat_stats_cache as cache_mod

    cache_mod._cache = dict(cache_mod._EMPTY_CACHE)
    yield
    cache_mod._cache = dict(cache_mod._EMPTY_CACHE)


def _stub_client(monkeypatch, alert_counts_by_filter, fortiview_rows_by_view):
    def fake_get_alert_counts(self, adom, filter):
        return alert_counts_by_filter[filter]

    def fake_run_fortiview(self, adom, view, time_range, limit=1000, filter=None, **_kw):
        return fortiview_rows_by_view[view]

    monkeypatch.setattr("app.faz_client.FAZClient.get_alert_counts", fake_get_alert_counts)
    monkeypatch.setattr("app.faz_client.FAZClient.run_fortiview", fake_run_fortiview)
    monkeypatch.setattr("app.faz_client.FAZClient.logout", lambda self: None)


def test_poll_all_targets_populates_cache_and_writes_rollup(targets_file, history_db, monkeypatch):
    import app.threat_stats_cache as cache_mod
    from app.threat_stats_history import get_latest_rollup

    _stub_client(
        monkeypatch,
        alert_counts_by_filter={
            "ackflag=no": 5,
            "ackflag=no and severity=critical": 1,
            "ackflag=no and severity=high": 2,
            "ackflag=no and severity=medium": 1,
            "ackflag=no and severity=low": 1,
        },
        fortiview_rows_by_view={
            "top-type": [{"type": "IPS", "count": 100, "blockedsessions": 80}],
            "top-threats": [{"threatname": "Eicar.Test.Virus", "count": 40}],
            "top-countries": [{"srccountry": "China", "count": 60}],
        },
    )

    cache_mod.poll_all_targets()

    cached = cache_mod.get_cached()
    assert cached["alerts_unacked_total"] == 5
    assert cached["alerts_unacked_by_severity"] == {"critical": 1, "high": 2, "medium": 1, "low": 1}
    assert cached["ips_detections_24h"] == 100
    assert cached["ips_blocked_24h"] == 80
    assert cached["ips_blocked_pct"] == 80.0
    assert cached["top_signatures"] == [{"signature": "Eicar.Test.Virus", "count": 40}]
    assert cached["top_source_countries"] == [{"country": "China", "count": 60}]
    assert cached["collected_at"] is not None

    rollup = get_latest_rollup()
    assert rollup["alerts_unacked_total"] == 5
    assert rollup["ips_blocked_pct"] == 80.0


def test_poll_all_targets_skips_target_with_threat_poll_disabled(
    tmp_path, monkeypatch, history_db
):
    import app.faz_targets as faz_targets_mod
    import app.threat_stats_cache as cache_mod

    monkeypatch.setattr(faz_targets_mod, "FAZ_TARGETS_FILE", tmp_path / "faz_targets.json")
    from app.faz_targets import create_target

    create_target("Primary", host="192.168.64.4", adom="root", token="tok", threat_poll_enabled=False)

    calls = []

    def fake_get_alert_counts(self, adom, filter):
        calls.append(filter)
        return 0

    monkeypatch.setattr("app.faz_client.FAZClient.get_alert_counts", fake_get_alert_counts)

    cache_mod.poll_all_targets()

    assert calls == []
    # No target polled ok -> stale-but-honest: cache left at its initial empty state.
    assert cache_mod.get_cached()["collected_at"] is None


def test_poll_all_targets_leaves_cache_unchanged_when_target_raises(
    targets_file, history_db, monkeypatch
):
    import app.threat_stats_cache as cache_mod
    from app.faz_client import FAZError

    seeded = {
        "alerts_unacked_total": 3,
        "alerts_unacked_by_severity": {"critical": 1, "high": 0, "medium": 1, "low": 1},
        "ips_detections_24h": 10,
        "ips_blocked_24h": 5,
        "ips_blocked_pct": 50.0,
        "top_signatures": [],
        "top_source_countries": [],
        "collected_at": "2026-09-10T00:00:00+00:00",
    }
    cache_mod._cache = dict(seeded)

    def fake_get_alert_counts(self, adom, filter):
        raise FAZError("boom")

    monkeypatch.setattr("app.faz_client.FAZClient.get_alert_counts", fake_get_alert_counts)
    monkeypatch.setattr("app.faz_client.FAZClient.logout", lambda self: None)

    cache_mod.poll_all_targets()  # must not raise

    assert cache_mod.get_cached() == seeded


def test_poll_all_targets_zero_detections_gives_zero_blocked_pct(
    targets_file, history_db, monkeypatch
):
    import app.threat_stats_cache as cache_mod

    _stub_client(
        monkeypatch,
        alert_counts_by_filter={
            "ackflag=no": 0,
            "ackflag=no and severity=critical": 0,
            "ackflag=no and severity=high": 0,
            "ackflag=no and severity=medium": 0,
            "ackflag=no and severity=low": 0,
        },
        fortiview_rows_by_view={"top-type": [], "top-threats": [], "top-countries": []},
    )

    cache_mod.poll_all_targets()

    assert cache_mod.get_cached()["ips_blocked_pct"] == 0.0
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `uv run pytest tests/test_threat_stats_cache.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.threat_stats_cache'`

- [ ] **Step 5: Implement `app/threat_stats_cache.py`**

```python
"""Background cache for FAZ threat-activity: unacknowledged alert counts by
severity, and 24h IPS detection activity (count, blocked %, top signatures,
top source countries). Structured like app/log_stats_cache.py: a background
poller on its own APScheduler interval writes into a lock-guarded in-memory
dict; app/routes/external_api_routes.py reads a snapshot and never blocks on
a live poll.

Per-target opt-out: a target with threat_poll_enabled=False (see
app/faz_targets.py) is skipped entirely for this poller, though it's still
polled by faz_health_cache/log_stats_cache as normal.
"""

from __future__ import annotations

import datetime
import threading
import time

from app.config import Config

SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low")

_lock = threading.RLock()
_EMPTY_CACHE: dict = {
    "alerts_unacked_total": 0,
    "alerts_unacked_by_severity": {sev: 0 for sev in SEVERITIES},
    "ips_detections_24h": 0,
    "ips_blocked_24h": 0,
    "ips_blocked_pct": 0.0,
    "top_signatures": [],
    "top_source_countries": [],
    "collected_at": None,
}
_cache: dict = dict(_EMPTY_CACHE)


def get_cached() -> dict:
    with _lock:
        return dict(_cache)


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _last_24h_range(now: datetime.datetime) -> tuple[str, str]:
    start = now - datetime.timedelta(hours=24)
    fmt = "%Y-%m-%dT%H:%M:%S%z"
    return start.strftime(fmt), now.strftime(fmt)


def _merge_top_lists(lists: list[list[dict]], key: str, limit: int = 5) -> list[dict]:
    """Sum "count" across every target's top-N list by `key`, then return
    the fleet-wide top `limit` sorted descending. Same "one fleet across
    multiple FAZ targets" model log_stats_cache.py already uses for device
    dedup."""
    totals: dict[str, int] = {}
    for rows in lists:
        for row in rows:
            name = row.get(key, "")
            totals[name] = totals.get(name, 0) + int(row.get("count", 0) or 0)
    ranked = sorted(totals.items(), key=lambda kv: kv[1], reverse=True)
    return [{key: name, "count": count} for name, count in ranked[:limit]]


def _poll_one_target(client) -> dict:
    """Collect one target's threat stats. Raises FAZError/Exception on any
    failure — the caller decides whether to skip this target or abort."""
    alerts_unacked_total = client.get_alert_counts(client.adom, "ackflag=no")
    alerts_unacked_by_severity = {
        sev: client.get_alert_counts(client.adom, f"ackflag=no and severity={sev}")
        for sev in SEVERITIES
    }

    now = datetime.datetime.now(datetime.timezone.utc)
    time_range = _last_24h_range(now)

    type_rows = client.run_fortiview(client.adom, "top-type", time_range, limit=50)
    ips_row = next(
        (r for r in type_rows if str(r.get("type", "")).strip().lower() == "ips"), None
    )
    ips_detections_24h = int(ips_row.get("count", 0) or 0) if ips_row else 0
    ips_blocked_24h = int(ips_row.get("blockedsessions", 0) or 0) if ips_row else 0

    signature_rows = client.run_fortiview(
        client.adom, "top-threats", time_range, limit=5, filter="type==ips"
    )
    country_rows = client.run_fortiview(
        client.adom, "top-countries", time_range, limit=5, filter="type==ips"
    )

    return {
        "alerts_unacked_total": alerts_unacked_total,
        "alerts_unacked_by_severity": alerts_unacked_by_severity,
        "ips_detections_24h": ips_detections_24h,
        "ips_blocked_24h": ips_blocked_24h,
        "top_signatures": [
            {"signature": r.get("threatname", ""), "count": int(r.get("count", 0) or 0)}
            for r in signature_rows
        ],
        "top_source_countries": [
            {"country": r.get("srccountry", ""), "count": int(r.get("count", 0) or 0)}
            for r in country_rows
        ],
    }


def poll_all_targets() -> None:
    import app.threat_stats_history as history
    from app.app_logger import app_log
    from app.faz_client import FAZClient, FAZError, summarize_connection_error
    from app.faz_targets import list_targets

    results: list[dict] = []
    polled_ok = False
    for target in list_targets():
        label = target.get("label")
        host = target.get("host")
        adom = target.get("adom", "root")
        if not label or not host or not target.get("threat_poll_enabled", True):
            continue
        try:
            with FAZClient(
                host=host,
                token=target.get("token", ""),
                adom=adom,
                verify_ssl=Config.FAZ_VERIFY_SSL,
                timeout=Config.FAZ_REQUEST_TIMEOUT,
            ) as client:
                results.append(_poll_one_target(client))
        except FAZError as exc:
            app_log("WARN", "threat_stats_cache", f"threat-stats poll failed for {label}: {exc}")
            continue
        except Exception as exc:
            app_log(
                "WARN",
                "threat_stats_cache",
                f"threat-stats poll failed for {label} ({host}): {summarize_connection_error(exc)}",
            )
            continue
        polled_ok = True

    if not polled_ok:
        # Every enabled target was unreachable (or none are enabled) this
        # cycle. Leave the cache and persisted history untouched
        # (stale-but-honest) rather than overwriting with a fabricated
        # "zero threats" reading.
        return

    alerts_unacked_total = sum(r["alerts_unacked_total"] for r in results)
    alerts_unacked_by_severity = {
        sev: sum(r["alerts_unacked_by_severity"][sev] for r in results) for sev in SEVERITIES
    }
    ips_detections_24h = sum(r["ips_detections_24h"] for r in results)
    ips_blocked_24h = sum(r["ips_blocked_24h"] for r in results)
    ips_blocked_pct = (
        round(ips_blocked_24h / ips_detections_24h * 100, 1) if ips_detections_24h else 0.0
    )
    top_signatures = _merge_top_lists([r["top_signatures"] for r in results], "signature")
    top_source_countries = _merge_top_lists(
        [r["top_source_countries"] for r in results], "country"
    )

    collected_at = _now()
    with _lock:
        _cache["alerts_unacked_total"] = alerts_unacked_total
        _cache["alerts_unacked_by_severity"] = alerts_unacked_by_severity
        _cache["ips_detections_24h"] = ips_detections_24h
        _cache["ips_blocked_24h"] = ips_blocked_24h
        _cache["ips_blocked_pct"] = ips_blocked_pct
        _cache["top_signatures"] = top_signatures
        _cache["top_source_countries"] = top_source_countries
        _cache["collected_at"] = collected_at

    history.init_db()
    history.write_rollup(
        alerts_unacked_total=alerts_unacked_total,
        alerts_unacked_by_severity=alerts_unacked_by_severity,
        ips_detections_24h=ips_detections_24h,
        ips_blocked_24h=ips_blocked_24h,
        ips_blocked_pct=ips_blocked_pct,
        top_signatures=top_signatures,
        top_source_countries=top_source_countries,
        collected_at=collected_at,
    )
    history.prune_old_rows()


def poll_now() -> None:
    """Kick off a non-blocking poll of all targets in a daemon thread."""
    t = threading.Thread(target=poll_all_targets, name="threat_stats_poll_now", daemon=True)
    t.start()


def init_scheduler(app) -> None:
    """Register a recurring APScheduler job and run the first poll immediately.

    No-op if Config.THREAT_STATS_POLL_DISABLED (set by tests/conftest.py)."""
    if Config.THREAT_STATS_POLL_DISABLED:
        return

    from apscheduler.schedulers.background import BackgroundScheduler

    poll_now()

    scheduler = BackgroundScheduler()
    scheduler.add_job(
        func=poll_all_targets,
        trigger="interval",
        seconds=Config.THREAT_STATS_POLL_INTERVAL,
        id="threat_stats_poll",
        replace_existing=True,
        max_instances=1,
    )
    scheduler.start()
```

Note: `client.adom` is used directly (the `FAZClient` instance is already scoped to the target's ADOM by its constructor), matching how `log_stats_cache.py` relies on `FAZClient(adom=adom, ...)` rather than re-passing `adom` into every call.

- [ ] **Step 6: Wire the scheduler into `app/__init__.py`**

Add after the `_LOG_STATS_STARTED` block:

```python
    if not app.config.get("_THREAT_STATS_STARTED"):
        app.config["_THREAT_STATS_STARTED"] = True
        from app.threat_stats_cache import init_scheduler as init_threat_stats_scheduler
        from app.threat_stats_history import init_db as init_threat_stats_db

        init_threat_stats_db()
        init_threat_stats_scheduler(app)
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `uv run pytest tests/test_threat_stats_cache.py tests/test_config.py -v` (if `test_config.py` doesn't exist, just run the first file)
Expected: PASS (4 tests)

- [ ] **Step 8: Run the full suite to confirm nothing else broke**

Run: `uv run pytest -q`
Expected: PASS, no regressions

- [ ] **Step 9: Commit**

```bash
git add app/threat_stats_cache.py app/config.py app/__init__.py tests/conftest.py tests/test_threat_stats_cache.py
git commit -m "feat: add threat_stats_cache poller for unacked alerts and 24h IPS activity"
```

---

### Task 5: Admin → FAZ Targets — "Threat Polling" checkbox

**Files:**
- Modify: `app/routes/admin_routes.py`
- Modify: `app/templates/admin.html`
- Modify: `app/static/js/admin.js`
- Test: `tests/test_admin_routes.py`

**Interfaces:**
- Consumes: `create_target`/`update_target`'s new `threat_poll_enabled` kwarg (Task 3).
- Produces: `POST /admin/api/faz-targets` and `PUT /admin/api/faz-targets/<label>` now accept `"threat_poll_enabled"` (bool, default `True` when omitted) in the JSON body; `_mask_target` passes it through unchanged (not sensitive).

- [ ] **Step 1: Write failing tests**

Add to `tests/test_admin_routes.py`, near the other `faz_targets_crud_for_admin`-style tests:

```python
def test_faz_targets_create_defaults_threat_poll_enabled_true(client, faz_targets_file):
    _login(client, "admin1")
    csrf = _csrf(client)
    resp = client.post(
        "/admin/api/faz-targets",
        json={"label": "Primary", "host": "192.168.64.4", "adom": "root", "token": "tok"},
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 201
    assert resp.get_json()["threat_poll_enabled"] is True


def test_faz_targets_create_threat_poll_enabled_false(client, faz_targets_file):
    _login(client, "admin1")
    csrf = _csrf(client)
    resp = client.post(
        "/admin/api/faz-targets",
        json={
            "label": "Primary",
            "host": "192.168.64.4",
            "adom": "root",
            "token": "tok",
            "threat_poll_enabled": False,
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 201
    assert resp.get_json()["threat_poll_enabled"] is False


def test_faz_targets_update_threat_poll_enabled(client, faz_targets_file):
    _login(client, "admin1")
    csrf = _csrf(client)
    client.post(
        "/admin/api/faz-targets",
        json={"label": "Primary", "host": "192.168.64.4", "adom": "root", "token": "tok"},
        headers={"X-CSRF-Token": csrf},
    )
    resp = client.put(
        "/admin/api/faz-targets/Primary",
        json={"host": "192.168.64.4", "adom": "root", "threat_poll_enabled": False},
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 200
    assert resp.get_json()["threat_poll_enabled"] is False
```

Adapt `_login`/`_csrf` calls to match this file's actual existing helper signatures (read the top of `tests/test_admin_routes.py` for the exact fixture/helper names already used by neighboring `faz_targets_*` tests — reuse them verbatim rather than inventing new ones).

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_admin_routes.py -k threat_poll_enabled -v`
Expected: FAIL — response JSON has no `threat_poll_enabled` key yet (create/update routes don't parse it)

- [ ] **Step 3: Implement the route changes**

In `app/routes/admin_routes.py`, update `api_faz_targets_create` and `api_faz_targets_update`:

```python
@bp.route("/api/faz-targets", methods=["POST"])
@_admin_required
def api_faz_targets_create():
    data = request.get_json(silent=True) or {}
    label = (data.get("label") or "").strip()
    if not label:
        return jsonify({"error": "label is required"}), 400
    host = data.get("host", "")
    adom = data.get("adom", "root")
    token = data.get("token", "")
    snmp_overrides = {k: data[k] for k in _SNMP_OVERRIDE_FIELDS if data.get(k)}
    threat_poll_enabled = bool(data.get("threat_poll_enabled", True))
    ok = create_target(label, host, adom, token, snmp_overrides, threat_poll_enabled)
    if not ok:
        return jsonify({"error": f"Target '{label}' already exists"}), 409
    app_log("INFO", "admin", "FAZ target created", by=session["user"], target=label)
    return jsonify(_mask_target(get_target(label))), 201


@bp.route("/api/faz-targets/<label>", methods=["PUT"])
@_admin_required
def api_faz_targets_update(label: str):
    data = request.get_json(silent=True) or {}
    host = data.get("host", "")
    adom = data.get("adom", "root")
    token = data.get("token", "")
    snmp_overrides = {k: data[k] for k in _SNMP_OVERRIDE_FIELDS if data.get(k)}
    threat_poll_enabled = bool(data.get("threat_poll_enabled", True))
    ok = update_target(label, host, adom, token, snmp_overrides, threat_poll_enabled)
    if not ok:
        return jsonify({"error": f"Target '{label}' not found"}), 404
    app_log("INFO", "admin", "FAZ target updated", by=session["user"], target=label)
    return jsonify(_mask_target(get_target(label)))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_admin_routes.py -v`
Expected: PASS (all tests in the file, including the 3 new ones)

- [ ] **Step 5: Update the Admin UI — table column**

In `app/templates/admin.html`, update the FAZ Targets table header (around line 67):

```html
        <tr><th>Label</th><th>Host</th><th>ADOM</th><th>Threat Polling</th><th>Actions</th></tr>
```

- [ ] **Step 6: Update the Admin UI — modal checkbox**

In `app/templates/admin.html`, add a form group inside `#fazTargetModal`'s `.modal-body`, after the API Token field (around line 250):

```html
      <div class="form-group form-check">
        <label>
          <input type="checkbox" id="fazTargetThreatPollInput" checked />
          Include in threat polling (unacked alerts, IPS activity)
        </label>
      </div>
```

- [ ] **Step 7: Update `app/static/js/admin.js` — table render, modal open/save**

In `renderFazTargets()` (around line 163), add a cell before `actions`:

```javascript
      tr.appendChild(el('td', { text: t.threat_poll_enabled ? 'On' : 'Off' }));
```

In `openFazTargetModal()` (around line 195), set the checkbox from the target being edited (default checked for a new target):

```javascript
    document.getElementById('fazTargetThreatPollInput').checked = target ? !!target.threat_poll_enabled : true;
```

In `saveFazTarget()` (around line 218), read the checkbox and include it in both the create and update request bodies:

```javascript
    const threatPollEnabled = document.getElementById('fazTargetThreatPollInput').checked;
    ...
    if (mode === 'create') {
      resp = await fetch('/admin/api/faz-targets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ label, host, adom, token, threat_poll_enabled: threatPollEnabled }),
      });
    } else {
      const body = { host, adom, threat_poll_enabled: threatPollEnabled };
      if (token) body.token = token;
      resp = await fetch(`/admin/api/faz-targets/${encodeURIComponent(origLabel)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
    }
```

- [ ] **Step 8: Manually verify in the browser**

Run: `uv run python wsgi.py`, log in as an admin, open Admin → FAZ Targets, create a target with the checkbox unchecked, confirm the table shows "Off" and editing it shows the checkbox unchecked; toggle it on and confirm the table updates to "On".

- [ ] **Step 9: Commit**

```bash
git add app/routes/admin_routes.py app/templates/admin.html app/static/js/admin.js tests/test_admin_routes.py
git commit -m "feat: add per-target threat-polling checkbox to Admin > FAZ Targets"
```

---

### Task 6: `"threats"` key in `GET /external/api/executive/summary`

**Files:**
- Modify: `app/routes/external_api_routes.py`
- Test: `tests/test_external_api_routes.py`

**Interfaces:**
- Consumes: `threat_stats_cache.get_cached()` (Task 4), `threat_stats_history.get_latest_rollup()` (Task 2).
- Produces: response payload gains `"threats": {"alerts_unacked_total": int, "alerts_unacked_by_severity": {"critical": int, "high": int, "medium": int, "low": int}, "ips_detections_24h": int, "ips_blocked_pct": float, "top_signatures": [{"signature": str, "count": int}], "top_source_countries": [{"country": str, "count": int}], "collected_at": str | None}`.

- [ ] **Step 1: Write failing test**

Add to `tests/test_external_api_routes.py`:

```python
def test_threats_key_shape_from_cache(client, monkeypatch):
    raw = _enable_and_token()

    import app.faz_health_cache as health_mod
    import app.log_stats_cache as logstats_mod
    import app.threat_stats_cache as threat_mod

    monkeypatch.setattr(health_mod, "get_all_cached", lambda: [])
    monkeypatch.setattr(
        logstats_mod,
        "get_cached",
        lambda: {"logging_devices": [], "silent_devices": [], "collected_at": None},
    )
    monkeypatch.setattr(
        threat_mod,
        "get_cached",
        lambda: {
            "alerts_unacked_total": 5,
            "alerts_unacked_by_severity": {"critical": 1, "high": 2, "medium": 1, "low": 1},
            "ips_detections_24h": 100,
            "ips_blocked_24h": 80,
            "ips_blocked_pct": 80.0,
            "top_signatures": [{"signature": "Eicar.Test.Virus", "count": 40}],
            "top_source_countries": [{"country": "China", "count": 60}],
            "collected_at": "2026-09-11T00:00:00+00:00",
        },
    )

    resp = client.get("/external/api/executive/summary", headers={"Authorization": f"Bearer {raw}"})
    assert resp.status_code == 200
    threats = resp.get_json()["threats"]
    assert threats["alerts_unacked_total"] == 5
    assert threats["alerts_unacked_by_severity"] == {"critical": 1, "high": 2, "medium": 1, "low": 1}
    assert threats["ips_detections_24h"] == 100
    assert threats["ips_blocked_pct"] == 80.0
    assert threats["top_signatures"] == [{"signature": "Eicar.Test.Virus", "count": 40}]
    assert threats["top_source_countries"] == [{"country": "China", "count": 60}]
    assert threats["collected_at"] == "2026-09-11T00:00:00+00:00"


def test_threats_key_falls_back_to_history_when_cache_empty(client, monkeypatch):
    raw = _enable_and_token()

    import app.faz_health_cache as health_mod
    import app.log_stats_cache as logstats_mod
    import app.threat_stats_cache as threat_mod
    import app.threat_stats_history as threat_history_mod

    monkeypatch.setattr(health_mod, "get_all_cached", lambda: [])
    monkeypatch.setattr(
        logstats_mod,
        "get_cached",
        lambda: {"logging_devices": [], "silent_devices": [], "collected_at": None},
    )
    monkeypatch.setattr(threat_mod, "get_cached", lambda: {"collected_at": None})
    monkeypatch.setattr(
        threat_history_mod,
        "get_latest_rollup",
        lambda: {
            "alerts_unacked_total": 2,
            "alerts_unacked_by_severity": {"critical": 0, "high": 0, "medium": 1, "low": 1},
            "ips_detections_24h": 10,
            "ips_blocked_24h": 5,
            "ips_blocked_pct": 50.0,
            "top_signatures": [],
            "top_source_countries": [],
            "collected_at": "2026-09-10T00:00:00+00:00",
        },
    )

    resp = client.get("/external/api/executive/summary", headers={"Authorization": f"Bearer {raw}"})
    threats = resp.get_json()["threats"]
    assert threats["alerts_unacked_total"] == 2
    assert threats["collected_at"] == "2026-09-10T00:00:00+00:00"


def test_threats_key_all_zero_when_no_cache_and_no_history(client, monkeypatch):
    raw = _enable_and_token()

    import app.faz_health_cache as health_mod
    import app.log_stats_cache as logstats_mod
    import app.threat_stats_cache as threat_mod
    import app.threat_stats_history as threat_history_mod

    monkeypatch.setattr(health_mod, "get_all_cached", lambda: [])
    monkeypatch.setattr(
        logstats_mod,
        "get_cached",
        lambda: {"logging_devices": [], "silent_devices": [], "collected_at": None},
    )
    monkeypatch.setattr(threat_mod, "get_cached", lambda: {"collected_at": None})
    monkeypatch.setattr(threat_history_mod, "get_latest_rollup", lambda: None)

    resp = client.get("/external/api/executive/summary", headers={"Authorization": f"Bearer {raw}"})
    threats = resp.get_json()["threats"]
    assert threats["alerts_unacked_total"] == 0
    assert threats["alerts_unacked_by_severity"] == {"critical": 0, "high": 0, "medium": 0, "low": 0}
    assert threats["ips_detections_24h"] == 0
    assert threats["ips_blocked_pct"] == 0.0
    assert threats["top_signatures"] == []
    assert threats["top_source_countries"] == []
    assert threats["collected_at"] is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_external_api_routes.py -k threats_key -v`
Expected: FAIL with `KeyError: 'threats'`

- [ ] **Step 3: Implement**

In `app/routes/external_api_routes.py`, add a helper and wire it into `executive_summary()`:

```python
def _build_threats(cache: dict, rollup: dict | None) -> dict:
    source = cache if cache.get("collected_at") is not None else (rollup or {})
    return {
        "alerts_unacked_total": source.get("alerts_unacked_total", 0),
        "alerts_unacked_by_severity": source.get(
            "alerts_unacked_by_severity", {"critical": 0, "high": 0, "medium": 0, "low": 0}
        ),
        "ips_detections_24h": source.get("ips_detections_24h", 0),
        "ips_blocked_pct": source.get("ips_blocked_pct", 0.0),
        "top_signatures": source.get("top_signatures", []),
        "top_source_countries": source.get("top_source_countries", []),
        "collected_at": source.get("collected_at"),
    }
```

Update `executive_summary()`'s imports and body:

```python
    from app import faz_health_cache, log_stats_cache, threat_stats_cache
    from app.config import Config
    from app.log_stats_history import get_latest_rollup
    from app.threat_stats_history import get_latest_rollup as get_latest_threat_rollup
```

...and before the `return jsonify(...)`:

```python
    threat_cache = threat_stats_cache.get_cached()
    threat_rollup = None if threat_cache.get("collected_at") is not None else get_latest_threat_rollup()
    threats = _build_threats(threat_cache, threat_rollup)
```

...and add `"threats": threats,` to the returned dict, after `"infra": _build_infra_list(targets),`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_external_api_routes.py -v`
Expected: PASS (all tests in the file, including the 3 new ones)

- [ ] **Step 5: Run the full suite and ruff**

Run: `uv run ruff check . && uv run pytest -q`
Expected: PASS, no regressions

- [ ] **Step 6: Commit**

```bash
git add app/routes/external_api_routes.py tests/test_external_api_routes.py
git commit -m "feat: expose threat activity under executive summary's threats key"
```

---

### Task 7: Docs — README.md, CHANGELOG.md, .env.example, faz_targets.example.json

**Files:**
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `.env.example`
- Modify: `faz_targets.example.json`

**Interfaces:** none (documentation only).

- [ ] **Step 1: Update `.env.example`**

After the `SILENT_DEVICE_THRESHOLD_MINUTES`/`LOG_STATS_POLL_INTERVAL` block, add:

```
# Threat activity polling for the external API — unacked FAZ alerts by
# severity and 24h IPS detection activity (see README.md)
# THREAT_STATS_POLL_INTERVAL=900
```

- [ ] **Step 2: Update `faz_targets.example.json`**

```json
[
  {
    "label": "FortiAnalyzer Primary",
    "host": "192.168.64.4",
    "adom": "root",
    "token": "faz-primary-bearer-token",
    "threat_poll_enabled": true
  }
]
```

- [ ] **Step 3: Update `README.md`**

In the "Admin → FAZ Targets" bullet (around line 37), append: "and a per-target **Threat Polling** checkbox (default on) controlling whether it's included in the threat-activity collector below."

In the "External API" bullet (around line 60-75), after the existing `"infra"` sentence, add:

"Also includes a `"threats"` key — `{alerts_unacked_total, alerts_unacked_by_severity: {critical, high, medium, low}, ips_detections_24h, ips_blocked_pct, top_signatures: [{signature, count}] (top 5), top_source_countries: [{country, count}] (top 5), collected_at}` — from a third background poller (`app/threat_stats_cache.py`, `THREAT_STATS_POLL_INTERVAL` in `.env.example`, default 900s) that queries each FAZ target's unacknowledged alert counts (`/eventmgmt/adom/<adom>/alerts/count`) and 24h FortiView Threat Type / Threats / Countries reports, filtered to IPS. Targets can be excluded via the **Threat Polling** checkbox in Admin → FAZ Targets."

- [ ] **Step 4: Add a `CHANGELOG.md` entry**

Add a new dated section at the top (use today's date):

```markdown
## 2026-09-11

### Added

- External API: `GET /external/api/executive/summary` gains a `"threats"`
  key — unacknowledged FortiAnalyzer alert counts by severity, and 24h IPS
  detection activity (count, blocked %, top 5 signatures, top 5 source
  countries) — from a new background poller (`app/threat_stats_cache.py`,
  `THREAT_STATS_POLL_INTERVAL`, default 900s) using
  `/eventmgmt/adom/<adom>/alerts/count` and the FortiView run/poll pattern
  (`top-type`, `top-threats`, `top-countries`, filtered to IPS). Rollups
  persist in `logstats.db` alongside the existing log-volume history.
- Admin → FAZ Targets: a per-target "Threat Polling" checkbox (default on)
  controls whether a target is included in the new threat-activity poller.
```

- [ ] **Step 5: Commit**

```bash
git add README.md CHANGELOG.md .env.example faz_targets.example.json
git commit -m "docs: document the threat activity collector and threat-polling target flag"
```

---

## Out of scope

The 4tExecutive-side consumption (extractors, a Threat Activity card on the Logging & Visibility domain page, the four-number strip on the scorecard header per `design-a-command-center.html`'s bottom card, RAG on `alerts_unacked_by_severity.critical`) lives in a separate repo (`~/code/github/web/4tExecutive`) and needs its own plan/session there, once this plan's `"threats"` payload is live to build against.
