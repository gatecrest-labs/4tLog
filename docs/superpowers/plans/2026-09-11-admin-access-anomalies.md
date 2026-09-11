# Admin Access Anomalies Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the existing `app/threat_stats_cache.py` poller (shipped in the threat-activity-collector plan, 2026-09-11) with two more FortiView views — `admin-logins` and `failed-authentication-attempts` — and expose a new `"admin_access"` key in `GET /external/api/executive/summary`: `{failed_admin_logins_24h, devices_with_failed_logins, top_failed_sources (5), admin_logins_outside_hours_24h, business_hours, collected_at}`.

**Architecture:** One additional per-target FortiView collection step inside the *same* poll cycle the existing threat-activity poller already runs (no new scheduler, no new cache module) — `_poll_one_target` grows two more `run_fortiview` calls, `poll_all_targets` grows two more aggregation steps, and the existing `threat_stats_history` table grows four new columns (migration-safe `ALTER TABLE ADD COLUMN`, since `CREATE TABLE IF NOT EXISTS` alone won't touch an already-existing table). `external_api_routes.py` gains a new top-level `"admin_access"` key, sibling to `"threats"`, built the same cache-first/history-fallback way.

**Tech Stack:** Flask, APScheduler, `requests`, `sqlite3` (stdlib), `zoneinfo.ZoneInfo` (stdlib, already used by `FAZClient.local_time_range`), pytest + `monkeypatch`.

**Spec:** `~/Downloads/4texecutive2.md` §6, Prompt W3-2 (Wave 3 / P13) — this plan implements the 4tlog half only. The 4tExecutive-side consumption (two RAG rows on the Configuration Posture domain) is **out of scope** — separate repo/session, same as P12.

## Global Constraints

- Follow the established `threat_stats_cache.py`/`threat_stats_history.py` pattern exactly: lock-guarded in-memory cache, stale-but-honest on total poll failure, cache-first/history-fallback in the route.
- Never hit the lab FAZ appliance from tests — every test mocks `FAZClient` methods, following the existing `_stub_client` helper pattern in `tests/test_threat_stats_cache.py`.
- **Vendor-confirmed field names** (unlike P12's top-threats/top-type, which had zero confirmed row-column names, this task has real evidence): the vendored spec's `fortiview.json` embeds an HTML appendix table of Filterable/Sortable fields per view, inside the `url` parameter's `description` string (`api-info/FortiAnalyzer 7.6.7 FortiAnalyzer Modules fortiview.json`, `definitions.fortiview.view-name.run.add.req.properties.params.items.properties.url.description`). For `admin-logins`: sortable fields are `duration, f_user, fortigate, login_fail_num, login_num, total_change` (filterable: `dvid, f_user, timescale`). For `failed-authentication-attempts`: sortable fields are `agg_logid, fortigate, int_tunnelname, login_type, logintype, logview_filter, src_ip, subtype, total_num, user_src` (filterable: `community, dstip, dvid, initiator, interface, logid, logintype, method, policyid, remip, srcip, ssid, stamac, subtype, timescale, ui, user, vpntunnel, xauthuser`). Use these exact field names when reading rows: `admin-logins` rows carry `fortigate` (device name), `f_user` (username), `login_num` (successful logins), `login_fail_num` (failed logins); `failed-authentication-attempts` rows carry `fortigate` (device name), `src_ip` (source IP), `total_num` (count). These are still not live-confirmed (no lab access), so keep the same docstring convention as `get_sys_status`/`run_fortiview`: state plainly that the *field names* trace to the vendored spec's appendix table but the exact row shape is unconfirmed against live hardware.
- `THREAT_STATS_POLL_INTERVAL`/`THREAT_STATS_POLL_DISABLED` already exist and are reused as-is — no new scheduler or Config poll-interval knob for this feature.
- New Config knobs: `ADMIN_ACCESS_BUSINESS_HOURS` (default `"08:00-18:00"`), `ADMIN_ACCESS_TIMEZONE` (default `"America/Chicago"`) — both plain strings, parsed at poll time, not at Config-load time (matches the rest of `Config`'s style of storing raw env-derived values).
- `schema_version` in the executive-summary payload stays `1` — additive-only, same precedent as `"infra"` and `"threats"`.
- SQLite schema changes to an *already-shipped* table must be migration-safe: use `PRAGMA table_info` to check for each new column's existence before `ALTER TABLE ... ADD COLUMN`, never assume `CREATE TABLE IF NOT EXISTS` alone will add columns to a table that already exists on disk with the old 8-column schema.

---

### Task 1: `app/threat_stats_history.py` — migration-safe schema extension

**Files:**
- Modify: `app/threat_stats_history.py`
- Test: `tests/test_threat_stats_history.py`

**Interfaces:**
- Produces: `init_db()` now also ensures 4 new columns exist on `threat_stats_history` (idempotent, safe to call against a database created by the pre-existing 8-column schema). `write_rollup(...)` and `get_latest_rollup()` gain 4 new parameters/return keys: `failed_admin_logins_24h: int`, `devices_with_failed_logins: int`, `top_failed_sources: list[dict]`, `admin_logins_outside_hours_24h: int` — added after the existing `top_source_countries` parameter/key, before `collected_at`.

- [ ] **Step 1: Write failing tests**

Add to `tests/test_threat_stats_history.py`:

```python
def test_write_and_get_latest_rollup_includes_admin_access_fields(history_db):
    from app.threat_stats_history import get_latest_rollup, write_rollup

    write_rollup(
        alerts_unacked_total=5,
        alerts_unacked_by_severity={"critical": 1, "high": 2, "medium": 1, "low": 1},
        ips_detections_24h=100,
        ips_blocked_24h=80,
        ips_blocked_pct=80.0,
        top_signatures=[{"signature": "Eicar.Test.Virus", "count": 40}],
        top_source_countries=[{"country": "China", "count": 60}],
        failed_admin_logins_24h=7,
        devices_with_failed_logins=2,
        top_failed_sources=[{"source": "203.0.113.5", "count": 4}],
        admin_logins_outside_hours_24h=3,
        collected_at="2026-09-11T00:00:00+00:00",
    )
    rollup = get_latest_rollup()
    assert rollup["failed_admin_logins_24h"] == 7
    assert rollup["devices_with_failed_logins"] == 2
    assert rollup["top_failed_sources"] == [{"source": "203.0.113.5", "count": 4}]
    assert rollup["admin_logins_outside_hours_24h"] == 3


def test_init_db_migrates_pre_existing_table_missing_admin_access_columns(tmp_path, monkeypatch):
    import sqlite3

    import app.threat_stats_history as history_mod

    path = tmp_path / "logstats.db"
    monkeypatch.setattr(history_mod, "DB_PATH", path)

    # Simulate a database created by the OLD (pre-this-task) 8-column schema —
    # no failed_admin_logins_24h/devices_with_failed_logins/top_failed_sources/
    # admin_logins_outside_hours_24h columns, with one existing row.
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE threat_stats_history (
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
    conn.execute(
        "INSERT INTO threat_stats_history VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ("2026-09-10T00:00:00+00:00", 1, "{}", 0, 0, 0.0, "[]", "[]"),
    )
    conn.commit()
    conn.close()

    history_mod.init_db()  # must not raise, must add the 4 new columns

    rollup = history_mod.get_latest_rollup()
    assert rollup["collected_at"] == "2026-09-10T00:00:00+00:00"
    assert rollup["failed_admin_logins_24h"] == 0
    assert rollup["devices_with_failed_logins"] == 0
    assert rollup["top_failed_sources"] == []
    assert rollup["admin_logins_outside_hours_24h"] == 0

    # A second init_db() call (e.g. app restart) against the now-migrated
    # table must also be a no-op, not raise "duplicate column".
    history_mod.init_db()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_threat_stats_history.py -k admin_access -v`
Expected: FAIL — `TypeError: write_rollup() got an unexpected keyword argument 'failed_admin_logins_24h'` for the first test; `sqlite3.OperationalError: table threat_stats_history already exists` or a missing-column error for the second (since `init_db()` doesn't yet migrate).

- [ ] **Step 3: Implement the migration and extended read/write functions**

In `app/threat_stats_history.py`, replace `init_db()` with:

```python
_NEW_COLUMNS: dict[str, str] = {
    "failed_admin_logins_24h": "INTEGER NOT NULL DEFAULT 0",
    "devices_with_failed_logins": "INTEGER NOT NULL DEFAULT 0",
    "top_failed_sources": "TEXT NOT NULL DEFAULT '[]'",
    "admin_logins_outside_hours_24h": "INTEGER NOT NULL DEFAULT 0",
}


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
        existing = {row[1] for row in conn.execute("PRAGMA table_info(threat_stats_history)")}
        for column, ddl_type in _NEW_COLUMNS.items():
            if column not in existing:
                conn.execute(f"ALTER TABLE threat_stats_history ADD COLUMN {column} {ddl_type}")
```

Update `write_rollup`:

```python
def write_rollup(
    alerts_unacked_total: int,
    alerts_unacked_by_severity: dict,
    ips_detections_24h: int,
    ips_blocked_24h: int,
    ips_blocked_pct: float,
    top_signatures: list[dict],
    top_source_countries: list[dict],
    failed_admin_logins_24h: int,
    devices_with_failed_logins: int,
    top_failed_sources: list[dict],
    admin_logins_outside_hours_24h: int,
    collected_at: str,
) -> None:
    with contextlib.closing(_connect()) as conn, conn:
        conn.execute(
            "INSERT INTO threat_stats_history "
            "(collected_at, alerts_unacked_total, alerts_unacked_by_severity, "
            "ips_detections_24h, ips_blocked_24h, ips_blocked_pct, "
            "top_signatures, top_source_countries, failed_admin_logins_24h, "
            "devices_with_failed_logins, top_failed_sources, admin_logins_outside_hours_24h) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                collected_at,
                alerts_unacked_total,
                json.dumps(alerts_unacked_by_severity),
                ips_detections_24h,
                ips_blocked_24h,
                ips_blocked_pct,
                json.dumps(top_signatures),
                json.dumps(top_source_countries),
                failed_admin_logins_24h,
                devices_with_failed_logins,
                json.dumps(top_failed_sources),
                admin_logins_outside_hours_24h,
            ),
        )
```

Update `get_latest_rollup`:

```python
def get_latest_rollup() -> dict | None:
    with contextlib.closing(_connect()) as conn, conn:
        row = conn.execute(
            "SELECT collected_at, alerts_unacked_total, alerts_unacked_by_severity, "
            "ips_detections_24h, ips_blocked_24h, ips_blocked_pct, "
            "top_signatures, top_source_countries, failed_admin_logins_24h, "
            "devices_with_failed_logins, top_failed_sources, admin_logins_outside_hours_24h "
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
        failed_admin_logins_24h,
        devices_with_failed_logins,
        top_failed_sources,
        admin_logins_outside_hours_24h,
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
        "failed_admin_logins_24h": failed_admin_logins_24h,
        "devices_with_failed_logins": devices_with_failed_logins,
        "top_failed_sources": json.loads(top_failed_sources),
        "admin_logins_outside_hours_24h": admin_logins_outside_hours_24h,
    }
```

`prune_old_rows` is unchanged.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_threat_stats_history.py -v`
Expected: PASS (all tests in the file, including the 2 new ones)

- [ ] **Step 5: Commit**

```bash
git add app/threat_stats_history.py tests/test_threat_stats_history.py
git commit -m "feat: extend threat_stats_history with admin-access rollup columns"
```

---

### Task 2: `app/threat_stats_cache.py` — admin-logins/failed-authentication-attempts collection

**Files:**
- Modify: `app/config.py`
- Modify: `app/threat_stats_cache.py`
- Test: `tests/test_threat_stats_cache.py`

**Interfaces:**
- Consumes: `threat_stats_history.write_rollup(...)`'s 4 new parameters (Task 1), `FAZClient.run_fortiview`/`local_time_range` (pre-existing, unchanged).
- Produces: `get_cached()`'s return dict gains 4 new keys: `failed_admin_logins_24h: int`, `devices_with_failed_logins: int`, `top_failed_sources: list[dict]` (`[{"source": str, "count": int}]`), `admin_logins_outside_hours_24h: int` — flat, alongside the existing threat keys, sharing the same `collected_at`. `_poll_one_target`'s signature changes from `_poll_one_target(client) -> dict` to `_poll_one_target(client, now: datetime.datetime) -> dict` (hoisting `now` up to `poll_all_targets` so every target in one poll cycle shares one timestamp, and so tests can control "now" without monkeypatching `datetime.datetime.now`).

- [ ] **Step 1: Add Config knobs**

In `app/config.py`, after the `THREAT_STATS_POLL_DISABLED` block:

```python
    # Business-hours window for the admin-access anomaly detector
    # (app/threat_stats_cache.py) — "outside hours" admin logins are
    # flagged relative to this window. Format: "HH:MM-HH:MM" in
    # ADMIN_ACCESS_TIMEZONE (an IANA zone name).
    ADMIN_ACCESS_BUSINESS_HOURS = os.environ.get("ADMIN_ACCESS_BUSINESS_HOURS", "08:00-18:00")
    ADMIN_ACCESS_TIMEZONE = os.environ.get("ADMIN_ACCESS_TIMEZONE", "America/Chicago")
```

- [ ] **Step 2: Write failing tests for the business-hours helpers**

Add to `tests/test_threat_stats_cache.py`:

```python
def test_parse_business_hours_default():
    from app.threat_stats_cache import _parse_business_hours

    start, end = _parse_business_hours()
    assert start.hour == 8 and start.minute == 0
    assert end.hour == 18 and end.minute == 0


def test_parse_business_hours_respects_config(monkeypatch):
    from app.config import Config
    from app.threat_stats_cache import _parse_business_hours

    monkeypatch.setattr(Config, "ADMIN_ACCESS_BUSINESS_HOURS", "09:30-17:15")
    start, end = _parse_business_hours()
    assert (start.hour, start.minute) == (9, 30)
    assert (end.hour, end.minute) == (17, 15)


def test_business_hours_range_returns_todays_window_so_far(monkeypatch):
    import datetime

    from app.config import Config
    from app.threat_stats_cache import _business_hours_range

    monkeypatch.setattr(Config, "ADMIN_ACCESS_BUSINESS_HOURS", "08:00-18:00")
    monkeypatch.setattr(Config, "ADMIN_ACCESS_TIMEZONE", "UTC")

    class FakeClient:
        def local_time_range(self, start_iso, end_iso):
            return (start_iso, end_iso)  # identity passthrough for this test

    now_utc = datetime.datetime(2026, 9, 11, 14, 0, 0, tzinfo=datetime.timezone.utc)
    result = _business_hours_range(FakeClient(), now_utc)
    assert result is not None
    start_iso, end_iso = result
    assert start_iso.startswith("2026-09-11T08:00:00")
    assert end_iso.startswith("2026-09-11T14:00:00")  # clamped to "now", not 18:00


def test_business_hours_range_returns_none_before_business_hours_start(monkeypatch):
    import datetime

    from app.config import Config
    from app.threat_stats_cache import _business_hours_range

    monkeypatch.setattr(Config, "ADMIN_ACCESS_BUSINESS_HOURS", "08:00-18:00")
    monkeypatch.setattr(Config, "ADMIN_ACCESS_TIMEZONE", "UTC")

    class FakeClient:
        def local_time_range(self, start_iso, end_iso):
            return (start_iso, end_iso)

    now_utc = datetime.datetime(2026, 9, 11, 5, 0, 0, tzinfo=datetime.timezone.utc)
    assert _business_hours_range(FakeClient(), now_utc) is None
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run pytest tests/test_threat_stats_cache.py -k "business_hours" -v`
Expected: FAIL with `ImportError`/`AttributeError` — `_parse_business_hours`/`_business_hours_range` don't exist yet.

- [ ] **Step 4: Implement the business-hours helpers**

In `app/threat_stats_cache.py`, add near the top (after the `SEVERITIES` constant), with the new import:

```python
from zoneinfo import ZoneInfo
```

```python
def _parse_business_hours() -> tuple[datetime.time, datetime.time]:
    """Parse Config.ADMIN_ACCESS_BUSINESS_HOURS ("HH:MM-HH:MM") into
    (start, end) datetime.time objects."""
    start_str, _, end_str = Config.ADMIN_ACCESS_BUSINESS_HOURS.partition("-")
    start_h, start_m = (int(x) for x in start_str.split(":"))
    end_h, end_m = (int(x) for x in end_str.split(":"))
    return datetime.time(start_h, start_m), datetime.time(end_h, end_m)


def _business_hours_range(client, now_utc: datetime.datetime) -> tuple[str, str] | None:
    """Today's business-hours window "so far" (per Config.ADMIN_ACCESS_TIMEZONE
    and Config.ADMIN_ACCESS_BUSINESS_HOURS), converted to the FAZ appliance's
    local time via client.local_time_range, as (start, end) strings suitable
    for run_fortiview's time_range. Returns None if business hours haven't
    started yet today in ADMIN_ACCESS_TIMEZONE (nothing to count).

    Known limitation: only considers TODAY's business window intersected
    with "now", not a rolling 24h lookback — if the poll runs shortly after
    local midnight, yesterday's business window (which may still partly
    fall within the trailing 24h admin-logins query) is not counted as
    "business hours", so admin_logins_outside_hours_24h can be a slight
    overestimate in the few hours after midnight. Acceptable for an
    informational executive-summary metric; not exact-audit-grade.
    """
    start_time, end_time = _parse_business_hours()
    tz = ZoneInfo(Config.ADMIN_ACCESS_TIMEZONE)
    now_local = now_utc.astimezone(tz)
    business_start_local = now_local.replace(
        hour=start_time.hour, minute=start_time.minute, second=0, microsecond=0
    )
    business_end_local = now_local.replace(
        hour=end_time.hour, minute=end_time.minute, second=0, microsecond=0
    )
    business_end_local = min(business_end_local, now_local)
    if business_start_local >= business_end_local:
        return None
    business_start_utc = business_start_local.astimezone(datetime.timezone.utc)
    business_end_utc = business_end_local.astimezone(datetime.timezone.utc)
    return client.local_time_range(business_start_utc.isoformat(), business_end_utc.isoformat())
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_threat_stats_cache.py -k "business_hours" -v`
Expected: PASS (4 tests)

- [ ] **Step 6: Commit**

```bash
git add app/config.py app/threat_stats_cache.py tests/test_threat_stats_cache.py
git commit -m "feat: add business-hours window helpers for admin-access anomaly detection"
```

- [ ] **Step 7: Extend the existing test stub for multi-call views**

The existing `_stub_client` helper's `fake_run_fortiview` maps `view -> rows` via a flat dict, returning the same rows for every call to a given view. This task calls `admin-logins` **twice** per target with different `time_range` arguments (once for the full 24h window, once for the business-hours-so-far sub-window) — the stub must be able to return different rows for each call.

Modify `_stub_client` in `tests/test_threat_stats_cache.py` so each entry in `fortiview_rows_by_view` may be either a plain list of row dicts (returned for every call to that view, unchanged behavior for `top-type`/`top-threats`/`top-countries`), or a list of lists (a queue, popped in call order — one queue entry consumed per call to that view):

```python
def _stub_client(
    monkeypatch, alert_counts_by_filter, fortiview_rows_by_view, local_time_range=None
):
    def fake_get_alert_counts(self, adom, filter):
        return alert_counts_by_filter[filter]

    call_counts: dict[str, int] = {}

    def fake_run_fortiview(self, adom, view, time_range, limit=1000, filter=None, **_kw):
        entry = fortiview_rows_by_view[view]
        if entry and isinstance(entry[0], list):
            idx = call_counts.get(view, 0)
            call_counts[view] = idx + 1
            return entry[idx]
        return entry

    monkeypatch.setattr("app.faz_client.FAZClient.get_alert_counts", fake_get_alert_counts)
    monkeypatch.setattr("app.faz_client.FAZClient.run_fortiview", fake_run_fortiview)
    monkeypatch.setattr("app.faz_client.FAZClient.logout", lambda self: None)
    if local_time_range is not None:
        monkeypatch.setattr(
            "app.faz_client.FAZClient.local_time_range",
            lambda self, start_iso, end_iso: local_time_range,
        )
```

Note: with a stubbed `local_time_range` returning one fixed tuple (as most existing tests already do via the `local_time_range=` kwarg), the "24h" and "business-hours" calls to `run_fortiview` for `admin-logins` will both receive that same `time_range` argument from the poller's point of view (since `local_time_range` is stubbed to always return the same thing) — that's fine, the stub distinguishes the two calls by *call order*, not by inspecting `time_range`.

Run the full existing `tests/test_threat_stats_cache.py -v` after this change (before adding any new tests) to confirm the stub change is backward-compatible and every pre-existing test in the file still passes unmodified.

- [ ] **Step 8: Commit the stub extension on its own**

```bash
git add tests/test_threat_stats_cache.py
git commit -m "test: let threat_stats_cache's FAZClient stub return per-call fortiview rows"
```

- [ ] **Step 9: Write failing tests for the admin-access collection and aggregation**

Add to `tests/test_threat_stats_cache.py`:

```python
def test_poll_all_targets_populates_admin_access_fields(targets_file, history_db, monkeypatch):
    import app.threat_stats_cache as cache_mod
    from app.threat_stats_history import get_latest_rollup

    _stub_client(
        monkeypatch,
        alert_counts_by_filter={
            "ackflag=no": 0,
            "ackflag=no and severity=critical": 0,
            "ackflag=no and severity=high": 0,
            "ackflag=no and severity=medium": 0,
            "ackflag=no and severity=low": 0,
        },
        fortiview_rows_by_view={
            "top-type": [],
            "top-threats": [],
            "top-countries": [],
            "admin-logins": [
                # Call 1: full 24h window.
                [
                    {"fortigate": "FGT-A", "f_user": "admin", "login_num": 10, "login_fail_num": 3},
                    {"fortigate": "FGT-B", "f_user": "svc", "login_num": 2, "login_fail_num": 0},
                ],
                # Call 2: business-hours-so-far window.
                [
                    {"fortigate": "FGT-A", "f_user": "admin", "login_num": 6, "login_fail_num": 1},
                ],
            ],
            "failed-authentication-attempts": [
                {"fortigate": "FGT-A", "src_ip": "203.0.113.5", "total_num": 3},
                {"fortigate": "FGT-A", "src_ip": "203.0.113.9", "total_num": 1},
            ],
        },
        local_time_range=("2026-09-11T08:00:00", "2026-09-11T14:00:00"),
    )

    cache_mod.poll_all_targets()

    cached = cache_mod.get_cached()
    assert cached["failed_admin_logins_24h"] == 3  # sum of login_fail_num across admin-logins 24h rows
    assert cached["devices_with_failed_logins"] == 1  # only FGT-A has login_fail_num > 0
    assert cached["top_failed_sources"] == [
        {"source": "203.0.113.5", "count": 3},
        {"source": "203.0.113.9", "count": 1},
    ]
    # total login_num (24h) = 10 + 2 = 12; business-hours login_num = 6;
    # outside_hours = max(12 - 6, 0) = 6
    assert cached["admin_logins_outside_hours_24h"] == 6

    rollup = get_latest_rollup()
    assert rollup["failed_admin_logins_24h"] == 3
    assert rollup["devices_with_failed_logins"] == 1
    assert rollup["admin_logins_outside_hours_24h"] == 6


def test_poll_all_targets_admin_access_zero_when_business_hours_havent_started(
    targets_file, history_db, monkeypatch
):
    """When _business_hours_range returns None (business hours haven't
    started yet today), only ONE admin-logins call happens — all logins in
    the 24h window count as outside-hours."""
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
        fortiview_rows_by_view={
            "top-type": [],
            "top-threats": [],
            "top-countries": [],
            "admin-logins": [
                {"fortigate": "FGT-A", "f_user": "admin", "login_num": 5, "login_fail_num": 0},
            ],
            "failed-authentication-attempts": [],
        },
        local_time_range=("2026-09-11T00:00:00", "2026-09-11T05:00:00"),
    )
    # Force _business_hours_range to return None regardless of wall-clock time.
    monkeypatch.setattr("app.threat_stats_cache._business_hours_range", lambda client, now: None)

    cache_mod.poll_all_targets()

    cached = cache_mod.get_cached()
    assert cached["admin_logins_outside_hours_24h"] == 5
```

Note: in the second test, `fortiview_rows_by_view["admin-logins"]` is a plain list (not a list-of-lists), which is intentional — `_business_hours_range` is monkeypatched to return `None`, so `run_fortiview` for `admin-logins` is only ever called once, and the stub's "plain list = same rows every call" behavior naturally applies.

- [ ] **Step 10: Run tests to verify they fail**

Run: `uv run pytest tests/test_threat_stats_cache.py -k "admin_access" -v`
Expected: FAIL — `KeyError: 'failed_admin_logins_24h'` (cache dict doesn't have the key yet).

- [ ] **Step 11: Implement the collection and aggregation**

In `app/threat_stats_cache.py`, extend `_EMPTY_CACHE`:

```python
_EMPTY_CACHE: dict = {
    "alerts_unacked_total": 0,
    "alerts_unacked_by_severity": {sev: 0 for sev in SEVERITIES},
    "ips_detections_24h": 0,
    "ips_blocked_24h": 0,
    "ips_blocked_pct": 0.0,
    "top_signatures": [],
    "top_source_countries": [],
    "failed_admin_logins_24h": 0,
    "devices_with_failed_logins": 0,
    "top_failed_sources": [],
    "admin_logins_outside_hours_24h": 0,
    "collected_at": None,
}
```

Change `_poll_one_target`'s signature and body — add the `now` parameter and the two new FortiView calls, reusing the already-computed `time_range` for the admin-logins 24h call:

```python
def _poll_one_target(client, now: datetime.datetime) -> dict:
    """Collect one target's threat stats. Raises FAZError/Exception on any
    failure — the caller decides whether to skip this target or abort."""
    alerts_unacked_total = client.get_alert_counts(client.adom, "ackflag=no")
    alerts_unacked_by_severity = {
        sev: client.get_alert_counts(client.adom, f"ackflag=no and severity={sev}")
        for sev in SEVERITIES
    }

    utc_start, utc_end = _last_24h_range(now)
    # FortiAnalyzer interprets FortiView's time-range in the appliance's own
    # configured timezone, not UTC (see FAZClient.local_time_range's
    # docstring for the live-confirmed finding) — convert before using it,
    # same as app/routes/log_search_routes.py does for log searches.
    time_range = client.local_time_range(utc_start, utc_end)

    type_rows = client.run_fortiview(client.adom, "top-type", time_range, limit=50)
    ips_row = next((r for r in type_rows if str(r.get("type", "")).strip().lower() == "ips"), None)
    ips_detections_24h = int(ips_row.get("count", 0) or 0) if ips_row else 0
    ips_blocked_24h = int(ips_row.get("blockedsessions", 0) or 0) if ips_row else 0

    signature_rows = client.run_fortiview(
        client.adom, "top-threats", time_range, limit=5, filter="type==ips"
    )
    country_rows = client.run_fortiview(
        client.adom, "top-countries", time_range, limit=5, filter="type==ips"
    )

    # Admin access anomalies (P13): row field names ("fortigate", "f_user",
    # "login_num", "login_fail_num" for admin-logins; "fortigate", "src_ip",
    # "total_num" for failed-authentication-attempts) trace to the vendored
    # spec's Filterable/Sortable-field appendix table (see this plan's
    # Global Constraints) — not yet confirmed live against real hardware.
    admin_logins_24h_rows = client.run_fortiview(client.adom, "admin-logins", time_range, limit=1000)
    failed_auth_rows = client.run_fortiview(
        client.adom, "failed-authentication-attempts", time_range, limit=1000
    )

    failed_admin_logins_24h = sum(
        int(r.get("login_fail_num", 0) or 0) for r in admin_logins_24h_rows
    )
    total_logins_24h = sum(int(r.get("login_num", 0) or 0) for r in admin_logins_24h_rows)
    devices_with_failed_login_names = {
        r.get("fortigate", "")
        for r in admin_logins_24h_rows
        if int(r.get("login_fail_num", 0) or 0) > 0
    }
    devices_with_failed_login_names.discard("")

    business_range = _business_hours_range(client, now)
    if business_range is not None:
        business_rows = client.run_fortiview(client.adom, "admin-logins", business_range, limit=1000)
        business_logins = sum(int(r.get("login_num", 0) or 0) for r in business_rows)
    else:
        business_logins = 0
    admin_logins_outside_hours_24h = max(total_logins_24h - business_logins, 0)

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
        "failed_admin_logins_24h": failed_admin_logins_24h,
        "devices_with_failed_login_names": devices_with_failed_login_names,
        "top_failed_sources": [
            {"source": r.get("src_ip", ""), "count": int(r.get("total_num", 0) or 0)}
            for r in failed_auth_rows
        ],
        "admin_logins_outside_hours_24h": admin_logins_outside_hours_24h,
    }
```

In `poll_all_targets`, pass `now` into `_poll_one_target` (compute it once, before the loop, alongside the existing `results`/`polled_ok` setup) and extend the aggregation block:

```python
def poll_all_targets() -> None:
    import app.threat_stats_history as history
    from app.app_logger import app_log
    from app.faz_client import FAZClient, FAZError, summarize_connection_error
    from app.faz_targets import list_targets

    now = datetime.datetime.now(datetime.timezone.utc)
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
                results.append(_poll_one_target(client, now))
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
    top_source_countries = _merge_top_lists([r["top_source_countries"] for r in results], "country")

    failed_admin_logins_24h = sum(r["failed_admin_logins_24h"] for r in results)
    admin_logins_outside_hours_24h = sum(r["admin_logins_outside_hours_24h"] for r in results)
    devices_with_failed_logins = len(
        set().union(*(r["devices_with_failed_login_names"] for r in results))
    ) if results else 0
    top_failed_sources = _merge_top_lists([r["top_failed_sources"] for r in results], "source")

    collected_at = _now()
    with _lock:
        _cache["alerts_unacked_total"] = alerts_unacked_total
        _cache["alerts_unacked_by_severity"] = alerts_unacked_by_severity
        _cache["ips_detections_24h"] = ips_detections_24h
        _cache["ips_blocked_24h"] = ips_blocked_24h
        _cache["ips_blocked_pct"] = ips_blocked_pct
        _cache["top_signatures"] = top_signatures
        _cache["top_source_countries"] = top_source_countries
        _cache["failed_admin_logins_24h"] = failed_admin_logins_24h
        _cache["devices_with_failed_logins"] = devices_with_failed_logins
        _cache["top_failed_sources"] = top_failed_sources
        _cache["admin_logins_outside_hours_24h"] = admin_logins_outside_hours_24h
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
        failed_admin_logins_24h=failed_admin_logins_24h,
        devices_with_failed_logins=devices_with_failed_logins,
        top_failed_sources=top_failed_sources,
        admin_logins_outside_hours_24h=admin_logins_outside_hours_24h,
        collected_at=collected_at,
    )
    history.prune_old_rows()
```

`poll_now`/`init_scheduler` are unchanged.

- [ ] **Step 12: Run tests to verify they pass**

Run: `uv run pytest tests/test_threat_stats_cache.py -v`
Expected: PASS (all tests in the file, including the new ones)

- [ ] **Step 13: Run the full suite**

Run: `uv run pytest -q`
Expected: PASS, no regressions

- [ ] **Step 14: Commit**

```bash
git add app/threat_stats_cache.py tests/test_threat_stats_cache.py
git commit -m "feat: collect admin-logins/failed-authentication-attempts into threat_stats_cache"
```

---

### Task 3: `"admin_access"` key in `GET /external/api/executive/summary`

**Files:**
- Modify: `app/routes/external_api_routes.py`
- Test: `tests/test_external_api_routes.py`

**Interfaces:**
- Consumes: `threat_stats_cache.get_cached()`'s 4 new keys and `threat_stats_history.get_latest_rollup()`'s 4 new keys (Task 2/1), `Config.ADMIN_ACCESS_BUSINESS_HOURS`/`Config.ADMIN_ACCESS_TIMEZONE` (Task 2).
- Produces: response payload gains `"admin_access": {"failed_admin_logins_24h": int, "devices_with_failed_logins": int, "top_failed_sources": [{"source": str, "count": int}], "admin_logins_outside_hours_24h": int, "business_hours": str, "collected_at": str | None}`. `business_hours` is built fresh from current `Config` values on every request (not stored in the cache/history — same reasoning as the existing `"silent_device_threshold_minutes"` field a few lines above, which also reads `Config` directly rather than persisting a threshold that was live at poll time).

- [ ] **Step 1: Write failing tests**

Add to `tests/test_external_api_routes.py`:

```python
def test_admin_access_key_shape_from_cache(client, monkeypatch):
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
            "alerts_unacked_total": 0,
            "alerts_unacked_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "ips_detections_24h": 0,
            "ips_blocked_24h": 0,
            "ips_blocked_pct": 0.0,
            "top_signatures": [],
            "top_source_countries": [],
            "failed_admin_logins_24h": 4,
            "devices_with_failed_logins": 1,
            "top_failed_sources": [{"source": "203.0.113.5", "count": 4}],
            "admin_logins_outside_hours_24h": 2,
            "collected_at": "2026-09-11T12:00:00+00:00",
        },
    )

    resp = client.get("/external/api/executive/summary", headers={"Authorization": f"Bearer {raw}"})
    assert resp.status_code == 200
    admin_access = resp.get_json()["admin_access"]
    assert admin_access["failed_admin_logins_24h"] == 4
    assert admin_access["devices_with_failed_logins"] == 1
    assert admin_access["top_failed_sources"] == [{"source": "203.0.113.5", "count": 4}]
    assert admin_access["admin_logins_outside_hours_24h"] == 2
    assert admin_access["business_hours"] == "08:00-18:00 America/Chicago"
    assert admin_access["collected_at"] == "2026-09-11T12:00:00+00:00"


def test_admin_access_business_hours_reflects_config_override(client, monkeypatch):
    raw = _enable_and_token()

    import app.faz_health_cache as health_mod
    import app.log_stats_cache as logstats_mod
    import app.threat_stats_cache as threat_mod
    from app.config import Config

    monkeypatch.setattr(Config, "ADMIN_ACCESS_BUSINESS_HOURS", "09:00-17:00")
    monkeypatch.setattr(Config, "ADMIN_ACCESS_TIMEZONE", "UTC")
    monkeypatch.setattr(health_mod, "get_all_cached", lambda: [])
    monkeypatch.setattr(
        logstats_mod,
        "get_cached",
        lambda: {"logging_devices": [], "silent_devices": [], "collected_at": None},
    )
    monkeypatch.setattr(threat_mod, "get_cached", lambda: {"collected_at": None})

    resp = client.get("/external/api/executive/summary", headers={"Authorization": f"Bearer {raw}"})
    assert resp.get_json()["admin_access"]["business_hours"] == "09:00-17:00 UTC"


def test_admin_access_all_zero_when_no_cache_and_no_history(client, monkeypatch):
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
    admin_access = resp.get_json()["admin_access"]
    assert admin_access["failed_admin_logins_24h"] == 0
    assert admin_access["devices_with_failed_logins"] == 0
    assert admin_access["top_failed_sources"] == []
    assert admin_access["admin_logins_outside_hours_24h"] == 0
    assert admin_access["collected_at"] is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_external_api_routes.py -k admin_access -v`
Expected: FAIL with `KeyError: 'admin_access'`

- [ ] **Step 3: Implement**

In `app/routes/external_api_routes.py`, add a helper next to `_build_threats`:

```python
def _build_admin_access(cache: dict, rollup: dict | None) -> dict:
    from app.config import Config

    source = cache if cache.get("collected_at") is not None else (rollup or {})
    return {
        "failed_admin_logins_24h": source.get("failed_admin_logins_24h", 0),
        "devices_with_failed_logins": source.get("devices_with_failed_logins", 0),
        "top_failed_sources": source.get("top_failed_sources", []),
        "admin_logins_outside_hours_24h": source.get("admin_logins_outside_hours_24h", 0),
        "business_hours": f"{Config.ADMIN_ACCESS_BUSINESS_HOURS} {Config.ADMIN_ACCESS_TIMEZONE}",
        "collected_at": source.get("collected_at"),
    }
```

In `executive_summary()`, reuse the already-fetched `threat_cache`/`threat_rollup` (computed for `_build_threats`) rather than re-reading the cache/history a second time:

```python
    threats = _build_threats(threat_cache, threat_rollup)
    admin_access = _build_admin_access(threat_cache, threat_rollup)
```

...and add `"admin_access": admin_access,` to the returned dict, after `"threats": threats,`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_external_api_routes.py -v`
Expected: PASS (all tests in the file, including the 3 new ones)

- [ ] **Step 5: Run the full suite and ruff**

Run: `uv run ruff check . && uv run ruff format --check . && uv run pytest -q`
Expected: PASS, no regressions (run BOTH `ruff check` and `ruff format --check` — the previous plan's final review found `ruff check` alone was insufficient to catch formatting regressions)

- [ ] **Step 6: Commit**

```bash
git add app/routes/external_api_routes.py tests/test_external_api_routes.py
git commit -m "feat: expose admin-access anomalies under executive summary's admin_access key"
```

---

### Task 4: Docs — README.md, CHANGELOG.md, .env.example

**Files:**
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `.env.example`

**Interfaces:** none (documentation only).

- [ ] **Step 1: Update `.env.example`**

After the `THREAT_STATS_POLL_INTERVAL` block, add:

```
# Business-hours window for the admin-access anomaly detector (see README.md)
# ADMIN_ACCESS_BUSINESS_HOURS=08:00-18:00
# ADMIN_ACCESS_TIMEZONE=America/Chicago
```

- [ ] **Step 2: Update `README.md`**

In the External API bullet, after the `"threats"` key sentence added by the previous plan, add:

"Also includes an `"admin_access"` key — `{failed_admin_logins_24h, devices_with_failed_logins, top_failed_sources: [{source, count}] (top 5), admin_logins_outside_hours_24h, business_hours, collected_at}` — from the same threat-activity poller, using FortiView's `admin-logins` and `failed-authentication-attempts` reports. `business_hours` (default `08:00-18:00 America/Chicago`, configurable via `ADMIN_ACCESS_BUSINESS_HOURS`/`ADMIN_ACCESS_TIMEZONE` in `.env.example`) describes the window `admin_logins_outside_hours_24h` is measured against — note it only accounts for the current calendar day's business window in the configured timezone, so the few hours right after local midnight can slightly overcount 'outside hours' logins."

- [ ] **Step 3: Add a `CHANGELOG.md` entry**

Add a new dated section at the top (use today's date):

```markdown
## 2026-09-11

### Added

- External API: `GET /external/api/executive/summary` gains an
  `"admin_access"` key — failed admin login counts, devices with failed
  logins, top 5 failed-login source IPs, and an outside-business-hours
  admin-login count — from the existing threat-activity poller
  (`app/threat_stats_cache.py`), now also querying FortiView's
  `admin-logins` and `failed-authentication-attempts` reports. Business
  hours are configurable via `ADMIN_ACCESS_BUSINESS_HOURS`/
  `ADMIN_ACCESS_TIMEZONE` in `.env.example` (default `08:00-18:00
  America/Chicago`). Rollups persist in `logstats.db` alongside the
  existing threat-activity history (migration-safe column addition).
```

- [ ] **Step 4: Commit**

```bash
git add README.md CHANGELOG.md .env.example
git commit -m "docs: document the admin-access anomaly detector"
```

---

## Out of scope

The 4tExecutive-side consumption (two RAG rows — failed logins: green < 5, amber < 20, red >= 20; outside-hours logins: informational — on the Configuration Posture domain page) lives in a separate repo (`~/code/github/web/4tExecutive`) and needs its own plan/session there, once this plan's `"admin_access"` payload is live to build against.
