# VPN Tunnel Coverage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the existing `app/threat_stats_cache.py` poller (threat-activity-collector, admin-access-anomalies) with two more FortiView views — `site-to-site-ipsec` and `ssl-dialup-ipsec` — and expose a new `"vpn"` key in `GET /external/api/executive/summary`: `{ipsec_tunnels_total, ipsec_tunnels_down, ssl_vpn_users_now, collected_at}`.

**Architecture:** A third pair of per-target FortiView collection calls, folded into the SAME poll cycle the existing collector already runs — no new scheduler, no new cache module, same `threat_stats_history` table (a third migration-safe column batch). Unlike the alert/IPS/admin-access metrics, FortiAnalyzer's FortiView API has no "tunnel status" field — `site-to-site-ipsec`/`ssl-dialup-ipsec` are session-log views, not live device-config views. Tunnel liveness is therefore *inferred*: a tunnel/user is "up"/"connected now" if at least one of its logged sessions in the trailing 24h window has no end timestamp (still open); a tunnel is "down" if it was seen at all in the last 24h (so it's a real, previously-working tunnel) but every session for it has since closed. This mirrors the same "recent log presence = liveness" philosophy `log_stats_cache.py`'s silent-device detection already uses, and is explicitly documented as an approximation, not a live tunnel-status API.

**Tech Stack:** Flask, APScheduler, `requests`, `sqlite3` (stdlib), pytest + `monkeypatch`.

**Spec:** `~/Downloads/4texecutive2.md` §6, Prompt W3-3 (Wave 3 / P14) — this plan implements the 4tlog third of that prompt only. The 4thealth-plus half (`devices_not_forwarding_to_faz` on `device_review`) and the 4tExecutive half (extractors, RAG rows) are **separate repos** and out of scope here — each needs its own session in its own working directory.

## Global Constraints

- Follow the established `threat_stats_cache.py`/`threat_stats_history.py` pattern exactly: lock-guarded in-memory cache, stale-but-honest on total poll failure, cache-first/history-fallback in the route, migration-safe SQLite column additions (`PRAGMA table_info` + `ALTER TABLE ADD COLUMN`, per the precedent already in `threat_stats_history.py`'s `_NEW_COLUMNS` dict).
- Never hit the lab FAZ appliance from tests — every test mocks `FAZClient` methods via the existing `_stub_client` helper in `tests/test_threat_stats_cache.py`.
- **Vendor-confirmed field names** (same evidence source as the admin-access-anomalies plan): the vendored spec's `fortiview.json` embeds an HTML appendix table of Filterable/Sortable fields per view inside the `url` parameter's `description` string. For `site-to-site-ipsec`: filterable fields are `dvid, e_time, locip, max_duration, max_traffic_in, max_traffic_out, min_duration, min_traffic_in, min_traffic_out, remip, s_time, timescale, tunnelid, vpnname`; sortable fields are `bandwidth, duration, locip, remip, traffic_in, traffic_out, vpnname`. For `ssl-dialup-ipsec`: filterable fields are `dvid, max_duration, max_traffic_in, max_traffic_out, min_duration, min_traffic_in, min_traffic_out, remip, s_time, timescale, tunneltype, user_agg, vpntunnel, vpnusergroup, xauthuser_agg`; sortable fields are `bandwidth, connections, device_group, duration, end_time, f_user, fv_dtime_tz_conv_e_time_t, remip, traffic_in, traffic_out, vpn_type_group`. Use these field names when reading rows: `site-to-site-ipsec` rows carry `vpnname` (tunnel name), `tunnelid` (fallback identity), `e_time` (session end timestamp — falsy/absent means the session is still open); `ssl-dialup-ipsec` rows carry `f_user` (username), `end_time` (session end timestamp — falsy/absent means still connected). These are still not live-confirmed against real hardware — keep the established docstring convention (`get_sys_status`/`run_fortiview`/the admin-access views) of stating plainly that field names trace to the vendored spec's appendix but the row shape overall is unconfirmed.
- No new Config knobs and no new scheduler — reuses `THREAT_STATS_POLL_INTERVAL`/`THREAT_STATS_POLL_DISABLED` and the poll cycle's already-converted 24h `time_range` as-is (same reuse pattern `admin-logins`'s 24h call already established: no extra `local_time_range`/`get_sys_status` round trip needed for this feature).
- `schema_version` in the executive-summary payload stays `1` — additive-only, same precedent as `"infra"`/`"threats"`/`"admin_access"`.
- Both `uv run ruff check .` AND `uv run ruff format --check .` must be clean on every touched file before each commit (lesson carried forward from the two prior plans' final reviews).

---

### Task 1: `app/threat_stats_history.py` — migration-safe schema extension

**Files:**
- Modify: `app/threat_stats_history.py`
- Test: `tests/test_threat_stats_history.py`

**Interfaces:**
- Produces: `init_db()` now also ensures 3 more columns exist on `threat_stats_history` (idempotent, safe against a database created by any earlier schema — 8-column original or the 12-column admin-access schema). `write_rollup(...)`/`get_latest_rollup()` gain 3 new parameters/return keys: `ipsec_tunnels_total: int`, `ipsec_tunnels_down: int`, `ssl_vpn_users_now: int` — added after the existing `admin_logins_outside_hours_24h` parameter/key, before `collected_at`.

- [ ] **Step 1: Write failing tests**

Add to `tests/test_threat_stats_history.py`:

```python
def test_write_and_get_latest_rollup_includes_vpn_fields(history_db):
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
        ipsec_tunnels_total=6,
        ipsec_tunnels_down=1,
        ssl_vpn_users_now=12,
        collected_at="2026-09-11T00:00:00+00:00",
    )
    rollup = get_latest_rollup()
    assert rollup["ipsec_tunnels_total"] == 6
    assert rollup["ipsec_tunnels_down"] == 1
    assert rollup["ssl_vpn_users_now"] == 12


def test_init_db_migrates_pre_existing_table_missing_vpn_columns(tmp_path, monkeypatch):
    import sqlite3

    import app.threat_stats_history as history_mod

    path = tmp_path / "logstats.db"
    monkeypatch.setattr(history_mod, "DB_PATH", path)

    # Simulate a database created by the admin-access-era 12-column schema —
    # no ipsec_tunnels_total/ipsec_tunnels_down/ssl_vpn_users_now columns,
    # with one existing row.
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
            top_source_countries TEXT NOT NULL,
            failed_admin_logins_24h INTEGER NOT NULL DEFAULT 0,
            devices_with_failed_logins INTEGER NOT NULL DEFAULT 0,
            top_failed_sources TEXT NOT NULL DEFAULT '[]',
            admin_logins_outside_hours_24h INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    conn.execute(
        "INSERT INTO threat_stats_history VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("2026-09-10T00:00:00+00:00", 1, "{}", 0, 0, 0.0, "[]", "[]", 0, 0, "[]", 0),
    )
    conn.commit()
    conn.close()

    history_mod.init_db()  # must not raise, must add the 3 new columns

    rollup = history_mod.get_latest_rollup()
    assert rollup["collected_at"] == "2026-09-10T00:00:00+00:00"
    assert rollup["ipsec_tunnels_total"] == 0
    assert rollup["ipsec_tunnels_down"] == 0
    assert rollup["ssl_vpn_users_now"] == 0

    # A second init_db() call (e.g. app restart) against the now-migrated
    # table must also be a no-op, not raise "duplicate column".
    history_mod.init_db()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_threat_stats_history.py -k vpn -v`
Expected: FAIL — `TypeError: write_rollup() got an unexpected keyword argument 'ipsec_tunnels_total'` for the first test; a missing-column error for the second (since `init_db()` doesn't yet migrate these 3 columns).

- [ ] **Step 3: Implement**

In `app/threat_stats_history.py`, extend `_NEW_COLUMNS`:

```python
_NEW_COLUMNS: dict[str, str] = {
    "failed_admin_logins_24h": "INTEGER NOT NULL DEFAULT 0",
    "devices_with_failed_logins": "INTEGER NOT NULL DEFAULT 0",
    "top_failed_sources": "TEXT NOT NULL DEFAULT '[]'",
    "admin_logins_outside_hours_24h": "INTEGER NOT NULL DEFAULT 0",
    "ipsec_tunnels_total": "INTEGER NOT NULL DEFAULT 0",
    "ipsec_tunnels_down": "INTEGER NOT NULL DEFAULT 0",
    "ssl_vpn_users_now": "INTEGER NOT NULL DEFAULT 0",
}
```

`init_db()` is unchanged (it already loops `_NEW_COLUMNS` generically).

Update `write_rollup`'s signature (add after `admin_logins_outside_hours_24h`, before `collected_at`):

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
    ipsec_tunnels_total: int,
    ipsec_tunnels_down: int,
    ssl_vpn_users_now: int,
    collected_at: str,
) -> None:
    with contextlib.closing(_connect()) as conn, conn:
        conn.execute(
            "INSERT INTO threat_stats_history "
            "(collected_at, alerts_unacked_total, alerts_unacked_by_severity, "
            "ips_detections_24h, ips_blocked_24h, ips_blocked_pct, "
            "top_signatures, top_source_countries, failed_admin_logins_24h, "
            "devices_with_failed_logins, top_failed_sources, admin_logins_outside_hours_24h, "
            "ipsec_tunnels_total, ipsec_tunnels_down, ssl_vpn_users_now) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                ipsec_tunnels_total,
                ipsec_tunnels_down,
                ssl_vpn_users_now,
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
            "devices_with_failed_logins, top_failed_sources, admin_logins_outside_hours_24h, "
            "ipsec_tunnels_total, ipsec_tunnels_down, ssl_vpn_users_now "
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
        ipsec_tunnels_total,
        ipsec_tunnels_down,
        ssl_vpn_users_now,
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
        "ipsec_tunnels_total": ipsec_tunnels_total,
        "ipsec_tunnels_down": ipsec_tunnels_down,
        "ssl_vpn_users_now": ssl_vpn_users_now,
    }
```

`prune_old_rows` is unchanged. **Note:** the pre-existing `threat_stats_cache.py`'s `poll_all_targets()` call to `write_rollup(...)` will now fail to compile against this new required-parameter signature until Task 2 updates it — same situation as the admin-access-anomalies plan's Task 1. Add the 3 new params there too, as a minimal literal-default patch (`ipsec_tunnels_total=0, ipsec_tunnels_down=0, ssl_vpn_users_now=0`), exactly mirroring how that prior plan's Task 1 patched the admin-access params — Task 2 fully replaces these placeholders with real computed values.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_threat_stats_history.py -v`
Expected: PASS (all tests in the file, including the 2 new ones)

- [ ] **Step 5: Run the full suite**

Run: `uv run pytest -q`
Expected: PASS, no regressions (this confirms the `threat_stats_cache.py` placeholder patch above compiles and doesn't break anything)

- [ ] **Step 6: Commit**

```bash
git add app/threat_stats_history.py app/threat_stats_cache.py tests/test_threat_stats_history.py
git commit -m "feat: extend threat_stats_history with VPN coverage rollup columns"
```

---

### Task 2: `app/threat_stats_cache.py` — site-to-site-ipsec/ssl-dialup-ipsec collection

**Files:**
- Modify: `app/threat_stats_cache.py`
- Test: `tests/test_threat_stats_cache.py`

**Interfaces:**
- Consumes: `threat_stats_history.write_rollup(...)`'s 3 new parameters (Task 1), `FAZClient.run_fortiview` (pre-existing, unchanged), the already-computed `time_range` inside `_poll_one_target` (reused, no new conversion call).
- Produces: `get_cached()`'s return dict gains 3 new keys: `ipsec_tunnels_total: int`, `ipsec_tunnels_down: int`, `ssl_vpn_users_now: int` — flat, alongside the existing keys, sharing the same `collected_at`.

- [ ] **Step 1: Write failing tests**

Add to `tests/test_threat_stats_cache.py`. Reuse the existing `_stub_client`/`targets_file`/`history_db`/`clear_threat_stats_cache` fixtures already in this file — do not redefine them.

```python
def test_poll_all_targets_populates_vpn_fields(targets_file, history_db, monkeypatch):
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
            "admin-logins": [],
            "failed-authentication-attempts": [],
            "site-to-site-ipsec": [
                # Tunnel A: one open session (no e_time) -> up.
                {"vpnname": "Tunnel-A", "e_time": 0, "locip": "10.0.0.1", "remip": "203.0.113.1"},
                # Tunnel B: one closed session (has e_time) -> down (seen, but not currently open).
                {
                    "vpnname": "Tunnel-B",
                    "e_time": 1757600000,
                    "locip": "10.0.0.2",
                    "remip": "203.0.113.2",
                },
                # Tunnel B again, still closed in this row too.
                {
                    "vpnname": "Tunnel-B",
                    "e_time": 1757600100,
                    "locip": "10.0.0.2",
                    "remip": "203.0.113.2",
                },
            ],
            "ssl-dialup-ipsec": [
                {"f_user": "alice", "end_time": 0, "remip": "198.51.100.1"},  # connected now
                {"f_user": "bob", "end_time": 1757600200, "remip": "198.51.100.2"},  # disconnected
            ],
        },
        local_time_range=("2026-09-10T08:00:00", "2026-09-11T08:00:00"),
    )

    cache_mod.poll_all_targets()

    cached = cache_mod.get_cached()
    assert cached["ipsec_tunnels_total"] == 2  # Tunnel-A, Tunnel-B
    assert cached["ipsec_tunnels_down"] == 1  # only Tunnel-B has no open session
    assert cached["ssl_vpn_users_now"] == 1  # only alice has an open session

    rollup = get_latest_rollup()
    assert rollup["ipsec_tunnels_total"] == 2
    assert rollup["ipsec_tunnels_down"] == 1
    assert rollup["ssl_vpn_users_now"] == 1


def test_poll_all_targets_vpn_fields_zero_when_no_sessions(targets_file, history_db, monkeypatch):
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
            "admin-logins": [],
            "failed-authentication-attempts": [],
            "site-to-site-ipsec": [],
            "ssl-dialup-ipsec": [],
        },
        local_time_range=("2026-09-10T08:00:00", "2026-09-11T08:00:00"),
    )

    cache_mod.poll_all_targets()

    cached = cache_mod.get_cached()
    assert cached["ipsec_tunnels_total"] == 0
    assert cached["ipsec_tunnels_down"] == 0
    assert cached["ssl_vpn_users_now"] == 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_threat_stats_cache.py -k vpn -v`
Expected: FAIL — `KeyError: 'ipsec_tunnels_total'` (cache dict doesn't have the key yet).

- [ ] **Step 3: Implement**

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
    "ipsec_tunnels_total": 0,
    "ipsec_tunnels_down": 0,
    "ssl_vpn_users_now": 0,
    "collected_at": None,
}
```

In `_poll_one_target`, after the admin-access collection block (after `admin_logins_outside_hours_24h = max(total_logins_24h - business_logins, 0)`), add:

```python
    # VPN coverage (P14): FortiView has no live "tunnel status" field —
    # site-to-site-ipsec/ssl-dialup-ipsec are session-log views, so
    # liveness is inferred from the trailing 24h window: a tunnel/user is
    # "up"/"connected now" if at least one logged session has no end
    # timestamp (e_time/end_time falsy means still open); a tunnel is
    # "down" if it was seen at all in the last 24h but every session for
    # it has since closed. Same "recent log presence = liveness"
    # philosophy as log_stats_cache.py's silent-device detection — an
    # approximation, not a live device-config query. Row field names
    # ("vpnname", "e_time" for site-to-site-ipsec; "f_user", "end_time"
    # for ssl-dialup-ipsec) trace to the vendored spec's Filterable/
    # Sortable-field appendix table — not yet confirmed live.
    site_to_site_rows = client.run_fortiview(
        client.adom, "site-to-site-ipsec", time_range, limit=1000
    )
    ssl_dialup_rows = client.run_fortiview(client.adom, "ssl-dialup-ipsec", time_range, limit=1000)

    tunnel_up: dict[str, bool] = {}
    for row in site_to_site_rows:
        name = row.get("vpnname") or row.get("tunnelid") or ""
        if not name:
            continue
        is_open = not row.get("e_time")
        tunnel_up[name] = tunnel_up.get(name, False) or is_open

    ssl_users_now_names = {
        row.get("f_user", "") for row in ssl_dialup_rows if not row.get("end_time")
    }
    ssl_users_now_names.discard("")
```

Add the new keys to `_poll_one_target`'s return dict:

```python
        "admin_logins_outside_hours_24h": admin_logins_outside_hours_24h,
        "ipsec_tunnel_names": set(tunnel_up.keys()),
        "ipsec_tunnel_up_names": {name for name, up in tunnel_up.items() if up},
        "ssl_vpn_users_now_names": ssl_users_now_names,
    }
```

In `poll_all_targets`, after the `top_failed_sources = _merge_top_lists(...)` line, add the fleet-wide aggregation:

```python
    all_tunnel_names: set = set().union(*(r["ipsec_tunnel_names"] for r in results)) if results else set()
    all_up_tunnel_names: set = (
        set().union(*(r["ipsec_tunnel_up_names"] for r in results)) if results else set()
    )
    ipsec_tunnels_total = len(all_tunnel_names)
    ipsec_tunnels_down = len(all_tunnel_names - all_up_tunnel_names)
    ssl_vpn_users_now = (
        len(set().union(*(r["ssl_vpn_users_now_names"] for r in results))) if results else 0
    )
```

Add the new keys to the cache-write block:

```python
        _cache["admin_logins_outside_hours_24h"] = admin_logins_outside_hours_24h
        _cache["ipsec_tunnels_total"] = ipsec_tunnels_total
        _cache["ipsec_tunnels_down"] = ipsec_tunnels_down
        _cache["ssl_vpn_users_now"] = ssl_vpn_users_now
        _cache["collected_at"] = collected_at
```

Add the new keyword args to the `history.write_rollup(...)` call:

```python
        admin_logins_outside_hours_24h=admin_logins_outside_hours_24h,
        ipsec_tunnels_total=ipsec_tunnels_total,
        ipsec_tunnels_down=ipsec_tunnels_down,
        ssl_vpn_users_now=ssl_vpn_users_now,
        collected_at=collected_at,
    )
```

(This replaces Task 1's temporary `ipsec_tunnels_total=0, ipsec_tunnels_down=0, ssl_vpn_users_now=0` placeholder patch with the real computed values.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_threat_stats_cache.py -v`
Expected: PASS (all tests in the file, including the 2 new ones)

- [ ] **Step 5: Run the full suite**

Run: `uv run pytest -q`
Expected: PASS, no regressions

- [ ] **Step 6: Commit**

```bash
git add app/threat_stats_cache.py tests/test_threat_stats_cache.py
git commit -m "feat: collect site-to-site-ipsec/ssl-dialup-ipsec into threat_stats_cache"
```

---

### Task 3: `"vpn"` key in `GET /external/api/executive/summary`

**Files:**
- Modify: `app/routes/external_api_routes.py`
- Test: `tests/test_external_api_routes.py`

**Interfaces:**
- Consumes: `threat_stats_cache.get_cached()`'s 3 new keys and `threat_stats_history.get_latest_rollup()`'s 3 new keys (Task 1/2). Reuses the already-fetched `threat_cache`/`threat_rollup` variables the route already computes for `_build_threats`/`_build_admin_access`.
- Produces: response payload gains `"vpn": {"ipsec_tunnels_total": int, "ipsec_tunnels_down": int, "ssl_vpn_users_now": int, "collected_at": str | None}`.

- [ ] **Step 1: Write failing tests**

Add to `tests/test_external_api_routes.py`:

```python
def test_vpn_key_shape_from_cache(client, monkeypatch):
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
            "failed_admin_logins_24h": 0,
            "devices_with_failed_logins": 0,
            "top_failed_sources": [],
            "admin_logins_outside_hours_24h": 0,
            "ipsec_tunnels_total": 6,
            "ipsec_tunnels_down": 1,
            "ssl_vpn_users_now": 12,
            "collected_at": "2026-09-11T12:00:00+00:00",
        },
    )

    resp = client.get("/external/api/executive/summary", headers={"Authorization": f"Bearer {raw}"})
    assert resp.status_code == 200
    vpn = resp.get_json()["vpn"]
    assert vpn["ipsec_tunnels_total"] == 6
    assert vpn["ipsec_tunnels_down"] == 1
    assert vpn["ssl_vpn_users_now"] == 12
    assert vpn["collected_at"] == "2026-09-11T12:00:00+00:00"


def test_vpn_key_all_zero_when_no_cache_and_no_history(client, monkeypatch):
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
    vpn = resp.get_json()["vpn"]
    assert vpn["ipsec_tunnels_total"] == 0
    assert vpn["ipsec_tunnels_down"] == 0
    assert vpn["ssl_vpn_users_now"] == 0
    assert vpn["collected_at"] is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_external_api_routes.py -k vpn_key -v`
Expected: FAIL with `KeyError: 'vpn'`

- [ ] **Step 3: Implement**

In `app/routes/external_api_routes.py`, add a helper next to `_build_admin_access`:

```python
def _build_vpn(cache: dict, rollup: dict | None) -> dict:
    """VPN tunnel/SSL-VPN-user coverage summary, preferring cache over
    history rollup. Follows the same cache-first/history-fallback pattern
    as threats/admin_access."""
    source = cache if cache.get("collected_at") is not None else (rollup or {})
    return {
        "ipsec_tunnels_total": source.get("ipsec_tunnels_total", 0),
        "ipsec_tunnels_down": source.get("ipsec_tunnels_down", 0),
        "ssl_vpn_users_now": source.get("ssl_vpn_users_now", 0),
        "collected_at": source.get("collected_at"),
    }
```

In `executive_summary()`, reuse the already-fetched `threat_cache`/`threat_rollup`:

```python
    threats = _build_threats(threat_cache, threat_rollup)
    admin_access = _build_admin_access(threat_cache, threat_rollup)
    vpn = _build_vpn(threat_cache, threat_rollup)
```

...and add `"vpn": vpn,` to the returned dict, after `"admin_access": admin_access,`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_external_api_routes.py -v`
Expected: PASS (all tests in the file, including the 2 new ones)

- [ ] **Step 5: Run the full suite and ruff**

Run: `uv run ruff check . && uv run ruff format --check . && uv run pytest -q`
Expected: PASS, no regressions

- [ ] **Step 6: Commit**

```bash
git add app/routes/external_api_routes.py tests/test_external_api_routes.py
git commit -m "feat: expose VPN tunnel coverage under executive summary's vpn key"
```

---

### Task 4: Docs — README.md, CHANGELOG.md

**Files:**
- Modify: whichever of `README.md`/`readme.md` exists on disk (this repo's root doc filenames are lowercase — verify with `ls` before editing, don't create a new file with different casing)
- Modify: whichever of `CHANGELOG.md`/`changelog.md` exists on disk

**Interfaces:** none (documentation only). No `.env.example` changes — this feature adds no new Config knobs.

- [ ] **Step 1: Update the README**

In the External API bullet, after the `"admin_access"` key sentence added by the previous plan, add:

"Also includes a `"vpn"` key — `{ipsec_tunnels_total, ipsec_tunnels_down, ssl_vpn_users_now, collected_at}` — from the same threat-activity poller, using FortiView's `site-to-site-ipsec` and `ssl-dialup-ipsec` reports. FortiAnalyzer has no live tunnel-status API; a tunnel/user is counted as currently up/connected if it has an open (no end-timestamp) session in the trailing 24h, and `ipsec_tunnels_down` counts tunnels seen in that window with no currently-open session — an inference from recent log activity, not a live device-config query."

- [ ] **Step 2: Add a changelog entry**

Add a new dated section at the top (use today's date, or append to today's section if one already exists from an earlier commit today):

```markdown
### Added

- External API: `GET /external/api/executive/summary` gains a `"vpn"` key
  — `ipsec_tunnels_total`, `ipsec_tunnels_down`, `ssl_vpn_users_now` — from
  the existing threat-activity poller (`app/threat_stats_cache.py`), now
  also querying FortiView's `site-to-site-ipsec` and `ssl-dialup-ipsec`
  reports. Tunnel/user liveness is inferred from open (no end-timestamp)
  sessions in the trailing 24h window, since FortiView has no live
  tunnel-status field. Rollups persist in `logstats.db` alongside the
  existing threat/admin-access history (migration-safe column addition).
```

- [ ] **Step 3: Commit**

```bash
git add README.md readme.md CHANGELOG.md changelog.md
git commit -m "docs: document VPN tunnel coverage in the threat-activity collector"
```

(Only the files that actually exist on disk will be staged — `git add` on a nonexistent path errors, so drop whichever pair doesn't apply before running this.)

---

## Out of scope

- **4thealth-plus** (`~/code/github/ai/4thealth-plus`): exposing `devices_not_forwarding_to_faz` (a count derived from the existing per-device FortiAnalyzer Logging CIS check already run by the device review rollup) plus a capped 50-name details list, inside the existing `device_review` executive-summary object. Separate repo, separate session.
- **4tExecutive** (`~/code/github/web/4tExecutive`): extractors for both new fields; `ipsec_tunnels_down` joining the Availability & Change domain (green 0, amber 1-2, red > 2); `devices_not_forwarding_to_faz` joining the Logging & Visibility domain (green 0, amber 1-3, red > 3). Also still owes the P12/P13 4tExecutive-side consumption from the two prior plans. Separate repo, separate session.
