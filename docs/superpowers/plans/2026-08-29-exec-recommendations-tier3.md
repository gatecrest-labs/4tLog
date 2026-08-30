# Exec Recommendations Tier 3 — 4tlog Summary API & Silent-Device Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give 4tlog its first external API — a bearer-token-authenticated
`/external/api/executive/summary` endpoint reporting FAZ fleet health, plus new
FAZ-`logstats`-backed silent-device detection and a real numeric log-volume metric, so
4tExecutive's `faz_health`/`log_volume_trend` widgets stop being permanently empty.

**Architecture:** A new `FAZClient.get_log_stats()` method calls FortiAnalyzer's
`/logview/adom/<adom>/logstats` JSON-RPC resource. A new `log_stats_cache.py` module polls it on
its own APScheduler interval (independent of the existing SNMP health poll), classifies each
device silent/logging against a configurable threshold, and persists one fleet-wide rollup row
per poll to a new `logstats.db` SQLite file so the summary endpoint survives a cold start. A new
`api_tokens.py` + CLI (`manage_api_tokens.py`, mirroring the existing `manage_users.py` pattern)
manages bearer tokens; a new `external_api_routes.py` blueprint exposes the summary endpoint
behind a feature flag and token auth.

**Tech Stack:** Flask, SQLite (`sqlite3`, stdlib), APScheduler, pytest, `requests` (already used
by `FAZClient`).

**Spec:** `docs/superpowers/specs/2026-08-29-exec-recommendations-tier3-4tlog-design.md` in the
`4tExecutive` repo (`/Users/alanw/code/github/web/4tExecutive`) — sections 2–6. This plan
implements the 4tlog side; the companion plan
`docs/superpowers/plans/2026-08-29-exec-recommendations-tier3-4texecutive.md` in the
4tExecutive repo implements the widget-consumption side this plan's payload feeds.

## Global Constraints

- No `atomic_write_json` helper exists in this repo (unlike 4thealth+/4tExecutive) — `api_tokens.json`
  and any other new JSON store use the same plain `json.dump(..., indent=2)` pattern already
  established in `app/faz_targets.py`.
- Bearer tokens are SHA-256-hashed at rest; the plaintext is returned exactly once, at creation.
- Every new background poll wraps each target's work in its own try/except so one FAZ appliance
  being unreachable never aborts the cycle for the others — same shape as
  `faz_health_cache.poll_all_targets()`.
- Every new scheduler must be disableable via an env-flag-gated `Config` attribute, checked in
  `tests/conftest.py`, so the test suite never starts a real background poller (mirrors
  `FAZ_HEALTH_POLL_DISABLED`).
- `pytest -q` and `uv run ruff check .` must pass before each commit.
- Token management is CLI-only in this project (`manage_api_tokens.py`), not a web Admin UI page —
  this repo's existing convention for credential-shaped management is a CLI tool
  (`manage_users.py`), not an Admin web form; a token Admin UI is future work if actually needed.
  The `external_api_enabled` toggle is also CLI-only (`manage_api_tokens.py enable`/`disable`).

---

## File Structure

- `app/faz_client.py` (modify) — add `get_log_stats(adom=None)`.
- `app/log_stats_cache.py` (new) — background poller, in-memory cache, silent-device
  classification.
- `app/log_stats_history.py` (new) — `logstats.db` SQLite persistence: `init_db()`,
  `write_rollup()`, `get_latest_rollup()`, `prune_old_rows()`.
- `app/api_tokens.py` (new) — SHA-256 bearer token store backed by `api_tokens.json`.
- `app/app_settings.py` (new) — `external_api_enabled` flag backed by `app_settings.json`.
- `manage_api_tokens.py` (new, repo root) — CLI: `create`/`list`/`revoke`/`enable`/`disable`.
- `app/routes/external_api_routes.py` (new) — `/external/api/executive/summary` blueprint.
- `app/config.py` (modify) — `SILENT_DEVICE_THRESHOLD_MINUTES`, `LOG_STATS_POLL_INTERVAL`,
  `LOG_STATS_POLL_DISABLED`.
- `app/__init__.py` (modify) — register the new blueprint, start the new scheduler, init
  `logstats.db`.
- `tests/conftest.py` (modify) — default `LOG_STATS_POLL_DISABLED=true`.
- `api_tokens.example.json`, `app_settings.example.json` (new) — committed examples, matching
  the `faz_targets.example.json` convention.
- `.gitignore` (modify) — add `api_tokens.json`, `app_settings.json`, `logstats.db`.
- `readme.md` (modify) — document the new external API under "Current features".
- Tests: `tests/test_faz_client.py`, `tests/test_log_stats_cache.py` (new),
  `tests/test_log_stats_history.py` (new), `tests/test_api_tokens.py` (new),
  `tests/test_external_api_routes.py` (new), `tests/test_manage_api_tokens.py` (new).

---

### Task 1: `FAZClient.get_log_stats()`

**Files:**
- Modify: `app/faz_client.py`
- Modify: `tests/test_faz_client.py`

**Interfaces:**
- Produces: `FAZClient.get_log_stats(adom: str | None = None) -> list[dict]`, each dict
  `{"devid": str, "devname": str, "last_log_timestamp": int | None, "lograte": float}`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_faz_client.py`:

```python
def test_get_log_stats_folds_vdoms_to_one_record_per_device(monkeypatch):
    client, calls = _client(
        monkeypatch,
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "data": {
                        "devs": [
                            {
                                "devid": "FGT001",
                                "devname": "FGT-branch1",
                                "vdoms": [
                                    {"vdom": "root", "last-log-timestamp": 1000, "lograte": 5.0},
                                    {"vdom": "traffic", "last-log-timestamp": 1200, "lograte": 3.5},
                                ],
                            },
                            {
                                "devid": "FGT002",
                                "devname": "FGT-branch2",
                                "vdoms": [
                                    {"vdom": "root", "last-log-timestamp": 900, "lograte": 0.0},
                                ],
                            },
                        ]
                    }
                },
            }
        ],
    )
    stats = client.get_log_stats()
    assert stats == [
        {"devid": "FGT001", "devname": "FGT-branch1", "last_log_timestamp": 1200, "lograte": 8.5},
        {"devid": "FGT002", "devname": "FGT-branch2", "last_log_timestamp": 900, "lograte": 0.0},
    ]
    assert calls[0]["json"]["params"][0]["url"] == "/logview/adom/root/logstats"


def test_get_log_stats_empty_vdoms_yields_none_timestamp(monkeypatch):
    client, _ = _client(
        monkeypatch,
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {"data": {"devs": [{"devid": "FGT003", "devname": "FGT-branch3", "vdoms": []}]}},
            }
        ],
    )
    stats = client.get_log_stats()
    assert stats == [{"devid": "FGT003", "devname": "FGT-branch3", "last_log_timestamp": None, "lograte": 0.0}]


def test_get_log_stats_uses_explicit_adom_override(monkeypatch):
    client, calls = _client(
        monkeypatch,
        [{"jsonrpc": "2.0", "id": 1, "result": {"data": {"devs": []}}}],
    )
    client.get_log_stats(adom="corp")
    assert calls[0]["json"]["params"][0]["url"] == "/logview/adom/corp/logstats"


def test_get_log_stats_empty_devs_list(monkeypatch):
    client, _ = _client(
        monkeypatch,
        [{"jsonrpc": "2.0", "id": 1, "result": {"data": {"devs": []}}}],
    )
    assert client.get_log_stats() == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_faz_client.py -k get_log_stats -v`
Expected: FAIL — `AttributeError: 'FAZClient' object has no attribute 'get_log_stats'`.

- [ ] **Step 3: Write the implementation**

In `app/faz_client.py`, add after `get_devices()` (before `local_time_range`):

```python
    def get_log_stats(self, adom: str | None = None) -> list[dict]:
        """Per-device log stats for the given ADOM (defaults to self.adom),
        from /logview/adom/<adom>/logstats. Returns one record per device,
        vdoms folded together: last_log_timestamp is the max (most recent)
        across the device's vdoms, lograte is their sum. A device with no
        vdoms (never logged) gets last_log_timestamp=None, lograte=0.0.

        Request/response shape confirmed against the vendored spec
        (api-info/.../logview.json, logview.logstats.get.{req,resp}) — not
        yet confirmed live against real hardware."""
        target_adom = adom or self.adom
        body = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "get",
            "params": [{"url": f"/logview/adom/{target_adom}/logstats", "apiver": 3}],
            "session": None,
        }
        result = self._unwrap_result(self._post(body))
        devs = (result.get("data") or {}).get("devs") or []
        stats = []
        for dev in devs:
            vdoms = dev.get("vdoms") or []
            timestamps = [v.get("last-log-timestamp") for v in vdoms if v.get("last-log-timestamp")]
            stats.append(
                {
                    "devid": dev.get("devid", ""),
                    "devname": dev.get("devname", ""),
                    "last_log_timestamp": max(timestamps) if timestamps else None,
                    "lograte": sum(v.get("lograte", 0.0) for v in vdoms),
                }
            )
        return stats
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_faz_client.py -k get_log_stats -v`
Expected: PASS

- [ ] **Step 5: Run the full faz_client test file**

Run: `uv run pytest tests/test_faz_client.py -v`
Expected: PASS, no regressions.

- [ ] **Step 6: Commit**

```bash
git add app/faz_client.py tests/test_faz_client.py
git commit -m "Add FAZClient.get_log_stats() for per-device log rate/last-log-time"
```

---

### Task 2: Config additions and silent-device classification helper

**Files:**
- Modify: `app/config.py`
- Modify: `tests/conftest.py`
- Create: `app/log_stats_cache.py`
- Create: `tests/test_log_stats_cache.py`

**Interfaces:**
- Produces: `Config.SILENT_DEVICE_THRESHOLD_MINUTES` (int, default 60),
  `Config.LOG_STATS_POLL_INTERVAL` (int, default 300), `Config.LOG_STATS_POLL_DISABLED` (bool).
- Produces: `log_stats_cache.classify_devices(stats: list[dict], now: float) -> tuple[list[dict], list[dict]]`
  returning `(logging_devices, silent_devices)`, each a list of the same dicts `get_log_stats()`
  returns.

- [ ] **Step 1: Add Config attributes**

In `app/config.py`, after the `LOG_SEARCH_*` block:

```python
    # Log stats polling (app/log_stats_cache.py) — silent-device detection
    # and log volume, independent cadence from the SNMP health poll since
    # logstats is a cheap JSON-RPC call with no SNMP round-trip.
    SILENT_DEVICE_THRESHOLD_MINUTES = int(os.environ.get("SILENT_DEVICE_THRESHOLD_MINUTES", "60"))
    LOG_STATS_POLL_INTERVAL = int(os.environ.get("LOG_STATS_POLL_INTERVAL", "300"))

    # Set by tests/conftest.py to skip starting the background log-stats
    # poller (real network calls) during the test suite.
    LOG_STATS_POLL_DISABLED = (
        os.environ.get("LOG_STATS_POLL_DISABLED", "false").lower() == "true"
    )
```

- [ ] **Step 2: Add the test-suite default**

In `tests/conftest.py`, after the `FAZ_HEALTH_POLL_DISABLED` line:

```python
os.environ.setdefault("LOG_STATS_POLL_DISABLED", "true")
```

- [ ] **Step 3: Write the failing classification tests**

Create `tests/test_log_stats_cache.py`:

```python
import pytest


def test_classify_devices_splits_logging_and_silent():
    from app.log_stats_cache import classify_devices

    now = 10_000.0
    stats = [
        {"devid": "A", "devname": "a", "last_log_timestamp": 9_900, "lograte": 1.0},  # 100s ago: logging
        {"devid": "B", "devname": "b", "last_log_timestamp": 6_000, "lograte": 0.0},  # ~66min ago: silent
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
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `uv run pytest tests/test_log_stats_cache.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.log_stats_cache'`.

- [ ] **Step 5: Write the implementation**

Create `app/log_stats_cache.py`:

```python
"""Background cache for FAZ log-stats-based silent-device detection and
fleet log volume. Structured like app/faz_health_cache.py: a background
poller on its own APScheduler interval writes into a lock-guarded
in-memory dict; app/routes/external_api_routes.py reads a snapshot and
never blocks on a live poll.
"""

from __future__ import annotations

import threading
import time

from app.config import Config

_lock = threading.RLock()
_cache: dict = {"logging_devices": [], "silent_devices": [], "collected_at": None}


def classify_devices(
    stats: list[dict], now: float, threshold_minutes: int
) -> tuple[list[dict], list[dict]]:
    """Split get_log_stats() records into (logging, silent). A device is
    silent if now - last_log_timestamp exceeds threshold_minutes, or if
    last_log_timestamp is None/0 (FAZ has never received a log from it —
    no grace period for that case)."""
    threshold_seconds = threshold_minutes * 60
    logging_devices = []
    silent_devices = []
    for dev in stats:
        ts = dev.get("last_log_timestamp")
        if ts and (now - ts) <= threshold_seconds:
            logging_devices.append(dev)
        else:
            silent_devices.append(dev)
    return logging_devices, silent_devices


def get_cached() -> dict:
    """Snapshot of the latest poll: {"logging_devices": [...], "silent_devices": [...],
    "collected_at": iso-str | None}."""
    with _lock:
        return dict(_cache)
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `uv run pytest tests/test_log_stats_cache.py -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add app/config.py tests/conftest.py app/log_stats_cache.py tests/test_log_stats_cache.py
git commit -m "Add silent-device classification and log-stats poll config"
```

---

### Task 3: `logstats.db` persistence (fleet-wide rollup history)

**Files:**
- Create: `app/log_stats_history.py`
- Create: `tests/test_log_stats_history.py`
- Modify: `.gitignore`

**Interfaces:**
- Produces: `log_stats_history.init_db() -> None`,
  `log_stats_history.write_rollup(devices_logging: int, devices_silent: int, total_lograte: float, collected_at: str) -> None`,
  `log_stats_history.get_latest_rollup() -> dict | None` (keys: `devices_logging`,
  `devices_silent`, `total_lograte`, `collected_at`),
  `log_stats_history.prune_old_rows(retention_days: int = 30) -> None`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_log_stats_history.py`:

```python
import datetime

import pytest


@pytest.fixture
def history_db(tmp_path, monkeypatch):
    path = tmp_path / "logstats.db"
    import app.log_stats_history as history_mod

    monkeypatch.setattr(history_mod, "DB_PATH", path)
    history_mod.init_db()
    yield path


def test_get_latest_rollup_none_when_empty(history_db):
    from app.log_stats_history import get_latest_rollup

    assert get_latest_rollup() is None


def test_write_and_read_latest_rollup(history_db):
    from app.log_stats_history import get_latest_rollup, write_rollup

    write_rollup(devices_logging=10, devices_silent=1, total_lograte=42.5, collected_at="2026-08-29T09:00:00Z")
    write_rollup(devices_logging=11, devices_silent=0, total_lograte=50.0, collected_at="2026-08-29T09:05:00Z")

    latest = get_latest_rollup()
    assert latest == {
        "devices_logging": 11,
        "devices_silent": 0,
        "total_lograte": 50.0,
        "collected_at": "2026-08-29T09:05:00Z",
    }


def test_prune_old_rows_removes_rows_past_retention(history_db):
    from app.log_stats_history import get_latest_rollup, prune_old_rows, write_rollup

    old_ts = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=40)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    recent_ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    write_rollup(devices_logging=1, devices_silent=0, total_lograte=1.0, collected_at=old_ts)
    write_rollup(devices_logging=2, devices_silent=0, total_lograte=2.0, collected_at=recent_ts)

    prune_old_rows(retention_days=30)

    import sqlite3

    import app.log_stats_history as history_mod

    conn = sqlite3.connect(history_mod.DB_PATH)
    rows = conn.execute("SELECT collected_at FROM log_volume_history").fetchall()
    conn.close()
    assert rows == [(recent_ts,)]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_log_stats_history.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.log_stats_history'`.

- [ ] **Step 3: Write the implementation**

Create `app/log_stats_history.py`:

```python
"""SQLite-backed history of fleet-wide log-volume rollups, one row per
log_stats_cache poll cycle. Exists so the /external/api/executive/summary
route can serve the last-known state immediately after a restart, before
the first new poll completes, instead of returning nulls for one full
poll interval. Schema mirrors 4tExecutive's metrics_db.py snapshots table.
"""

from __future__ import annotations

import datetime
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "logstats.db"


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(DB_PATH)


def init_db() -> None:
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS log_volume_history (
                collected_at TEXT NOT NULL,
                devices_logging INTEGER NOT NULL,
                devices_silent INTEGER NOT NULL,
                total_lograte REAL NOT NULL
            )
            """
        )


def write_rollup(
    devices_logging: int, devices_silent: int, total_lograte: float, collected_at: str
) -> None:
    with _connect() as conn:
        conn.execute(
            "INSERT INTO log_volume_history "
            "(collected_at, devices_logging, devices_silent, total_lograte) VALUES (?, ?, ?, ?)",
            (collected_at, devices_logging, devices_silent, total_lograte),
        )


def get_latest_rollup() -> dict | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT collected_at, devices_logging, devices_silent, total_lograte "
            "FROM log_volume_history ORDER BY collected_at DESC LIMIT 1"
        ).fetchone()
    if row is None:
        return None
    collected_at, devices_logging, devices_silent, total_lograte = row
    return {
        "collected_at": collected_at,
        "devices_logging": devices_logging,
        "devices_silent": devices_silent,
        "total_lograte": total_lograte,
    }


def prune_old_rows(retention_days: int = 30) -> None:
    cutoff = (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=retention_days)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    with _connect() as conn:
        conn.execute("DELETE FROM log_volume_history WHERE collected_at < ?", (cutoff,))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_log_stats_history.py -v`
Expected: PASS

- [ ] **Step 5: Add `logstats.db` to `.gitignore`**

In `.gitignore`, alongside the existing `metrics.db`-style entries (check the file for where
`faz_targets.json`/similar local-state files are excluded and add nearby):

```
logstats.db
```

- [ ] **Step 6: Commit**

```bash
git add app/log_stats_history.py tests/test_log_stats_history.py .gitignore
git commit -m "Add logstats.db persistence for fleet-wide log volume rollups"
```

---

### Task 4: Wire the poller — `log_stats_cache.poll_all_targets()` + scheduler

**Files:**
- Modify: `app/log_stats_cache.py`
- Modify: `tests/test_log_stats_cache.py`

**Interfaces:**
- Produces: `log_stats_cache.poll_all_targets() -> None`, `log_stats_cache.poll_now() -> None`,
  `log_stats_cache.init_scheduler(app: Flask) -> None`.
- Consumes: `app.faz_targets.list_targets()`, `FAZClient.get_log_stats()` (Task 1),
  `classify_devices()` (Task 2), `log_stats_history.write_rollup()`/`prune_old_rows()` (Task 3).

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_log_stats_cache.py`:

```python
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
    import app.log_stats_history as history_mod

    monkeypatch.setattr(history_mod, "DB_PATH", path)
    history_mod.init_db()
    yield path


@pytest.fixture(autouse=True)
def clear_log_stats_cache():
    import app.log_stats_cache as cache_mod

    cache_mod._cache = {"logging_devices": [], "silent_devices": [], "collected_at": None}
    yield
    cache_mod._cache = {"logging_devices": [], "silent_devices": [], "collected_at": None}


def test_poll_all_targets_populates_cache_and_writes_rollup(targets_file, history_db, monkeypatch):
    import app.log_stats_cache as cache_mod
    from app.log_stats_history import get_latest_rollup

    def fake_get_log_stats(self, adom=None):
        return [
            {"devid": "A", "devname": "a", "last_log_timestamp": int(__import__("time").time()), "lograte": 4.0},
            {"devid": "B", "devname": "b", "last_log_timestamp": 1, "lograte": 0.0},
        ]

    monkeypatch.setattr("app.faz_client.FAZClient.get_log_stats", fake_get_log_stats)
    monkeypatch.setattr("app.faz_client.FAZClient.logout", lambda self: None)

    cache_mod.poll_all_targets()

    cached = cache_mod.get_cached()
    assert [d["devid"] for d in cached["logging_devices"]] == ["A"]
    assert [d["devid"] for d in cached["silent_devices"]] == ["B"]
    assert cached["collected_at"] is not None

    rollup = get_latest_rollup()
    assert rollup["devices_logging"] == 1
    assert rollup["devices_silent"] == 1
    assert rollup["total_lograte"] == 4.0


def test_poll_all_targets_skips_unreachable_target_without_aborting(targets_file, history_db, monkeypatch):
    import app.log_stats_cache as cache_mod
    from app.faz_client import FAZError

    def fake_get_log_stats(self, adom=None):
        raise FAZError("boom")

    monkeypatch.setattr("app.faz_client.FAZClient.get_log_stats", fake_get_log_stats)
    monkeypatch.setattr("app.faz_client.FAZClient.logout", lambda self: None)

    cache_mod.poll_all_targets()  # must not raise

    cached = cache_mod.get_cached()
    assert cached["logging_devices"] == []
    assert cached["silent_devices"] == []


def test_poll_all_targets_dedupes_devices_seen_across_multiple_targets(tmp_path, monkeypatch, history_db):
    import app.faz_targets as faz_targets_mod
    import app.log_stats_cache as cache_mod

    monkeypatch.setattr(faz_targets_mod, "FAZ_TARGETS_FILE", tmp_path / "faz_targets.json")
    from app.faz_targets import create_target

    create_target("Primary", host="192.168.64.4", adom="root", token="tok")
    create_target("Secondary", host="192.168.64.5", adom="root", token="tok2")

    now = int(__import__("time").time())

    def fake_get_log_stats(self, adom=None):
        # Same devid ("SHARED") visible from both targets; last poll wins.
        return [{"devid": "SHARED", "devname": "shared", "last_log_timestamp": now, "lograte": 1.0}]

    monkeypatch.setattr("app.faz_client.FAZClient.get_log_stats", fake_get_log_stats)
    monkeypatch.setattr("app.faz_client.FAZClient.logout", lambda self: None)

    cache_mod.poll_all_targets()

    cached = cache_mod.get_cached()
    assert len(cached["logging_devices"]) == 1
    assert cached["logging_devices"][0]["devid"] == "SHARED"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_log_stats_cache.py -k poll_all_targets -v`
Expected: FAIL — `AttributeError: module 'app.log_stats_cache' has no attribute 'poll_all_targets'`.

- [ ] **Step 3: Write the implementation**

Replace `app/log_stats_cache.py`'s `get_cached()` ending with the poller (append after
`get_cached()`):

```python
def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def poll_all_targets() -> None:
    import app.log_stats_history as history
    from app.app_logger import app_log
    from app.faz_client import FAZClient, FAZError, summarize_connection_error
    from app.faz_targets import list_targets

    now = time.time()
    devices_by_id: dict[str, dict] = {}
    for target in list_targets():
        label = target.get("label")
        host = target.get("host")
        adom = target.get("adom", "root")
        if not label or not host:
            continue
        try:
            with FAZClient(
                host=host,
                token=target.get("token", ""),
                adom=adom,
                verify_ssl=Config.FAZ_VERIFY_SSL,
                timeout=Config.FAZ_REQUEST_TIMEOUT,
            ) as client:
                stats = client.get_log_stats()
        except FAZError as exc:
            app_log("WARNING", "log_stats_cache", f"logstats poll failed for {label}: {exc}")
            continue
        except Exception as exc:
            app_log(
                "WARNING",
                "log_stats_cache",
                f"logstats poll failed for {label} ({host}): {summarize_connection_error(exc)}",
            )
            continue
        for dev in stats:
            devices_by_id[dev["devid"]] = dev  # last target seen for a devid wins

    logging_devices, silent_devices = classify_devices(
        list(devices_by_id.values()), now, Config.SILENT_DEVICE_THRESHOLD_MINUTES
    )
    collected_at = _now()
    with _lock:
        _cache["logging_devices"] = logging_devices
        _cache["silent_devices"] = silent_devices
        _cache["collected_at"] = collected_at

    total_lograte = sum(d.get("lograte", 0.0) for d in logging_devices)
    history.init_db()
    history.write_rollup(
        devices_logging=len(logging_devices),
        devices_silent=len(silent_devices),
        total_lograte=total_lograte,
        collected_at=collected_at,
    )
    history.prune_old_rows()


def poll_now() -> None:
    """Kick off a non-blocking poll of all targets in a daemon thread."""
    t = threading.Thread(target=poll_all_targets, name="log_stats_poll_now", daemon=True)
    t.start()


def init_scheduler(app) -> None:
    """Register a recurring APScheduler job and run the first poll immediately.

    No-op if Config.LOG_STATS_POLL_DISABLED (set by tests/conftest.py)."""
    if Config.LOG_STATS_POLL_DISABLED:
        return

    from apscheduler.schedulers.background import BackgroundScheduler

    poll_now()

    scheduler = BackgroundScheduler()
    scheduler.add_job(
        func=poll_all_targets,
        trigger="interval",
        seconds=Config.LOG_STATS_POLL_INTERVAL,
        id="log_stats_poll",
        replace_existing=True,
        max_instances=1,
    )
    scheduler.start()
```

Add the needed imports at the top of `app/log_stats_cache.py`:

```python
import datetime
```

(alongside the existing `threading`/`time` imports).

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_log_stats_cache.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add app/log_stats_cache.py tests/test_log_stats_cache.py
git commit -m "Poll FAZ log stats on a dedicated interval and persist fleet rollups"
```

---

### Task 5: `api_tokens.py` and `app_settings.py`

**Files:**
- Create: `app/api_tokens.py`
- Create: `app/app_settings.py`
- Create: `tests/test_api_tokens.py`
- Create: `api_tokens.example.json`
- Create: `app_settings.example.json`
- Modify: `.gitignore`

**Interfaces:**
- Produces: `api_tokens.create_token(name: str) -> tuple[str, dict]`,
  `api_tokens.list_tokens() -> list[dict]`, `api_tokens.revoke_token(token_id: str) -> bool`,
  `api_tokens.validate_token(raw: str) -> dict | None`.
- Produces: `app_settings.get_setting(key: str, default=None)`,
  `app_settings.set_setting(key: str, value) -> None`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_api_tokens.py`:

```python
import pytest


@pytest.fixture
def tokens_file(tmp_path, monkeypatch):
    path = tmp_path / "api_tokens.json"
    import app.api_tokens as tokens_mod

    monkeypatch.setattr(tokens_mod, "_TOKENS_PATH", path)
    yield path


def test_list_tokens_empty_when_no_file(tokens_file):
    from app.api_tokens import list_tokens

    assert list_tokens() == []


def test_create_returns_plaintext_once_and_never_stores_it(tokens_file):
    from app.api_tokens import create_token, list_tokens

    raw, record = create_token("4tExecutive poller")
    assert raw.startswith("4tl_")
    assert record["name"] == "4tExecutive poller"
    assert "token_hash" not in record

    listed = list_tokens()
    assert len(listed) == 1
    assert "token_hash" not in listed[0]
    assert raw not in str(listed)


def test_validate_token_roundtrip(tokens_file):
    from app.api_tokens import create_token, validate_token

    raw, record = create_token("test")
    validated = validate_token(raw)
    assert validated["id"] == record["id"]


def test_validate_token_rejects_wrong_value(tokens_file):
    from app.api_tokens import create_token, validate_token

    create_token("test")
    assert validate_token("wrong-token") is None


def test_validate_token_rejects_revoked(tokens_file):
    from app.api_tokens import create_token, revoke_token, validate_token

    raw, record = create_token("test")
    assert revoke_token(record["id"]) is True
    assert validate_token(raw) is None


def test_revoke_unknown_id_returns_false(tokens_file):
    from app.api_tokens import revoke_token

    assert revoke_token("does-not-exist") is False


def test_app_settings_defaults_to_disabled(tmp_path, monkeypatch):
    import app.app_settings as settings_mod

    monkeypatch.setattr(settings_mod, "_SETTINGS_PATH", tmp_path / "app_settings.json")
    from app.app_settings import get_setting

    assert get_setting("external_api_enabled", False) is False


def test_app_settings_set_and_get(tmp_path, monkeypatch):
    import app.app_settings as settings_mod

    monkeypatch.setattr(settings_mod, "_SETTINGS_PATH", tmp_path / "app_settings.json")
    from app.app_settings import get_setting, set_setting

    set_setting("external_api_enabled", True)
    assert get_setting("external_api_enabled", False) is True
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_api_tokens.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.api_tokens'`.

- [ ] **Step 3: Write `app/api_tokens.py`**

```python
"""Bearer token management for the external API. Tokens are SHA-256-hashed
in api_tokens.json (gitignored); the plaintext is returned exactly once,
at creation, and never stored. Follows the plain json.dump pattern already
established in app/faz_targets.py (this repo has no atomic-write helper)."""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
import uuid
from pathlib import Path

_TOKENS_PATH = Path(__file__).parent.parent / "api_tokens.json"
_lock = threading.Lock()

TOKEN_PREFIX = "4tl_"


def _load() -> list[dict]:
    if not _TOKENS_PATH.exists():
        return []
    try:
        with _TOKENS_PATH.open() as f:
            return json.load(f).get("tokens", [])
    except (json.JSONDecodeError, OSError):
        return []


def _save(tokens: list[dict]) -> None:
    with _TOKENS_PATH.open("w") as f:
        json.dump({"tokens": tokens}, f, indent=2)


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def create_token(name: str) -> tuple[str, dict]:
    """Create a new token. Returns (plaintext, record) — plaintext is shown once."""
    raw = TOKEN_PREFIX + secrets.token_hex(32)
    record = {
        "id": str(uuid.uuid4()),
        "name": name.strip(),
        "token_hash": _hash(raw),
        "enabled": True,
    }
    with _lock:
        tokens = _load()
        tokens.append(record)
        _save(tokens)
    safe = {k: v for k, v in record.items() if k != "token_hash"}
    return raw, safe


def list_tokens() -> list[dict]:
    with _lock:
        tokens = _load()
    return [{k: v for k, v in t.items() if k != "token_hash"} for t in tokens]


def revoke_token(token_id: str) -> bool:
    with _lock:
        tokens = _load()
        remaining = [t for t in tokens if t.get("id") != token_id]
        if len(remaining) == len(tokens):
            return False
        _save(remaining)
    return True


def validate_token(raw: str) -> dict | None:
    if not raw:
        return None
    h = _hash(raw)
    with _lock:
        tokens = _load()
    for t in tokens:
        if t.get("token_hash") == h and t.get("enabled", True):
            return {k: v for k, v in t.items() if k != "token_hash"}
    return None
```

- [ ] **Step 4: Write `app/app_settings.py`**

```python
"""Application settings — persistent key/value store backed by app_settings.json."""

from __future__ import annotations

import json
import threading
from pathlib import Path

_SETTINGS_PATH = Path(__file__).parent.parent / "app_settings.json"
_DEFAULTS: dict = {"external_api_enabled": False}
_lock = threading.Lock()


def _load() -> dict:
    if not _SETTINGS_PATH.exists():
        return dict(_DEFAULTS)
    try:
        with _SETTINGS_PATH.open() as f:
            data = json.load(f)
        return {**_DEFAULTS, **data}
    except (json.JSONDecodeError, OSError):
        return dict(_DEFAULTS)


def _save(data: dict) -> None:
    with _SETTINGS_PATH.open("w") as f:
        json.dump(data, f, indent=2)


def get_setting(key: str, default=None):
    with _lock:
        data = _load()
    return data.get(key, default)


def set_setting(key: str, value) -> None:
    with _lock:
        data = _load()
        data[key] = value
        _save(data)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_api_tokens.py -v`
Expected: PASS

- [ ] **Step 6: Add example files and gitignore entries**

Create `api_tokens.example.json`:

```json
{
  "tokens": []
}
```

Create `app_settings.example.json`:

```json
{
  "external_api_enabled": false
}
```

In `.gitignore`, add alongside `faz_targets.json`/`users.json`:

```
api_tokens.json
app_settings.json
```

- [ ] **Step 7: Commit**

```bash
git add app/api_tokens.py app/app_settings.py tests/test_api_tokens.py \
  api_tokens.example.json app_settings.example.json .gitignore
git commit -m "Add bearer token store and settings flag for the external API"
```

---

### Task 6: `manage_api_tokens.py` CLI

**Files:**
- Create: `manage_api_tokens.py`
- Create: `tests/test_manage_api_tokens.py`

**Interfaces:**
- Consumes: `app.api_tokens.{create_token,list_tokens,revoke_token}`,
  `app.app_settings.{get_setting,set_setting}` (Task 5).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_manage_api_tokens.py`:

```python
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent.parent / "manage_api_tokens.py"


@pytest.fixture
def isolated_files(tmp_path, monkeypatch):
    monkeypatch.setattr("app.api_tokens._TOKENS_PATH", tmp_path / "api_tokens.json")
    monkeypatch.setattr("app.app_settings._SETTINGS_PATH", tmp_path / "app_settings.json")
    yield tmp_path


def test_create_and_list(isolated_files):
    from app.api_tokens import list_tokens

    import manage_api_tokens

    manage_api_tokens.cmd_create(_Args(name="test-token"))
    tokens = list_tokens()
    assert len(tokens) == 1
    assert tokens[0]["name"] == "test-token"


def test_revoke(isolated_files):
    from app.api_tokens import create_token, list_tokens

    import manage_api_tokens

    _, record = create_token("to-revoke")
    manage_api_tokens.cmd_revoke(_Args(token_id=record["id"]))
    assert list_tokens() == []


def test_enable_disable(isolated_files):
    from app.app_settings import get_setting

    import manage_api_tokens

    manage_api_tokens.cmd_enable(_Args())
    assert get_setting("external_api_enabled") is True
    manage_api_tokens.cmd_disable(_Args())
    assert get_setting("external_api_enabled") is False


class _Args:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_manage_api_tokens.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'manage_api_tokens'`.

- [ ] **Step 3: Write `manage_api_tokens.py`**

```python
#!/usr/bin/env python3
"""CLI tool to manage the external API's bearer tokens and enable flag."""

import argparse
import sys


def cmd_create(args):
    from app.api_tokens import create_token

    raw, record = create_token(args.name)
    print(f"Token created: {record['name']} (id={record['id']})")
    print(f"Plaintext (shown once): {raw}")


def cmd_list(_args):
    from app.api_tokens import list_tokens

    tokens = list_tokens()
    if not tokens:
        print("No tokens configured.")
        return
    print(f"{'ID':<38} {'Name':<24} {'Enabled':<8}")
    print("-" * 72)
    for t in tokens:
        print(f"{t['id']:<38} {t['name']:<24} {str(t.get('enabled', True)):<8}")


def cmd_revoke(args):
    from app.api_tokens import revoke_token

    if revoke_token(args.token_id):
        print(f"Token '{args.token_id}' revoked.")
    else:
        print(f"Token '{args.token_id}' not found.", file=sys.stderr)
        sys.exit(1)


def cmd_enable(_args):
    from app.app_settings import set_setting

    set_setting("external_api_enabled", True)
    print("External API enabled.")


def cmd_disable(_args):
    from app.app_settings import set_setting

    set_setting("external_api_enabled", False)
    print("External API disabled.")


parser = argparse.ArgumentParser(description="4tlog external API token management")
sub = parser.add_subparsers(dest="command", required=True)

p_create = sub.add_parser("create", help="Create a new bearer token")
p_create.add_argument("name")
p_create.set_defaults(func=cmd_create)

p_list = sub.add_parser("list", help="List all tokens")
p_list.set_defaults(func=cmd_list)

p_revoke = sub.add_parser("revoke", help="Revoke a token by ID")
p_revoke.add_argument("token_id")
p_revoke.set_defaults(func=cmd_revoke)

p_enable = sub.add_parser("enable", help="Enable the external API")
p_enable.set_defaults(func=cmd_enable)

p_disable = sub.add_parser("disable", help="Disable the external API")
p_disable.set_defaults(func=cmd_disable)

if __name__ == "__main__":
    args = parser.parse_args()
    args.func(args)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_manage_api_tokens.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add manage_api_tokens.py tests/test_manage_api_tokens.py
git commit -m "Add manage_api_tokens.py CLI for external API tokens and enable flag"
```

---

### Task 7: `/external/api/executive/summary` route

**Files:**
- Create: `app/routes/external_api_routes.py`
- Create: `tests/test_external_api_routes.py`
- Modify: `app/__init__.py`

**Interfaces:**
- Produces: `GET /external/api/executive/summary` — 503 when disabled, 401 when unauthorized,
  200 with the payload from spec section 2 otherwise.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_external_api_routes.py`:

```python
import pytest


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setattr("app.api_tokens._TOKENS_PATH", tmp_path / "api_tokens.json")
    monkeypatch.setattr("app.app_settings._SETTINGS_PATH", tmp_path / "app_settings.json")
    monkeypatch.setattr("app.faz_targets.FAZ_TARGETS_FILE", tmp_path / "faz_targets.json")
    import app.log_stats_history as history_mod

    monkeypatch.setattr(history_mod, "DB_PATH", tmp_path / "logstats.db")
    history_mod.init_db()

    from app import create_app

    return create_app()


@pytest.fixture
def client(app):
    return app.test_client()


def _enable_and_token():
    from app.api_tokens import create_token
    from app.app_settings import set_setting

    set_setting("external_api_enabled", True)
    raw, _ = create_token("test")
    return raw


def test_returns_503_when_disabled(client):
    resp = client.get("/external/api/executive/summary")
    assert resp.status_code == 503


def test_returns_401_when_no_token(client):
    from app.app_settings import set_setting

    set_setting("external_api_enabled", True)
    resp = client.get("/external/api/executive/summary")
    assert resp.status_code == 401


def test_returns_401_when_invalid_token(client):
    from app.app_settings import set_setting

    set_setting("external_api_enabled", True)
    resp = client.get(
        "/external/api/executive/summary", headers={"Authorization": "Bearer wrong"}
    )
    assert resp.status_code == 401


def test_happy_path_shape(client, monkeypatch):
    raw = _enable_and_token()

    import app.faz_health_cache as health_mod
    import app.log_stats_cache as logstats_mod

    monkeypatch.setattr(
        health_mod,
        "get_all_cached",
        lambda: [
            {"label": "Primary", "status": "green", "disk_used": "Free 40GB, Total 100GB"},
            {"label": "Secondary", "status": "red", "disk_used": "Free 5GB, Total 100GB"},
        ],
    )
    monkeypatch.setattr(
        logstats_mod,
        "get_cached",
        lambda: {
            "logging_devices": [{"devid": "A", "lograte": 5.0}, {"devid": "B", "lograte": 3.0}],
            "silent_devices": [{"devid": "C", "lograte": 0.0}],
            "collected_at": "2026-08-29T18:00:00Z",
        },
    )

    resp = client.get(
        "/external/api/executive/summary", headers={"Authorization": f"Bearer {raw}"}
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["schema_version"] == 1
    assert body["faz_targets_total"] == 2
    assert body["faz_targets_healthy"] == 1
    assert body["faz_disk_used_pct"] == 95.0
    assert body["devices_logging"] == 2
    assert body["devices_silent"] == 1
    assert body["silent_device_threshold_minutes"] == 60
    assert body["log_volume_events_per_sec"] == 8.0
    assert body["log_stats_collected_at"] == "2026-08-29T18:00:00Z"


def test_falls_back_to_persisted_rollup_when_cache_empty(client, monkeypatch):
    raw = _enable_and_token()

    import app.faz_health_cache as health_mod
    import app.log_stats_cache as logstats_mod
    from app.log_stats_history import write_rollup

    monkeypatch.setattr(health_mod, "get_all_cached", lambda: [])
    monkeypatch.setattr(
        logstats_mod,
        "get_cached",
        lambda: {"logging_devices": [], "silent_devices": [], "collected_at": None},
    )
    write_rollup(
        devices_logging=7, devices_silent=1, total_lograte=12.5, collected_at="2026-08-29T17:00:00Z"
    )

    resp = client.get(
        "/external/api/executive/summary", headers={"Authorization": f"Bearer {raw}"}
    )
    body = resp.get_json()
    assert body["devices_logging"] == 7
    assert body["devices_silent"] == 1
    assert body["log_volume_events_per_sec"] == 12.5
    assert body["log_stats_collected_at"] == "2026-08-29T17:00:00Z"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_external_api_routes.py -v`
Expected: FAIL — route not registered / import errors.

- [ ] **Step 3: Write `app/routes/external_api_routes.py`**

```python
"""External API — bearer-token-authenticated read-only endpoints for
4tExecutive. No browser session required.

Authentication: Authorization: Bearer <token> (see app/api_tokens.py).
Feature gate: app.app_settings.get_setting("external_api_enabled") — when
disabled, every route returns 503.

Endpoints:
  GET /external/api/executive/summary   Fleet-wide metrics for 4tExecutive
"""

from __future__ import annotations

import re

from flask import Blueprint, jsonify, request

from app.api_tokens import validate_token
from app.app_settings import get_setting

bp = Blueprint("external_api", __name__, url_prefix="/external/api")

_DISK_USAGE_RE = re.compile(r"Free\s+([\d.]+)\s*\w+,\s*Total\s+([\d.]+)\s*\w+")


def _feature_enabled() -> bool:
    return get_setting("external_api_enabled", False)


def _authenticate():
    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        return None
    return validate_token(auth[7:].strip())


def _gate():
    if not _feature_enabled():
        return jsonify({"error": "External API is disabled"}), 503
    if _authenticate() is None:
        return jsonify({"error": "Unauthorized — valid Bearer token required"}), 401
    return None


def _parse_disk_used_pct(disk_used: str | None) -> float | None:
    """"Free 40GB, Total 100GB" -> 60.0 (used percent). None if unparseable."""
    if not disk_used:
        return None
    match = _DISK_USAGE_RE.search(disk_used)
    if not match:
        return None
    free, total = float(match.group(1)), float(match.group(2))
    if total <= 0:
        return None
    return round((total - free) / total * 100, 1)


@bp.route("/executive/summary")
def executive_summary():
    gate_error = _gate()
    if gate_error is not None:
        return gate_error

    from app import faz_health_cache, log_stats_cache
    from app.config import Config
    from app.log_stats_history import get_latest_rollup

    targets = faz_health_cache.get_all_cached()
    faz_targets_total = len(targets)
    faz_targets_healthy = sum(1 for t in targets if t.get("status") in ("green", "yellow"))
    disk_pcts = [
        pct for t in targets if (pct := _parse_disk_used_pct(t.get("disk_used"))) is not None
    ]
    faz_disk_used_pct = max(disk_pcts) if disk_pcts else None

    log_cache = log_stats_cache.get_cached()
    if log_cache.get("collected_at") is not None:
        devices_logging = len(log_cache["logging_devices"])
        devices_silent = len(log_cache["silent_devices"])
        log_volume_events_per_sec = sum(d.get("lograte", 0.0) for d in log_cache["logging_devices"])
        log_stats_collected_at = log_cache["collected_at"]
    else:
        rollup = get_latest_rollup()
        if rollup is not None:
            devices_logging = rollup["devices_logging"]
            devices_silent = rollup["devices_silent"]
            log_volume_events_per_sec = rollup["total_lograte"]
            log_stats_collected_at = rollup["collected_at"]
        else:
            devices_logging = 0
            devices_silent = 0
            log_volume_events_per_sec = 0.0
            log_stats_collected_at = None

    return jsonify(
        {
            "schema_version": 1,
            "faz_targets_total": faz_targets_total,
            "faz_targets_healthy": faz_targets_healthy,
            "faz_disk_used_pct": faz_disk_used_pct,
            "devices_logging": devices_logging,
            "devices_silent": devices_silent,
            "silent_device_threshold_minutes": Config.SILENT_DEVICE_THRESHOLD_MINUTES,
            "log_volume_events_per_sec": log_volume_events_per_sec,
            "log_stats_collected_at": log_stats_collected_at,
        }
    )
```

- [ ] **Step 4: Register the blueprint and start the scheduler**

In `app/__init__.py`, add `"app.routes.external_api_routes"` to `_BLUEPRINT_MODULES`:

```python
_BLUEPRINT_MODULES: list[str] = [
    "app.routes.auth_routes",
    "app.routes.dashboard_routes",
    "app.routes.log_search_routes",
    "app.routes.admin_routes",
    "app.routes.external_api_routes",
]
```

After the existing `init_faz_health_scheduler(app)` block, add:

```python
    if not app.config.get("_LOG_STATS_STARTED"):
        app.config["_LOG_STATS_STARTED"] = True
        from app.log_stats_cache import init_scheduler as init_log_stats_scheduler
        from app.log_stats_history import init_db as init_log_stats_db

        init_log_stats_db()
        init_log_stats_scheduler(app)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_external_api_routes.py -v`
Expected: PASS

- [ ] **Step 6: Run the full suite**

Run: `uv run pytest -q`
Expected: PASS, zero failures.

- [ ] **Step 7: Run lint**

Run: `uv run ruff check .`
Expected: no errors. Fix any and re-run.

- [ ] **Step 8: Commit**

```bash
git add app/routes/external_api_routes.py tests/test_external_api_routes.py app/__init__.py
git commit -m "Add GET /external/api/executive/summary endpoint"
```

---

### Task 8: Documentation

**Files:**
- Modify: `readme.md`

- [ ] **Step 1: Document the new feature**

In `readme.md`, under "Current features", add a bullet after the "Log Search Tab" bullet:

```markdown
- **External API**: read-only `GET /external/api/executive/summary` for 4tExecutive, gated by a
  bearer token (`manage_api_tokens.py create <name>`) and an enable flag
  (`manage_api_tokens.py enable`/`disable`). Reports FAZ fleet health/disk, silent-device counts
  (from FortiAnalyzer `logview/logstats`, polled independently of the SNMP health cycle — see
  `SILENT_DEVICE_THRESHOLD_MINUTES`/`LOG_STATS_POLL_INTERVAL` in `.env.example`), and fleet log
  volume.
```

Add to the "Quick start (development)" block, after the `faz_targets.example.json` line:

```bash
cp api_tokens.example.json api_tokens.json
cp app_settings.example.json app_settings.json
```

- [ ] **Step 2: Document new env vars in `.env.example`**

Add near the existing `SNMP_POLL_INTERVAL` entry:

```
SILENT_DEVICE_THRESHOLD_MINUTES=60
LOG_STATS_POLL_INTERVAL=300
```

- [ ] **Step 3: Commit**

```bash
git add readme.md .env.example
git commit -m "Document the external API in readme.md and .env.example"
```

---

### Task 9: Full-suite verification

**Files:** none (verification only)

- [ ] **Step 1: Run the full test suite**

Run: `uv run pytest -q`
Expected: PASS, zero failures.

- [ ] **Step 2: Run lint**

Run: `uv run ruff check .`
Expected: no errors.

- [ ] **Step 3: Manual smoke check**

```bash
cp api_tokens.example.json api_tokens.json
cp app_settings.example.json app_settings.json
uv run python manage_api_tokens.py enable
uv run python manage_api_tokens.py create "smoke-test"
# copy the printed plaintext token
uv run python wsgi.py &
curl -s http://localhost:5443/external/api/executive/summary   # expect 401, no token
curl -s -H "Authorization: Bearer <token>" http://localhost:5443/external/api/executive/summary
# expect 200 with schema_version, faz_targets_total, devices_logging, etc.
```

Confirm the response is valid JSON matching spec section 2's shape, then stop the dev server.

- [ ] **Step 4: Report results to the user**

No commit for this task — verification only.

---

## Self-Review Notes

- **Spec coverage:** design doc §2 (payload contract) → Task 7; §3 (silent-device
  classification) → Task 2; §4 (collector & persistence) → Tasks 3–4; §5 (FAZClient) → Task 1;
  §6 (external API infra) → Tasks 5–7 (Admin UI descoped to CLI per this plan's Global
  Constraints, a documented implementation-time decision the design doc explicitly deferred).
- **Type consistency:** `get_log_stats()`'s return shape (`devid`/`devname`/`last_log_timestamp`/
  `lograte`) is used identically by `classify_devices()` (Task 2), `poll_all_targets()` (Task 4),
  and the route's `log_volume_events_per_sec` sum (Task 7).
- **Backward compatibility:** this is 4tlog's first external API — no existing consumers to
  break. The route itself only ships once `external_api_enabled` is explicitly turned on via the
  CLI, so a fresh deploy's default state (flag off) is unchanged from today.
