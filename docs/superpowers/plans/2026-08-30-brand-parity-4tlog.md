# Brand & UI Parity — 4tlog Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring 4tlog's topbar brand mark and Admin page to visual parity with 4thealth-plus by (1) swapping the emoji-and-text brand mark for an inline SVG extracted from 4tlog's own unused on-brand asset, (2) fixing a pre-existing CSS/markup class-name mismatch that leaves the four existing Admin tabs unstyled, and (3) adding a genuinely new host-metrics (CPU/Memory/Disk) collector and a 5th Admin tab exposing it as range-selectable charts.

**Architecture:** The brand mark and admin-tab styling fix are pure markup/CSS changes (Task 1) — no backend code, since 4tlog's stylesheet already carries the correct declarations, just under different selector names than the templates use. Host-metrics collection follows the two patterns this codebase already uses twice: an APScheduler background-poll module (`host_metrics_cache.py`, mirroring `log_stats_cache.py`) writing into a SQLite history module (`host_metrics_history.py`, mirroring `log_stats_history.py`, extended with a range query since this data has no other in-app precedent for that). A new admin API endpoint and client-rendered SVG charts (ported from 4thealth-plus's `admin.js`) complete the panel.

**Tech Stack:** Flask, Jinja2, vanilla JS, SQLite, APScheduler, `psutil` (new dependency), pytest.

**Spec:** `docs/superpowers/specs/2026-08-30-brand-parity-4tlog-design.md`

## Global Constraints

- No changes to 4thealth-plus — it is the read-only reference model for this work.
- No changes to login, base-chrome mechanisms (theme toggle, CSRF, logout), or the *content* of the four existing admin panels (Groups & Permissions, Users, Logs, FAZ Targets) — confirmed in the spec to already match 4thealth-plus's conventions.
- 4tlog's own working mechanisms (hand-rolled CSRF via `app/security.py`, JS/`localStorage` theme toggle, the `_BLUEPRINT_MODULES` registration pattern) are kept as-is.
- Every existing test must still pass unmodified — this plan is additive (new files, new panel, plus a class-name rename that no existing test references — confirmed via `grep -rn "brand-icon|panel-header|admin-tab-btn" tests/` returning zero matches).
- Test dates must never be hardcoded absolute values checked against a real `datetime.now()`-based range filter — a prior sibling project's plan shipped a test with a fixed date that silently fell outside its own range window once real time moved past it. Every test in this plan that seeds a timestamp for a range query computes it as `datetime.datetime.now(datetime.timezone.utc)`-relative at test-run time (see this codebase's own `prune_old_rows` tests for the established convention), never a literal string like `"2026-08-30T06:00:00Z"`.

## Corrections to the design spec (found while planning)

The design spec (section 4) said the existing 4 admin tabs are "already styled identically in 4tlog's own stylesheet." Reading `app/static/css/style.css` directly disproved this: 4tlog's CSS defines `.admin-tab`/`.admin-tab.active`/`.admin-panel-header` with declarations *identical* to 4thealth-plus's — but `app/templates/admin.html` and `app/static/js/admin.js` use different class names (`.admin-tab-btn`, `.panel-header`) that have **zero matching CSS anywhere in the file**. The four existing admin tabs and panel headers render with default browser button/div styling today — a pre-existing bug, not something this plan introduced. Since the explicit goal is admin-page visual parity with 4thealth-plus (whose own `admin.html` uses `.admin-tab`/`.admin-panel-header` — the same names 4tlog's CSS already expects), Task 1 renames the four existing tab buttons and four existing panel-header divs to the class names 4tlog's CSS already defines, plus the one JS selector that switches on `.admin-tab-btn`. This is a pure rename (no CSS added, no behavior changed) affecting only class attributes and one querySelector string; confirmed safe via a full-repo grep showing no test asserts on the old names.

---

## File Structure

- **Modify** `app/templates/base.html` — swap the emoji brand-icon for an inline SVG brand mark.
- **Modify** `app/static/css/style.css` — add `.brand-mark` + extend `.topbar-brand`; add the ported `.hm-*` block; remove the now-dead `.brand-icon` rule.
- **Modify** `app/templates/admin.html` — rename `.admin-tab-btn`→`.admin-tab` and `.panel-header`→`.admin-panel-header` on the four existing tabs/panels; add a 5th "Host Metrics" tab/panel.
- **Modify** `app/static/js/admin.js` — rename the `.admin-tab-btn` selector to `.admin-tab`; add host-metrics chart-rendering functions and the lazy-load tab-click branch.
- **Create** `app/host_metrics_history.py` — SQLite persistence + range query for host-metrics history.
- **Create** `app/host_metrics_cache.py` — `psutil`-based poll function + APScheduler wiring.
- **Modify** `app/config.py` — add `HOST_METRICS_POLL_INTERVAL` / `HOST_METRICS_POLL_DISABLED`.
- **Modify** `app/__init__.py` — wire the new scheduler module in alongside the two existing ones.
- **Modify** `app/routes/admin_routes.py` — add `GET /admin/api/host-metrics`.
- **Modify** `pyproject.toml` — add `psutil` to `dependencies`.
- **Modify** `.gitignore` — add `hostmetrics.db`.
- **Modify** `tests/conftest.py` — add `HOST_METRICS_POLL_DISABLED` env default.
- **Create** `tests/test_host_metrics_history.py`.
- **Create** `tests/test_host_metrics_cache.py`.
- **Modify** `tests/test_admin_routes.py` — add coverage for the new endpoint.

---

## Task 1: Brand mark and admin-tab class-name fix

**Files:**
- Modify: `app/templates/base.html`
- Modify: `app/templates/admin.html`
- Modify: `app/static/js/admin.js:17-25` (the tab-switching block only)
- Modify: `app/static/css/style.css` (`.topbar-brand`, `.brand-icon`, new `.brand-mark`)
- Test: none new (this is a pure markup/CSS/selector-rename task with no test currently covering the old names — verified via the Global Constraints grep). Verification is the full test suite staying green plus a manual visual check.

**Interfaces:**
- Produces: `.admin-tab` and `.admin-panel-header` become the live class names used by both the template and `admin.js`'s querySelectorAll calls — Task 5 (the new Host Metrics tab/panel) must use these same names, not the old `.admin-tab-btn`/`.panel-header`.

- [ ] **Step 1: Swap the brand mark in base.html**

In `app/templates/base.html`, replace:

```html
  <div class="topbar-brand">
    <span class="brand-icon">&#128269;</span> 4tlog
  </div>
```

with:

```html
  <div class="topbar-brand">
    <svg class="brand-mark" width="28" height="28" viewBox="0 0 96 96" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
      <path d="M48 6 L86 26 V70 L48 90 L10 70 V26 Z" fill="#f4f6f8"/>
      <path d="M48 6 L86 26 L48 46 L10 26 Z" fill="#3f7fd1"/>
      <rect x="24" y="46" width="30" height="4.4" rx="2.2" fill="#141a24"/>
      <rect x="24" y="56" width="44" height="4.4" rx="2.2" fill="#141a24"/>
      <rect x="24" y="66" width="20" height="4.4" rx="2.2" fill="#141a24"/>
    </svg>
    4tlog
  </div>
```

(This is the icon group extracted verbatim from `app/static/img/logo-console-v2.svg`'s `<g transform="translate(28, 22)">` block — same paths, just without the outer translate and without the background plate/text elements that logo file also carries. The icon file itself is left untouched; it stays unused as a full-lockup asset for any future non-topbar use.)

- [ ] **Step 2: Add `.brand-mark` CSS and extend `.topbar-brand`**

In `app/static/css/style.css`, find:

```css
.topbar-brand {
  font-size: 1.1rem;
  font-weight: 700;
  letter-spacing: .5px;
  color: #fff;
  white-space: nowrap;
}

.brand-icon { margin-right: .3rem; }
```

Replace with:

```css
.topbar-brand {
  display: flex;
  align-items: center;
  font-size: 1.1rem;
  font-weight: 700;
  letter-spacing: .5px;
  color: #fff;
  white-space: nowrap;
}

.brand-mark {
  width: 28px;
  height: 28px;
  flex-shrink: 0;
  margin-right: .4rem;
  vertical-align: middle;
}
```

(This deletes the now-dead `.brand-icon` rule and adds `.brand-mark`, matching 4thealth-plus's own `.topbar-brand`/`.brand-mark` declarations exactly.)

- [ ] **Step 3: Rename the four existing admin tab buttons and panel headers**

In `app/templates/admin.html`, there are four occurrences of `class="admin-tab-btn ..."` (one has `active` too) on the tab buttons, and four occurrences of `class="panel-header"` on the panel-header divs. Rename all of them:

- `class="admin-tab-btn active"` → `class="admin-tab active"` (the Groups & Permissions button)
- `class="admin-tab-btn"` → `class="admin-tab"` (the three other buttons: Users, Logs, FAZ Targets)
- `class="panel-header"` → `class="admin-panel-header"` (all four panel-header divs)

Do not change `data-panel` attribute values, button text, or anything else in this file in this step — Step 4 of this task handles the JS selector, and Task 5 adds the 5th tab/panel using these corrected class names from the start.

- [ ] **Step 4: Rename the JS tab-switching selector**

In `app/static/js/admin.js`, lines 17-25, replace:

```javascript
  // ── Admin sub-tab switching ────────────────────────────────────────────────
  document.querySelectorAll('.admin-tab-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.admin-tab-btn').forEach((b) => b.classList.remove('active'));
      document.querySelectorAll('.admin-panel').forEach((p) => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById(btn.dataset.panel).classList.add('active');
      if (btn.dataset.panel === 'panel-logs') loadLogs();
    });
  });
```

with:

```javascript
  // ── Admin sub-tab switching ────────────────────────────────────────────────
  document.querySelectorAll('.admin-tab').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.admin-tab').forEach((b) => b.classList.remove('active'));
      document.querySelectorAll('.admin-panel').forEach((p) => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById(btn.dataset.panel).classList.add('active');
      if (btn.dataset.panel === 'panel-logs') loadLogs();
    });
  });
```

(Only `.admin-tab-btn` → `.admin-tab` changes, in both places it appears in this block — everything else, including the `panel-logs` lazy-load branch, is unchanged. Task 5 adds a new branch to this same block for the Host Metrics panel.)

- [ ] **Step 5: Run the full test suite**

Run: `uv run pytest -q`
Expected: PASS, same count as baseline — nothing in this task touches Python logic or any string a test asserts on.

- [ ] **Step 6: Commit**

```bash
git add app/templates/base.html app/templates/admin.html app/static/js/admin.js app/static/css/style.css
git commit -m "Replace emoji brand mark with inline SVG; fix admin-tab/panel-header class mismatch"
```

---

## Task 2: Host-metrics history module

**Files:**
- Create: `app/host_metrics_history.py`
- Modify: `.gitignore`
- Test: `tests/test_host_metrics_history.py`

**Interfaces:**
- Produces: `RANGES: dict[str, datetime.timedelta]` (keys `"1h"`, `"4h"`, `"12h"`, `"1d"`, `"7d"`, `"14d"`), `DEFAULT_RANGE: str` (`"1h"`), `init_db() -> None`, `write_snapshot(cpu_percent: float, memory_percent: float, disk_percent: float, collected_at: str) -> None`, `get_history(since: str) -> list[dict]` (each dict: `{"collected_at": str, "cpu_percent": float, "memory_percent": float, "disk_percent": float}`, ordered ascending by `collected_at`), `prune_old_rows(retention_days: int = 30) -> None`. Task 3's `host_metrics_cache.py` and Task 4's new route both import from this module.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_host_metrics_history.py`:

```python
import datetime

import pytest


@pytest.fixture
def history_db(tmp_path, monkeypatch):
    path = tmp_path / "hostmetrics.db"
    import app.host_metrics_history as history_mod

    monkeypatch.setattr(history_mod, "DB_PATH", path)
    history_mod.init_db()
    yield path


def test_get_history_empty_when_no_rows(history_db):
    from app.host_metrics_history import get_history

    assert get_history("2020-01-01T00:00:00Z") == []


def test_write_and_read_history_in_range(history_db):
    from app.host_metrics_history import get_history, write_snapshot

    write_snapshot(
        cpu_percent=10.0, memory_percent=40.0, disk_percent=55.0,
        collected_at="2026-08-29T09:00:00Z",
    )
    write_snapshot(
        cpu_percent=12.5, memory_percent=41.0, disk_percent=55.5,
        collected_at="2026-08-29T09:05:00Z",
    )

    rows = get_history("2026-08-29T09:00:00Z")

    assert rows == [
        {"collected_at": "2026-08-29T09:00:00Z", "cpu_percent": 10.0, "memory_percent": 40.0, "disk_percent": 55.0},
        {"collected_at": "2026-08-29T09:05:00Z", "cpu_percent": 12.5, "memory_percent": 41.0, "disk_percent": 55.5},
    ]


def test_get_history_excludes_rows_before_since(history_db):
    from app.host_metrics_history import get_history, write_snapshot

    write_snapshot(
        cpu_percent=10.0, memory_percent=40.0, disk_percent=55.0,
        collected_at="2026-08-29T08:00:00Z",
    )
    write_snapshot(
        cpu_percent=12.5, memory_percent=41.0, disk_percent=55.5,
        collected_at="2026-08-29T09:05:00Z",
    )

    rows = get_history("2026-08-29T09:00:00Z")

    assert rows == [
        {"collected_at": "2026-08-29T09:05:00Z", "cpu_percent": 12.5, "memory_percent": 41.0, "disk_percent": 55.5},
    ]


def test_prune_old_rows_removes_rows_past_retention(history_db):
    from app.host_metrics_history import prune_old_rows, write_snapshot

    old_ts = (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=40)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    recent_ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    write_snapshot(cpu_percent=1.0, memory_percent=1.0, disk_percent=1.0, collected_at=old_ts)
    write_snapshot(cpu_percent=2.0, memory_percent=2.0, disk_percent=2.0, collected_at=recent_ts)

    prune_old_rows(retention_days=30)

    import sqlite3

    import app.host_metrics_history as history_mod

    conn = sqlite3.connect(history_mod.DB_PATH)
    rows = conn.execute("SELECT collected_at FROM host_metrics_history").fetchall()
    conn.close()
    assert rows == [(recent_ts,)]
```

Note the two range-query tests use fixed dates in the past (`2026-08-29T...`), not relative-to-now dates — this is safe because `get_history(since)` is a pure `collected_at >= since` string comparison with no dependency on the real wall clock (unlike the API endpoint in Task 4, which computes `since` from `datetime.now()` and does need the relative-timestamp treatment the Global Constraints section describes).

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_host_metrics_history.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.host_metrics_history'`

- [ ] **Step 3: Write the implementation**

Create `app/host_metrics_history.py`:

```python
"""SQLite-backed history of host CPU/Memory/Disk utilization, one row per
app.host_metrics_cache poll cycle. Schema/pattern mirrors
app/log_stats_history.py, extended with a range query since the Admin >
Host Metrics panel charts trends over a selectable window rather than only
ever needing the latest value.
"""

from __future__ import annotations

import contextlib
import datetime
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "hostmetrics.db"

RANGES: dict[str, datetime.timedelta] = {
    "1h": datetime.timedelta(hours=1),
    "4h": datetime.timedelta(hours=4),
    "12h": datetime.timedelta(hours=12),
    "1d": datetime.timedelta(days=1),
    "7d": datetime.timedelta(days=7),
    "14d": datetime.timedelta(days=14),
}
DEFAULT_RANGE = "1h"


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(DB_PATH)


def init_db() -> None:
    with contextlib.closing(_connect()) as conn, conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS host_metrics_history (
                collected_at TEXT NOT NULL,
                cpu_percent REAL NOT NULL,
                memory_percent REAL NOT NULL,
                disk_percent REAL NOT NULL
            )
            """
        )


def write_snapshot(
    cpu_percent: float, memory_percent: float, disk_percent: float, collected_at: str
) -> None:
    with contextlib.closing(_connect()) as conn, conn:
        conn.execute(
            "INSERT INTO host_metrics_history "
            "(collected_at, cpu_percent, memory_percent, disk_percent) VALUES (?, ?, ?, ?)",
            (collected_at, cpu_percent, memory_percent, disk_percent),
        )


def get_history(since: str) -> list[dict]:
    with contextlib.closing(_connect()) as conn, conn:
        rows = conn.execute(
            "SELECT collected_at, cpu_percent, memory_percent, disk_percent "
            "FROM host_metrics_history WHERE collected_at >= ? ORDER BY collected_at ASC",
            (since,),
        ).fetchall()
    return [
        {
            "collected_at": collected_at,
            "cpu_percent": cpu_percent,
            "memory_percent": memory_percent,
            "disk_percent": disk_percent,
        }
        for collected_at, cpu_percent, memory_percent, disk_percent in rows
    ]


def prune_old_rows(retention_days: int = 30) -> None:
    cutoff = (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=retention_days)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    with contextlib.closing(_connect()) as conn, conn:
        conn.execute("DELETE FROM host_metrics_history WHERE collected_at < ?", (cutoff,))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_host_metrics_history.py -v`
Expected: PASS, 4/4

- [ ] **Step 5: Add the new DB file to .gitignore**

In `.gitignore`, find the line `logstats.db` and add a new line immediately after it:

```
hostmetrics.db
```

- [ ] **Step 6: Run the full test suite**

Run: `uv run pytest -q`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add app/host_metrics_history.py tests/test_host_metrics_history.py .gitignore
git commit -m "Add host-metrics history module (SQLite persistence + range query)"
```

---

## Task 3: Host-metrics scheduler module

**Files:**
- Create: `app/host_metrics_cache.py`
- Modify: `app/config.py`
- Modify: `tests/conftest.py`
- Modify: `pyproject.toml`
- Test: `tests/test_host_metrics_cache.py`

**Interfaces:**
- Consumes: `app.host_metrics_history.write_snapshot`, `app.host_metrics_history.prune_old_rows` (Task 2).
- Produces: `poll_host_metrics() -> None`, `poll_now() -> None`, `init_scheduler(app) -> None`. Task 4's app-factory wiring (in `app/__init__.py`) calls `init_scheduler`.

- [ ] **Step 1: Add the psutil dependency**

In `pyproject.toml`, in the `dependencies` list, add a new line after `"cryptography>=49.0.0",`:

```toml
    "psutil>=6.0",
```

Run: `uv sync` to install it.

- [ ] **Step 2: Add config flags**

In `app/config.py`, after the existing block:

```python
    # Set by tests/conftest.py to skip starting the background health
    # poller (real network/SNMP calls) during the test suite.
    FAZ_HEALTH_POLL_DISABLED = os.environ.get("FAZ_HEALTH_POLL_DISABLED", "false").lower() == "true"
```

add:

```python

    # Host CPU/Memory/Disk polling (app/host_metrics_cache.py) — local
    # psutil reads, independent cadence from the FAZ-facing pollers since
    # there's no network round-trip to amortize.
    HOST_METRICS_POLL_INTERVAL = int(os.environ.get("HOST_METRICS_POLL_INTERVAL", "60"))

    # Set by tests/conftest.py to skip starting the background host-metrics
    # poller during the test suite.
    HOST_METRICS_POLL_DISABLED = os.environ.get("HOST_METRICS_POLL_DISABLED", "false").lower() == "true"
```

- [ ] **Step 3: Add the test-suite env default**

In `tests/conftest.py`, after the line `os.environ.setdefault("LOG_STATS_POLL_DISABLED", "true")`, add:

```python
os.environ.setdefault("HOST_METRICS_POLL_DISABLED", "true")
```

- [ ] **Step 4: Write the failing tests**

Create `tests/test_host_metrics_cache.py`:

```python
import pytest


@pytest.fixture
def history_db(tmp_path, monkeypatch):
    path = tmp_path / "hostmetrics.db"
    import app.host_metrics_history as history_mod

    monkeypatch.setattr(history_mod, "DB_PATH", path)
    history_mod.init_db()
    yield path


def test_poll_host_metrics_writes_snapshot(history_db, monkeypatch):
    import psutil

    import app.host_metrics_cache as cache_mod
    from app.host_metrics_history import get_history

    monkeypatch.setattr(psutil, "cpu_percent", lambda: 12.5)
    monkeypatch.setattr(
        psutil, "virtual_memory", lambda: type("_VM", (), {"percent": 40.0})()
    )
    monkeypatch.setattr(
        psutil, "disk_usage", lambda path: type("_DU", (), {"percent": 55.0})()
    )

    cache_mod.poll_host_metrics()

    rows = get_history("1970-01-01T00:00:00Z")
    assert len(rows) == 1
    assert rows[0]["cpu_percent"] == 12.5
    assert rows[0]["memory_percent"] == 40.0
    assert rows[0]["disk_percent"] == 55.0


def test_init_scheduler_noop_when_disabled(monkeypatch):
    import app.host_metrics_cache as cache_mod
    from app.config import Config

    monkeypatch.setattr(Config, "HOST_METRICS_POLL_DISABLED", True)
    calls = []
    monkeypatch.setattr(cache_mod, "poll_now", lambda: calls.append("called"))

    cache_mod.init_scheduler(app=None)

    assert calls == []
```

- [ ] **Step 5: Run tests to verify they fail**

Run: `uv run pytest tests/test_host_metrics_cache.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.host_metrics_cache'`

- [ ] **Step 6: Write the implementation**

Create `app/host_metrics_cache.py`:

```python
"""Background poller for host CPU/Memory/Disk utilization, persisted so the
Admin > Host Metrics panel can chart trends across restarts. Structured like
app/log_stats_cache.py: a poll function writes into
app/host_metrics_history.py's SQLite store. Unlike log_stats_cache.py there
is no in-memory `_cache` dict here — Admin's range-query API is the only
consumer, and it reads the history store directly; nothing needs an instant
in-process snapshot the way FAZ health's dashboard cards do.
"""

from __future__ import annotations

import datetime
import threading

import psutil

from app.config import Config


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def poll_host_metrics() -> None:
    import app.host_metrics_history as history

    cpu_percent = psutil.cpu_percent()
    memory_percent = psutil.virtual_memory().percent
    disk_percent = psutil.disk_usage("/").percent
    history.write_snapshot(
        cpu_percent=cpu_percent,
        memory_percent=memory_percent,
        disk_percent=disk_percent,
        collected_at=_now(),
    )
    history.prune_old_rows()


def poll_now() -> None:
    """Kick off a non-blocking poll in a daemon thread."""
    t = threading.Thread(target=poll_host_metrics, name="host_metrics_poll_now", daemon=True)
    t.start()


def init_scheduler(app) -> None:
    """Register a recurring APScheduler job and run the first poll immediately.

    No-op if Config.HOST_METRICS_POLL_DISABLED (set by tests/conftest.py) —
    keeps the test suite from starting a real background polling thread.
    """
    if Config.HOST_METRICS_POLL_DISABLED:
        return

    from apscheduler.schedulers.background import BackgroundScheduler

    poll_now()

    scheduler = BackgroundScheduler()
    scheduler.add_job(
        func=poll_host_metrics,
        trigger="interval",
        seconds=Config.HOST_METRICS_POLL_INTERVAL,
        id="host_metrics_poll",
        replace_existing=True,
        max_instances=1,
    )
    scheduler.start()
```

`psutil.cpu_percent()` called with no interval argument returns `0.0` on its very first call in a process (no prior baseline to compare against) and an accurate reading on every subsequent call — this is the same behavior 4tExecutive's own equivalent collector already has and ships with; not a defect to fix here, just expected behavior that self-corrects on the next poll cycle.

- [ ] **Step 7: Run tests to verify they pass**

Run: `uv run pytest tests/test_host_metrics_cache.py -v`
Expected: PASS, 2/2

- [ ] **Step 8: Run the full test suite**

Run: `uv run pytest -q`
Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add app/host_metrics_cache.py app/config.py tests/conftest.py tests/test_host_metrics_cache.py pyproject.toml uv.lock
git commit -m "Add host-metrics scheduler module (psutil poll + APScheduler wiring)"
```

---

## Task 4: Wire the scheduler into the app factory, add the API endpoint

**Files:**
- Modify: `app/__init__.py`
- Modify: `app/routes/admin_routes.py`
- Test: `tests/test_admin_routes.py`

**Interfaces:**
- Consumes: `app.host_metrics_cache.init_scheduler` (Task 3), `app.host_metrics_history.{RANGES, DEFAULT_RANGE, get_history}` (Task 2).
- Produces: `GET /admin/api/host-metrics?range=<key>` → `{"cpu": [{"ts": <epoch_seconds>, "v": <float>}, ...], "mem": [...], "disk": [...]}`. Task 5's `admin.js` chart-rendering code fetches this endpoint.

- [ ] **Step 1: Wire the scheduler into the app factory**

In `app/__init__.py`, after the existing block:

```python
    if not app.config.get("_LOG_STATS_STARTED"):
        app.config["_LOG_STATS_STARTED"] = True
        from app.log_stats_cache import init_scheduler as init_log_stats_scheduler
        from app.log_stats_history import init_db as init_log_stats_db

        init_log_stats_db()
        init_log_stats_scheduler(app)

    return app
```

insert a third block before `return app`:

```python
    if not app.config.get("_HOST_METRICS_STARTED"):
        app.config["_HOST_METRICS_STARTED"] = True
        from app.host_metrics_cache import init_scheduler as init_host_metrics_scheduler
        from app.host_metrics_history import init_db as init_host_metrics_db

        init_host_metrics_db()
        init_host_metrics_scheduler(app)

    return app
```

- [ ] **Step 2: Write the failing tests**

In `tests/test_admin_routes.py`, add:

```python
def test_host_metrics_api_blocked_for_viewer(client):
    _login(client, "viewer1")
    resp = client.get("/admin/api/host-metrics")
    assert resp.status_code == 403


def test_host_metrics_api_returns_shape(client, tmp_path, monkeypatch):
    import datetime

    import app.host_metrics_history as history_mod

    monkeypatch.setattr(history_mod, "DB_PATH", tmp_path / "hostmetrics.db")
    history_mod.init_db()
    # A relative-to-now timestamp, not a fixed literal — the endpoint under
    # test filters by "since = now - range", so a hardcoded past date would
    # silently fall outside the window once real time moves past it (see
    # this plan's Global Constraints section).
    recent_ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    history_mod.write_snapshot(
        cpu_percent=12.5, memory_percent=40.0, disk_percent=55.0, collected_at=recent_ts,
    )
    expected_epoch = int(datetime.datetime.fromisoformat(recent_ts).timestamp())

    _login(client, "admin1")
    resp = client.get("/admin/api/host-metrics?range=1d")

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["cpu"] == [{"ts": expected_epoch, "v": 12.5}]
    assert body["mem"] == [{"ts": expected_epoch, "v": 40.0}]
    assert body["disk"] == [{"ts": expected_epoch, "v": 55.0}]


def test_host_metrics_api_defaults_invalid_range(client, tmp_path, monkeypatch):
    import datetime

    import app.host_metrics_history as history_mod

    monkeypatch.setattr(history_mod, "DB_PATH", tmp_path / "hostmetrics.db")
    history_mod.init_db()
    recent_ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    history_mod.write_snapshot(
        cpu_percent=5.0, memory_percent=10.0, disk_percent=15.0, collected_at=recent_ts,
    )

    _login(client, "admin1")
    resp = client.get("/admin/api/host-metrics?range=not-a-real-range")

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["cpu"] == [{"ts": int(datetime.datetime.fromisoformat(recent_ts).timestamp()), "v": 5.0}]
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run pytest tests/test_admin_routes.py -k host_metrics_api -v`
Expected: FAIL with 404 (route doesn't exist yet)

- [ ] **Step 4: Add the endpoint**

In `app/routes/admin_routes.py`, add to the imports:

```python
import datetime
```

(alongside the existing `from flask import ...` line — this repo's existing convention in this file has no other `import datetime`, so add it as its own top-level import line before the `from flask import` line, matching the file's existing style of stdlib imports first.)

Add a new section, following the file's existing `# ── Logs API ── ...` section divider convention, after the Logs API section:

```python
# ── Host Metrics API ──────────────────────────────────────────────────────────


@bp.route("/api/host-metrics")
@_admin_required
def api_host_metrics():
    import app.host_metrics_history as history

    range_key = request.args.get("range", history.DEFAULT_RANGE)
    if range_key not in history.RANGES:
        range_key = history.DEFAULT_RANGE

    since_dt = datetime.datetime.now(datetime.timezone.utc) - history.RANGES[range_key]
    since = since_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    rows = history.get_history(since)

    result = {"cpu": [], "mem": [], "disk": []}
    for row in rows:
        ts = int(datetime.datetime.fromisoformat(row["collected_at"]).timestamp())
        result["cpu"].append({"ts": ts, "v": row["cpu_percent"]})
        result["mem"].append({"ts": ts, "v": row["memory_percent"]})
        result["disk"].append({"ts": ts, "v": row["disk_percent"]})
    return jsonify(result)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_admin_routes.py -k host_metrics_api -v`
Expected: PASS, 3/3

- [ ] **Step 6: Run the full test suite**

Run: `uv run pytest -q`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add app/__init__.py app/routes/admin_routes.py tests/test_admin_routes.py
git commit -m "Wire host-metrics scheduler into app factory; add /admin/api/host-metrics"
```

---

## Task 5: Host Metrics admin panel (markup, CSS, charts)

**Files:**
- Modify: `app/templates/admin.html` (add the 5th tab + panel)
- Modify: `app/static/css/style.css` (add the `.hm-*` block)
- Modify: `app/static/js/admin.js` (add chart rendering + tab-click branch)
- Test: none new — this task is markup/CSS/client-JS with no server-side logic; the endpoint it calls is already tested in Task 4. Verified via the full suite staying green and a manual browser smoke check (deferred to this plan's Finish task, same as the 4tExecutive sibling project's approach for JS-only work no Python test can cover).

**Interfaces:**
- Consumes: `GET /admin/api/host-metrics?range=<key>` (Task 4), the `.admin-tab`/`.admin-panel`/`.admin-panel-header` class names (Task 1).

- [ ] **Step 1: Add the 5th tab button and panel to admin.html**

In `app/templates/admin.html`, in the `#adminTabs` div, add a 5th button after the FAZ Targets button:

```html
<div class="admin-tabs" id="adminTabs">
  <button class="admin-tab active" data-panel="panel-groups">Groups &amp; Permissions</button>
  <button class="admin-tab" data-panel="panel-users">Users</button>
  <button class="admin-tab" data-panel="panel-logs">Logs</button>
  <button class="admin-tab" data-panel="panel-faz-targets">FAZ Targets</button>
  <button class="admin-tab" data-panel="panel-host-metrics">Host Metrics</button>
</div>
```

(This assumes Task 1's rename already landed — the four existing buttons should already read `class="admin-tab"`/`class="admin-tab active"` at this point in the plan.)

After the closing `</div>` of `panel-faz-targets` (and before the `groupModal` overlay div), add the new panel:

```html
<div class="admin-panel" id="panel-host-metrics">
  <div class="admin-panel-header">
    <h2>Host Metrics</h2>
  </div>
  <div class="hm-header">
    <div class="hm-range-row">
      <button type="button" class="btn btn-sm hm-range-btn active" data-range="1h">1 hour</button>
      <button type="button" class="btn btn-sm hm-range-btn" data-range="4h">4 hours</button>
      <button type="button" class="btn btn-sm hm-range-btn" data-range="12h">12 hours</button>
      <button type="button" class="btn btn-sm hm-range-btn" data-range="1d">1 day</button>
      <button type="button" class="btn btn-sm hm-range-btn" data-range="7d">7 days</button>
      <button type="button" class="btn btn-sm hm-range-btn" data-range="14d">14 days</button>
    </div>
    <div class="hm-cards">
      <div class="hm-card">
        <div class="hm-card-title">CPU</div>
        <div id="hmCpuChart" class="hm-chart"></div>
      </div>
      <div class="hm-card">
        <div class="hm-card-title">Memory</div>
        <div id="hmMemChart" class="hm-chart"></div>
      </div>
      <div class="hm-card">
        <div class="hm-card-title">Disk</div>
        <div id="hmDiskChart" class="hm-chart"></div>
      </div>
    </div>
  </div>
</div>
```

- [ ] **Step 2: Port the `.hm-*` CSS block**

Append to the end of `app/static/css/style.css`:

```css

/* ── Host resource graphs (Admin) ────────────────────────────────────── */
.hm-header { margin-bottom: 1.25rem; }
.hm-range-row {
  display: flex;
  align-items: center;
  gap: .5rem;
  flex-wrap: wrap;
  margin-bottom: .75rem;
}
.hm-range-btn.active {
  background: var(--primary);
  color: #fff;
  border-color: var(--primary);
}
.hm-cards {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 1rem;
}
@media (max-width: 900px) {
  .hm-cards { grid-template-columns: 1fr; }
}
.hm-card {
  padding: .75rem;
  background: var(--surface-alt);
  border: 1px solid var(--border);
  border-radius: 6px;
}
.hm-card-title {
  font-size: .85rem;
  font-weight: 600;
  margin-bottom: .5rem;
  display: flex;
  align-items: center;
  gap: .35rem;
}
.hm-chart {
  display: flex;
  flex-direction: column;
}
.hm-svg-wrap { height: 100px; }
.hm-svg {
  width: 100%;
  height: 100%;
  display: block;
  overflow: visible;
}
.hm-area {
  fill: var(--primary);
  opacity: .12;
}
.hm-line {
  fill: none;
  stroke: var(--primary);
  stroke-width: 1.5;
  vector-effect: non-scaling-stroke;
  stroke-linejoin: round;
  stroke-linecap: round;
}
.hm-dot {
  fill: var(--primary);
  opacity: 0;
  transition: opacity .15s ease;
}
.hm-svg:hover .hm-dot { opacity: 1; }
.hm-axis {
  display: flex;
  gap: 2px;
  margin-top: .3rem;
  border-top: 1px solid var(--border);
  padding-top: .25rem;
}
.hm-tick {
  flex: 1;
  min-width: 2px;
  font-size: .65rem;
  color: var(--text-muted);
  text-align: center;
  white-space: nowrap;
  overflow: hidden;
}
```

(Ported verbatim from 4thealth-plus's `style.css` — confirmed 4tlog has zero `.hm-*` rules today. `var(--primary)`, `var(--surface-alt)`, `var(--border)`, `var(--text-muted)` are all already defined in 4tlog's existing `:root` token block, same names 4thealth-plus uses, so no token-block edits are needed here — unlike 4tExecutive's sibling project, which had a different token-naming scheme to reconcile.)

- [ ] **Step 3: Add the tab-click branch and chart-rendering JS**

In `app/static/js/admin.js`, extend the tab-switching block (already renamed to `.admin-tab` in Task 1) with a new branch:

```javascript
  document.querySelectorAll('.admin-tab').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.admin-tab').forEach((b) => b.classList.remove('active'));
      document.querySelectorAll('.admin-panel').forEach((p) => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById(btn.dataset.panel).classList.add('active');
      if (btn.dataset.panel === 'panel-logs') loadLogs();
      if (btn.dataset.panel === 'panel-host-metrics' && !_hostMetricsLoaded) {
        _hostMetricsLoaded = true;
        loadHostMetrics('1h');
      }
    });
  });
```

(Only the new `if (btn.dataset.panel === 'panel-host-metrics' ...)` branch is added; the rest of this block is exactly what Task 1 left it as.)

Add a new module-level flag near the top of the file, alongside the existing `const state = { ... };` line:

```javascript
  let _hostMetricsLoaded = false;
```

Append the chart-rendering section to the end of the file, before the final `init();` call and closing `})();`:

```javascript
  // ── Host Metrics ───────────────────────────────────────────────────────────
  const HM_CHARTS = [
    { key: 'cpu', el: 'hmCpuChart' },
    { key: 'mem', el: 'hmMemChart' },
    { key: 'disk', el: 'hmDiskChart' },
  ];

  function hmEsc(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function hmAxisLabel(ts, showDate) {
    const d = new Date(ts * 1000);
    return showDate
      ? d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
      : d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
  }

  const HM_VB_W = 300;
  const HM_VB_H = 100;

  function renderHmChart(chartEl, series, showDate) {
    if (!series.length) {
      chartEl.innerHTML = '<div class="text-muted" style="padding:1rem 0">No data yet.</div>';
      return;
    }
    const n = series.length;
    const vals = series.map((p) => (p.v == null ? null : Math.max(0, Math.min(100, p.v))));
    const xAt = (i) => (n === 1 ? HM_VB_W / 2 : (i / (n - 1)) * HM_VB_W);
    const yAt = (v) => HM_VB_H - (v / 100) * HM_VB_H;

    const pts = vals.map((v, i) => (v == null ? null : `${xAt(i).toFixed(2)},${yAt(v).toFixed(2)}`));
    const linePts = pts.filter((p) => p !== null).join(' ');
    const areaPts = linePts ? `0,${HM_VB_H} ${linePts} ${HM_VB_W},${HM_VB_H}` : '';

    const dots = vals
      .map((v, i) => {
        if (v == null) return '';
        const title = `${hmAxisLabel(series[i].ts, true)}: ${v.toFixed(1)}%`;
        return `<circle class="hm-dot" cx="${xAt(i).toFixed(2)}" cy="${yAt(v).toFixed(2)}" r="1.6"><title>${hmEsc(title)}</title></circle>`;
      })
      .join('');

    const svg = `<svg class="hm-svg" viewBox="0 0 ${HM_VB_W} ${HM_VB_H}" preserveAspectRatio="none">
      ${areaPts ? `<polygon class="hm-area" points="${areaPts}"></polygon>` : ''}
      ${linePts ? `<polyline class="hm-line" points="${linePts}"></polyline>` : ''}
      ${dots}
    </svg>`;

    const tickIdxs = [...new Set([0, 0.25, 0.5, 0.75, 1].map((f) => Math.min(n - 1, Math.round(f * (n - 1)))))];
    const axis = series
      .map((p, i) => `<div class="hm-tick">${tickIdxs.includes(i) ? hmEsc(hmAxisLabel(p.ts, showDate)) : ''}</div>`)
      .join('');

    chartEl.innerHTML = `<div class="hm-svg-wrap">${svg}</div><div class="hm-axis">${axis}</div>`;
  }

  async function loadHostMetrics(range) {
    document.querySelectorAll('.hm-range-btn').forEach((b) => b.classList.toggle('active', b.dataset.range === range));

    const resp = await fetch('/admin/api/host-metrics?range=' + encodeURIComponent(range));
    if (!resp.ok) return;
    const data = await resp.json();
    const showDate = range === '7d' || range === '14d';
    HM_CHARTS.forEach(({ key, el: elId }) => {
      renderHmChart(document.getElementById(elId), data[key] || [], showDate);
    });
  }

  document.querySelectorAll('.hm-range-btn').forEach((btn) => {
    btn.addEventListener('click', () => loadHostMetrics(btn.dataset.range));
  });
```

(This is 4thealth-plus's `renderHmChart`/`hmAxisLabel`/`loadHostMetrics` ported near-verbatim — renamed the local `esc()` helper to `hmEsc()` and the `renderHmChart` parameter from `el` to `chartEl` to avoid colliding with this file's own top-level `el(tag, attrs, children)` DOM-builder helper, which 4thealth-plus's `admin.js` doesn't have. No periodic `setInterval` auto-refresh is added — 4tExecutive's sibling implementation of this same feature didn't add one either, and the range-button click already re-fetches on demand.)

- [ ] **Step 4: Manual smoke check**

This step needs a running server and a browser, not `pytest` — no automated test in this repo exercises client-side JS chart rendering (confirmed: no JS test runner in this project). Run the dev server, log in as an admin user, go to Admin → Host Metrics, and confirm:
- The three chart cards show real line charts once at least one poll has completed (wait up to ~60 seconds after server start for the first poll, or seed a row directly via a Python shell using `app.host_metrics_history.write_snapshot`).
- Clicking each range button re-fetches and redraws without a page reload (watch the Network tab for `/admin/api/host-metrics?range=...` requests).
- The other four tabs (Groups & Permissions, Users, Logs, FAZ Targets) now render with proper tab/panel-header styling (Task 1's fix) instead of the previous unstyled buttons/headers.
- The topbar's new SVG brand mark renders correctly in both light and dark theme.

- [ ] **Step 5: Run the full test suite**

Run: `uv run pytest -q`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add app/templates/admin.html app/static/css/style.css app/static/js/admin.js
git commit -m "Add Host Metrics admin panel with range-selectable client-rendered charts"
```

---

## Task 6: Finish

- [ ] **Step 1: Run the full test suite**

Run: `uv run pytest -q`
Expected: PASS, 0 failures.

- [ ] **Step 2: Run lint**

Run: `uv run ruff check .` (and `uv run ruff format --check .` if this repo's CI enforces it — check `.github/workflows/` for the exact commands and use those verbatim).
Expected: no errors.

- [ ] **Step 3: Manual smoke check**

With the dev server running (repeats Task 5 Step 4's checks plus the rest of the app, for a full pass):
- Log in, confirm the topbar brand mark renders in both themes.
- Click through all five Admin tabs — confirm all five (not just the new one) now render with correct tab/panel-header styling.
- On the Host Metrics tab, change the range and confirm charts redraw without a page reload.
- Confirm the four pre-existing panels' functionality (create/edit/delete a group, create/edit/delete a FAZ target, view users, view/filter/clear logs) still works exactly as before — this plan should not have changed any of their behavior, only their CSS class names.

- [ ] **Step 4: Report results to the user**

Summarize: test suite status, lint status, and a plain-language description of what the manual smoke check confirmed (or any issue found and how it was resolved).
