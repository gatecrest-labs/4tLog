# Brand & UI Parity — 4tlog — Design

Date: 2026-08-30
Repos: `4tlog` (this repo). Reference/model: `4thealth-plus` (`/Users/alanw/code/github/ai/4thealth-plus`) — unmodified by this work.
Related: second of two sub-projects bringing 4tExecutive and 4tlog to visual/structural parity with 4thealth-plus. 4tExecutive's equivalent work is complete and merged (`docs/superpowers/specs/2026-08-30-brand-parity-4texecutive-design.md` in that repo).

## 1. Scope

Unlike 4tExecutive, 4tlog already shares almost all of 4thealth-plus's chrome conventions — same `.login-page`/`.login-card`/`.form-group`/`.btn` CSS classes, same `.admin-tabs`/`.admin-panel` tab-switching pattern, same CSRF-header-injecting `fetch()` monkeypatch, same flash-message block, same APScheduler-based background-cache module pattern (`faz_health_cache.py`, `log_stats_cache.py`) and SQLite-history persistence pattern (`log_stats_history.py`). This spec is narrower than 4tExecutive's as a result.

In scope:
- Replace the topbar's emoji-and-text brand mark with an inline SVG mark, extracted from 4tlog's own already-on-brand (but currently unused) `logo-console-v2.svg` asset — no new artwork, no color changes.
- Add a genuinely new host-metrics collector (CPU/Memory/Disk via `psutil`, following the existing scheduler+SQLite-history pattern used twice already) and a 5th Admin tab exposing it as range-selectable, client-rendered charts — matching 4thealth-plus's Admin page pattern.

Out of scope (confirmed via investigation, not assumed):
- **Login page** — already matches 4thealth-plus's structure and CSS classes (`.login-page`, `.login-card`, `.login-title`, `.login-subtitle`, `.form-group`, `.form-control`, `.btn.btn-primary.btn-block`), already extends `base.html` (whose topbar is itself gated on `session.get('user')`, so a logged-out login page already renders topbar-free — effectively already "standalone" in appearance without needing to become a separate HTML document). No changes.
- **Base chrome besides the brand mark** — nav links, theme toggle (JS/`localStorage`-based, already matching 4thealth-plus's own mechanism, unlike 4tExecutive which needed a deliberate correction to *not* adopt this), logout (already a POST form), CSRF (4tlog's own hand-rolled header/session-token scheme, working correctly, not to be touched or unified with Flask-WTF).
- **Existing 4 admin panels** (Groups & Permissions, Users, Logs, FAZ Targets) — unchanged, only a 5th panel is added alongside them.
- Any change to 4thealth-plus.
- Any new dashboard widget, RAG logic beyond the health/silent-device features 4tlog already ships.

## 2. Brand mark

4tlog's `app/static/img/logo-console-v2.svg` is a full lockup (520×140, dark-navy background plate + icon + "4tLog" wordmark text + "REPORTING · WEB CONSOLE" tagline). Its icon group uses the *same* base hexagon path as 4thealth-plus's inline topbar mark (`M48 6 L86 26 V70 L48 90 L10 70 V26 Z`), with a blue top facet (`#3f7fd1`, matching the Gatecrest Labs brand guide's 4tLog color) and three horizontal bars in ink (`#141a24`) — the guide's "stacked bars = log entries/reporting" glyph.

- Extract just the icon group's paths/rects (no background plate rect, no text elements) into a standalone inline `<svg>` in `base.html`'s `.topbar-brand` slot, viewBox `0 0 96 96`, sized 28×28 with `class="brand-mark"` — the exact slot and sizing convention 4thealth-plus uses.
- No new CSS custom properties needed for color — the blue is a hard fill (`#3f7fd1`) inside the SVG itself, same as how 4thealth-plus hard-fills its own green/orange accents directly in the SVG rather than via a CSS variable.
- Add a `.brand-mark` CSS rule (does not exist in 4tlog's stylesheet today) plus the `display:flex;align-items:center` 4thealth-plus adds to `.topbar-brand` for the icon to sit inline with the "4tlog" text — a ~10-line CSS addition, not a stylesheet replacement (4tlog's stylesheet already carries `.admin-tabs`/`.admin-panel`/most other shared chrome; only `.brand-mark` and the new `.hm-*` block below are missing).
- The `<span class="brand-icon">&#128269;</span>` emoji is removed from `base.html`; the existing `.brand-icon` CSS rule (`margin-right: .3rem`) becomes dead and is removed from `style.css` in the same change.

## 3. Host-metrics collector

No existing host-metrics collection of any kind exists in 4tlog today (confirmed: zero references to `psutil`, `cpu_percent`, `memory_percent`, `disk_percent`, or any host-metrics-shaped table). This is genuinely new, but it slots into two patterns 4tlog already uses twice:

- **Scheduler module** (new `app/host_metrics_cache.py`, mirroring `app/log_stats_cache.py`'s shape): a `poll_host_metrics()` function reading `psutil.cpu_percent()`, `psutil.virtual_memory().percent`, `psutil.disk_usage("/").percent`, writing straight into the history store below (no separate in-memory `_cache` dict is needed here, unlike `log_stats_cache.py` — nothing else in 4tlog needs an instant in-process read of the latest value; the only consumer is the Admin System panel's range-query API). A `poll_now()` daemon-thread kicker and an `init_scheduler(app)` function follow the exact shape of the existing two modules, including the `Config.HOST_METRICS_POLL_DISABLED` no-op guard for tests.
- **History module** (new `app/host_metrics_history.py`, mirroring `app/log_stats_history.py`'s shape): SQLite at `hostmetrics.db` (sibling to `logstats.db`), table `host_metrics_history(collected_at TEXT NOT NULL, cpu_percent REAL, memory_percent REAL, disk_percent REAL)`, `init_db()`, `write_snapshot(cpu_percent, memory_percent, disk_percent, collected_at)`, and — new relative to the log-stats module, since that one only ever needed "latest" — a range query: `get_history(since: str) -> list[dict]` returning all rows with `collected_at >= since`, ordered ascending. Same `prune_old_rows(retention_days=30)` convention, called after every write.
- **Config additions** (`app/config.py`, alongside the existing `LOG_STATS_POLL_INTERVAL`/`LOG_STATS_POLL_DISABLED` pair): `HOST_METRICS_POLL_INTERVAL` (default `60` seconds — this data changes fast enough that the 300s log-stats cadence would be too coarse; 4tExecutive's own equivalent `poll_self()` runs every 60s) and `HOST_METRICS_POLL_DISABLED` (default `false`, set to `true` by `tests/conftest.py`, following the exact naming/env-var convention of the other two poll-disable flags).
- **App factory wiring** (`app/__init__.py`): a third `if not app.config.get("_HOST_METRICS_STARTED")` block, immediately after the existing `_LOG_STATS_STARTED` block, calling `init_db()` then `init_scheduler(app)` — same shape as the log-stats wiring.
- **Dependency**: add `psutil` to `pyproject.toml`'s `dependencies` list (not present today).

**Range keys**: 4tlog has no pre-existing app-wide range-selector convention to stay consistent with (unlike 4tExecutive, which had to correct 4thealth-plus's `1h/4h/12h/1d/7d/14d` set down to its own actual `4h/12h/1d/7d/14d/30d`). 4tlog is free to adopt 4thealth-plus's exact range set and default (`1h` active by default) with no correction needed.

## 4. Admin page: new Host Metrics panel

- A 5th `.admin-tab-btn` (4tlog's actual button class — confirmed distinct from 4thealth-plus's `.admin-tab`, but already styled identically in 4tlog's own stylesheet) added to the existing `#adminTabs` row: `data-panel="panel-host-metrics"`, label "Host Metrics".
- A 5th `.admin-panel` div, `id="panel-host-metrics"`, containing 4thealth-plus's exact `hm-header`/`hm-range-row`/`hm-cards` structure: a row of range buttons (`1h`/`4h`/`12h`/`1d`/`7d`/`14d`, `1h` active) above three `.hm-card` blocks (CPU/Memory/Disk) with empty `#hmCpuChart`/`#hmMemChart`/`#hmDiskChart` targets for client-side rendering.
- Port 4thealth-plus's `.hm-*` CSS block (`.hm-header` through `.hm-tick`, ~80 lines) verbatim into 4tlog's `style.css` — confirmed absent today.
- Extend `app/static/js/admin.js`'s existing tab-click handler (`if (btn.dataset.panel === 'panel-logs') loadLogs();`) with `if (btn.dataset.panel === 'panel-host-metrics' && !_hostMetricsLoaded) loadHostMetrics('1h');` (lazy-loaded on first visit, matching the Logs panel's existing lazy-load pattern, rather than eagerly fetching on every admin page load regardless of which tab is open).
- Port 4thealth-plus's `renderHmChart`/`hmAxisLabel`/range-button-wiring JS into the same IIFE `admin.js` already uses (a plain closure-scoped set of functions, consistent with how Groups/FAZ-Targets/Logs are each their own section within the one file — no new file).

## 5. New API endpoint

`GET /admin/api/host-metrics?range=<key>`, added to `app/routes/admin_routes.py` alongside the existing Logs API section, decorated `@_admin_required` (matching every other admin API route — inherits the existing CSRF/security-header/JSON-error-shape handling for free, since `/admin/api/` is already in `app/__init__.py`'s JSON-error-response path list).

- Validates `range` against the range-key dict living in `host_metrics_history.py`; invalid/missing defaults to `1h`.
- Returns `{"cpu": [{"ts": <epoch_seconds>, "v": <float>}, ...], "mem": [...], "disk": [...]}`, converting `host_metrics_history.get_history(since)`'s ISO `collected_at` strings to epoch seconds the same way 4tExecutive's equivalent endpoint does (`int(datetime.fromisoformat(ts).timestamp())` — safe here too, since 4tlog also requires Python ≥3.11 and this app's own `_now()` helpers already write trailing-`Z` UTC ISO strings the same way).

## 6. Testing

- New `tests/test_host_metrics_cache.py`, following `tests/test_log_stats_cache.py`'s existing shape exactly (confirmed present, one test file per scheduler module): `poll_host_metrics()` writes a row with mocked `psutil` values; `init_scheduler()` no-ops when `Config.HOST_METRICS_POLL_DISABLED` is true.
- New `tests/test_host_metrics_history.py`, following `tests/test_log_stats_history.py`'s existing shape exactly (confirmed present): `init_db()`/`write_snapshot()`/`get_history()` round-trip, `prune_old_rows()` behavior.
- `tests/test_admin_routes.py` gains: a 403-for-viewer test and a 200/shape test for the new `/admin/api/host-metrics` endpoint, using this file's existing `app`/`client`/`_login`/`_csrf` fixture pattern.
- `tests/conftest.py` gains `os.environ.setdefault("HOST_METRICS_POLL_DISABLED", "true")`, alongside the two existing poll-disable env vars — required so the test suite doesn't start a real background psutil-polling thread.
- No test changes needed for login, base chrome (besides confirming the brand-mark markup renders), or the four existing admin panels — this is additive, not a restructuring, so their existing tests are unaffected.
