# SD-WAN Link Health Tab Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an `SD-WAN` tab showing per-device, per-interface latency, jitter, packet loss, SLA status and bandwidth (24h) from FortiAnalyzer's SD-WAN FortiView views.

**Architecture:** A new collector-owned poller (`app/sdwan_cache.py`, patterned on `app/threat_stats_cache.py`) runs four FortiView views per target, normalizes rows with a tolerant pure parser (`app/sdwan_parse.py`), and stores a snapshot in memory and in `collector_store`. A new blueprint serves `/sdwan` and `/api/sdwan` from that cache (never live FAZ calls), with ADOM filtering like the Dashboard.

**Tech Stack:** Flask, APScheduler, `FAZClient.run_fortiview`, pytest, vanilla JS + inline SVG (no new dependencies).

**Spec:** `docs/superpowers/specs/2026-11-13-sdwan-link-health-design.md`

## Global Constraints

- Views polled: `sdwan-dev-stats`, `sdwan-intf-sla-status-line`, `sdwan-perf-stats-line`, `sdwan-intf-bandwidth-line`. Do **not** use `sdwan-intf-sla-status`, `sdwan-link-view`, `sdwan-intf-traffic-line` (removed in FAZ 8.0.x, `-32005 Cannot find FortiView`).
- Fixed 24h window via `client.local_time_range(start_iso, end_iso)`; `SDWAN_POLL_INTERVAL` default `300` seconds; `SDWAN_POLL_DISABLED` flag (set `true` in `tests/conftest.py`).
- Page requests read the cache only; they never call the FAZ. `max_instances=1` on the scheduler job.
- Tab key `sdwan`, nav name `SD-WAN`, endpoint `sdwan.index`; `tab_required("sdwan")`; ADOM filtering via `get_allowed_adoms` exactly as `app/routes/dashboard_routes.py`.
- Row key names/units from FortiView SD-WAN views are **unconfirmed** (lab has no SD-WAN data). The parser must drop unparseable rows rather than invent values, must not convert units, and tests built from invented rows must say "synthetic" in their docstring.
- "No SD-WAN data" is its own state and is never rendered as healthy or as zeros.
- No new JS/Python dependencies. Per-view failures never abort other views or other targets.
- Public repo: do not commit unscrubbed fixtures; read any recorded fixture before committing it.
- Commits end with `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`. Run `uv run ruff check .` and `uv run ruff format --check app/ tests/ wsgi.py manage_users.py manage_api_tokens.py` before each commit.

## Review Focus

Input classes the spec implies but would otherwise go untested, each pinned by a test in the owning task:

1. FortiView rows with missing/misnamed keys, non-numeric values, or no interface/time -> dropped, no crash, no fabricated zeros (Task 1).
2. Every view empty or unsupported -> target `state == "no_data"`, and the page shows the empty state, not "healthy" (Tasks 2 and 4).
3. One view raises `FAZError(code=-32005)` ("Cannot find FortiView") -> that view `unsupported`, other three still polled and parsed (Task 2).
4. A user without the `sdwan` tab gets 403, and a user restricted to one ADOM never sees another target's data (Task 3).
5. Interface/device names or error text containing HTML (`<img onerror=...>`) must be escaped on the page (Task 4).

---

### Task 1: Config flags and the tolerant row normalizer

**Files:**
- Modify: `app/config.py` (near `THREAT_STATS_POLL_*`, ~line 101), `tests/conftest.py`, `.env.example`
- Create: `app/sdwan_parse.py`
- Test: `tests/test_sdwan_parse.py`

**Interfaces:**
- Produces: `Config.SDWAN_POLL_INTERVAL: int`, `Config.SDWAN_POLL_DISABLED: bool`;
  `parse_interfaces(view_rows: dict[str, list[dict]]) -> list[dict]` where `view_rows` maps a view name (`"sdwan-perf-stats-line"`, `"sdwan-intf-sla-status-line"`, `"sdwan-intf-bandwidth-line"`; `sdwan-dev-stats` is not parsed here) to its raw rows. Each returned entry (sorted worst-first, see below):
  `{"device": str, "interface": str, "sla_status": "ok"|"fail"|None, "sla_met_pct": float|None, "latency": Stat|None, "jitter": Stat|None, "packetloss": Stat|None, "in_bw": Stat|None, "out_bw": Stat|None, "series": {"latency": [[t, v], ...], "jitter": [...], "packetloss": [...], "in_bw": [...], "out_bw": [...]}}`
  where `Stat = {"latest": float, "min": float, "avg": float, "max": float}` and each series has at most `MAX_SERIES_POINTS = 48` points (bucket-averaged, time-ordered, `t` is the raw time value as a string).
  Also `MAX_SERIES_POINTS` and `worst_first_key(entry) -> tuple`.

- [ ] **Step 1: Write failing tests** in `tests/test_sdwan_parse.py` (module docstring: rows are **synthetic**, built from the 7.6.7 spec's field names, not real captures):
  - `test_perf_rows_become_stats_per_device_interface`: rows `{"dvid": "FGT-A", "interface": "wan1", "time": "2026-11-13 10:00", "latency": 20, "jitter": 2, "packetloss": 0}` and a second at `11:00` with latency 40 -> one entry, `latency == {"latest": 40.0, "min": 20.0, "avg": 30.0, "max": 40.0}`, series `[["2026-11-13 10:00", 20.0], ["2026-11-13 11:00", 40.0]]`.
  - `test_rows_missing_interface_or_time_are_dropped`, `test_non_numeric_values_are_ignored_not_zeroed` (`"latency": "n/a"` -> `latency is None`, never `0`), `test_unknown_keys_only_returns_empty_list`, `test_key_lookup_is_case_insensitive_and_accepts_aliases` (`"Interface"`, `"devid"` accepted for `dvid`).
  - `test_sla_status_from_latest_sla_available`: `sla_available` rows `1` then `0` (time-ordered) -> `sla_status == "fail"`, `sla_met_pct == 50.0`; with no SLA rows -> `sla_status is None`. Heuristic (document in the function docstring as unconfirmed): if every value is within 0..1 it is a fraction (x100), else already a percent.
  - `test_series_is_downsampled_to_max_points`: 200 rows -> `len(series["latency"]) == MAX_SERIES_POINTS`, still time-ordered.
  - `test_entries_sorted_worst_first`: a `fail` SLA entry sorts before an `ok` one; among equals, higher packetloss then higher latency first; entries with no stats last.
- [ ] **Step 2: Run** `uv run pytest tests/test_sdwan_parse.py -q` -> Expected: FAIL (module missing).
- [ ] **Step 3: Implement** `app/sdwan_parse.py` per the Interfaces block. One alias table at module top (`interface`: `interface, intf`; `device`: `dvid, devid, dev`; `time`: `time, timescale`; `latency`, `jitter`, `packetloss`; `in_bw`: `inbandwidth, inbandwidthused`; `out_bw`: `outbandwidth, outbandwidthused`; `sla`: `sla_available, intf_available`). Values are floats via a helper that returns `None` on anything non-numeric (including bools and `""`). No unit conversion.
- [ ] **Step 4: Add config.** In `app/config.py` add `SDWAN_POLL_INTERVAL = int(os.environ.get("SDWAN_POLL_INTERVAL", "300"))` and `SDWAN_POLL_DISABLED` (same `"true"` parsing as `THREAT_STATS_POLL_DISABLED`). Add `os.environ.setdefault("SDWAN_POLL_DISABLED", "true")` to `tests/conftest.py`. Document `# SDWAN_POLL_INTERVAL=300` in `.env.example` next to the threat setting.
- [ ] **Step 5: Run** `uv run pytest tests/test_sdwan_parse.py tests/test_config.py -q` -> Expected: PASS.
- [ ] **Step 6: Commit** `feat: SD-WAN row normalizer and poll config`.

---

### Task 2: The SD-WAN poller and collector registration

**Files:**
- Create: `app/sdwan_cache.py`
- Modify: `app/collector.py` (`start_all_schedulers`, and the module docstring list of pollers), `tests/test_collector.py`
- Test: `tests/test_sdwan_cache.py`

**Interfaces:**
- Consumes: `parse_interfaces`, `Config.SDWAN_*` (Task 1); `FAZClient.run_fortiview(adom, view, time_range, limit=..., devices=None)`, `FAZClient.local_time_range`, `FAZError.code`; `collector_store.write_cache/read_cache`; `app.faz_targets.list_targets`.
- Produces in `app/sdwan_cache.py`: `CACHE_KEY = "sdwan_stats"`, `VIEWS: tuple[str, ...]` (the four views, in the Global Constraints order), `get_cached() -> dict`, `poll_all_targets() -> None`, `poll_now() -> None`, `init_scheduler(app) -> None` (job id `sdwan_poll`, `max_instances=1`, no-op when `Config.SDWAN_POLL_DISABLED`).
  Snapshot: `{"targets": [TargetEntry, ...], "collected_at": iso | None}` with
  `TargetEntry = {"label", "adom", "host", "collected_at", "state": "ok"|"no_data"|"error", "error": str | None, "views": {view: {"status": "ok"|"empty"|"unsupported"|"error", "rows": int, "error": str | None}}, "interfaces": [...]}`.

- [ ] **Step 1: Write failing tests** in `tests/test_sdwan_cache.py` (reuse the `targets_file` fixture style from `tests/test_threat_stats_cache.py`; monkeypatch `app.faz_client.FAZClient.run_fortiview`, `.local_time_range`, `.logout` as that file does):
  - `test_poll_populates_snapshot_and_writes_collector_store`: fake `run_fortiview` returns synthetic perf rows for `sdwan-perf-stats-line` and `[]` otherwise -> target `state == "ok"`, `views["sdwan-perf-stats-line"]["status"] == "ok"`, others `"empty"`, `interfaces` non-empty, and `collector_store.read_cache(CACHE_KEY)` equals the cached snapshot.
  - `test_all_views_empty_is_no_data_state` (Review Focus 2): every view returns `[]` -> `state == "no_data"`, `interfaces == []`.
  - `test_unsupported_view_does_not_abort_the_others` (Review Focus 3): the SLA-line view raises `FAZError("Cannot find FortiView", code=-32005)`; the other three are still called and parsed; that view `status == "unsupported"`.
  - `test_other_fazerror_marks_only_that_view_error`: `FAZError("boom", code=-32603)` -> that view `"error"` with the message; others unaffected; target `state` still `"ok"`/`"no_data"` by the remaining views.
  - `test_unreachable_target_is_error_state_and_others_still_polled`: two targets, first raises `ConnectionError` constructing/using the client -> first `state == "error"` with a message from `summarize_connection_error`, second `"ok"`.
  - `test_uses_local_time_range_for_every_view`: all four calls receive the sentinel range returned by the patched `local_time_range`.
  - `test_get_cached_picks_up_newer_collector_snapshot_after_first_read` and `test_get_cached_keeps_in_memory_snapshot_newer_than_stored` mirroring the regression tests in `tests/test_threat_stats_cache.py` (compare `collected_at`).
  - In `tests/test_collector.py` add `"sdwan"` to both `start_all_schedulers` tests' monkeypatched recorders and expected sorted list (`["faz_health", "host_metrics", "log_stats", "sdwan", "threat_stats"]`).
- [ ] **Step 2: Run** `uv run pytest tests/test_sdwan_cache.py tests/test_collector.py -q` -> Expected: FAIL.
- [ ] **Step 3: Implement** `app/sdwan_cache.py`. Poll structure mirrors `threat_stats_cache.poll_all_targets`: iterate `list_targets()`, skip entries without `label`/`host`, open `FAZClient(host, token, adom, verify_ssl=Config.FAZ_VERIFY_SSL, timeout=Config.FAZ_REQUEST_TIMEOUT)`, compute the window once per target (`now - 24h` to `now`, ISO, through `client.local_time_range`), call `run_fortiview(adom, view, window, limit=1000)` per view inside its own try/except (`FAZError` with `.code == -32005` -> `unsupported`; other `FAZError` -> `error`; rows `[]` -> `empty`). Only the three line views feed `parse_interfaces`; `sdwan-dev-stats` is stored as a row count/status only in v1 (its rows are kept out of the snapshot until their shape is confirmed). Target `state`: `error` if the client could not be used at all; else `no_data` when no view returned rows, else `ok`. Use the exact "merge newer on every read" logic from the `get_cached` of `app/log_stats_cache.py` (compare top-level `collected_at`). Write the snapshot with `collector_store.write_cache(CACHE_KEY, snapshot)` after each cycle, always (unlike threat stats, errors are shown, not hidden).
- [ ] **Step 4: Register in `app/collector.py`**: import and call `init_scheduler(None)` for `app.sdwan_cache` in `start_all_schedulers`, and add SD-WAN to the module docstring's poller list.
- [ ] **Step 5: Run** `uv run pytest tests/test_sdwan_cache.py tests/test_collector.py -q` -> Expected: PASS.
- [ ] **Step 6: Commit** `feat: SD-WAN poller with per-view failure isolation`.

---

### Task 3: Blueprint, tab registration and API

**Files:**
- Create: `app/routes/sdwan_routes.py`, `app/templates/sdwan.html` (minimal placeholder extending `base.html`, filled in Task 4)
- Modify: `app/__init__.py` (`_BLUEPRINT_MODULES`), any test that hardcodes the tab list (run the suite; fix `tests/test_registry.py` / `tests/test_groups.py` expectations if they enumerate tabs)
- Test: `tests/test_sdwan_routes.py`

**Interfaces:**
- Consumes: `app.sdwan_cache.get_cached()` (Task 2); `get_allowed_adoms(user, ad_groups=..., role=...)` and `tab_required` as used in `app/routes/dashboard_routes.py`.
- Produces: blueprint `sdwan` (`bp`), `registry.register("sdwan", "SD-WAN", "sdwan.index")`, `GET /sdwan` -> HTML, `GET /api/sdwan` -> `{"targets": [TargetEntry, ...], "collected_at": str | None}` filtered to the caller's allowed ADOM/target labels (same label filter the dashboard applies).

- [ ] **Step 1: Write failing tests** in `tests/test_sdwan_routes.py` (fixtures copied from `tests/test_tab_routes.py`: `app`, `client`, `_login`; group `g1` with `allowed_tabs=["dashboard", "sdwan"]` for the allowed case):
  - `test_sdwan_requires_login` (302 to `/login`), `test_sdwan_blocked_without_tab_permission` (403 for a user whose group lacks `sdwan`; JSON 403 for `/api/sdwan`) (Review Focus 4).
  - `test_api_returns_cached_targets`: monkeypatch `app.routes.sdwan_routes.get_cached` to return two targets -> both returned for an admin.
  - `test_api_filters_targets_by_allowed_adoms`: monkeypatch `get_allowed_adoms` to return `{"A"}` -> only target labelled `A` returned (Review Focus 4). Mirror how `tests/test_admin_routes.py`/dashboard tests stub it; if no stub exists, patch the imported name in `app.routes.sdwan_routes`.
  - `test_api_empty_cache_returns_empty_targets_list` (`{"targets": [], "collected_at": None}`).
  - `test_nav_shows_sd_wan_tab_for_permitted_user`: page body contains `SD-WAN`.
- [ ] **Step 2: Run** `uv run pytest tests/test_sdwan_routes.py -q` -> Expected: FAIL.
- [ ] **Step 3: Implement** the blueprint, template placeholder, and add `"app.routes.sdwan_routes"` to `_BLUEPRINT_MODULES` (after `dashboard_routes`). `GET /api/sdwan` filters `targets` by `label` against the allowed set (`None` means unrestricted), as `api_dashboard` does.
- [ ] **Step 4: Run** `uv run pytest -q` (whole suite) -> Expected: PASS (fix hardcoded tab-list expectations if any test enumerates tabs).
- [ ] **Step 5: Commit** `feat: SD-WAN tab, routes and permission key`.

---

### Task 4: The SD-WAN page (table, summary, charts, states)

**Files:**
- Modify: `app/templates/sdwan.html`, `app/static/css/style.css` (add `.sdwan-*` rules reusing existing tokens/classes: `page-header`, `card-grid`, `infra-card`, `status-*`, `text-muted`, `text-danger`)
- Create: `app/static/js/sdwan.js`
- Test: `tests/test_sdwan_routes.py` (page markup), manual browser check

**Interfaces:**
- Consumes: `GET /api/sdwan` payload (Task 3). `escHtml` as defined in `app/static/js/dashboard.js` (copy it; do not couple the scripts).
- Produces: DOM ids `sdwanRoot`, `lastUpdated`, `refreshBtn`, `autoRefresh`; JS functions `renderTarget(target) -> string`, `renderSparkline(points) -> string` (inline SVG), and a `UNITS` constant (`latency: "ms"`, `jitter: "ms"`, `packetloss: "%"`, `bw: "raw"`) with a comment that units are unconfirmed pending a real capture.

- [ ] **Step 1: Write failing test** `test_sdwan_page_has_root_and_script` asserting the permitted user's `/sdwan` HTML contains `id="sdwanRoot"` and `js/sdwan.js`.
- [ ] **Step 2: Run** it -> Expected: FAIL.
- [ ] **Step 3: Implement the template and `sdwan.js`** in the Dashboard's style (header with title, `last-updated`, auto-refresh select defaulting to 1 min, refresh button; fetch `/api/sdwan`). Per target render: title with host/ADOM and `collected_at` with a stale marker when older than 3x `300s`; then one of
  - `state == "error"`: error card with the escaped message;
  - `state == "no_data"`: the exact copy *"No SD-WAN data from this FortiAnalyzer in the last 24h. SD-WAN performance SLA health checks and SLA logging must be enabled on the FortiGate."*, plus a muted per-view status line (e.g. `unsupported` views listed) — never a green/"healthy" style;
  - `state == "ok"`: summary strip (interface count, SLA-met % across interfaces that have one, worst latency, worst loss) and the interface table in the API's order (already worst-first) with columns Device, Interface, SLA badge (`ok`/`fail`/`—`), Latency, Jitter, Loss, In/Out, 24h trend (`renderSparkline` of `series.latency`). Missing stats render `—`, never `0`.
  Escape every interpolated value with `escHtml` (Review Focus 5). Bump the `?v=` query on the script/CSS tags only if existing convention requires it.
- [ ] **Step 4: Run** `uv run pytest tests/test_sdwan_routes.py -q` -> Expected: PASS.
- [ ] **Step 5: Verify in the browser with a synthetic snapshot.** Rebuild (`docker compose up -d --build`, then `docker compose up -d --force-recreate nginx` only if nginx returns 502), log in with a temp admin, and seed the collector store for the *web* container (in `/app/data/collector_state.db`) with a throwaway snapshot via `docker compose exec -T app python -c ...` calling `collector_store.write_cache("sdwan_stats", {...})` containing: one `ok` target with two interfaces (one `fail`), one with an interface named `<img src=x onerror=alert(1)>`, one `no_data`, one `error`. Check each renders as described, no alert fires, and the HTML shows the name as text. Remove the seeded data (re-run the collector poll or `DELETE FROM cache_state WHERE cache_key='sdwan_stats'`) and the temp account afterwards. Also check with no seed: the real lab (no SD-WAN data) shows the `no_data` empty state, not "healthy".
- [ ] **Step 6: Commit** `feat: SD-WAN page with link table, trends and empty states`.

---

### Task 5: Self-test checks, 8.0.2 fixture re-record, docs

**Files:**
- Modify: `app/faz_selftest.py` (`_CHECKS`), `tests/test_faz_selftest.py` (counts if it asserts the registry size), `tests/test_faz_replay_fixtures.py` (`EXPECTED`), `tests/fixtures/faz_8.0.2/exchanges.json` (re-recorded), `readme.md`, `changelog.md`, `container.md` only if it lists pollers/settings
- Test: `tests/test_faz_selftest.py`, `tests/test_faz_replay_fixtures.py`

**Interfaces:**
- Consumes: `app.sdwan_cache.VIEWS` (Task 2), `_fortiview(view, **kwargs)` helper already in `app/faz_selftest.py`.
- Produces: four self-test checks with ids `sdwan_dev_stats`, `sdwan_intf_sla_status_line`, `sdwan_perf_stats_line`, `sdwan_intf_bandwidth_line` (label `FortiView <view>`, feature `SD-WAN tab`, needs `("time_range",)`).

- [ ] **Step 1: Write failing tests**: in `tests/test_faz_selftest.py`, a test asserting the four ids exist in the report and that a fake client whose `run_fortiview` raises `FAZError("Cannot find FortiView", code=-32005)` for one of them reports that check `error` while the others are `ok`.
- [ ] **Step 2: Run** -> Expected: FAIL.
- [ ] **Step 3: Implement** the four checks, built by iterating `sdwan_cache.VIEWS` so the views live in one place.
- [ ] **Step 4: Run** `uv run pytest tests/test_faz_replay_fixtures.py -q` -> Expected: FAIL (the recorded 8.0.2 capture has no SD-WAN exchanges).
- [ ] **Step 5: Re-record the fixture** against the lab: `uv run python scripts/record_faz_fixture.py` (follow its docstring; it overwrites `tests/fixtures/faz_8.0.2/exchanges.json`). **Read the output file before committing** (public repo): no tokens, real hostnames, serials, IPs. Update `EXPECTED["faz_8.0.2"]` summary to `{"ok": 16, "denied": 0, "error": 2, "skipped": 0}` (the four new checks return zero rows on the lab, which counts as `ok`).
- [ ] **Step 6: Run** the full suite plus lint/format -> Expected: PASS.
- [ ] **Step 7: Docs.** `readme.md`: a short SD-WAN section (what the tab shows, `SDWAN_POLL_INTERVAL`, that it needs SD-WAN performance SLA health checks/logging on the FortiGate, the four views used and the three removed in 8.0.x, row shapes unconfirmed until first real capture). `changelog.md`: an `Added` entry dated the implementation day. Mention the new `sdwan` tab key for group permissions.
- [ ] **Step 8: Commit** `feat: SD-WAN self-test checks, 8.0.2 fixture, docs`.

---

## Self-review notes

- **Spec coverage:** collector/poll/per-view isolation (Task 2), tolerant normalizer and unconfirmed-shape handling (Task 1), read side with ADOM/tab gating and read-through (Tasks 2-3), UI with empty/error states and SVG trends (Task 4), self-test check and fixture recorder coverage (Task 5, which also covers the recorder because `scripts/record_faz_fixture.py` records the self-test's own calls), docs/config. Non-goals (rules/app views, event viewer, ranges, alerting, external API, SQLite history, per-target flag) intentionally have no tasks.
- **Spec adjustment:** the design said "extend `scripts/record_faz_fixture.py`"; it records whatever the self-test calls, so adding the self-test checks (Task 5) is sufficient and the script is unchanged.
- **Deliberate v1 scope call:** `sdwan-dev-stats` is polled and its status/row count surfaced, but its rows are not parsed or shown until their shape can be confirmed on real data.
- **Known unknowns resolved at first real capture:** exact row keys and units, the `sla_available`/`intf_available` encoding (fraction vs percent heuristic in Task 1), and whether `sdwan-dev-stats` warrants a summary card.
