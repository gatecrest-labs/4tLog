# Silent-device drill-down details + collector/web process split

Source: `~/Downloads/4texecutive2.md` "Wave 4" — prompts W4-2 (P6) and W4-3
(P15), this repo's portion. Sibling repo 4thealth-plus does the equivalent
split independently; no coordination needed beyond following the same
pattern (SQLite WAL read-through, `RUN_SCHEDULERS=inline`, `schema_version`
+ `freshness` map).

## Current state (confirmed by reading code, not assumed)

- `app/__init__.py::create_app()` starts four `BackgroundScheduler`s inline,
  each guarded by an `app.config["_X_STARTED"]` flag: `faz_health_cache`,
  `log_stats_cache`, `threat_stats_cache`, `host_metrics_cache`.
- `app/log_stats_cache.py` — in-memory `_cache = {"logging_devices": [],
  "silent_devices": [], "collected_at": None}`. `silent_devices` is a list
  of raw FAZ logstats rows (`devid`, `devname`, `last_log_timestamp`,
  `lograte`). Rollup counts persist to `app/log_stats_history.py`
  (`logstats.db`, `log_volume_history` table) — counts only, not the
  device list.
- `app/threat_stats_cache.py` — in-memory `_cache` dict backing the
  `threats`/`admin_access`/`vpn` executive-summary keys. Rollup persists to
  `app/threat_stats_history.py` (same `logstats.db` file, different table).
- `app/faz_health_cache.py` — in-memory `_cache: dict[label, dict]`, one
  entry per FAZ target. No SQLite persistence at all today — a fresh
  process shows every target as "gray" until its first poll completes.
- `app/host_metrics_cache.py` — writes straight to
  `app/host_metrics_history.py` (`hostmetrics.db`); not read by the
  executive summary route, so out of scope for the SQLite read-through
  work (it already persists every cycle).
- `app/routes/external_api_routes.py::executive_summary()` — reads
  `faz_health_cache.get_all_cached()`, `log_stats_cache.get_cached()`
  (falling back to `log_stats_history.get_latest_rollup()` — counts only),
  `threat_stats_cache.get_cached()` (falling back to
  `threat_stats_history.get_latest_rollup()`). `schema_version: 1` today.
- `docker-compose.yml` — single `app` service (gunicorn, `--workers 1`
  pinned specifically because the scheduler/cache lived in that one
  process) + an `nginx` TLS sidecar.
- No existing `RUN_SCHEDULERS` or `DATA_DIR` config.

## Piece 1 — silent-device drill-down (`silent_details`)

Add `silent_details` to `log_stats_cache`'s in-memory cache and the
`devices_silent`-reporting section of the executive summary: a list of
`{devid, devname, last_log_at}`, capped at 50, **most-stale-first** (oldest
`last_log_timestamp` first; devices that have never logged — `None`/`0` —
sort first of all, ahead of any device with a real timestamp, since "never
logged" is more severe than "logged a long time ago"). `last_log_at` is an
ISO-8601 UTC string, or `null` for "never logged."

- `classify_devices()` is unaffected (still just partitions logging vs.
  silent).
- New pure function `build_silent_details(silent_devices, limit=50)` in
  `log_stats_cache.py`, called from `poll_all_targets()` right after
  `classify_devices()`.
- Cache shape becomes `{"logging_devices": [...], "silent_devices": [...],
  "silent_details": [...], "collected_at": ...}`.
- `executive_summary()` adds a `"devices_silent_details"` key alongside the
  existing `devices_silent` count (top-level, not nested, matching the
  flat style of `devices_logging`/`devices_silent`).
- Document the cap/ordering in `readme.md` (next to the existing
  `devices_silent` paragraph) and `changelog.md`.
- Tests: `build_silent_details` ordering/cap/null-handling in
  `tests/test_log_stats_cache.py`; route-level test in
  `tests/test_external_api_routes.py` asserting the key's shape using
  fixture data (monkeypatched cache, no live FAZ).

## Piece 2 — collector/web process split

1. **`app/collector.py`** — new entrypoint, `python -m app.collector`.
   Calls each cache module's `init_*_db()` then `init_scheduler(app=None)`
   for all four pollers (health, log stats, threat stats, host metrics).
   Confirmed none of the four `init_scheduler(app)` bodies dereference
   `app` — the parameter exists only because `faz_health_cache` type-hints
   it as `Flask`; passing `None` is safe. Loops forever (`time.sleep`)
   after starting the schedulers so the process stays alive under Docker.

2. **`Config.RUN_SCHEDULERS`** (env, default `"collector"`). In
   `create_app()`, DB `init_*_db()` calls always run (so a web worker can
   read tables that may not exist yet), but the four `init_*_scheduler()`
   calls only run when `RUN_SCHEDULERS=inline` — that flag reproduces
   today's single-process dev behavior. Default (`collector`, or anything
   else) starts no schedulers in the web process.

3. **`app/collector_store.py`** — new module: SQLite WAL-mode key/value
   store (`cache_state(cache_key PRIMARY KEY, payload, collected_at)`),
   `init_db()` / `write_cache(key, dict)` / `read_cache(key) -> dict |
   None`. `Config.DATA_DIR` (env, default: repo root, same directory the
   existing `*.db` files already land in) controls where every SQLite file
   lives (`logstats.db`, `hostmetrics.db`, `collector_state.db`) so
   docker-compose can point both services at one shared volume.

4. **Read-through wiring** — `faz_health_cache`, `log_stats_cache`, and
   `threat_stats_cache` (the three the executive summary route reads)
   each: (a) call `collector_store.write_cache(<key>, snapshot)` at the
   end of every successful poll cycle; (b) their `get_cached()` /
   `get_all_cached()` fall back to `collector_store.read_cache(<key>)` —
   and repopulate the in-memory dict from it — when the in-memory cache is
   still at its empty/startup state. This makes the in-memory dict a
   read-through cache in front of SQLite, per the spec, without changing
   any existing call site's return shape.

5. **`docker-compose.yml`** — split `app` into `web` (gunicorn, unchanged
   command, `RUN_SCHEDULERS` left at its `collector` default) and
   `collector` (`command: python -m app.collector`, no exposed port, no
   `nginx` dependency), both sharing a new named volume mounted at
   `DATA_DIR` for the SQLite files, plus the existing JSON bind mounts
   (already host-mounted, so already shared). Update `Dockerfile`'s
   `--workers 1` comment (no longer required for correctness once the web
   process starts no scheduler, but left at 1 as the conservative
   production default — a follow-up, not this PR) and `container.md`.

6. **`schema_version: 2`** — bump `executive_summary()`'s
   `schema_version` from `1` to `2` (introducing the concept — 4tlog has
   never bumped it before) and add a `"freshness"` map: `{"faz_health":
   collected_at, "log_stats": collected_at, "threats": collected_at}` (one
   entry per field-group the route reports, using each source's own
   `collected_at`/`last_updated`, `None` if never polled). All v1 keys —
   including the new `devices_silent_details` from Piece 1, added in the
   same release — are kept as-is; this is additive only, following the
   same "additive, no version bump needed" precedent this repo used for
   `infra`/`threats`/`admin_access`/`vpn`, except this time the shape
   actually changes (new top-level `freshness` key) so the version bump is
   warranted.

7. **Tests**:
   - `collector_store.py`: round-trip write/read, missing key returns
     `None`, WAL mode is active.
   - Each of the three caches: `get_cached()`/`get_all_cached()` returns
     the SQLite-persisted snapshot when the in-memory cache is empty
     (simulating a freshly-started web worker that never polled).
   - Cross-process simulation: write via one cache module instance's
     `poll_all_targets()` (module A), then via a second import context /
     monkeypatched fresh in-memory `_cache` (simulating module B / a
     second app instance) confirm `get_cached()` returns the same values
     — proving the SQLite layer, not shared process memory, is carrying
     the data.
   - `executive_summary()` route test: `schema_version == 2` and
     `freshness` present with the three expected keys.
   - `app/collector.py`: smoke test that `main()`/`start_all_schedulers()`
     calls each `init_scheduler` (monkeypatched) exactly once and does not
     raise when all four `*_POLL_DISABLED` flags are set (test-suite-safe,
     same convention as `create_app()`).

## Sequencing / delivery

Implementing directly with TDD (small, verifiable steps) rather than
fanning out to parallel subagents — the two pieces share files
(`log_stats_cache.py`, `external_api_routes.py`, `readme.md`) closely
enough that sequential, reviewed steps are safer than parallel merges.
Order: Piece 1 (silent_details) first since it's self-contained and low
risk, then Piece 2 (collector_store → read-through wiring → collector.py →
schema_version/freshness → docker-compose/Dockerfile/docs) since later
steps depend on earlier ones.

Full test suite + `ruff check` run before opening the PR.
