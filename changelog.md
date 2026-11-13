# Changelog

## 2026-11-13

### Added

- **SD-WAN tab** (`/sdwan`, tab key `sdwan`): per-interface latency, jitter, packet loss,
  SLA status and bandwidth with a 24h trend, from FortiAnalyzer's SD-WAN FortiView views.
  A new collector poller (`app/sdwan_cache.py`, `SDWAN_POLL_INTERVAL`, default 300s) polls
  `sdwan-dev-stats`, `sdwan-intf-sla-status-line`, `sdwan-perf-stats-line` and
  `sdwan-intf-bandwidth-line` per target; each view and each target fails independently. No
  SD-WAN data is its own state, never shown as healthy; a target whose views all failed (e.g.
  a token without FortiView access) or returned rows 4tlog cannot interpret says so instead
  (the row keys received are logged). Each target shows when it was collected and how old that
  is; a view that hits the 1000-row limit is flagged as truncated; devices and health checks on
  the same interface are kept apart. Row field names/units are unconfirmed until a
  FortiAnalyzer with SD-WAN data can be captured (the lab has none).
- Admin → API Self-Test checks the four SD-WAN views; the 8.0.2 replay fixture was
  re-recorded to include them.

### Fixed

- Web workers kept serving the first collector snapshot they read, so the Dashboard (and
  threat/log stats) went stale until the container restarted; each read now follows the
  collector's newer snapshot.
- `tzdata` is now a regular dependency: slim container images ship no timezone database, so
  FortiAnalyzer-local time conversion silently fell back to UTC.
- nginx re-resolves the `app` upstream, so rebuilding the app container no longer causes 502s
  until nginx is restarted.
- The FAZ fixture recorder (`scripts/record_faz_fixture.py`) now redacts list-valued secrets
  (`adm_pass` comes back as `["ENC", "<hash>"]`, which was left in the capture) and replaces
  MAC addresses; the 8.0.2 fixture was re-recorded with it. The encrypted `adm_pass` value in
  the earlier 8.0.2 capture is still in git history; rotate the lab device's admin password if
  that matters.

## 2026-11-05

### Fixed

- **FortiAnalyzer 8.0.2 compatibility.** FortiView runs are now always scoped to a device
  set (`All_FortiGate` by default; `FAZClient.run_fortiview(..., devices=[...])` to
  override). The 7.6.7 spec marks `device` optional, but 8.0.2 rejects an unscoped run with
  `-32005 No eligible device(s)`, which broke every Threat/Admin-access metric.
- The Threat poll no longer discards a whole target when the appliance rejects the
  `type==ips` filter on `top-threats` / `top-countries` (8.0.2 answers `-32002 filter 'type'
  not supported`). Just those two lists (`top_signatures`, `top_source_countries`) are left
  empty and a WARN is logged; there is deliberately no unfiltered fallback, which would show
  all-traffic data as IPS data. Any other FortiView error still fails the target.
- `FAZError` now carries the appliance error code (`.code`).

### Added

- `FAZClient.version` (`FAZVersion`, orders on major.minor.patch, compares with tuples):
  read lazily from `/sys/status`, `None` if unavailable.
- **Admin -> API Self-Test** (`POST /admin/api/faz-selftest`, `app/faz_selftest.py`): runs the
  read-only calls the app makes (status, log view, devices, log stats, alert counts, every
  FortiView view, a one-row log search) and reports ok / denied (-11) / error / skipped with
  the feature that depends on each. Runs only on an explicit click.
- Recorded FortiAnalyzer fixtures: `FAZ_RECORD_FILE` / `scripts/record_faz_fixture.py` capture
  scrubbed JSON-RPC traffic (secrets, device credentials, IPv4s, serials, UUIDs, e-mails,
  supplied literals); `app/faz_recorder.py::ReplayTransport` replays it so tests run the real
  client, the self-test and the threat poll offline. First fixture: `tests/fixtures/faz_8.0.2`
  (a lab appliance that receives no logs, so FortiView/log-search rows are empty: it pins
  request acceptance, not row field names).

### Known open items

- FortiView row field names (`srccountry`, `login_fail_num`, `e_time`, `end_time`, `dvid`, ...)
  are still unconfirmed against live data. The vendored spec's `top-countries` columns list
  `dstcountry`, not `srccountry`.
- The IPS-only filter has no accepted form for `top-countries` on 8.0.2 (`type`, `logtype`
  and `threattype_s` are all rejected); `top-threats` accepts `threattype_s`, but its value
  vocabulary is unverified, so it is not used.

## 2026-09-12

### Added

- External API: `GET /external/api/executive/summary` gains a
  `"devices_silent_details"` key alongside the existing `devices_silent`
  count — up to 50 silent devices as `{devid, devname, last_log_at}`,
  most-severe-first: devices FortiAnalyzer has never logged from at all
  sort ahead of every device with a real (but stale) timestamp, and among
  those, the oldest `last_log_timestamp` sorts first. `last_log_at` is an
  ISO-8601 UTC string or `null` for "never logged." Built by
  `app/log_stats_cache.py::build_silent_details()`; empty when the route
  falls back to the persisted rollup (counts only, no device list survives
  a restart).
- Collector/web process split: pollers (FAZ health, log stats, threat
  stats, host metrics) now run in a dedicated `python -m app.collector`
  process by default; web (gunicorn) workers start no schedulers unless
  `RUN_SCHEDULERS=inline` (single-process dev mode). The three caches the
  executive summary route reads (`faz_health_cache`, `log_stats_cache`,
  `threat_stats_cache`) persist their latest snapshot to a shared SQLite
  WAL store (`app/collector_store.py`) after every poll; each cache's
  in-memory dict is now a read-through cache in front of that store, so a
  web worker that has never polled still serves the collector's latest
  data. `docker-compose.yml` splits the old single `app` service into
  `web` and `collector` services sharing a data volume.
- External API: `GET /external/api/executive/summary`'s `schema_version`
  bumps from `1` to `2` and gains a `"freshness"` map —
  `{"faz_health": collected_at, "log_stats": collected_at, "threats":
  collected_at}` — reporting how stale each field group's source is,
  independent of whether the payload came from the in-memory cache or the
  SQLite read-through fallback. All v1 keys are unchanged.

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
- External API: `GET /external/api/executive/summary` gains a `"vpn"` key
  — `ipsec_tunnels_total`, `ipsec_tunnels_down`, `ssl_vpn_users_now` — from
  the existing threat-activity poller (`app/threat_stats_cache.py`), now
  also querying FortiView's `site-to-site-ipsec` and `ssl-dialup-ipsec`
  reports. Tunnel/user liveness is inferred from open (no end-timestamp)
  sessions in the trailing 24h window, since FortiView has no live
  tunnel-status field. Rollups persist in `logstats.db` alongside the
  existing threat/admin-access history (migration-safe column addition).

## 2026-09-10

### Added

- External API: `GET /external/api/executive/summary` gains an `"infra"`
  list — one entry per configured FortiAnalyzer target
  (`{role, label, hostname, version, cpu, mem, disk_used_pct, ha_role,
  status, last_updated}`), sourced from the existing `faz_health_cache`
  poll cache with no extra network calls. Never includes a target's
  host/IP or bearer token. Shaped to match 4thealth-plus's own `"infra"`
  key so 4tExecutive can merge management-plane health from every source
  into one Infrastructure card.

## 2026-07-26

### Added

- Log Search results table now pins six columns first — Date/Time, Source,
  Destination, Port, Action, Firewall — in that order, before any other
  returned fields.
- Log Search: a live refine filter above the results table narrows an
  already-fetched search without re-querying FortiAnalyzer. Supports plain
  substring or regex matching, with a Negate option, and applies to
  pagination, the row count, and CSV/JSON export.
- Log Search: a "Columns" picker lets you show/hide non-pinned columns; the
  choice is remembered in your browser across searches and log types.
