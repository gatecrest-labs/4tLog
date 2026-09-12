# Changelog

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
