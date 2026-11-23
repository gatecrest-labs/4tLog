# Changelog

## 2026-11-23

### Fixed

- **Connection Timeline no longer stops short on a burst of logs.** More than 1,000 logs can
  share one receive second (a device uploading a delayed batch), and a FortiAnalyzer search
  returns at most 1,000 rows however you page it, so a build used to get stuck re-reading the
  same 1,000 rows and report "FortiAnalyzer returning fewer logs than it counted" (4,381 of
  11,082 on the lab appliance). The build now splits such a second with `sessionid` (then
  `srcport`) range filters, sized by FortiAnalyzer's exact `total-count`, until every part fits
  in one search. A second that no field can split is reported as a `burst` gap with how many
  logs were not reached, instead of a silent shortfall.
- A parallel build that took over from the first search inside a busy second could count rows
  of that second twice after a restart; it keeps the first search's rows counted.

### Added (Continue)

- **Continue on a partial Connection Timeline.** When a build stops short (the row cap, the time
  limit, a cancel) the banner offers **Continue**: a new job reads only the stretches that were
  not reached into the same timeline, skipping the rows already counted in the second each one
  starts at, and merges the coverage. It can be repeated until the timeline is complete; each
  Continue gets its own row cap and a time limit sized to what is left. A build can be continued
  once (the click consumes it), by the user who started it, while the partial result is kept
  (`CONN_TIMELINE_JOB_LIFETIME_SECS`). Seconds no search could split stay reported as a `burst`
  gap: reading them again would give the same answer. Verified on the lab FortiAnalyzer: a
  3-hour build capped at 4,000 rows was finished by two Continues at 13,912 rows, none counted
  twice. `POST /api/conn-timeline/<job_id>/continue` returns the new `job_id`; a partial result's
  coverage carries `resumable`.

### Changed

- **A burst is read in parallel, and the time limit grows with the work.** The parts of a split
  second are searched by up to `CONN_TIMELINE_WORKERS` threads, each with its own connection
  (the lab's 11,326-log hour took 113 s one search at a time). The build's time limit now
  starts at `CONN_TIMELINE_DEADLINE_SECS` and, once the matched total is known, grows to
  `CONN_TIMELINE_DEADLINE_SECS_PER_1K` (10) seconds per 1,000 matched logs, up to
  `CONN_TIMELINE_DEADLINE_MAX_SECS` (1200), so a window of 100,000 logs is not cut off at 120 s.
  On the lab FortiAnalyzer (a UTM VM) a search costs 2-7 s however small and concurrent searches
  slow each other down, so the parallel split gained little there (86 s against 94 s for a
  7,249-log burst); a faster appliance should gain more.

### Added

- **Build diagnostics** for the Connection Timeline, to find out why a build says "built from X of
  Y matched": the coverage now carries `diagnostics` (rows FortiAnalyzer returned, rows each
  filter dropped, rows out of time order, how every search ended and the time it reached), and
  the build's audit log entry includes it. `scripts/check_timeline_coverage.py` runs the same
  build against a real FortiAnalyzer and compares `itime_t` with `eventtime`. No behaviour change.

## 2026-11-22 (later)

### Added

- **Peer path picture** on the Connection Timeline: select a peer and the page draws, below
  everything, the source IP, the firewall(s) in the middle, the destination IP, the ports seen
  and a graph of how long the traffic has been present (first and last seen, active intervals),
  once per direction. Each firewall row has a **Details** button that opens Log Search in a new
  window for that peer, firewall and the whole timeline window. The roll-up gains a compact
  `paths` list (peer, role, firewall, port, bucket, count, first/last seen); `flows` is unchanged.
- **ADOM picker** on Log Search and the Connection Timeline: an ADOM dropdown next to Target,
  filled from the FortiAnalyzer (`FAZClient.get_adoms`, `GET /api/log-search/adoms` and
  `/api/conn-timeline/adoms`) and defaulting to the target's configured ADOM. Group limits stay
  per target, so a group that can use a target can pick any of its ADOMs. The name is checked
  before it goes into a FortiAnalyzer URL, the chosen ADOM is audited, and timeline links into
  Log Search carry it (`adom` query parameter).
- Timeline builds in parallel (`CONN_TIMELINE_WORKERS`, default 4): one probe search over the
  whole window and, only if the window is big, the rest in time slices searched at once, each on
  its own FortiAnalyzer connection. A running build offers partial pictures that the page draws
  as it goes, with a "Still fetching" banner. Coverage reports `gaps`, each time range not
  fetched, which the chart greys out.
- Screenshots of the Connection Timeline in the readme (`docs/images/`).

### Changed

- A page whose session has expired or been replaced (e.g. another app on the same host name
  sharing the `4tlog_session` cookie) now gets "Your session expired or was replaced. Please log
  in again." (401) on its API calls, instead of the misleading "CSRF validation failed".
- Timeline defaults: fetch size 1,000 (the submit limit), row cap 100,000, time limit 120 s.
- Fewer round trips per search, from measurements on an 8.0.2 lab appliance (every search costs
  about 3 s however small, paging past 1,000 rows only returns empty pages): the build restarts
  at the submit limit instead of probing past it, takes the exact total from the fetch instead
  of waiting for the count call, and polls a running search quickly.
- A FortiAnalyzer "API rate limit" error is waited out and retried a few times instead of
  failing the build.

## 2026-11-22

### Added

- **Connection Timeline tab** (`/conn-timeline`, tab key `conn_timeline`): one IP address over a
  time window (1 hour by default, 7 days at most), drawn as a swim lane per firewall/VDOM with
  allowed (green), denied (red, hatched) and other actions per time slice, plus top peers, top
  ports and a per-firewall policy table (ID and name; policy 0 is the implicit deny). Clicking a
  bar shows that slice's ports, peers and policies and opens Log Search on exactly those logs;
  clicking a peer or port filters the page without another FortiAnalyzer call. IP addresses
  only, no hostname lookups.
- Builds read raw traffic logs (`app/conn_timeline_job.py`): one oldest-first log search, paged
  500 rows at a time and rolled up into counts as it goes (`app/conn_timeline.py`), at most
  20,000 rows and about 90 seconds per build. The exact matched total comes from
  `logsearch/count`, so the page says whether it is complete or partial and greys out the time
  it didn't reach. If a FortiAnalyzer stops returning rows at the 1,000-row submit limit, the
  build continues from its last timestamp without counting a row twice. Builds run as
  background jobs (one per user, two app-wide), owned by the user who started them, and every
  build is audited under the `conn_timeline` app-log component.
- `FAZClient.submit_log_search`, `fetch_log_search`, `get_log_search_count` and
  `delete_log_search`: the log-search steps one at a time, for paging.
- `scripts/check_faz_paging.py`: a read-only check of how a FortiAnalyzer pages a large log
  search (count call, offsets past 1,000, fetch size, action values).
- Demo mode: three featured hosts with a story each (a jump server across two firewalls with a
  denied SMB burst, a busy DNS server past 1,000 rows an hour, a branch camera denied on its way
  out), log-search paging, `logsearch/count` and task delete on the synthetic FortiAnalyzer,
  and the tab for the `branch-analysts` group.

### Changed

- Log Search reads its form from the URL (`target`, `logtype`, `device`, `src`, `dst`, `ports`,
  `start`, `end`, repeated `filter=field==value`, `run=1`), so other tabs can link to a search;
  custom ranges take seconds.

## 2026-11-16

### Added

- **Demo mode** (`DEMO_MODE=true`): runs the whole app with no FortiAnalyzer, on a built-in
  synthetic one (`app/demo_faz.py`) for the fictional Gatecrest Labs: two FortiAnalyzers
  (7.6 and 7.4), seven FortiGates and an offline DR appliance, so the Dashboard shows green,
  yellow and offline cards, the SD-WAN tab a failing link and a silent device, Log Search
  generated traffic/attack/webfilter/app-ctrl/event logs, and the API self-test 18 passing
  checks. Data is deterministic per host, view and time; response shapes, `/sys/status` fields
  and the traffic field list are seeded from the 8.0.2 fixture. Users, groups, targets,
  settings and tokens come from `app/demo_data/`, never the operator's own files.
- Demo mode never contacts a real FortiAnalyzer: `FAZClient` refuses any host that is not a
  built-in `*.demo.invalid` host before sending a request, fixture recording is off, and SNMP
  readings are synthetic.
- Demo mode is read-only: Admin API changes (targets, groups, settings, tokens, log level) and
  4tSuite group pushes answer 403; the API self-test still runs. A banner on every page, and the
  demo sign-ins (`demo-admin` / `demo-analyst`, password `gatecrest-demo`) on the login page.
- `docker-compose.demo.yml`: one container on http://localhost:8100 (bound to `127.0.0.1`,
  `DEMO_PORT` to change it), needing no `.env` or local JSON files. It has its own Compose
  project (`4tlog-demo`) and image tag (`4tlog:demo`), so it runs beside a real stack without
  replacing its image or containers. In demo mode `SECRET_KEY` is optional, `RUN_SCHEDULERS`
  defaults to `inline` and `DATA_DIR` to `.demo-data/`.
- `docs/local-demo-mac.md`: step-by-step guide to running the demo on a Mac, with Docker or
  `uv`: prerequisites, checking out a branch, updating the container, cleanup, troubleshooting.
- `tests/test_demo_mode.py`: refusing real targets, seeds, disabled writes, the banner, ADOM
  restriction, and the synthetic FortiAnalyzer through the real pollers and routes.

### Changed

- An empty `DATA_DIR` now falls back to the default location instead of the working directory.

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
