<picture>
  <source media="(prefers-color-scheme: dark)" srcset="logo-dark.svg">
  <img alt="4tLog logo" src="logo.svg" width="240">
</picture>

A Flask web application for interacting with FortiAnalyzer. Phase 1 provides
a working dashboard frame with bcrypt login, group-based access control, and
an admin interface for managing users, groups, and targets. Phase 2 makes the
Dashboard tab real — live FortiAnalyzer health cards backed by a background
poller, plus an Admin sub-tab for managing which FAZ appliances are polled —
and adds TLS for the Docker deployment (reverse-proxy container terminating
TLS in front of the app, mirroring the RHEL/Nginx setup) — see
[container.md](container.md). Phase 3 makes the Log Search tab real: a
targeted FortiAnalyzer traffic-log search (required source/destination IP,
optional port/service and advanced field filters, time range) with a
paginated results table (client-side, page size 10/25/50/100, up to the
configured result cap) and client-side CSV/JSON export.

> Note: This is an independent open-source project and is not affiliated with, endorsed by, or supported by Fortinet, Inc. FortiManager is a trademark of Fortinet, Inc.

> Note: This a work in progress. It will change as I continue to build it out. Any recommendations are encouraged. 

Project documentation:

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [SUPPORT.md](SUPPORT.md)
- [docs/superpowers/README.md](docs/superpowers/README.md)
- [LICENSE](LICENSE)

## Current features

- **Authentication**: bcrypt-secured local user accounts
- **Admin Tab**: a tabbed page — Groups & Permissions, Users (read-only,
  managed via the `manage_users.py` CLI), Logs, FAZ Targets, Host Metrics,
  and External API (see below for each)
- **Admin → FAZ Targets**: CRUD for the FortiAnalyzer appliances the
  Dashboard polls (label, host, ADOM, bearer token, optional per-target SNMP
  credential overrides) — backed by `faz_targets.json`, edits take effect on
  the next poll cycle without an app restart
- **Admin → Host Metrics**: this server's own CPU/Memory/Disk utilization,
  charted over a selectable time range (1 hour up to 14 days). This is about
  the 4tlog host itself, not any FortiAnalyzer appliance — useful for
  confirming the app has the headroom to keep up with polling.
- **Dashboard Tab**: live FortiAnalyzer health cards — status/hostname/
  version/serial/HA mode/HA role/disk usage from FAZ's JSON-RPC status API,
  plus CPU/mem gauges from SNMPv3 when `SNMP_ENABLED=true` — refreshed by a
  background poller so page loads never block on a live FAZ/SNMP call.
  Group membership can restrict which targets a user's cards show, reusing
  the same `adom_restrict`/`allowed_adoms` group fields as ADOM access
  control. See "Reading the health cards" below for what each card's color
  means.
- **Log Search Tab**: targeted FAZ log search — source/destination IP
  (required, no ANY/ANY; either side may be `ANY`/`ALL` or left blank to mean
  "no filter on this field"), optional port/service and advanced field
  filters, time range (presets or custom), a paginated results table
  (client-side, page size 10/25/50/100, Source/Destination IP columns pinned
  first, up to the configured result cap), CSV/JSON export of the
  currently-loaded results
- **External API**: read-only `GET /external/api/executive/summary` for
  4tExecutive, gated by a bearer token and an enable flag — both now
  manageable from **Admin → External API** (toggle the enable checkbox,
  generate/revoke tokens from a table; a token's value is shown once, at
  creation, and never stored in plaintext). The same `manage_api_tokens.py`
  CLI still works if you'd rather script it. Reports FAZ fleet health/disk,
  silent-device counts (from FortiAnalyzer `logview/logstats`, polled
  independently of the SNMP health cycle — see
  `SILENT_DEVICE_THRESHOLD_MINUTES`/`LOG_STATS_POLL_INTERVAL` in
  `.env.example`), and fleet log volume.
- **Inline Help**: a "?" button in the nav opens a help panel with
  Dashboard/Log Search/Admin guidance, filtered to the logged-in user's
  permitted tabs
- **Deployment**: Docker (with TLS via an Nginx reverse-proxy sidecar
  container) and RHEL bare-metal (Gunicorn/Nginx/systemd)

## Reading the health cards

Each Dashboard card for a FortiAnalyzer appliance has a colored stripe down
its left edge:

| Color | Meaning |
|---|---|
| 🟢 Green | Reachable and healthy — CPU and memory are both under the warning threshold (`CPU_WARN`/`MEM_WARN` in `.env.example`, default 70%). |
| 🟡 Yellow | Reachable, but CPU or memory is at or above the warning threshold and below critical. |
| 🔴 Red | Reachable, but CPU or memory is at or above the critical threshold (`CPU_CRIT`/`MEM_CRIT`, default 90%). |
| ⚪ Gray | Not polled yet — the appliance was just added, or the app just started. |
| ⚫ Dark gray ("offline") | The last poll couldn't reach or authenticate to the appliance at all (network/auth failure) — see the card's error line for detail. |

CPU/memory gauges — and the yellow/red states, which are driven entirely by
those numbers — only apply when `SNMP_ENABLED=true` and SNMP credentials are
configured. Without SNMP, a card is green whenever it's reachable (no
CPU/mem numbers to flag a warning), gray before the first poll, or offline
if the appliance can't be reached at all.

## Quick start (development)

```bash
uv sync
cp .env.example .env               # set SECRET_KEY (uv run python manage_users.py secret)
cp users.example.json users.json
cp groups.example.json groups.json
cp faz_targets.example.json faz_targets.json
cp api_tokens.example.json api_tokens.json
cp app_settings.example.json app_settings.json
uv run python manage_users.py add admin --role admin
uv run python wsgi.py              # http://localhost:5443 (PORT defaults to 5443; add certs/ for HTTPS)
```

## Deployment

- Docker: see [container.md](container.md)
- RHEL bare-metal: see [docs/deployment.md](docs/deployment.md)

## Quality checks

```bash
uv run ruff check .
uv run pytest -q
```

GitHub Actions runs the same checks on pushes and pull requests.

## License

MIT. See [LICENSE](LICENSE).

## Legacy Ansible scaffold

The original proof-of-concept for FAZ log search was an Ansible playbook.
`app/faz_client.py` (Phase 2) already replaces its health/status calls;
the playbook's log-search filter-building logic has been ported into
`faz_client.py`'s `search_logs()`/`build_filter_expression()` as of Phase 3.
Until then the playbook remains in the repo for reference — see
[ansible/readme.md](ansible/readme.md).
