# Changelog

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
