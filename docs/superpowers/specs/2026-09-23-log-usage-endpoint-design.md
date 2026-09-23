# External API: `/external/api/log-usage` — Design

Date: 2026-09-23
Status: Approved for planning

## Problem

4thealth-plus (a sibling app, `~/code/github/ai/4thealth-plus`) is building a
"Log-Based Rule Review" feature: for one FortiManager policy rule, flag which
configured source/destination host members and service ports never actually
appeared in traffic over the last N days. That requires FortiAnalyzer log
data, which 4tlog already owns end-to-end (`app/faz_client.py::search_logs()`,
`app/log_search_filters.py`). Rather than duplicate FAZ connectivity into
4thealth-plus, 4tlog exposes one new authenticated endpoint that runs the
search server-side and returns only the aggregated result.

This document is the 4tlog-side implementation spec. It was originally
drafted as a handoff spec from the 4thealth-plus repo
(`docs/superpowers/specs/2026-09-23-log-usage-endpoint-design.md` there) and
is now the authoritative, refined version for this repo — see that file's
history for the original request/response contract this refines.

## Scope

- One new route: `POST /external/api/log-usage`, added directly to the
  existing `app/routes/external_api_routes.py` (216 lines today — no need
  for a sibling module).
- Bearer-token authenticated, same gate as `executive/summary`
  (`app.api_tokens.validate_token`, `app.app_settings.get_setting("external_api_enabled")`).
- Returns only aggregated distinct values (`srcips`, `dstips`, `dstports`)
  — never raw log rows.
- Read-only: only searches existing FAZ logs, changes nothing.

## Out of scope

- Any new UI in 4tlog.
- Any change to the existing internal `/api/log-search` route.
- Caching — each call runs a live FAZ search, same as internal Log Search
  today.
- A batched multi-device FAZ search call. `FAZClient.search_logs()`
  currently accepts one `device` string (wrapped internally as
  `[{"devid": device}]`); nothing in this codebase confirms FAZ's
  `/logview/adom/<adom>/logsearch` resource accepts more than one devid per
  call, and this codebase's own convention (see `get_sys_status()`'s
  docstring) is to not assume unconfirmed FAZ behavior. This endpoint calls
  `search_logs()` once per resolved device, sequentially.

## Request / response contract

`POST /external/api/log-usage`

```json
{
  "adom": "Enterprise Services",
  "devices": ["FW-DC-01", "FW-DC-02"],
  "policyid": 123,
  "days": 30
}
```

Validation (`400` on any failure, naming the offending field):
- `adom`: required, non-empty string.
- `devices`: required, non-empty list of strings — FortiGate hostnames as
  FMG/4thealth-plus knows them, **not** FAZ device serials.
- `policyid`: required, positive integer.
- `days`: required, integer, 1–60 inclusive. This endpoint **rejects**
  out-of-range values rather than clamping them — it's a contract boundary;
  the caller (4thealth-plus) owns its own input hygiene and this endpoint
  should fail loudly on a malformed request rather than silently
  substituting a different window.

**Target resolution:** match `adom` case-insensitively against each
`faz_targets.json` entry's `"adom"` field via `app.faz_targets.list_targets()`
(confirmed: each entry has `label`, `host`, `adom`, `token`, plus optional
SNMP overrides — `app/faz_targets.py`). Zero matches → `404`
(`{"error": "No FortiAnalyzer target configured for ADOM '<adom>'"}`).
Multiple matches → query all matched targets, merge results (an unusual but
valid multi-FAZ-per-ADOM deployment).

**Device resolution:** for each matched target, call the existing
`FAZClient.get_devices()` (confirmed: returns `{devid, name, platform}`,
`devid` is the FortiGate's serial number — the value `search_logs()`'s
`device` parameter actually expects) and match requested `devices` entries
by `name`, case-insensitive. Unmatched names go into `devices_not_found` —
non-fatal.

**Log search:** for each resolved `devid`, one call:
```python
client.local_time_range(start_iso, end_iso)  # -> local_start, local_end
client.search_logs(
    logtype="traffic",
    device=devid,
    filter_expression=f"policyid=={policyid}",
    start_time=local_start,
    end_time=local_end,
    limit=Config.LOG_SEARCH_MAX_RESULTS,
    poll_interval=Config.LOG_SEARCH_POLL_INTERVAL,
    timeout=Config.LOG_SEARCH_TIMEOUT,
)
```
`start_iso`/`end_iso` are computed as `now - days` to `now` in UTC, then
converted to the target's local time via the existing `local_time_range()`
(same pattern `/api/log-search` already uses). A `FAZError` raised for one
device is caught, recorded in `device_errors[devname] = str(exc)`, and does
not stop the other devices' searches.

**Aggregation:** across every successful device's returned rows, collect
the distinct values of the `srcip`, `dstip`, and `dstport` log fields.
`log_count` is the total row count returned across all devices (post-cap).
`truncated` is `true` if *any* device's search hit `limit` exactly (an
indicator, not a guarantee, that more distinct values exist).

> **Field-name risk, explicitly flagged (not blocking):** `srcip`/`dstip`/
> `dstport` are the standard FortiOS traffic-log field names and match what
> `/api/log-search`'s own filter builder (`log_search_filters.py`) already
> assumes for the same log type. They have **not** been confirmed against a
> live FortiAnalyzer instance for this new endpoint specifically — same
> category of assumption `get_sys_status()`'s docstring already flags for
> its own fields. The implementation plan calls this out as a required
> live-validation step before this endpoint is considered production-ready,
> the same way `snmpwalk` confirmation is required before enabling SNMP
> polling in 4thealth-plus.

**Response:**
```json
{
  "policyid": 123,
  "days": 30,
  "time_range": {"start": "2026-08-24T00:00:00", "end": "2026-09-23T00:00:00"},
  "srcips": ["10.1.1.5", "10.1.1.6"],
  "dstips": ["10.2.2.10"],
  "dstports": [443, 8443],
  "log_count": 15234,
  "truncated": false,
  "devices_queried": ["FW-DC-01"],
  "devices_not_found": ["FW-DC-02"],
  "device_errors": {}
}
```

Zero matching devices (ADOM known, names not found) is **not** an error —
`200` with `devices_queried: []`, `devices_not_found` populated, empty
observed-value arrays. Zero log rows for devices that *were* found is also
`200` with empty arrays — a valid "no traffic" result. All devices erroring
out is `502` with `device_errors` populated and a representative top-level
`error` message.

## Error handling summary

| Failure | Status | Notes |
|---|---|---|
| `external_api_enabled` is false | `503` | Same as `executive/summary` |
| Missing/invalid bearer token | `401` | Same as `executive/summary` |
| Missing/invalid request field | `400` | Names the offending field |
| No FAZ target for `adom` | `404` | |
| Devices not found (ADOM known) | `200` | `devices_not_found` populated, non-fatal |
| `FAZError` on one device | `200` | Non-fatal, recorded in `device_errors` |
| `FAZError`/connection failure on every device | `502` | `device_errors` populated |

## Testing

Follow `tests/test_external_api_routes.py`'s existing fixture pattern
(tmp-path-backed `faz_targets.json`/`api_tokens.json`/`app_settings.json`
via `monkeypatch`, `create_app()`, mocked `FAZClient`):

- Auth/feature-gate matrix (disabled, no token, bad token, valid token) —
  reuse the existing pattern verbatim.
- ADOM→target matching: single match, multi-match (merge), no match (404).
- Device resolution: all found, none found, mixed — via a mocked
  `get_devices()`.
- Log search: mocked `search_logs()` per device; verify sequential
  per-device calls (not a single batched call with multiple devids).
- Aggregation: dedup across devices, `truncated` detection (any device at
  cap), `log_count` summing.
- Partial failure: one device's `search_logs()` raises `FAZError` →
  `device_errors` populated, other devices' results still returned.
- Total failure: every device's `search_logs()` raises → `502`.
- A fixture-row test asserting the endpoint reads `srcip`/`dstip`/`dstport`
  keys specifically (documents the assumption the live-validation task
  must confirm).

## Follow-up (not part of this plan)

Before enabling this endpoint's consumer (4thealth-plus's Log-Based Rule
Review feature) against production data, confirm the `srcip`/`dstip`/
`dstport` field names against a real FortiAnalyzer instance — e.g. via a
manual `/api/log-search` call inspecting the raw `fields`/`rows` this
endpoint's own aggregation logic assumes — and update this document if
they differ.
