# SD-WAN Link Health tab — Design

Date: 2026-11-13
Status: Approved for planning

## Intent

FortiAnalyzer's FortiView has an **SD-WAN** screen. 4tlog has no equivalent, so an
operator who wants to know "which WAN links are unhealthy right now?" has to leave
4tlog for the FAZ UI. This adds an **SD-WAN** tab that answers that one question from
the same FAZ connection 4tlog already holds: per-device, per-interface latency, jitter,
packet loss, SLA pass/fail, and bandwidth, with a 24h trend.

## Goals

- A new nav tab, `SD-WAN`, gated like every other tab (`tab_required("sdwan")`, a new
  `sdwan` tab key in group permissions, ADOM filtering like the Dashboard).
- Show, for the last 24h and per FAZ target: link/SLA summary, a per-interface table
  (latency, jitter, packet loss, SLA status, in/out bandwidth) and trend charts.
- Follow the Dashboard model: page requests read a cache and never block on live FAZ
  polling (project rule: "Preserve the cached Dashboard model").
- Work on FAZ 7.6.x and 8.0.x, tolerating views that a release does not have.
- Be honest about missing data: "no SD-WAN data" is a distinct state and is never
  rendered as "healthy" or as zeros.

## Non-goals (v1)

- Traffic by SD-WAN rule / application (the `sdwan-rules-*`, `sdwan-app-view` views).
  Candidate for a follow-up sub-tab.
- SD-WAN event log viewer (SLA failovers, link-state changes). Follow-up.
- Selectable time ranges. v1 caches one fixed 24h window; arbitrary ranges would need
  live FAZ calls per request, which breaks the cache model.
- Alerting/notifications, an external-API endpoint, persisted history in SQLite, and
  any write to the FAZ or FortiGate.
- Per-target opt-out flag (the threat poller has one; not needed yet).

## Anti-goals

- A tab that renders confidently from guessed data. The row shapes below are
  **unconfirmed** (see Constraints); anything unparseable is dropped, not defaulted.
- A poll failure or a missing view breaking other targets or other dashboards.

## Constraints and findings

Research done 2026-11-13 against the vendored 7.6.7 spec and the live lab FAZ (8.0.2):

- SD-WAN data is exposed through the **FortiView `/run` API** the app already uses
  (`FAZClient.run_fortiview`, submit -> poll -> fetch). No new transport is needed.
- The 7.6.7 spec lists 17 SD-WAN views. A read-only probe of 18 names on 8.0.2: 15 are
  accepted, 3 are gone (`-32005 Cannot find FortiView`): `sdwan-intf-sla-status`,
  `sdwan-link-view`, `sdwan-intf-traffic-line`. Do not depend on those three.
- Views v1 uses (all accepted on 8.0.2), with the spec's sortable fields:
  - `sdwan-dev-stats` — per-device summary (`sdwan_stats`)
  - `sdwan-intf-sla-status-line` — SLA availability over time
    (`interface, intf_available, sla, sla_available, time`)
  - `sdwan-perf-stats-line` — `interface, jitter, latency, packetloss, sla, time`
  - `sdwan-intf-bandwidth-line` — `bibandwidth, inbandwidth, interface, outbandwidth, time`
  - Filterable fields on these views include `dvid, interface, jitter, latency,
    packetloss, inbandwidthused, outbandwidthused, sdwan_status, level, timescale`.
- **The lab has no SD-WAN data.** The FortiWiFi-71G has no `subtype=="sdwan"` event logs
  and no `vwlname` in traffic logs; every accepted view returned zero rows. The exact
  row keys and units (ms vs us, bytes vs bits) are therefore **unconfirmed** and the
  spec's row schema is a generic placeholder. The existing `run_fortiview` docstring
  already notes this; callers must treat row keys defensively.
- FortiView device scope must be sent (`All_FortiGate` default) or 8.0.2 rejects the run.

## Approaches considered

1. **Link health tab (chosen).** Cached poll of the `*-line` and `sdwan-dev-stats`
   views; table + trend charts. Answers "which links are unhealthy".
2. Traffic by rule/app tab. Answers "what is using my WAN"; on-demand like Log Search.
   Deferred: user's priority is link health first.
3. SD-WAN event log viewer via existing Log Search plumbing. Cheapest, but gives events
   only, no trends. Deferred.

Chosen by the user on 2026-11-13. These stack; options 2 and 3 can become sub-tabs.

## Design

**Collector** — new `app/sdwan_cache.py`, structured like `app/threat_stats_cache.py`:
a lock-guarded in-memory snapshot written by an APScheduler job and mirrored to the
collector store (`collector_store.write_cache("sdwan_stats", ...)`), registered in
`app/collector.py::start_all_schedulers`. `RUN_SCHEDULERS=inline` behaves as for the
other pollers. Interval: `SDWAN_POLL_INTERVAL` (default 300s), disabled in tests via an
`SDWAN_POLL_DISABLED` flag, same as the others.

**Poll** — for each target, one `run_fortiview` per view above over a 24h window
(`FAZClient.local_time_range`, as the threat poller does). Each view is fetched
independently: a `-32005 Cannot find FortiView` marks that view `unsupported` for the
target; any other `FAZError` marks it `error` with a message; neither aborts the other
views or other targets. Snapshot shape is per target:
`{label, adom, collected_at, views: {<view>: {status: ok|empty|unsupported|error, rows, error}}, interfaces: [...], summary: {...}}`.

**Normalizer** — new `app/sdwan_parse.py`, pure functions turning raw rows into the
snapshot's `interfaces` list (one entry per `(device, interface)`: latest and 24h
min/avg/max of latency/jitter/loss, SLA availability %, in/out bandwidth, and downsampled
series for charts). Key lookup is tolerant (several candidate key names per field,
case-insensitive); rows missing the interface or time key are dropped; no defaults are
invented. A target is `no_data` only when every view is `empty`/`unsupported`.

**Read side** — `app/routes/sdwan_routes.py`: `GET /sdwan` (page) and
`GET /api/sdwan` (JSON, per target, ADOM-filtered via `get_allowed_adoms` exactly as the
Dashboard). `registry.register("sdwan", "SD-WAN", "sdwan.index")`, which also adds the tab
to `KNOWN_TABS` so admins can grant it to groups. Reads use the same "merge the
collector's newer snapshot on every read" pattern fixed in de27a14 (never freeze on the
first snapshot).

**UI** — `templates/sdwan.html` + `static/js/sdwan.js`, same look as the Dashboard.
Per target: header with `collected_at` and staleness; summary strip (links, SLA-met %,
worst latency/loss); interface table sorted worst-first with an SLA badge; small trend
charts per interface drawn as inline SVG (no new JS dependency — my call, keeps the
supply chain and CSP unchanged). States: loading, error (per target), and a dedicated
empty state: *"No SD-WAN data from this FortiAnalyzer in the last 24h. SD-WAN performance
SLA health checks and SLA logging must be enabled on the FortiGate."*

```
SD-WAN                                        [target v]   updated 14:05 (2m ago)
 Links 4   SLA met 97.2%   Worst latency 84ms   Worst loss 1.1%
 Device  Interface  SLA     Latency  Jitter  Loss   In/Out Mbps   24h trend
 FGT-A   wan2       FAIL    84 ms    9 ms    1.1%   12 / 3        ~~/\~~
 FGT-A   wan1       OK      18 ms    1 ms    0.0%   40 / 11       ______
```

**Compatibility checks** — add an SD-WAN check to `app/faz_selftest.py` (read-only,
reports per view `ok / unsupported / error` and whether any rows exist) so Admin -> API
Self-Test shows SD-WAN readiness after a FAZ upgrade. Extend
`scripts/record_faz_fixture.py` to capture these views so real shapes can be recorded
once a FortiGate with SD-WAN is attached (captures are scrubbed and read before commit;
the repo is public).

## Testing

- Unit tests for the normalizer with **synthetic rows built from the spec's field names**,
  labelled as synthetic in the test and docstrings (not real captures).
- Poller tests with `FAZClient.run_fortiview` monkeypatched: per-view isolation,
  `unsupported` on `-32005`, other `FAZError` -> `error`, per-target isolation, snapshot
  written to the collector store.
- Route tests: tab permission (403 without the tab), ADOM filtering, empty/no-data JSON.
- Cache read-through test mirroring the stale-snapshot regression tests.
- Self-test check tests. Lab verification of the empty state against the 8.0.2 FAZ in
  Docker; verification with real data is blocked until the lab has SD-WAN.

## Left to the builder

- Exact candidate key names per field and unit handling, to be settled when real rows can
  be captured; until then the normalizer is conservative and the first real capture should
  adjust it.
- Chart downsampling and styling details; table sort and badge colours consistent with
  the Dashboard.
- Names of config settings beyond `SDWAN_POLL_INTERVAL` / `SDWAN_POLL_DISABLED`.

## Risks

- **Unconfirmed row shapes** (largest risk). Mitigated by the tolerant normalizer, the
  explicit no-data state, and the fixture recorder; expect one follow-up fix when real
  SD-WAN data is available.
- **Cost of polling**: four FortiView runs per target per interval (two to three seconds
  each on the lab). 300s default keeps this light; `max_instances=1` prevents overlap.
