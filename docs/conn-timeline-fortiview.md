# Connection Timeline at 10,000 and 100,000 logs an hour: what FortiView can do

The Connection Timeline reads raw traffic logs. A FortiAnalyzer log search returns at most 1,000
rows, so every 1,000 logs cost a search (2-7 s on the lab appliance, a 3-hour window of about
14,000 logs takes 85-110 s). That is fine at 10,000 logs an hour and slow at 100,000. This note
records what `scripts/check_fortiview_summary.py` found on a FortiAnalyzer 8.0.2 about summarising
the same IP with FortiView instead, which aggregates on the appliance.

## What works

| Need | FortiView view | Notes |
|------|----------------|-------|
| Peers the host connected to | `top-destinations` with `srcip==HOST` | peers the host reached |
| Peers that connected to it | `top-sources` with `dstip==HOST` | one run per direction |
| Policies | `policy-hits` | hit counts, pass and block, per firewall |
| Applications | `top-applications` | |
| Countries | `top-countries` | |
| Allowed and denied | `session_pass` / `session_block` on every row | |
| Firewall | the `fortigate` field on every row | |

- Each run takes 3-8 s whatever the volume (a 3-hour window of 14,000 logs: 4 s, against about
  200 s for the raw build).
- Every peer is reachable: `count-total: true` returns `total-count-all`, and `offset` pages past
  the first 1,000 rows. **`offset` must be in the submit, not only the fetch.**
- The `srcip==`, `dstip==` and `and` filters narrow the run (`srcip==<an address nobody uses>`
  returns nothing).
- A view FortiAnalyzer does not have, or a filter field it does not support for a view, fails with
  `-32002 Invalid params: filter '<field>' not supported` or `Cannot find FortiView`.

## What does not

- **No ports or services**: `dstport` and `service` are not filterable and no view groups on them.
- **No time axis**: nothing returns counts per minute, so the lane chart still needs raw logs (or
  many small FortiView runs).
- **Different unit**: FortiView counts *sessions*, the timeline counts *logs*. Over 1,100 shared
  peers the logs per session were p50 1.0, p90 2.0, max 8: a long-lived connection writes several
  logs. Totals differ (about 12,000 sessions against 14,900 logs) and so does the top-10 (6 of 10
  in common). A summary built on FortiView has to say "sessions".

## Built

The Quick summary panel (design: `docs/superpowers/specs/2026-11-23-conn-timeline-quick-summary-design.md`)
implements the shape below: `app/conn_timeline_summary.py` builds the sections and
`POST /api/conn-timeline/summary` serves them one at a time.

## Recommended shape

A **Quick summary** from FortiView, shown in seconds, next to the raw timeline: peers (both
directions, allowed and denied), policies, applications, countries and per-firewall totals. For a
window whose matched count is far beyond what the raw build can read, show the summary and offer
the raw timeline for a narrower window or a single firewall. Label the counts as sessions.

## Related: an empty answer is not always true

Three times the appliance answered a finished search with nothing or with a short result, right
after heavy activity (a whole 3-hour window as 0 logs; minutes later 14,000). The build now runs an
empty first search again, up to twice, before reporting a window as empty.
