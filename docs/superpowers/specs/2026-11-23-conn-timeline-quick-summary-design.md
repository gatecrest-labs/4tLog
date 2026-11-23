# Connection Timeline: Quick summary panel (design)

Approved 2026-11-23. Short design for a small-to-medium change.

## Intent
For a very busy IP (10,000 to 100,000+ logs an hour) the raw timeline takes minutes, because every
1,000 logs cost a log search. FortiView aggregates on the FortiAnalyzer and answers in 3-8 s
whatever the volume (`docs/conn-timeline-fortiview.md`). The Quick summary gives the answer to
"what did this IP do?" in seconds, beside the raw timeline.

## Goals
- A panel above the timeline, filled in section by section as FortiView answers: allowed and
  denied totals, top peers, policies, applications, countries, per-firewall totals.
- Starts when Build is pressed, alongside the raw build; it never delays or replaces it.
- Honest units: labelled "sessions, counted by FortiAnalyzer" (a session can be several logs).
- When a raw build ends partial, the banner points at the summary for the complete picture.

## Non-goals / anti-goals
- No ports and no per-minute chart (FortiView cannot give them): the raw timeline stays the only
  source for those.
- Never merge FortiView counts into the raw timeline's tables (different units would contradict).
- No caching, no new background job store.
- Demo mode must not reach a real FortiAnalyzer and must not write configuration.

## Approaches considered
- **A, one small stateless endpoint per section, fetched in parallel by the page (chosen).**
  Sections appear as each 4-8 s run returns; no job store; the page keeps at most 3 requests in
  flight so a FortiAnalyzer is not given eight searches at once.
- B, one background job with polling like the timeline: consistent but heavier, every section
  waits for the slowest.
- C, merge into the raw tables: rejected, units differ by up to 8x.

## Design
- `POST /api/conn-timeline/summary` with `{target, adom, host, direction, device, preset |
  start_time/end_time, section}`; `section` is one of `peers`, `policies`,
  `applications`, `countries` (allowed/denied totals and per-firewall totals ride on `policies`,
  built from the same rows). Same input parsing, ADOM access check and audit log as a build.
  Returns `{section, rows, units: "sessions", unavailable?: reason, seconds}`.
- Mapping (FortiView views, filters per the findings doc): peers are `top-destinations` with
  `srcip==HOST` and/or `top-sources` with `dstip==HOST` (both, merged by peer, for "either
  direction"); policies `policy-hits`; applications `top-applications`; countries
  `top-countries`. Peers are paged with
  `count-total` and `offset` (sent on the submit) up to a cap, and the response says if rows
  were left out.
- The firewall chosen in the form is passed as the FortiView device scope; otherwise
  `All_FortiGate`.
- A view the appliance lacks (`Cannot find FortiView`, unsupported filter) gives that section
  `unavailable`, and the others still render. Other FortiAnalyzer errors are shown per section.
- Page: a `ctSummary` block rendered by pure functions in `conn_timeline.js` (testable like the
  rest), filled by a small queue that starts with Build and ignores answers from an older Build.
- Demo mode: `app/demo_faz.py` answers the same views with synthetic rows.
- The partial banner links to the summary.

## Left to the builder
Exact markup and styling, peer cap, section order within the panel, wording of the
"unavailable" and "rows left out" notes.
