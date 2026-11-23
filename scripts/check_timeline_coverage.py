"""Find out why a Connection Timeline build came up short, on a real FortiAnalyzer.

When the timeline says "built from 3,887 of 10,586 matched logs", rows went missing
somewhere between FortiAnalyzer's count and the page. This script runs the same
search for one IP and one window, and reports:

  1. The build's own accounting: rows returned, rows each filter dropped, how every
     search ended (see ``diagnostics`` in the build's coverage).
  2. A clock check on the raw rows: how far ``itime_t`` (receive time, which the
     build slices on) is from ``eventtime`` (when the firewall logged it), and
     whether rows come back in time order. Large gaps mean the FortiAnalyzer time
     range and the build's slices are on different clocks.

    uv run python scripts/check_timeline_coverage.py --host 10.1.1.2
    uv run python scripts/check_timeline_coverage.py --host 10.1.1.2 --hours 1 --workers 1

Strictly read-only: log searches and their deletion, no configuration. The output
holds counts, seconds and device-free timestamps only; the IP you pass is not echoed.
"""

from __future__ import annotations

import argparse
import collections
import datetime
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def _eventtime_secs(row: dict) -> int | None:
    value = str(row.get("eventtime", "")).strip()
    if not value.isdigit():
        return None
    n = int(value)
    while n > 10**11:
        n //= 1000
    return n


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--host", required=True, help="the IP address to build the timeline for")
    ap.add_argument("--label", help="faz_targets.json label (default: first target)")
    ap.add_argument("--hours", type=float, default=1.0, help="window (default 1)")
    ap.add_argument("--direction", default="either", choices=["either", "src", "dst"])
    ap.add_argument("--device", default="All_FortiGate")
    ap.add_argument("--workers", type=int, default=4, help="parallel slices (1 = single search)")
    ap.add_argument("--deadline", type=float, default=300.0, help="seconds before giving up")
    ap.add_argument("--json", action="store_true", help="print the full diagnostics as JSON")
    args = ap.parse_args(argv)

    from app.config import Config

    if Config.DEMO_MODE:
        from app import demo

        demo.activate()

    from app.conn_timeline import Timeline, build_filter, row_key
    from app.conn_timeline_job import collect
    from app.faz_client import FAZClient
    from app.faz_targets import get_target, list_targets

    target = get_target(args.label) if args.label else next(iter(list_targets()), None)
    if not target:
        print("No FAZ target found in faz_targets.json.", file=sys.stderr)
        return 2

    def new_client():
        return FAZClient(
            host=target["host"],
            token=target.get("token", ""),
            adom=target.get("adom", "root"),
            verify_ssl=Config.FAZ_VERIFY_SSL,
            timeout=Config.FAZ_REQUEST_TIMEOUT,
        )

    end = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    start = end - datetime.timedelta(hours=args.hours)
    filt = build_filter(args.host, args.direction, "all")
    timeline = Timeline(args.host, args.direction, start, end)

    # A side channel on the build: keep a sample of raw rows for the clock check.
    sample: list[dict] = []
    orig_add = timeline.add

    def add(row):
        if len(sample) < 20000:
            sample.append(row)
        return orig_add(row)

    timeline.add = add  # type: ignore[method-assign]

    t0 = time.monotonic()
    with new_client() as client:
        cov = collect(
            client,
            timeline,
            device=args.device,
            filter_expression=filt,
            start=start,
            end=end,
            max_rows=Config.CONN_TIMELINE_MAX_ROWS,
            page_size=Config.CONN_TIMELINE_PAGE_SIZE,
            deadline_at=time.monotonic() + args.deadline,
            deadline_per_1k=Config.CONN_TIMELINE_DEADLINE_SECS_PER_1K or None,
            deadline_max=Config.CONN_TIMELINE_DEADLINE_MAX_SECS,
            poll_interval=Config.LOG_SEARCH_POLL_INTERVAL,
            workers=max(1, args.workers),
            client_factory=new_client,
        )
    secs = time.monotonic() - t0
    diag = cov["diagnostics"]

    print(
        f"Window: last {args.hours:g}h, direction {args.direction}, {secs:.1f}s, "
        f"{cov['searches']} searches"
    )
    print(
        f"matched {cov['matched']}  fetched {cov['fetched']}  "
        f"complete {cov['complete']}  reason {cov['reason']}\n"
    )
    for key in (
        "rows_returned",
        "rows_kept",
        "rows_outside_slice",
        "rows_boundary_skipped",
        "rows_no_time",
        "rows_out_of_order",
        "short_pages",
    ):
        print(f"  {key:<24}{diag[key]:>8}")
    ended = collections.Counter(x["ended"] for x in diag["searches"])
    print(f"  searches ended          {dict(ended)}")
    over = [
        x
        for x in diag["searches"]
        if x["ended"] == "exhausted" and x["total"] is not None and x["rows"] < x["total"]
    ]
    print(f"  searches below total    {len(over)} of {len(diag['searches'])}")

    unique = len({row_key(r) for r in sample})
    print(f"  rows counted twice      {len(sample) - unique:>8}  (of {len(sample)} sampled)")

    # Clock check: receive time vs event time.
    gaps = []
    for r in sample:
        ev = _eventtime_secs(r)
        it = str(r.get("itime_t", ""))
        if ev is not None and it.isdigit():
            gaps.append(int(it) - ev)
    if gaps:
        gaps.sort()
        pct = lambda q: gaps[min(len(gaps) - 1, int(len(gaps) * q))]  # noqa: E731
        print(
            f"\nitime_t - eventtime over {len(gaps)} rows (seconds): min {gaps[0]}, "
            f"p50 {pct(0.5)}, p95 {pct(0.95)}, max {gaps[-1]}"
        )
        late = sum(1 for g in gaps if abs(g) > 60)
        print(f"  rows more than 60s apart: {late} ({100 * late / len(gaps):.1f}%)")
    else:
        print("\nNo rows with both itime_t and eventtime to compare.")

    if cov["matched"] and cov["fetched"] < cov["matched"]:
        lost = cov["matched"] - cov["fetched"]
        print(f"\nMissing {lost} of {cov['matched']}.")
        dropped = diag["rows_outside_slice"] + diag["rows_no_time"]
        if dropped >= lost * 0.5:
            print("  -> mostly rows the build dropped for their time: slicing clock mismatch.")
        elif diag["rows_returned"] < cov["matched"] - diag["rows_boundary_skipped"]:
            print("  -> FortiAnalyzer returned fewer rows than it counted (paging or count).")
    if args.json:
        print(json.dumps(diag, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
