"""Check how a FortiAnalyzer pages a log search, for the Connection Timeline.

The Connection Timeline builds its picture from up to 20,000 raw traffic logs.
A log search submit takes at most 1,000 rows, so the timeline pages through the
task with ``offset``. The vendored 7.6.7 spec doesn't say whether ``offset`` may
go past the submit limit, so this script asks a real FortiAnalyzer:

  1. Does ``logsearch/count/<tid>`` return the exact matched-log total?
  2. Does ``offset`` page past the first 1,000 rows?
  3. How many rows does one fetch return at most (500 per the spec, or 1,000)?
  4. Which ``action`` values do real traffic logs carry?

    uv run python scripts/check_faz_paging.py
    uv run python scripts/check_faz_paging.py --label "FortiAnalyzer Primary" --hours 48

Strictly read-only: one log search (submit, count, fetch) and then a delete of
that search task, which frees FortiAnalyzer's search slot and changes no
configuration. The output holds counts, timings and action names only, never
addresses or device names, so it is safe to paste into an issue or a chat.
"""

from __future__ import annotations

import argparse
import collections
import datetime
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

SUBMIT_LIMIT = 1000  # the spec's maximum for a submit
PAGE = 500  # the spec's maximum for a fetch
OFFSETS = (0, 500, 1000, 1500, 2000)


def _row_key(row: dict) -> tuple:
    return (row.get("id"), row.get("eventtime"), row.get("devid"), row.get("sessionid"))


def _wait_fetch(client, tid, offset, limit, timeout) -> tuple[dict, float]:
    """Fetch until FortiAnalyzer reports the page complete (percentage 100)."""
    started = time.monotonic()
    while True:
        res = client.fetch_log_search(tid, offset=offset, limit=limit)
        if res.get("percentage", 0) >= 100 or time.monotonic() - started > timeout:
            return res, time.monotonic() - started
        time.sleep(1.0)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--label", help="faz_targets.json label (default: first target)")
    ap.add_argument("--hours", type=float, default=24.0, help="window to search (default 24)")
    ap.add_argument("--device", default="All_FortiGate", help="devid (default All_FortiGate)")
    ap.add_argument("--timeout", type=float, default=120.0, help="seconds to wait per step")
    args = ap.parse_args(argv)

    from app.config import Config

    if Config.DEMO_MODE:
        from app import demo

        demo.activate()

    from app.faz_client import FAZClient, FAZError
    from app.faz_targets import get_target, list_targets

    target = get_target(args.label) if args.label else next(iter(list_targets()), None)
    if not target:
        print("No FAZ target found in faz_targets.json.", file=sys.stderr)
        return 2

    verdicts: dict[str, str] = {}
    client = FAZClient(
        host=target["host"],
        token=target.get("token", ""),
        adom=target.get("adom", "root"),
        verify_ssl=Config.FAZ_VERIFY_SSL,
        timeout=Config.FAZ_REQUEST_TIMEOUT,
    )
    with client:
        version = client.version
        print(f"FortiAnalyzer {version.train + '.' + str(version.patch) if version else '?'}")
        now = datetime.datetime.now(datetime.timezone.utc)
        start = (now - datetime.timedelta(hours=args.hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
        local_start, local_end = client.local_time_range(start, now.strftime("%Y-%m-%dT%H:%M:%SZ"))
        print(f"Window: last {args.hours:g}h, all traffic logs, oldest first\n")

        t0 = time.monotonic()
        tid = client.submit_log_search(
            "traffic", args.device, "", local_start, local_end, limit=SUBMIT_LIMIT, time_order="asc"
        )
        print(f"submit (limit {SUBMIT_LIMIT})        ok, {time.monotonic() - t0:.1f}s")
        try:
            matched = None
            t0 = time.monotonic()
            try:
                while True:
                    count = client.get_log_search_count(tid)
                    done = count.get("progress-percent", 0) >= 100
                    if done or time.monotonic() - t0 > args.timeout:
                        break
                    time.sleep(1.0)
                matched = count.get("matched-logs")
                state = "final" if done else "NOT final, timed out"
                print(
                    f"count                     matched {matched}, total {count.get('total-logs')}"
                    f", {state}, {time.monotonic() - t0:.1f}s"
                )
                verdicts["count"] = "WORKS" if done and matched is not None else "UNCLEAR"
            except FAZError as exc:
                print(f"count                     FAILED: {exc}")
                verdicts["count"] = "FAILS"

            seen: set = set()
            actions: collections.Counter = collections.Counter()
            per_offset = {}
            total_count = None
            for offset in OFFSETS:
                try:
                    res, secs = _wait_fetch(client, tid, offset, PAGE, args.timeout)
                except FAZError as exc:
                    print(f"fetch offset {offset:>5} limit {PAGE}  FAILED: {exc}")
                    per_offset[offset] = None
                    continue
                rows = res.get("data") or []
                new = [r for r in rows if _row_key(r) not in seen]
                seen.update(_row_key(r) for r in rows)
                actions.update(str(r.get("action", "")) for r in rows)
                total_count = res.get("total-count", total_count)
                per_offset[offset] = len(rows)
                stamps = [int(r["itime_t"]) for r in rows if str(r.get("itime_t", "")).isdigit()]
                order = ""
                if len(stamps) > 1:
                    order = ", oldest first" if stamps == sorted(stamps) else ", NOT time-ordered"
                print(
                    f"fetch offset {offset:>5} limit {PAGE}  {len(rows):>4} rows, {len(new):>4} new"
                    f"{order}, {secs:.1f}s"
                )

            try:
                res, secs = _wait_fetch(client, tid, 0, SUBMIT_LIMIT, args.timeout)
                big = len(res.get("data") or [])
                print(f"fetch offset     0 limit {SUBMIT_LIMIT} {big:>4} rows, {secs:.1f}s")
                verdicts["fetch"] = f"up to {big} rows per fetch" if big else "UNCLEAR"
            except FAZError as exc:
                print(f"fetch offset     0 limit {SUBMIT_LIMIT} FAILED: {exc}")
                verdicts["fetch"] = f"{PAGE} rows per fetch (limit {SUBMIT_LIMIT} refused)"
            if total_count is not None:
                print(f"fetch total-count field   {total_count}")
        finally:
            try:
                client.delete_log_search(tid)
                print("delete search task        ok")
            except FAZError as exc:
                print(f"delete search task        FAILED: {exc}")

    available = matched if isinstance(matched, int) else total_count
    past = per_offset.get(1000)
    if available is not None and available <= 1500:
        verdicts["paging"] = f"NOT TESTED: only {available} logs matched; rerun with --hours 72"
    elif past:
        verdicts["paging"] = f"WORKS ({past} rows at offset 1000)"
    elif past == 0:
        verdicts["paging"] = "STOPS at the submit limit (the timeline falls back to time slices)"
    else:
        verdicts["paging"] = "UNCLEAR (see the fetch lines above)"

    print("\nResult")
    print(f"  Matched-log count:     {verdicts.get('count', 'not run')}")
    print(f"  Paging past 1,000:     {verdicts['paging']}")
    print(f"  Fetch size:            {verdicts.get('fetch', 'not run')}")
    print(f"  Action values seen:    {', '.join(f'{a} {n}' for a, n in actions.most_common())}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
