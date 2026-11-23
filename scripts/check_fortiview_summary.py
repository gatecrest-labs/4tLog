"""Check what FortiView can summarise for one IP, for a fast Connection Timeline summary.

Reading every traffic log for a very busy IP costs a log search per 1,000 logs. FortiView
aggregates on the FortiAnalyzer, so a summary comes back in seconds whatever the volume.
This script asks, on a real appliance:

  1. Which FortiView views exist (top-destinations, top-sources, policy-hits,
     top-applications, top-countries) and how long does each take?
  2. Is the whole peer list reachable (``count-total``, ``offset`` paging)?
  3. Does the ``srcip==`` / ``dstip==`` filter narrow it?
  4. With --compare: how do FortiView's session counts compare with the log counts the
     Connection Timeline builds from raw logs, peer by peer?

    uv run python scripts/check_fortiview_summary.py --host 10.1.1.2 --hours 3
    uv run python scripts/check_fortiview_summary.py --host 10.1.1.2 --hours 3 --compare

Strictly read-only: FortiView runs and the deletion of their tasks. The output holds counts
and seconds only, never addresses or device names.
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

VIEWS = ("top-destinations", "top-sources", "policy-hits", "top-applications", "top-countries")


def _iso(dt: datetime.datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _run(client, view, time_range, filt, *, offset=0, limit=1000, count_total=False):
    """One FortiView run, polled to completion and deleted: (rows, total-count-all)."""
    base = f"/fortiview/adom/{client.adom}/{view}/run"
    submit = {
        "url": base,
        "apiver": 3,
        "time-range": {"start": time_range[0], "end": time_range[1]},
        "limit": limit,
        "device": [{"devid": "All_FortiGate"}],
        "filter": filt,
        "offset": offset,  # FortiAnalyzer reads the offset from the submit, not the fetch
        **({"count-total": True} if count_total else {}),
    }
    body = {"jsonrpc": "2.0", "id": client._next_id(), "method": "add", "params": [submit]}
    tid = client._unwrap_result(client._post({**body, "session": None}))["tid"]
    try:
        while True:
            fetch = {"url": f"{base}/{tid}", "apiver": 3, "limit": limit, "offset": offset}
            res = client._unwrap_result(
                client._post(
                    {
                        "jsonrpc": "2.0",
                        "id": client._next_id(),
                        "method": "get",
                        "params": [fetch],
                        "session": None,
                    }
                )
            )
            if res.get("percentage", 100) >= 100:
                return res.get("data") or [], res.get("total-count-all")
            time.sleep(0.3)
    finally:
        try:
            client._unwrap_result(
                client._post(
                    {
                        "jsonrpc": "2.0",
                        "id": client._next_id(),
                        "method": "delete",
                        "params": [{"url": f"{base}/{tid}", "apiver": 3}],
                        "session": None,
                    }
                )
            )
        except Exception:
            pass  # FortiAnalyzer expires tasks on its own


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--host", required=True, help="the IP address to summarise")
    ap.add_argument("--label", help="faz_targets.json label (default: first target)")
    ap.add_argument("--hours", type=float, default=3.0)
    ap.add_argument(
        "--compare", action="store_true", help="also build the raw timeline and compare"
    )
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
    peers: dict[str, int] = {}
    with new_client() as client:
        tr = client.local_time_range(_iso(start), _iso(end))
        print(f"Window: last {args.hours:g}h\n")
        for filt_name, filt in (
            ("as source", f"srcip=={args.host}"),
            ("as destination", f"dstip=={args.host}"),
        ):
            print(f"-- host {filt_name}")
            for view in VIEWS:
                t0 = time.monotonic()
                try:
                    rows, total = _run(client, view, tr, filt, count_total=True)
                except FAZError as exc:
                    print(f"  {view:<18} not available: {str(exc)[:70]}")
                    continue
                sessions = sum(int(r.get("sessions") or r.get("counts") or 0) for r in rows)
                print(
                    f"  {view:<18} {len(rows):>5} rows (total {total}), sessions {sessions:>7},"
                    f" {time.monotonic() - t0:4.1f}s"
                )
                if view == "top-destinations" and filt_name == "as source":
                    offset = len(rows)
                    while total and offset < total:
                        more, _ = _run(client, view, tr, filt, offset=offset)
                        if not more:
                            break
                        rows += more
                        offset += len(more)
                    print(f"  {'':<18} paged to {len(rows)} peers with offset (total {total})")
                    for r in rows:
                        peers[str(r.get("dstip"))] = int(r.get("session_pass") or 0) + int(
                            r.get("session_block") or 0
                        )

    if args.compare:
        from app.conn_timeline import Timeline, build_filter
        from app.conn_timeline_job import collect

        tl = Timeline(args.host, "src", start, end)
        with new_client() as client:
            cov = collect(
                client,
                tl,
                device="All_FortiGate",
                filter_expression=build_filter(args.host, "src", "all"),
                start=start,
                end=end,
                max_rows=Config.CONN_TIMELINE_MAX_ROWS,
                page_size=Config.CONN_TIMELINE_PAGE_SIZE,
                deadline_at=time.monotonic() + 900,
                poll_interval=Config.LOG_SEARCH_POLL_INTERVAL,
                workers=max(1, Config.CONN_TIMELINE_WORKERS),
                client_factory=new_client,
            )
        d = tl.to_dict()
        logs: collections.Counter = collections.Counter()
        for f in d["flows"]:
            logs[d["peers"][f[3]]] += f[-1]
        both = [p for p in logs if p in peers]
        ratios = sorted(logs[p] / peers[p] for p in both if peers[p])
        print(
            f"\nRaw build: matched {cov['matched']}, complete {cov['complete']}, "
            f"reason {cov['reason']}"
        )
        print(
            f"Raw build: {cov['fetched']} logs over {len(logs)} peers; FortiView: "
            f"{sum(peers.values())} sessions over {len(peers)} peers"
        )
        if ratios:
            q = lambda x: ratios[min(len(ratios) - 1, int(len(ratios) * x))]  # noqa: E731
            print(
                f"logs per session over {len(ratios)} shared peers: p50 {q(0.5):.2f}, "
                f"p90 {q(0.9):.2f}, max {ratios[-1]:.2f}"
            )
        top_logs = {p for p, _ in logs.most_common(10)}
        top_sess = {p for p, _ in sorted(peers.items(), key=lambda kv: -kv[1])[:10]}
        print(f"top-10 peers in common: {len(top_logs & top_sess)} of 10")
    return 0


if __name__ == "__main__":
    sys.exit(main())
