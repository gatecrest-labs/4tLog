"""Connection Timeline builds: paging raw logs out of FortiAnalyzer, as jobs.

A build can take tens of fetches, longer than a normal request should block, so
``POST /api/conn-timeline`` starts a short-lived background job and the page
polls it. Jobs live in this process's memory: the app runs one gunicorn worker
(with threads), so every request sees the same store. If the app ever runs
several worker processes, jobs need a shared store instead.

How one build reads FortiAnalyzer (:func:`collect`):

1. Submit one log search over the window, oldest first.
2. Fetch it page by page with ``offset``, rolling each page into the
   :class:`~app.conn_timeline.Timeline` and dropping the rows.
3. Ask ``logsearch/count/<tid>`` for the exact matched total, so the page can
   say how much of the traffic it covers.
4. Delete every search task at the end, whatever happened.

If a FortiAnalyzer stops returning rows at the submit limit (1,000) although
more matched, the build carries on with a new search that starts at the last
timestamp it has, skipping the rows it already counted. That keeps the
timeline complete whether or not ``offset`` pages past the submit limit, which
``scripts/check_faz_paging.py`` checks on a real appliance.
"""

from __future__ import annotations

import contextlib
import datetime
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from app.conn_timeline import Timeline, row_key, row_timestamp
from app.faz_client import FAZError

SUBMIT_LIMIT = 1000  # the spec's maximum for a log search submit
SLICES_PER_WORKER = 4  # parallel builds cut the window into this many slices per worker
MIN_SLICE_SECS = 60  # ... but never thinner than this
# A search returns at most SUBMIT_LIMIT rows, whatever the offset. When more than that
# share one second no time range narrows it, so the second is partitioned on these
# numeric fields instead (see split_second in _run_slice).
SPLIT_FIELDS = ("sessionid", "srcport")
MAX_SPLIT_DEPTH = 200  # backstop; every cut shrinks the set, so this is not reached
SNAPSHOT_SECS = 1.5  # how often a running build offers the page a partial picture


def _iso(dt: datetime.datetime) -> str:
    return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class _Stop(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _fetch_complete(client, tid, offset, page_size, deadline_at, poll_interval, is_cancelled):
    """Fetch one page, waiting while FortiAnalyzer is still filling it. A search
    usually finishes within a fraction of a second, so the first checks come
    quickly and only back off to ``poll_interval`` for a slow one."""
    delay = min(0.15, poll_interval)
    while True:
        page = client.fetch_log_search(tid, offset=offset, limit=page_size)
        if page.get("percentage", 100) >= 100:
            return page
        if is_cancelled():
            raise _Stop("cancelled")
        if time.monotonic() + delay >= deadline_at:
            raise _Stop("deadline")
        time.sleep(delay)
        delay = min(delay * 2, poll_interval)


class _Shared:
    """State common to the slices of one build: the lock that serialises
    rolling rows into the timeline, the row total, and the reason to stop."""

    def __init__(self, timeline, max_rows, on_progress, on_snapshot):
        self.timeline = timeline
        self.max_rows = max_rows
        self.on_progress = on_progress
        self.on_snapshot = on_snapshot
        self.lock = threading.Lock()
        self.fetched = 0
        self.stop: str | None = None  # cap | deadline | cancelled | error
        self.slices: list[dict] = []
        self.burst_gaps: list[tuple[int, int]] = []  # seconds whose rows could not all be read
        self.last_snapshot = time.monotonic()

    def set_stop(self, reason: str) -> None:
        with self.lock:
            if self.stop is None:
                self.stop = reason

    def report(self, phase: str) -> None:
        if self.on_progress is None and self.on_snapshot is None:
            return
        with self.lock:
            matched = self.slices[0]["matched"]
            final = self.slices[0]["matched_final"]
            if self.on_progress is not None:
                self.on_progress(
                    phase=phase,
                    fetched=self.fetched,
                    matched=matched,
                    matched_final=final,
                    searches=sum(s["searches"] for s in self.slices),
                )
            if self.on_snapshot and time.monotonic() - self.last_snapshot >= SNAPSHOT_SECS:
                self.last_snapshot = time.monotonic()
                self.on_snapshot()


def _new_slice(index: int, lo: int, hi: int, *, check_count: bool = True) -> dict:
    return {
        "index": index,
        "lo": lo,
        "hi": hi,
        "check_count": check_count,
        "started": False,
        "done": False,
        "matched": None,
        "matched_final": False,
        "count_ok": True,
        "fetched": 0,
        "searches": 0,
        "last_ts": None,
        "reason": None,
        "diag": {
            "rows_returned": 0,  # every row FortiAnalyzer handed back
            "rows_outside_slice": 0,  # dropped: receive time outside the slice we searched
            "rows_boundary_skipped": 0,  # dropped: already counted before a search restart
            "rows_no_time": 0,  # dropped: no usable timestamp, in a slice other than the first
            "rows_out_of_order": 0,  # rows older than the row before them (asc search)
            "short_pages": 0,  # fetches that returned fewer rows than an earlier one
            "rows_burst": 0,  # kept by splitting a second that held more than a search returns
            "burst_searches": 0,  # searches spent on that splitting
            "burst_unreached": 0,  # rows of such a second that no split could reach
            "burst_seconds": [],  # the seconds that needed splitting (epoch)
            "searches": [],
        },
        "unreached": 0,
        "more": False,  # a probe that stopped with rows left, for the slices to take over
        "boundary": None,
    }


def _plan_slices(lo: int, hi: int, workers: int, remaining: int | None) -> list[tuple[int, int]]:
    """Whole-second [lo, hi) time slices for the rest of a window after the probe.
    Each search costs a few seconds on the appliance however small it is, so
    there are no more slices than ``remaining`` rows could use (about two
    submit limits' worth each), nor than ``workers`` times a few so a busy slice
    doesn't leave the others idle."""
    span = max(hi - lo, 1)
    count = workers * SLICES_PER_WORKER
    if remaining is not None:
        count = min(count, -(-remaining // (2 * SUBMIT_LIMIT)))
    count = max(1, min(count, span // MIN_SLICE_SECS))
    edges = [lo + (span * i) // count for i in range(count)] + [hi]
    return [(edges[i], edges[i + 1]) for i in range(count)]


def _run_slice(
    client,
    sl: dict,
    shared: _Shared,
    *,
    single: bool,
    probe: bool = False,
    device,
    filter_expression,
    end_ts: int,
    page_size,
    deadline_at,
    poll_interval,
    submit_limit,
    is_cancelled,
) -> None:
    """Page one time slice into the shared timeline, oldest first. The slice's
    outcome (counts, why it stopped, the last time it reached) lands in ``sl``."""
    sl["started"] = True
    tids: list = []
    last_ts: int | None = None
    last_keys: set = set()
    boundary_ts: int | None = None
    boundary_keys: set = set()
    if sl["boundary"] is not None:  # taking over from a probe that stopped at this time
        boundary_ts, boundary_keys = sl["boundary"][0], set(sl["boundary"][1])
        # Rows at that second the probe counted stay counted if this slice restarts there.
        last_ts, last_keys = boundary_ts, set(boundary_keys)
    seg_start = datetime.datetime.fromtimestamp(sl["lo"], datetime.timezone.utc)
    last_slice = sl["hi"] >= end_ts
    # FortiAnalyzer's range includes both ends: stop a slice one second short so a
    # log on the edge is found, and counted, by exactly one slice.
    seg_end = datetime.datetime.fromtimestamp(
        sl["hi"] if last_slice or single else sl["hi"] - 1, datetime.timezone.utc
    )
    diag = sl["diag"]
    seen_max = 0  # the most rows one fetch has returned: FortiAnalyzer may cap below page_size
    reason = None

    def read_count(wait: bool):
        if not tids or sl["matched_final"] or not sl["count_ok"]:
            return
        while True:
            try:
                res = client.get_log_search_count(tids[0])
            except FAZError:
                sl["count_ok"] = False  # count call not supported: go by the fetches
                return
            if res.get("matched-logs") is not None:
                sl["matched"] = int(res["matched-logs"])
            if res.get("progress-percent", 0) >= 100:
                sl["matched_final"] = sl["matched"] is not None
                return
            if not wait or is_cancelled() or time.monotonic() + poll_interval >= deadline_at:
                return
            time.sleep(poll_interval)

    def check_stop():
        if shared.stop is not None:
            raise _Stop(shared.stop)
        if is_cancelled():
            raise _Stop("cancelled")
        if time.monotonic() >= deadline_at:
            raise _Stop("deadline")

    def split_second(ts: int, seen: set) -> tuple[int, set]:
        """Read every row with receive time ``ts`` when more than one search returns
        share it. ``seen`` holds the keys already counted; returns the rows this added
        and the keys now counted for the second.

        Searches over that one second are narrowed with ``field>=a and field<b``,
        cut at the median of the rows a search did return and sized by its exact
        ``total-count``, until each part fits in one search. A value too common for
        one field is split on the next; what no field can split is reported."""
        keys = set(seen)
        added_here = 0
        gave_up = False
        second_total: int | None = None
        when = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
        diag["burst_seconds"].append(ts)

        def search(cons: list[str]) -> tuple[list, int | None]:
            check_stop()
            local_start, local_end = client.local_time_range(_iso(when), _iso(when))
            filt = " and ".join([f"({filter_expression})"] * bool(filter_expression) + cons)
            tid = client.submit_log_search(
                "traffic", device, filt, local_start, local_end,
                limit=submit_limit, time_order="asc",
            )  # fmt: skip
            tids.append(tid)
            sl["searches"] += 1
            diag["burst_searches"] += 1
            shared.report("splitting")
            got: list = []
            total = None
            while True:
                check_stop()
                page = _fetch_complete(
                    client, tid, len(got), page_size, deadline_at, poll_interval, is_cancelled
                )
                rows = page.get("data") or []
                if isinstance(page.get("total-count"), int):
                    total = page["total-count"]
                got.extend(rows)
                done = total is not None and len(got) >= total
                if not rows or len(got) >= submit_limit or done:
                    break
            diag["searches"].append(
                {"rows": len(got), "total": total, "first_ts": ts, "last_ts": ts, "ended": "split"}
            )
            take(got)
            return got, total

        def take(rows: list) -> None:
            nonlocal added_here
            with shared.lock:
                for row in rows:
                    diag["rows_returned"] += 1
                    if row_timestamp(row) != ts:
                        continue
                    key = row_key(row)
                    if key in keys:
                        continue
                    if shared.stop is not None:
                        raise _Stop(shared.stop)
                    if shared.fetched >= shared.max_rows:
                        shared.stop = "cap"
                        raise _Stop("cap")
                    shared.timeline.add(row)
                    keys.add(key)
                    shared.fetched += 1
                    sl["fetched"] += 1
                    diag["rows_burst"] += 1
                    added_here += 1
            shared.report("splitting")

        def fits(rows: list, total: int | None) -> bool:
            return len(rows) >= total if total is not None else len(rows) < submit_limit

        def cut(cons, field_idx, lo, hi, first=None, parent_total=None, depth=0) -> None:
            """Read the rows matching ``cons`` and ``lo <= field < hi``; ``first`` is
            that search's result when it has been run already."""
            nonlocal gave_up, second_total
            field = SPLIT_FIELDS[field_idx]
            if first is None:
                bounds = [f"{field}>={lo}"] * (lo is not None) + [f"{field}<{hi}"] * (
                    hi is not None
                )
                first = search(cons + bounds)
            rows, total = first
            if second_total is None and not cons and lo is None and hi is None:
                second_total = total
            if fits(rows, total):
                return
            if depth > MAX_SPLIT_DEPTH or (
                parent_total is not None and total is not None and total >= parent_total
            ):
                gave_up = True  # the filter is not narrowing anything
                return
            vals = sorted(
                int(str(r[field]).strip()) for r in rows if str(r.get(field, "")).strip().isdigit()
            )
            if not vals or vals[0] == vals[-1]:
                if vals:  # every row seen shares one value: cut around it
                    v = vals[0]
                    if lo is None or v > lo:
                        cut(cons, field_idx, lo, v, None, total, depth + 1)
                    if hi is None or v + 1 < hi:
                        cut(cons, field_idx, v + 1, hi, None, total, depth + 1)
                    cons = cons + [f"{field}>={v}", f"{field}<{v + 1}"]
                    first = None
                else:  # the field is missing from the rows: the same rows, cut another way
                    cons = cons + [f"{field}>={lo}"] * (lo is not None)
                    cons = cons + [f"{field}<{hi}"] * (hi is not None)
                if field_idx + 1 >= len(SPLIT_FIELDS):
                    gave_up = True
                    return
                cut(cons, field_idx + 1, None, None, first if not vals else None, None, depth + 1)
                return
            pivot = vals[len(vals) // 2]
            if pivot == vals[0]:  # keep both halves non-empty
                pivot = next(v for v in vals if v > vals[0])
            cut(cons, field_idx, lo, pivot, None, total, depth + 1)
            cut(cons, field_idx, pivot, hi, None, total, depth + 1)

        cut([], 0, None, None)
        if gave_up:
            left = max(second_total - len(keys), 1) if second_total is not None else 1
            diag["burst_unreached"] += left
            sl["unreached"] += left
            shared.burst_gaps.append((ts, ts + 1))
        return added_here, keys

    try:
        while True:
            check_stop()
            local_start, local_end = client.local_time_range(_iso(seg_start), _iso(seg_end))
            tid = client.submit_log_search(
                "traffic",
                device,
                filter_expression,
                local_start,
                local_end,
                limit=submit_limit,
                time_order="asc",
            )
            tids.append(tid)
            sl["searches"] += 1
            shared.report("searching")
            offset = 0
            task_rows = 0
            added = 0
            prev_ts: int | None = None
            sd = {
                "rows": 0,
                "total": None,
                "first_ts": None,
                "last_ts": None,
                "ended": "stopped",
            }
            diag["searches"].append(sd)
            while True:
                check_stop()
                page = _fetch_complete(
                    client, tid, offset, page_size, deadline_at, poll_interval, is_cancelled
                )
                rows = page.get("data") or []
                total = page.get("total-count")
                if isinstance(total, int):
                    sd["total"] = total
                if seen_max and 0 < len(rows) < seen_max:
                    diag["short_pages"] += 1
                if sl["searches"] == 1 and isinstance(total, int):
                    # 8.0.2 reports the exact total on every finished fetch: no need to
                    # wait for the count call (about 2s on the lab appliance) per slice.
                    sl["matched"] = total
                    sl["matched_final"] = True
                with shared.lock:
                    for row in rows:
                        ts = row_timestamp(row)
                        diag["rows_returned"] += 1
                        sd["rows"] += 1
                        if ts is not None:
                            if prev_ts is not None and ts < prev_ts:
                                diag["rows_out_of_order"] += 1
                            prev_ts = ts
                            if sd["first_ts"] is None or ts < sd["first_ts"]:
                                sd["first_ts"] = ts
                            if sd["last_ts"] is None or ts > sd["last_ts"]:
                                sd["last_ts"] = ts
                        if not single:
                            # Slice edges overlap by a second on FortiAnalyzer's side:
                            # a row belongs to the slice its own time falls in.
                            if ts is None:
                                if sl["index"] != 0:
                                    diag["rows_no_time"] += 1
                                    continue
                            elif ts < sl["lo"] or (ts >= sl["hi"] and not last_slice):
                                diag["rows_outside_slice"] += 1
                                continue
                        key = row_key(row)
                        if boundary_ts is not None and ts is not None and ts <= boundary_ts:
                            if ts < boundary_ts or key in boundary_keys:
                                diag["rows_boundary_skipped"] += 1
                                continue  # counted already, before the search restarted
                        if shared.stop is not None:
                            raise _Stop(shared.stop)
                        if shared.fetched >= shared.max_rows:
                            shared.stop = "cap"
                            raise _Stop("cap")
                        shared.timeline.add(row)
                        shared.fetched += 1
                        sl["fetched"] += 1
                        added += 1
                        if ts is not None:
                            if ts != last_ts:
                                last_ts, last_keys = ts, {key}
                            else:
                                last_keys.add(key)
                            sl["last_ts"] = last_ts
                task_rows += len(rows)
                offset += len(rows)
                seen_max = max(seen_max, len(rows))
                if sl["searches"] == 1:
                    read_count(wait=False)
                shared.report("fetching")
                known = isinstance(total, int) and offset >= total
                if not rows or len(rows) < seen_max or (len(rows) < page_size and known):
                    sd["ended"] = "exhausted"
                    break  # this search has no more rows to give
                if task_rows >= submit_limit:
                    sd["ended"] = "submit_limit"
                    # Probing past the submit limit costs a round trip (1-2s on an
                    # 8.0.2 lab appliance that then returns nothing); restarting
                    # from the last timestamp below is the same work without it.
                    break

            more_expected = sl["matched"] is None or sl["fetched"] < sl["matched"]
            if not sl["matched_final"]:
                read_count(wait=False)
                more_expected = sl["matched"] is None or sl["fetched"] < sl["matched"]
            if probe and task_rows >= submit_limit and more_expected and added and last_ts:
                sl["more"], sl["boundary"] = True, (last_ts, set(last_keys))
                break  # a big window: the rest is shared out between workers
            if (
                task_rows >= submit_limit
                and more_expected
                and not added
                and boundary_ts is not None
            ):
                # The restart returned only rows already counted: more than a search
                # returns share the second the last one stopped in. Read that second
                # by partitioning it, then carry on from the next one.
                got, keys_now = split_second(boundary_ts, boundary_keys)
                added += got
                last_ts, last_keys = boundary_ts, set(keys_now)
                sl["last_ts"] = last_ts
                nxt = boundary_ts + 1
                if nxt > int(seg_end.timestamp()) or (
                    sl["matched"] is not None and sl["fetched"] >= sl["matched"]
                ):
                    break
                boundary_ts, boundary_keys = last_ts, set(keys_now)
                seg_start = datetime.datetime.fromtimestamp(nxt, datetime.timezone.utc)
                continue
            if task_rows >= submit_limit and more_expected and added and last_ts is not None:
                # The search stopped at the submit limit: continue from the
                # last timestamp, skipping the rows already counted there.
                boundary_ts, boundary_keys = last_ts, set(last_keys)
                seg_start = datetime.datetime.fromtimestamp(last_ts, datetime.timezone.utc)
                continue
            break
    except _Stop as stop:
        reason = stop.reason
        shared.set_stop(reason)
    finally:
        if reason != "cancelled":
            shared.report("counting")
            read_count(wait=True)
        for tid in tids:
            try:
                client.delete_log_search(tid)
            except Exception:
                pass  # FortiAnalyzer expires search tasks on its own
    counted = sl["check_count"] and not sl["more"]
    if reason is None and counted and sl["matched"] is not None and sl["fetched"] < sl["matched"]:
        reason = "burst" if sl["unreached"] else "incomplete"
    sl["reason"] = reason
    sl["done"] = True


def collect(
    client,
    timeline: Timeline,
    *,
    device: str,
    filter_expression: str,
    start: datetime.datetime,
    end: datetime.datetime,
    max_rows: int,
    page_size: int,
    deadline_at: float,
    poll_interval: float = 2.0,
    submit_limit: int = SUBMIT_LIMIT,
    on_progress=None,
    is_cancelled=lambda: False,
    workers: int = 1,
    client_factory=None,
    on_snapshot=None,
) -> dict:
    """Page the window's traffic logs into ``timeline``; return its coverage.

    With ``workers`` > 1 (and a ``client_factory`` giving each worker its own
    connection) the window is cut into time slices that are searched
    concurrently; ``on_snapshot`` is called now and then, with the timeline
    locked, so the page can draw what has arrived so far.

    Coverage: ``matched`` (FortiAnalyzer's exact total, or None if it couldn't
    be read), ``fetched`` (rows rolled up), ``complete``, ``reason`` (why it
    stopped short: cap, deadline, cancelled, incomplete), ``gaps`` (the time
    ranges not covered, when partial), ``through`` (where the first gap starts)
    and ``searches`` (log searches used)."""
    if client_factory is None:
        workers = 1
    lo, hi = int(start.timestamp()), int(end.timestamp())
    shared = _Shared(timeline, max_rows, on_progress, on_snapshot)
    # The first slice is the whole window. Alone it is the build; with workers it is a
    # probe: one search that, if the window turns out big, hands the rest to the others.
    shared.slices = [_new_slice(0, lo, hi)]
    kw = {
        "device": device,
        "filter_expression": filter_expression,
        "end_ts": hi,
        "page_size": page_size,
        "deadline_at": deadline_at,
        "poll_interval": poll_interval,
        "submit_limit": submit_limit,
        "is_cancelled": is_cancelled,
    }
    _run_slice(
        _RateLimited(client, is_cancelled, deadline_at),
        shared.slices[0],
        shared,
        single=True,
        probe=workers > 1,
        **kw,
    )
    probe = shared.slices[0]
    if probe["more"] and shared.stop is None and not is_cancelled():
        remaining = None
        if probe["matched"] is not None:
            remaining = max(probe["matched"] - shared.fetched, 0)
        resume = probe["boundary"][0]
        plan = _plan_slices(resume, hi, workers, remaining)
        for i, (slo, shi) in enumerate(plan, start=1):
            sl = _new_slice(i, slo, shi, check_count=False)
            if i == 1:
                sl["boundary"] = probe["boundary"]
            shared.slices.append(sl)

        def work(sl):
            if shared.stop is not None or is_cancelled() or time.monotonic() >= deadline_at:
                return  # never started: reported as a gap below
            try:
                with contextlib.ExitStack() as stack:
                    c = client_factory()
                    if hasattr(c, "__enter__"):
                        c = stack.enter_context(c)
                    _run_slice(
                        _RateLimited(c, is_cancelled, deadline_at), sl, shared, single=False, **kw
                    )
            except BaseException:
                shared.set_stop("error")
                raise

        with ThreadPoolExecutor(
            max_workers=workers, thread_name_prefix="conn-timeline-fetch"
        ) as pool:
            futures = [pool.submit(work, sl) for sl in shared.slices[1:]]
            errors = [f.exception() for f in futures]
        for exc in errors:
            if exc is not None:
                raise exc

    return _coverage(shared, is_cancelled)


class _RateLimited:
    """Wraps a client so a FortiAnalyzer "API rate limit" error is waited out and
    retried a few times instead of failing the whole build."""

    RETRIES = 4

    def __init__(self, client, is_cancelled, deadline_at):
        self._client = client
        self._is_cancelled = is_cancelled
        self._deadline_at = deadline_at

    def __getattr__(self, name):
        attr = getattr(self._client, name)
        if not callable(attr):
            return attr

        def call(*args, **kwargs):
            for attempt in range(self.RETRIES + 1):
                try:
                    return attr(*args, **kwargs)
                except FAZError as exc:
                    wait = 2.0 * (attempt + 1)
                    if (
                        "rate limit" not in str(exc).lower()
                        or attempt == self.RETRIES
                        or self._is_cancelled()
                        or time.monotonic() + wait >= self._deadline_at
                    ):
                        raise
                    time.sleep(wait)

        return call


def _coverage(shared: _Shared, is_cancelled) -> dict:
    slices = shared.slices
    matched = slices[0][
        "matched"
    ]  # the whole window's count; the slices after it only share the work
    final = slices[0]["matched_final"]
    reason = shared.stop
    if reason == "error":
        reason = None
    if reason is None:
        if any(not s["started"] for s in slices):
            reason = "cancelled" if is_cancelled() else "deadline"
        elif any(s["reason"] for s in slices):
            reason = next(s["reason"] for s in slices if s["reason"])
    if reason is None and matched is not None and shared.fetched < matched:
        reason = "burst" if shared.burst_gaps else "incomplete"
    complete = reason is None
    gaps: list[list[int]] = []
    if not complete:
        for s in slices:
            if s["started"] and not s["reason"]:
                continue
            frm = s["last_ts"] if s["started"] and s["last_ts"] is not None else s["lo"]
            if gaps and gaps[-1][1] >= frm:
                gaps[-1][1] = s["hi"]
            else:
                gaps.append([frm, s["hi"]])
        for lo_b, hi_b in shared.burst_gaps:
            gaps.append([lo_b, hi_b])
        gaps.sort()
    return {
        "matched": matched,
        "matched_final": final,
        "fetched": shared.fetched,
        "complete": complete,
        "reason": reason,
        "gaps": [[_iso_ts(a), _iso_ts(b)] for a, b in gaps],
        "through": _iso_ts(gaps[0][0]) if gaps and (gaps[0][0] > slices[0]["lo"]) else None,
        "searches": sum(s["searches"] for s in slices),
        "diagnostics": _diagnostics(slices),
    }


def _diagnostics(slices: list[dict]) -> dict:
    """Where the rows went, for working out why a build came up short: how many
    FortiAnalyzer returned, how many each filter dropped, and how every search
    ended. Counts and timestamps only, so it is safe to log and to share."""
    total = {
        k: sum(s["diag"][k] for s in slices)
        for k in (
            "rows_returned",
            "rows_outside_slice",
            "rows_boundary_skipped",
            "rows_no_time",
            "rows_out_of_order",
            "short_pages",
            "rows_burst",
            "burst_searches",
            "burst_unreached",
        )
    }
    total["burst_seconds"] = sorted({t for s in slices for t in s["diag"]["burst_seconds"]})
    total["rows_kept"] = sum(s["fetched"] for s in slices)
    total["searches"] = [x for s in slices for x in s["diag"]["searches"]]
    total["slices"] = [
        {
            "lo": s["lo"],
            "hi": s["hi"],
            "kept": s["fetched"],
            "returned": s["diag"]["rows_returned"],
            "matched": s["matched"],
            "reason": s["reason"],
            "searches": [
                {
                    "rows": x["rows"],
                    "total": x["total"],
                    "first_ts": x["first_ts"],
                    "last_ts": x["last_ts"],
                    "ended": x["ended"],
                }
                for x in s["diag"]["searches"]
            ],
        }
        for s in slices
    ]
    return total


def _iso_ts(ts: int) -> str:
    return _iso(datetime.datetime.fromtimestamp(ts, datetime.timezone.utc))


# ── Jobs ─────────────────────────────────────────────────────────────────────


class JobLimitError(Exception):
    """Too many builds running, with a message fit to show the user."""


class Job:
    def __init__(self, user: str, request: dict):
        self.id = secrets.token_urlsafe(16)
        self.user = user
        self.request = request
        self.created = time.monotonic()
        self.finished: float | None = None
        self.status = "running"  # running | done | failed | cancelled
        self.progress = {
            "phase": "starting",
            "fetched": 0,
            "matched": None,
            "matched_final": False,
            "searches": 0,
        }
        self.result: dict | None = None
        self.partial: dict | None = None  # what has been rolled up so far, while running
        self.error: str | None = None
        self._cancel = threading.Event()

    @property
    def running(self) -> bool:
        return self.status == "running"

    def cancel(self) -> None:
        self._cancel.set()

    def is_cancelled(self) -> bool:
        return self._cancel.is_set()

    def update(self, **progress) -> None:
        self.progress.update(progress)

    def set_partial(self, partial: dict) -> None:
        self.partial = partial

    def finish(self, status: str, result: dict | None = None, error: str | None = None) -> None:
        self.result, self.error = result, error
        self.finished = time.monotonic()
        self.partial = None
        self.status = status

    def to_dict(self) -> dict:
        out = {"id": self.id, "status": self.status, "progress": dict(self.progress)}
        if self.partial is not None and self.status == "running":
            out["partial"] = self.partial
        if self.result is not None:
            out["result"] = self.result
        if self.error is not None:
            out["error"] = self.error
        return out


class JobStore:
    """In-memory jobs, owned by the user who started them, dropped after
    ``lifetime`` seconds."""

    def __init__(self):
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def _purge(self, lifetime: float) -> None:
        now = time.monotonic()
        for job_id, job in list(self._jobs.items()):
            done_long_ago = job.finished is not None and now - job.finished > lifetime
            stuck = now - job.created > 3 * lifetime
            if done_long_ago or stuck:
                del self._jobs[job_id]

    def create(
        self, user: str, request: dict, *, max_running: int, max_per_user: int, lifetime: float
    ) -> Job:
        with self._lock:
            self._purge(lifetime)
            running = [j for j in self._jobs.values() if j.running]
            if sum(1 for j in running if j.user == user) >= max_per_user:
                raise JobLimitError(
                    "You already have a timeline building. Wait for it or cancel it first."
                )
            if len(running) >= max_running:
                raise JobLimitError("Too many timelines are building right now. Try again shortly.")
            job = Job(user, request)
            self._jobs[job.id] = job
            return job

    def get(self, job_id: str, user: str, lifetime: float) -> Job | None:
        """The job, only for the user who started it (anyone else: None)."""
        with self._lock:
            self._purge(lifetime)
            job = self._jobs.get(job_id)
        return job if job is not None and job.user == user else None

    def clear(self) -> None:
        with self._lock:
            self._jobs.clear()


STORE = JobStore()


def spawn(target) -> None:
    """Run ``target`` in a daemon thread. Tests replace this to run inline."""
    threading.Thread(target=target, name="conn-timeline", daemon=True).start()
