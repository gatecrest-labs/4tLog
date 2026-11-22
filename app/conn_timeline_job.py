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
SNAPSHOT_SECS = 1.5  # how often a running build offers the page a partial picture


def _iso(dt: datetime.datetime) -> str:
    return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class _Stop(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _fetch_complete(client, tid, offset, page_size, deadline_at, poll_interval, is_cancelled):
    """Fetch one page, waiting while FortiAnalyzer is still filling it."""
    while True:
        page = client.fetch_log_search(tid, offset=offset, limit=page_size)
        if page.get("percentage", 100) >= 100:
            return page
        if is_cancelled():
            raise _Stop("cancelled")
        if time.monotonic() + poll_interval >= deadline_at:
            raise _Stop("deadline")
        time.sleep(poll_interval)


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
        self.last_snapshot = time.monotonic()

    def set_stop(self, reason: str) -> None:
        with self.lock:
            if self.stop is None:
                self.stop = reason

    def report(self, phase: str) -> None:
        if self.on_progress is None and self.on_snapshot is None:
            return
        with self.lock:
            started = [s for s in self.slices if s["started"]]
            counted = [s["matched"] for s in started if s["matched"] is not None]
            matched = sum(counted) if counted else None
            final = len(started) == len(self.slices) and all(s["matched_final"] for s in started)
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


def _plan_slices(start, end, workers: int) -> list[tuple[int, int]]:
    """Whole-second [lo, hi) time slices. One slice unless building in parallel;
    then several times more slices than workers so a busy slice doesn't leave
    the others idle."""
    lo, hi = int(start.timestamp()), int(end.timestamp())
    span = max(hi - lo, 1)
    count = 1 if workers <= 1 else max(1, min(workers * SLICES_PER_WORKER, span // MIN_SLICE_SECS))
    edges = [lo + (span * i) // count for i in range(count)] + [hi]
    return [(edges[i], edges[i + 1]) for i in range(count)]


def _run_slice(
    client,
    sl: dict,
    shared: _Shared,
    *,
    single: bool,
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
    seg_start = datetime.datetime.fromtimestamp(sl["lo"], datetime.timezone.utc)
    last_slice = sl["hi"] >= end_ts
    # FortiAnalyzer's range includes both ends: stop a slice one second short so a
    # log on the edge is found, and counted, by exactly one slice.
    seg_end = datetime.datetime.fromtimestamp(
        sl["hi"] if last_slice or single else sl["hi"] - 1, datetime.timezone.utc
    )
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
            while True:
                check_stop()
                page = _fetch_complete(
                    client, tid, offset, page_size, deadline_at, poll_interval, is_cancelled
                )
                rows = page.get("data") or []
                total = page.get("total-count")
                if sl["searches"] == 1 and sl["matched"] is None and isinstance(total, int):
                    sl["matched"] = total  # 8.0.2 reports it on every fetch
                with shared.lock:
                    for row in rows:
                        ts = row_timestamp(row)
                        if not single:
                            # Slice edges overlap by a second on FortiAnalyzer's side:
                            # a row belongs to the slice its own time falls in.
                            if ts is None:
                                if sl["index"] != 0:
                                    continue
                            elif ts < sl["lo"] or (ts >= sl["hi"] and not last_slice):
                                continue
                        key = row_key(row)
                        if boundary_ts is not None and ts is not None and ts <= boundary_ts:
                            if ts < boundary_ts or key in boundary_keys:
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
                    break  # this search has no more rows to give

            more_expected = sl["matched"] is None or sl["fetched"] < sl["matched"]
            if not sl["matched_final"]:
                read_count(wait=False)
                more_expected = sl["matched"] is None or sl["fetched"] < sl["matched"]
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
    if reason is None and sl["matched"] is not None and sl["fetched"] < sl["matched"]:
        reason = "incomplete"  # FortiAnalyzer counted more than it would return
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
    plan = _plan_slices(start, end, workers)
    single = len(plan) == 1
    shared = _Shared(timeline, max_rows, on_progress, on_snapshot)
    shared.slices = [
        {
            "index": i,
            "lo": lo,
            "hi": hi,
            "started": False,
            "done": False,
            "matched": None,
            "matched_final": False,
            "count_ok": True,
            "fetched": 0,
            "searches": 0,
            "last_ts": None,
            "reason": None,
        }
        for i, (lo, hi) in enumerate(plan)
    ]
    end_ts = int(end.timestamp())
    kw = {
        "single": single,
        "device": device,
        "filter_expression": filter_expression,
        "end_ts": end_ts,
        "page_size": page_size,
        "deadline_at": deadline_at,
        "poll_interval": poll_interval,
        "submit_limit": submit_limit,
        "is_cancelled": is_cancelled,
    }

    def work(sl):
        if shared.stop is not None or is_cancelled() or time.monotonic() >= deadline_at:
            return  # never started: reported as a gap below
        if workers <= 1:
            _run_slice(client, sl, shared, **kw)
            return
        c = client_factory()
        try:
            with contextlib.ExitStack() as stack:
                if hasattr(c, "__enter__"):
                    c = stack.enter_context(c)
                _run_slice(c, sl, shared, **kw)
        except BaseException:
            shared.set_stop("error")
            raise

    if workers <= 1:
        for sl in shared.slices:
            work(sl)
    else:
        with ThreadPoolExecutor(
            max_workers=workers, thread_name_prefix="conn-timeline-fetch"
        ) as pool:
            futures = [pool.submit(work, sl) for sl in shared.slices]
            errors = [f.exception() for f in futures]
        for exc in errors:
            if exc is not None:
                raise exc

    return _coverage(shared, single, is_cancelled, deadline_at)


def _coverage(shared: _Shared, single: bool, is_cancelled, deadline_at) -> dict:
    slices = shared.slices
    # A lower bound while some slices never ran or have no count; ``final`` says when exact.
    counted = [s["matched"] for s in slices if s["matched"] is not None]
    matched = sum(counted) if counted else None
    final = all(s["matched_final"] for s in slices)
    reason = shared.stop
    if reason == "error":
        reason = None
    if reason is None:
        if any(not s["started"] for s in slices):
            reason = "cancelled" if is_cancelled() else "deadline"
        elif any(s["reason"] for s in slices):
            reason = next(s["reason"] for s in slices if s["reason"])
    if reason is None and matched is not None and shared.fetched < matched:
        reason = "incomplete"
    complete = reason is None
    gaps: list[list[int]] = []
    if not complete:
        for s in slices:
            if s["started"] and not s["reason"]:
                continue
            frm = s["last_ts"] if s["started"] and s["last_ts"] is not None else s["lo"]
            if single and s["last_ts"] is None:
                frm = s["lo"]
            if gaps and gaps[-1][1] >= frm:
                gaps[-1][1] = s["hi"]
            else:
                gaps.append([frm, s["hi"]])
    return {
        "matched": matched,
        "matched_final": final,
        "fetched": shared.fetched,
        "complete": complete,
        "reason": reason,
        "gaps": [[_iso_ts(a), _iso_ts(b)] for a, b in gaps],
        "through": _iso_ts(gaps[0][0]) if gaps and (gaps[0][0] > slices[0]["lo"]) else None,
        "searches": sum(s["searches"] for s in slices),
    }


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
