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

import datetime
import secrets
import threading
import time

from app.conn_timeline import Timeline, row_key, row_timestamp
from app.faz_client import FAZError

SUBMIT_LIMIT = 1000  # the spec's maximum for a log search submit


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
) -> dict:
    """Page the window's traffic logs into ``timeline``; return its coverage.

    Coverage: ``matched`` (FortiAnalyzer's exact total, or None if it couldn't
    be read), ``fetched`` (rows rolled up), ``complete``, ``reason`` (why it
    stopped short: cap, deadline, cancelled, incomplete), ``through`` (the last
    log time included, when partial) and ``searches`` (log searches used)."""
    state = {"matched": None, "matched_final": False, "count_ok": True}
    fetched = 0
    searches = 0
    reason = None
    tids: list = []
    last_ts: int | None = None
    last_keys: set = set()
    boundary_ts: int | None = None
    boundary_keys: set = set()
    seg_start = start

    def report(phase: str):
        if on_progress:
            on_progress(
                phase=phase,
                fetched=fetched,
                matched=state["matched"],
                matched_final=state["matched_final"],
                searches=searches,
            )

    def read_count(wait: bool):
        """Read the first search's count once, or until final when ``wait``."""
        if not tids or state["matched_final"] or not state["count_ok"]:
            return
        while True:
            try:
                res = client.get_log_search_count(tids[0])
            except FAZError:
                state["count_ok"] = False  # count call not supported: go by the fetches
                return
            if res.get("matched-logs") is not None:
                state["matched"] = int(res["matched-logs"])
            if res.get("progress-percent", 0) >= 100:
                state["matched_final"] = state["matched"] is not None
                return
            if not wait or is_cancelled() or time.monotonic() + poll_interval >= deadline_at:
                return
            time.sleep(poll_interval)

    try:
        while True:
            local_start, local_end = client.local_time_range(_iso(seg_start), _iso(end))
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
            searches += 1
            report("searching")
            offset = 0
            task_rows = 0
            added = 0
            while True:
                if is_cancelled():
                    raise _Stop("cancelled")
                if time.monotonic() >= deadline_at:
                    raise _Stop("deadline")
                page = _fetch_complete(
                    client, tid, offset, page_size, deadline_at, poll_interval, is_cancelled
                )
                rows = page.get("data") or []
                total = page.get("total-count")
                if searches == 1 and state["matched"] is None and isinstance(total, int):
                    state["matched"] = total  # 8.0.2 reports it on every fetch
                for row in rows:
                    ts = row_timestamp(row)
                    key = row_key(row)
                    if boundary_ts is not None and ts is not None and ts <= boundary_ts:
                        if ts < boundary_ts or key in boundary_keys:
                            continue  # counted already, before the search restarted
                    if fetched >= max_rows:
                        raise _Stop("cap")
                    timeline.add(row)
                    fetched += 1
                    added += 1
                    if ts is not None:
                        if ts != last_ts:
                            last_ts, last_keys = ts, {key}
                        else:
                            last_keys.add(key)
                task_rows += len(rows)
                offset += len(rows)
                if searches == 1:
                    read_count(wait=False)
                report("fetching")
                if len(rows) < page_size:
                    break  # this search has no more rows to give

            more_expected = state["matched"] is None or fetched < state["matched"]
            if not state["matched_final"]:
                read_count(wait=False)
                more_expected = state["matched"] is None or fetched < state["matched"]
            if task_rows >= submit_limit and more_expected and added and last_ts is not None:
                # The search stopped at the submit limit: continue from the
                # last timestamp, skipping the rows already counted there.
                boundary_ts, boundary_keys = last_ts, set(last_keys)
                seg_start = datetime.datetime.fromtimestamp(last_ts, datetime.timezone.utc)
                continue
            break
    except _Stop as stop:
        reason = stop.reason
    finally:
        if reason != "cancelled":
            report("counting")
            read_count(wait=True)
        for tid in tids:
            try:
                client.delete_log_search(tid)
            except Exception:
                pass  # FortiAnalyzer expires search tasks on its own

    matched = state["matched"]
    if reason is None and matched is not None and fetched < matched:
        reason = "incomplete"  # FortiAnalyzer counted more than it would return
    complete = reason is None
    return {
        "matched": matched,
        "matched_final": state["matched_final"],
        "fetched": fetched,
        "complete": complete,
        "reason": reason,
        "through": None if complete or last_ts is None else _iso_ts(last_ts),
        "searches": searches,
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

    def finish(self, status: str, result: dict | None = None, error: str | None = None) -> None:
        self.result, self.error = result, error
        self.finished = time.monotonic()
        self.status = status

    def to_dict(self) -> dict:
        out = {"id": self.id, "status": self.status, "progress": dict(self.progress)}
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
