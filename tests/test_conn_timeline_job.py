"""Connection Timeline builds: paging, continuation, limits, clean-up, jobs."""

import datetime
import itertools

import pytest

from app.conn_timeline import Timeline
from app.conn_timeline_job import JobLimitError, JobStore, collect
from app.faz_client import FAZError

UTC = datetime.timezone.utc
END = datetime.datetime(2026, 11, 22, 12, 0, tzinfo=UTC)
START = END - datetime.timedelta(hours=1)
HOST = "10.10.10.53"


def _rows(n, per_second=1, start=START):
    """n rows for HOST, oldest first, ``per_second`` sharing each timestamp."""
    base = int(start.timestamp())
    return [
        {
            "id": str(i),
            "itime_t": str(base + i // per_second),
            "devname": "GC-HQ-CORE",
            "devid": "FGVM01",
            "vd": "root",
            "srcip": "10.10.1.20",
            "dstip": HOST,
            "dstport": "53",
            "proto": "17",
            "action": "accept",
            "policyid": "40",
            "policyname": "DNS-In",
        }
        for i in range(n)
    ]


class FakeFAZ:
    """A log search that returns ``rows`` oldest first.

    ``task_limit`` caps how many rows one search returns (a FortiAnalyzer that
    won't page past its submit limit). ``count`` False makes the count call
    unsupported. ``pending`` fetches report percentage < 100 first."""

    def __init__(self, rows, *, task_limit=None, count=True, pending=0, total_count=True):
        self.rows = rows
        self.task_limit = task_limit
        self.count = count
        self.pending = pending
        self.total_count = total_count
        self.tasks = {}
        self.deleted = []
        self.fetches = 0
        self._ids = itertools.count(100)

    def local_time_range(self, start, end):
        return start, end

    def submit_log_search(self, logtype, device, filt, start, end, limit=1000, time_order="desc"):
        assert logtype == "traffic" and time_order == "asc"
        lo = datetime.datetime.fromisoformat(start.replace("Z", "+00:00")).timestamp()
        rows = [r for r in self.rows if int(r["itime_t"]) >= lo]
        if self.task_limit is not None:
            rows = rows[: self.task_limit]
        tid = next(self._ids)
        self.tasks[tid] = {
            "rows": rows,
            "matched": sum(1 for r in self.rows if int(r["itime_t"]) >= lo),
        }
        return tid

    def fetch_log_search(self, tid, offset=0, limit=500):
        self.fetches += 1
        if self.pending:
            self.pending -= 1
            return {"data": [], "percentage": 40}
        task = self.tasks[tid]
        page = {"data": task["rows"][offset : offset + limit], "percentage": 100}
        if self.total_count:
            page["total-count"] = task["matched"]
        return page

    def get_log_search_count(self, tid):
        if not self.count:
            raise FAZError("count not supported")
        return {"matched-logs": self.tasks[tid]["matched"], "progress-percent": 100}

    def delete_log_search(self, tid):
        self.deleted.append(tid)


def _collect(client, **kw):
    timeline = Timeline(HOST, "either", START, END)
    args = {
        "device": "All_FortiGate",
        "filter_expression": f"(srcip=={HOST} or dstip=={HOST})",
        "start": START,
        "end": END,
        "max_rows": 20000,
        "page_size": 500,
        "deadline_at": float("inf"),
        "poll_interval": 0,
    }
    args.update(kw)
    return collect(client, timeline, **args), timeline


def test_pages_everything_and_cleans_up():
    client = FakeFAZ(_rows(1234))
    cov, timeline = _collect(client)
    assert cov == {
        "matched": 1234,
        "matched_final": True,
        "fetched": 1234,
        "complete": True,
        "reason": None,
        "through": None,
        "searches": 1,
    }
    assert timeline.rows == 1234
    assert client.deleted == list(client.tasks)


def test_stops_at_the_row_cap_and_says_through_when():
    client = FakeFAZ(_rows(3000))
    cov, timeline = _collect(client, max_rows=1200)
    assert cov["complete"] is False and cov["reason"] == "cap"
    assert cov["fetched"] == timeline.rows == 1200
    assert cov["matched"] == 3000
    assert cov["through"] == "2026-11-22T11:19:59Z"  # row 1199's time
    assert client.deleted == list(client.tasks)


def test_continues_when_a_search_stops_at_the_submit_limit():
    # 4 rows share each second, so the 1,000-row boundary splits a timestamp.
    rows = _rows(2502, per_second=4)
    client = FakeFAZ(rows, task_limit=1000)
    cov, timeline = _collect(client)
    assert cov["searches"] == 3
    assert cov["complete"] is True and cov["fetched"] == 2502
    assert timeline.rows == 2502  # no row counted twice at the boundaries
    total = sum(f[-1] for f in timeline.to_dict()["flows"])
    assert total == 2502
    assert sorted(client.deleted) == sorted(client.tasks)


def test_incomplete_when_faz_returns_fewer_rows_than_it_counted():
    client = FakeFAZ(_rows(1500), task_limit=1000)
    # The continued search gives back nothing new, so the loop stops short.
    original = client.submit_log_search

    def submit_once_more(*a, **k):
        tid = original(*a, **k)
        if len(client.tasks) > 1:
            client.tasks[tid]["rows"] = []
        return tid

    client.submit_log_search = submit_once_more
    cov, _ = _collect(client)
    assert cov["complete"] is False and cov["reason"] == "incomplete"
    assert cov["fetched"] == 1000 and cov["matched"] == 1500


def test_matched_falls_back_to_total_count_when_count_is_unsupported():
    client = FakeFAZ(_rows(700), count=False)
    cov, _ = _collect(client)
    assert cov["matched"] == 700 and cov["matched_final"] is False
    assert cov["complete"] is True


def test_no_count_at_all_still_completes():
    client = FakeFAZ(_rows(700), count=False, total_count=False)
    cov, _ = _collect(client)
    assert cov["matched"] is None and cov["fetched"] == 700 and cov["complete"] is True


def test_waits_for_a_page_that_is_still_filling(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda *_: None)
    client = FakeFAZ(_rows(10), pending=2)
    cov, _ = _collect(client, poll_interval=0.01)
    assert cov["fetched"] == 10 and client.fetches == 3


def test_deadline_keeps_what_was_fetched(monkeypatch):
    clock = itertools.count(0, 1.0)
    monkeypatch.setattr("time.monotonic", lambda: next(clock))
    client = FakeFAZ(_rows(5000))
    cov, timeline = _collect(client, deadline_at=4)
    assert cov["reason"] == "deadline" and cov["complete"] is False
    assert 0 < cov["fetched"] < 5000 and timeline.rows == cov["fetched"]
    assert client.deleted == list(client.tasks)


def test_cancel_stops_and_deletes():
    client = FakeFAZ(_rows(5000))
    calls = itertools.count()
    cov, _ = _collect(client, is_cancelled=lambda: next(calls) >= 2)
    assert cov["reason"] == "cancelled"
    assert client.deleted == list(client.tasks)


def test_faz_error_propagates_after_deleting_the_search():
    client = FakeFAZ(_rows(2000))

    def broken(tid, offset=0, limit=500):
        if offset:
            raise FAZError("logview failed")
        return FakeFAZ.fetch_log_search(client, tid, offset, limit)

    client.fetch_log_search = broken
    with pytest.raises(FAZError):
        _collect(client)
    assert client.deleted == list(client.tasks)


def test_progress_is_reported():
    seen = []
    client = FakeFAZ(_rows(1100))
    _collect(client, on_progress=lambda **p: seen.append(p))
    phases = [p["phase"] for p in seen]
    assert phases[0] == "searching" and "fetching" in phases and phases[-1] == "counting"
    assert seen[-1]["fetched"] == 1100 and seen[-1]["matched"] == 1100


# ── Job store ────────────────────────────────────────────────────────────────


def test_job_store_limits_and_ownership():
    store = JobStore()
    a = store.create("alice", {}, max_running=2, max_per_user=1, lifetime=600)
    with pytest.raises(JobLimitError, match="already have"):
        store.create("alice", {}, max_running=2, max_per_user=1, lifetime=600)
    store.create("bob", {}, max_running=2, max_per_user=1, lifetime=600)
    with pytest.raises(JobLimitError, match="Too many"):
        store.create("carol", {}, max_running=2, max_per_user=1, lifetime=600)
    assert store.get(a.id, "alice", 600) is a
    assert store.get(a.id, "bob", 600) is None
    a.finish("done", result={"rows": 1})
    store.create("alice", {}, max_running=3, max_per_user=1, lifetime=600)
    assert a.to_dict()["result"] == {"rows": 1}


def test_finished_jobs_expire(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr("time.monotonic", lambda: clock[0])
    store = JobStore()
    job = store.create("alice", {}, max_running=2, max_per_user=1, lifetime=600)
    job.finish("done", result={})
    clock[0] += 599
    assert store.get(job.id, "alice", 600) is job
    clock[0] += 2
    assert store.get(job.id, "alice", 600) is None


def test_cancel_flag():
    store = JobStore()
    job = store.create("alice", {}, max_running=2, max_per_user=1, lifetime=600)
    assert not job.is_cancelled()
    job.cancel()
    assert job.is_cancelled() and job.running
