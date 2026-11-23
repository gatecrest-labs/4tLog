"""Connection Timeline: input rules and the roll-up of raw traffic logs.

The timeline answers "where did this host talk, through which firewalls, on
which ports, and was it allowed or denied?". Raw traffic logs (paged out of
FortiAnalyzer by :mod:`app.conn_timeline_job`) are rolled up here, one page at
a time, into counts. No raw row is kept.

The result is a set of **flows**: one count per distinct (firewall lane, time
bucket, verdict, peer, port, policy). Lookup tables hold each lane, peer, port
and policy once, and a flow refers to them by index, so even 20,000 rows make
a small JSON document. The page (``app/static/js/conn_timeline.js``) draws the
lanes and the top-N panels from the flows, so a click on a peer or a port can
filter the whole picture without another FortiAnalyzer call.
"""

from __future__ import annotations

import datetime
import ipaddress
import re

# ── Verdicts ─────────────────────────────────────────────────────────────────
#
# FortiGate traffic-log ``action`` values. Anything not listed is "other", so
# an unfamiliar value from a newer FortiOS never hides inside either color.

ALLOWED, DENIED, OTHER = 0, 1, 2
VERDICT_NAMES = ("allowed", "denied", "other")
ALLOWED_ACTIONS = frozenset({"accept", "close", "timeout", "server-rst", "client-rst"})
# ``ip-conn`` is not here: FortiGate logs it with msg "Connection Failed" and zero bytes for a
# connection a policy *allowed* that never completed (seen on a real FortiAnalyzer, under the
# same policy that accepts the host's normal traffic). It is neither accepted nor denied, so it
# falls to "other" and is shown as such.
DENIED_ACTIONS = frozenset({"deny", "block", "dropped"})


def verdict(action) -> int:
    a = str(action or "").strip().lower()
    if a in ALLOWED_ACTIONS:
        return ALLOWED
    if a in DENIED_ACTIONS:
        return DENIED
    return OTHER


# ── Inputs ───────────────────────────────────────────────────────────────────

DIRECTIONS = {"either": "either direction", "src": "as source", "dst": "as destination"}
VERDICT_FILTERS = ("all", "allowed", "denied")
PRESETS = {"15m": 15 * 60, "1h": 3600, "4h": 4 * 3600, "24h": 24 * 3600, "7d": 7 * 24 * 3600}
_DEVICE_RE = re.compile(r"^[A-Za-z0-9_.\-\[\]]{1,64}$")


class TimelineInputError(ValueError):
    """A request the timeline refuses, with a message fit to show the user."""


def parse_host(raw) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """One IPv4 or IPv6 address. Hostnames, ranges and subnets are refused."""
    try:
        return ipaddress.ip_address(str(raw or "").strip())
    except ValueError:
        raise TimelineInputError("Enter an IP address") from None


def parse_device(raw) -> str:
    device = str(raw or "All_FortiGate").strip() or "All_FortiGate"
    if not _DEVICE_RE.match(device):
        raise TimelineInputError("Invalid device")
    return device


def _parse_utc(value: str) -> datetime.datetime:
    try:
        dt = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        raise TimelineInputError(f"Invalid time '{value}'") from None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)


def parse_window(
    data: dict, max_hours: float, default_preset: str, now: datetime.datetime | None = None
) -> tuple[datetime.datetime, datetime.datetime, str | None]:
    """(start, end, preset) in UTC from ``preset`` or ``start_time``/``end_time``.

    With neither, the default preset applies (1 hour). A preset is measured back
    from ``now``. The window may not exceed ``max_hours`` (7 days)."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    preset = data.get("preset") or None
    start_raw, end_raw = data.get("start_time"), data.get("end_time")
    if preset is None and not start_raw and not end_raw:
        preset = default_preset
    if preset is not None:
        if preset not in PRESETS:
            raise TimelineInputError(f"Unknown time preset '{preset}'")
        start, end = now - datetime.timedelta(seconds=PRESETS[preset]), now
    else:
        if not start_raw or not end_raw:
            raise TimelineInputError("Give both a start and an end time")
        start, end = _parse_utc(start_raw), _parse_utc(end_raw)
        if end <= start:
            raise TimelineInputError("The end time must be after the start time")
    if (end - start).total_seconds() > max_hours * 3600 + 1:
        days = max_hours / 24
        limit = f"{days:g} days" if max_hours % 24 == 0 else f"{max_hours:g} hours"
        raise TimelineInputError(f"The time window can be at most {limit}")
    return start, end, preset


def build_filter(host, direction: str, verdict_filter: str = "all") -> str:
    """The FortiAnalyzer filter expression for one host and direction."""
    if direction not in DIRECTIONS:
        raise TimelineInputError(f"Unknown direction '{direction}'")
    if verdict_filter not in VERDICT_FILTERS:
        raise TimelineInputError(f"Unknown verdict filter '{verdict_filter}'")
    ip = str(host)
    if direction == "src":
        expr = f"(srcip=={ip})"
    elif direction == "dst":
        expr = f"(dstip=={ip})"
    else:
        expr = f"(srcip=={ip} or dstip=={ip})"
    if verdict_filter != "all":
        actions = sorted(ALLOWED_ACTIONS if verdict_filter == "allowed" else DENIED_ACTIONS)
        expr += " and (" + " or ".join(f"action=={a}" for a in actions) + ")"
    return expr


# ── Time buckets ─────────────────────────────────────────────────────────────

# Round steps, smallest first. The window gets the smallest step that keeps it
# to about 60 columns: 15m -> 15s, 1h -> 1m, 4h -> 5m, 24h -> 30m, 7d -> 3h.
BUCKET_STEPS = (15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400)
TARGET_BUCKETS = 60


def bucket_seconds(window_seconds: float) -> int:
    for step in BUCKET_STEPS:
        if window_seconds / step <= TARGET_BUCKETS:
            return step
    return BUCKET_STEPS[-1]


# ── Rows ─────────────────────────────────────────────────────────────────────

_PROTO_NAMES = {"1": "icmp", "6": "tcp", "17": "udp", "58": "icmp6", "132": "sctp"}


def row_timestamp(row: dict) -> int | None:
    """Epoch seconds of a log row: ``itime_t`` (8.0.2), else a numeric
    ``itime`` (some 7.x releases), else ``eventtime`` (s, ms, us or ns)."""
    for key in ("itime_t", "itime"):
        value = str(row.get(key, "")).strip()
        if value.isdigit():
            return int(value)
    value = str(row.get("eventtime", "")).strip()
    if value.isdigit():
        n = int(value)
        while n > 10**11:  # beyond year 5000 in seconds: a finer unit
            n //= 1000
        return n
    return None


def row_key(row: dict) -> tuple:
    """Identity of a log row, for skipping rows seen twice when a search is
    continued from its last timestamp."""
    if row.get("id"):
        return ("id", str(row["id"]))
    return tuple(str(row.get(k, "")) for k in ("eventtime", "devid", "vd", "sessionid", "srcip"))


def _norm_ip(value) -> str:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return str(value or "").strip()


def port_label(dstport, proto, service) -> str:
    name = _PROTO_NAMES.get(str(proto), f"proto {proto}" if proto not in (None, "") else "")
    port = str(dstport or "").strip()
    if name in ("icmp", "icmp6") or not port or port == "0":
        return name or str(service or "") or "unknown"
    return f"{port}/{name}" if name else port


class Timeline:
    """Rolls traffic rows up into flows, one page at a time."""

    def __init__(self, host, direction: str, start: datetime.datetime, end: datetime.datetime):
        self.host = _norm_ip(host)
        self.direction = direction
        self.start_ts = int(start.timestamp())
        self.end_ts = int(end.timestamp())
        self.step = bucket_seconds(self.end_ts - self.start_ts)
        self.n_buckets = max(1, -(-(self.end_ts - self.start_ts) // self.step))
        self.flows: dict[tuple, int] = {}
        # (peer, role, lane, port, bucket) -> [count, first_ts, last_ts]. Role 0 means the
        # host was the source of the connection, 1 the destination; the picture for a
        # selected peer needs it because "either direction" mixes both.
        self.paths: dict[tuple, list[int]] = {}
        self._lanes: dict[tuple, int] = {}
        self.lanes: list[dict] = []
        self._peers: dict[str, int] = {}
        self.peers: list[str] = []
        self._ports: dict[str, int] = {}
        self.ports: list[dict] = []
        self._policies: dict[tuple, int] = {}
        self.policies: list[dict] = []
        self.rows = 0
        self.untimed = 0
        self.unmatched = 0
        self.first_ts: int | None = None
        self.last_ts: int | None = None

    @staticmethod
    def _index(table: dict, items: list, key, make) -> int:
        idx = table.get(key)
        if idx is None:
            idx = table[key] = len(items)
            items.append(make())
        return idx

    def _peer_of(self, row: dict) -> str | None:
        src, dst = _norm_ip(row.get("srcip")), _norm_ip(row.get("dstip"))
        if self.direction == "src":
            return dst
        if self.direction == "dst":
            return src
        if src == self.host:
            return dst
        if dst == self.host:
            return src
        return None

    def add(self, row: dict) -> None:
        self.rows += 1
        ts = row_timestamp(row)
        if ts is None:
            self.untimed += 1
            return
        peer = self._peer_of(row)
        if peer is None:
            self.unmatched += 1  # the filter matched, but neither side is the host
            return
        bucket = min(max((ts - self.start_ts) // self.step, 0), self.n_buckets - 1)
        if self.first_ts is None or ts < self.first_ts:
            self.first_ts = ts
        if self.last_ts is None or ts > self.last_ts:
            self.last_ts = ts

        devname = str(row.get("devname") or row.get("devid") or "unknown")
        vd = str(row.get("vd") or "")
        lane = self._index(
            self._lanes,
            self.lanes,
            (devname, vd),
            lambda: {
                "devname": devname,
                "devid": str(row.get("devid") or ""),
                "vd": vd,
                "first_seen": ts,
            },
        )
        lane_meta = self.lanes[lane]
        lane_meta["first_seen"] = min(lane_meta["first_seen"], ts)

        p = self._index(self._peers, self.peers, peer, lambda: peer)
        label = port_label(row.get("dstport"), row.get("proto"), row.get("service"))
        o = self._index(
            self._ports,
            self.ports,
            label,
            lambda: {
                "label": label,
                "port": str(row.get("dstport") or ""),
                "proto": _PROTO_NAMES.get(str(row.get("proto")), str(row.get("proto") or "")),
                "service": str(row.get("service") or ""),
            },
        )
        policyid = str(row.get("policyid") or "")
        policyname = str(row.get("policyname") or "")
        y = self._index(
            self._policies,
            self.policies,
            (lane, policyid, policyname),
            lambda: {
                "lane": lane,
                "policyid": policyid,
                "policyname": policyname,
                "label": policy_label(policyid, policyname),
            },
        )
        outcome = verdict(row.get("action"))
        key = (lane, bucket, outcome, p, o, y)
        self.flows[key] = self.flows.get(key, 0) + 1

        if self.direction == "src":
            role = 0
        elif self.direction == "dst":
            role = 1
        else:
            role = 0 if _norm_ip(row.get("srcip")) == self.host else 1
        pkey = (p, role, lane, o, bucket)
        seen = self.paths.get(pkey)
        if seen is None:
            seen = self.paths[pkey] = [0, ts, ts, 0, 0, 0]  # count, first, last, then per verdict
        seen[0] += 1
        seen[1] = min(seen[1], ts)
        seen[2] = max(seen[2], ts)
        seen[3 + outcome] += 1

    def to_dict(self) -> dict:
        lanes = sorted(range(len(self.lanes)), key=lambda i: (self.lanes[i]["first_seen"], i))
        order = {old: new for new, old in enumerate(lanes)}
        multi_vdom: dict[str, int] = {}
        for lane in self.lanes:
            multi_vdom[lane["devname"]] = multi_vdom.get(lane["devname"], 0) + 1
        lane_out = []
        for old in lanes:
            lane = dict(self.lanes[old])
            lane["label"] = (
                f"{lane['devname']} [{lane['vd']}]"
                if multi_vdom[lane["devname"]] > 1 and lane["vd"]
                else lane["devname"]
            )
            lane_out.append(lane)
        policies = [dict(p, lane=order[p["lane"]]) for p in self.policies]
        flows = sorted(
            [order[k[0]], k[1], k[2], k[3], k[4], k[5], count] for k, count in self.flows.items()
        )
        paths = sorted([k[0], k[1], order[k[2]], k[3], k[4], *v] for k, v in self.paths.items())
        return {
            "start": _iso(self.start_ts),
            "end": _iso(self.end_ts),
            "bucket_seconds": self.step,
            "buckets": self.n_buckets,
            "lanes": lane_out,
            "peers": self.peers,
            "ports": self.ports,
            "policies": policies,
            "flow_fields": ["lane", "bucket", "verdict", "peer", "port", "policy", "count"],
            "flows": flows,
            "path_fields": [
                "peer",
                "role",
                "lane",
                "port",
                "bucket",
                "count",
                "first_ts",
                "last_ts",
                "allowed",
                "denied",
                "other",
            ],  # fmt: skip
            "paths": paths,
            "rows": self.rows,
            "untimed_rows": self.untimed,
            "unmatched_rows": self.unmatched,
            "first_log": _iso(self.first_ts) if self.first_ts is not None else None,
            "last_log": _iso(self.last_ts) if self.last_ts is not None else None,
        }


def policy_label(policyid: str, policyname: str) -> str:
    if policyid == "0":
        return "Implicit deny"
    if policyid and policyname:
        return f"{policyid} · {policyname}"
    return policyname or (f"Policy {policyid}" if policyid else "No policy")


def _iso(ts: int) -> str:
    return (
        datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )
