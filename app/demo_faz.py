"""Synthetic FortiAnalyzer for demo mode (``DEMO_MODE=true``).

:class:`DemoFAZ` is a drop-in for ``FAZClient._post`` (the same seam
:class:`app.faz_recorder.ReplayTransport` uses), so every real client method,
poller and route runs unchanged against it. It answers the JSON-RPC calls 4tlog
makes with generated data for the fictional Gatecrest Labs estate.

Seeded from the recorded fixtures: response envelopes, the ``/sys/status`` key
set and the traffic log field list (``app/demo_data/logfields.json``) come from
``tests/fixtures/faz_8.0.2``. The values are generated: deterministic per host,
view and time bucket, so a page reload shows the same numbers and the charts
move slowly over the day.

Nothing here touches the network. Demo hosts end in ``.demo.invalid`` (a
reserved TLD that never resolves) and :func:`is_demo_host` is the only way into
this module from :class:`app.faz_client.FAZClient`.

All addresses are private (RFC 1918) or documentation ranges (RFC 5737); all
names, serials and users are made up.
"""

from __future__ import annotations

import datetime
import heapq
import ipaddress
import itertools
import json
import random
import re
import threading
import zlib
from dataclasses import dataclass, field
from pathlib import Path

import requests

DEMO_HOST_SUFFIX = ".demo.invalid"
DATA_DIR = Path(__file__).parent / "demo_data"

_NO_PERMISSION = -11
_INVALID_PARAMS = -32002
_SERVER_ERROR = -32005


def is_demo_host(host: str) -> bool:
    return isinstance(host, str) and host.lower().endswith(DEMO_HOST_SUFFIX)


# ── The fictional estate ─────────────────────────────────────────────────────


@dataclass(frozen=True)
class Device:
    name: str
    sn: str
    platform: str
    lan: str  # internal /24 behind this FortiGate
    ip: str  # management address
    wan: tuple[str, ...] = ("wan1", "wan2")
    silent_for_minutes: int = 0  # >0: last log this long ago (silent device)
    degraded_wan: str | None = None  # SD-WAN member with poor latency/loss
    tunnel_down: bool = False
    failed_admin_logins: int = 0


@dataclass(frozen=True)
class Site:
    hostname: str
    serial: str
    version: str
    major: int
    minor: int
    patch: int
    build: str
    adom: str
    cpu: float  # SNMP CPU % baseline
    mem: float  # SNMP memory % baseline
    disk: str
    devices: tuple[Device, ...] = field(default_factory=tuple)
    alerts: dict = field(default_factory=dict)  # unacked alerts by severity
    ssl_vpn_users: tuple[str, ...] = ()
    offline: bool = False


_SITES: dict[str, Site] = {
    "faz-hq.demo.invalid": Site(
        hostname="GC-FAZ-HQ",
        serial="FAZ-VM0000000101",
        version="v7.6.4-build3596 250820 (GA.M)",
        major=7,
        minor=6,
        patch=4,
        build="3596",
        adom="root",
        cpu=22.0,
        mem=41.0,
        disk="Free 612.40GB, Total 1000.00GB",
        devices=(
            Device("GC-HQ-CORE-01", "FG6H0F0000000101", "FortiGate-600F", "10.10.10", "10.10.0.1"),
            Device("GC-HQ-CORE-02", "FG6H0F0000000102", "FortiGate-600F", "10.10.20", "10.10.0.2"),
            Device(
                "GC-HQ-EDGE",
                "FG2H0F0000000103",
                "FortiGate-200F",
                "10.10.30",
                "10.10.0.3",
                wan=("isp-a", "isp-b"),
            ),
        ),
        alerts={"critical": 2, "high": 9, "medium": 27, "low": 41},
        ssl_vpn_users=("avery", "blake", "casey", "devon", "emery"),
    ),
    "faz-branches.demo.invalid": Site(
        hostname="GC-FAZ-BR",
        serial="FAZ-VM0000000201",
        version="v7.4.7-build2620 250515 (GA.M)",
        major=7,
        minor=4,
        patch=7,
        build="2620",
        adom="branches",
        cpu=76.0,
        mem=63.0,
        disk="Free 141.10GB, Total 500.00GB",
        devices=(
            Device("GC-BR-NORTH", "FGT60F0000000201", "FortiGate-60F", "10.20.1", "10.20.0.1"),
            Device(
                "GC-BR-SOUTH",
                "FGT60F0000000202",
                "FortiGate-60F",
                "10.20.2",
                "10.20.0.2",
                failed_admin_logins=3,
            ),
            Device(
                "GC-BR-EAST",
                "FGT40F0000000203",
                "FortiGate-40F",
                "10.20.3",
                "10.20.0.3",
                degraded_wan="wan2",
            ),
            Device(
                "GC-BR-WEST",
                "FWF61F0000000204",
                "FortiWiFi-61F",
                "10.20.4",
                "10.20.0.4",
                silent_for_minutes=190,
                tunnel_down=True,
            ),
        ),
        alerts={"critical": 0, "high": 3, "medium": 11, "low": 18},
        ssl_vpn_users=("finley", "harper"),
    ),
    # Powered off: every call fails like an unreachable appliance would.
    "faz-dr.demo.invalid": Site(
        hostname="GC-FAZ-DR",
        serial="FAZ-VM0000000301",
        version="v7.6.4-build3596 250820 (GA.M)",
        major=7,
        minor=6,
        patch=4,
        build="3596",
        adom="root",
        cpu=0.0,
        mem=0.0,
        disk="",
        offline=True,
    ),
}

# External peers: documentation ranges only (RFC 5737).
_EXTERNAL = ("192.0.2", "198.51.100", "203.0.113")
_SERVICES = (
    # service, dstport, proto, app, appcat, weight
    ("HTTPS", 443, 6, "HTTPS.BROWSER", "Web.Client", 46),
    ("DNS", 53, 17, "DNS", "Network.Service", 18),
    ("HTTP", 80, 6, "HTTP.BROWSER", "Web.Client", 8),
    ("NTP", 123, 17, "NTP", "Network.Service", 4),
    ("SSH", 22, 6, "SSH", "Remote.Access", 4),
    ("RDP", 3389, 6, "RDP", "Remote.Access", 3),
    ("SMTPS", 465, 6, "SMTPS", "Email", 3),
    ("LDAPS", 636, 6, "LDAPS", "Network.Service", 3),
    ("SNMP", 161, 17, "SNMP", "Network.Service", 2),
    ("IKE", 500, 17, "IKE", "Network.Service", 2),
    ("SYSLOG", 514, 17, "Syslog", "Network.Service", 2),
)
_SIGNATURES = (
    "HTTP.URI.SQL.Injection",
    "Apache.Log4j.Error.Log.Remote.Code.Execution",
    "SSH.Brute.Force.Login",
    "Web.Server.Password.Files.Access",
    "Nmap.Script.Scanner",
    "PHP.CGI.Argument.Injection",
    "TLS.Heartbeat.Information.Disclosure",
)
_COUNTRIES = ("United States", "Netherlands", "Germany", "Brazil", "Singapore", "Canada", "India")
_WEB_CATEGORIES = (
    ("Information Technology", "docs.example.com", "passthrough"),
    ("Business", "crm.example.net", "passthrough"),
    ("News and Media", "news.example.org", "passthrough"),
    ("Streaming Media and Download", "video.example.com", "passthrough"),
    ("Malicious Websites", "bad.example.net", "blocked"),
    ("Phishing", "login-verify.example.org", "blocked"),
)


# ── Deterministic helpers ────────────────────────────────────────────────────


def _rng(*parts) -> random.Random:
    """A Random seeded from ``parts`` — stable across processes (unlike hash())."""
    return random.Random(zlib.crc32("|".join(str(p) for p in parts).encode()))


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _parse_local(value, default: datetime.datetime) -> datetime.datetime:
    """FAZ time-range strings are appliance-local; the demo appliances run on UTC."""
    if isinstance(value, (int, float)):
        return datetime.datetime.fromtimestamp(value, datetime.timezone.utc)
    try:
        dt = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00").replace(" ", "T"))
    except ValueError:
        return default
    return dt.replace(tzinfo=datetime.timezone.utc) if dt.tzinfo is None else dt


def _window(params: dict) -> tuple[datetime.datetime, datetime.datetime]:
    now = _now()
    tr = params.get("time-range") or {}
    end = min(_parse_local(tr.get("end"), now), now)
    start = _parse_local(tr.get("start"), end - datetime.timedelta(hours=1))
    if start > end:
        start, end = end, start
    return start, end


def snmp_reading(host: str) -> tuple[float, float] | None:
    """Synthetic (cpu %, memory %) for a demo host, wobbling minute to minute."""
    site = _SITES.get(host.lower()) if isinstance(host, str) else None
    if site is None or site.offline:
        return None
    rng = _rng(host, "snmp", int(_now().timestamp() // 60))
    return (
        round(max(site.cpu + rng.uniform(-4, 4), 1.0), 1),
        round(max(site.mem + rng.uniform(-2, 2), 1.0), 1),
    )


# ── Log search filter evaluation ─────────────────────────────────────────────

_TOKEN = re.compile(
    r"""\s*(?:(?P<lp>\()|(?P<rp>\))|(?P<kw>and|or)(?=[\s()]|$)|"""
    r"""(?P<cmp>[A-Za-z0-9_-]+)\s*(?P<op>==|!=|>=|<=)\s*(?P<val>"[^"]*"|[^\s()]+))""",
    re.IGNORECASE,
)


def _tokenize(expr: str) -> list[tuple]:
    tokens, pos = [], 0
    expr = expr.strip()
    while pos < len(expr):
        m = _TOKEN.match(expr, pos)
        if not m or m.end() == pos:
            raise ValueError(f"cannot parse filter near {expr[pos : pos + 20]!r}")
        pos = m.end()
        if m.group("lp"):
            tokens.append(("(",))
        elif m.group("rp"):
            tokens.append((")",))
        elif m.group("kw"):
            tokens.append((m.group("kw").lower(),))
        else:
            tokens.append(("cmp", m.group("cmp"), m.group("op"), m.group("val").strip('"')))
        while pos < len(expr) and expr[pos].isspace():
            pos += 1
    return tokens


def compile_filter(expr: str):
    """Compile the subset of FAZ filter syntax that build_filter_expression()
    emits (and/or, parentheses, ==, !=, >=, <=, CIDR values) into a predicate
    over a log row. An empty expression matches everything."""
    tokens = _tokenize(expr or "")
    if not tokens:
        return lambda row: True
    pos = 0

    def peek():
        return tokens[pos] if pos < len(tokens) else (None,)

    def parse_or():
        nonlocal pos
        left = parse_and()
        while peek()[0] == "or":
            pos += 1
            right = parse_and()
            left = (lambda a, b: lambda r: a(r) or b(r))(left, right)
        return left

    def parse_and():
        nonlocal pos
        left = parse_atom()
        while peek()[0] == "and":
            pos += 1
            right = parse_atom()
            left = (lambda a, b: lambda r: a(r) and b(r))(left, right)
        return left

    def parse_atom():
        nonlocal pos
        tok = peek()
        if tok[0] == "(":
            pos += 1
            inner = parse_or()
            if peek()[0] != ")":
                raise ValueError("unbalanced parentheses in filter")
            pos += 1
            return inner
        if tok[0] == "cmp":
            pos += 1
            return _comparison(tok[1], tok[2], tok[3])
        raise ValueError(f"unexpected token {tok!r} in filter")

    predicate = parse_or()
    if pos != len(tokens):
        raise ValueError("trailing tokens in filter")
    return predicate


def _comparison(fieldname: str, op: str, value: str):
    def as_ip(v):
        try:
            return ipaddress.ip_address(str(v))
        except ValueError:
            return None

    network = None
    if "/" in value:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            network = None

    def test(row: dict) -> bool:
        actual = row.get(fieldname)
        if actual is None:
            return op == "!="
        if network is not None:
            ip = as_ip(actual)
            hit = ip is not None and ip in network
            return hit if op == "==" else (not hit if op == "!=" else False)
        a_ip, v_ip = as_ip(actual), as_ip(value)
        if a_ip is not None and v_ip is not None:
            a, v = int(a_ip), int(v_ip)
        else:
            try:
                a, v = float(actual), float(value)
            except (TypeError, ValueError):
                a, v = str(actual).lower(), str(value).lower()
        if op == "==":
            return a == v
        if op == "!=":
            return a != v
        if op == ">=":
            return a >= v
        return a <= v

    return test


# ── Generated log rows ───────────────────────────────────────────────────────

_ROW_STEP_SECONDS = 9  # roughly one log row per site every 9-27 seconds
_MAX_SCAN = 60_000  # rows generated per search at most (a 7-day window is capped)
_TASK_ROWS = 25_000  # rows one demo log search keeps for paging
_STORED_ROWS = 150_000  # rows kept across every open demo task
GENERATED_LOGTYPES = ("traffic", "attack", "webfilter", "app-ctrl", "event")


def _weighted_service(rng: random.Random):
    total = sum(s[5] for s in _SERVICES)
    pick = rng.uniform(0, total)
    for s in _SERVICES:
        pick -= s[5]
        if pick <= 0:
            return s
    return _SERVICES[0]


def _base_row(site: Site, dev: Device, ts: datetime.datetime, rng: random.Random) -> dict:
    ext = f"{rng.choice(_EXTERNAL)}.{rng.randint(10, 250)}"
    src = f"{dev.lan}.{rng.randint(10, 200)}"
    inbound = rng.random() < 0.08
    return {
        "date": ts.strftime("%Y-%m-%d"),
        "time": ts.strftime("%H:%M:%S"),
        "itime": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "itime_t": str(int(ts.timestamp())),
        "eventtime": str(int(ts.timestamp() * 1_000_000_000) + rng.randint(0, 999_999_999)),
        "tz": "+0000",
        "devid": dev.sn,
        "devname": dev.name,
        "vd": "root",
        "srcip": ext if inbound else src,
        "dstip": src if inbound else ext,
        "srcport": str(rng.randint(1024, 65535)),
        "srcintf": dev.wan[0] if inbound else "internal",
        "dstintf": "internal" if inbound else rng.choice(dev.wan),
        "srccountry": rng.choice(_COUNTRIES) if inbound else "Reserved",
        "dstcountry": "Reserved" if inbound else rng.choice(_COUNTRIES),
        "sessionid": str(rng.randint(100_000, 9_999_999)),
    }


def _row(site: Site, dev: Device, logtype: str, ts: datetime.datetime, rng) -> dict:
    row = _base_row(site, dev, ts, rng)
    service, port, proto, app, appcat, _w = _weighted_service(rng)
    row.update({"dstport": str(port), "proto": str(proto), "service": service})
    if logtype == "traffic":
        deny = rng.random() < 0.07
        sent, rcvd = rng.randint(60, 90_000), rng.randint(60, 2_400_000)
        row.update(
            {
                "type": "traffic",
                "subtype": "forward",
                "logid": "0000000013",
                "level": "notice",
                "action": "deny" if deny else rng.choice(("accept", "close", "close", "timeout")),
                "policyid": str(rng.choice((1, 2, 5, 12, 20))),
                "policyname": rng.choice(("LAN-to-Internet", "Servers-Out", "Guest", "VPN-HQ")),
                "policytype": "policy",
                "app": app,
                "appcat": appcat,
                "duration": str(rng.randint(0, 600)),
                "sentbyte": str(0 if deny else sent),
                "rcvdbyte": str(0 if deny else rcvd),
                "sentpkt": str(0 if deny else max(sent // 900, 1)),
                "rcvdpkt": str(0 if deny else max(rcvd // 1300, 1)),
                "trandisp": "noop" if deny else "snat",
            }
        )
    elif logtype == "attack":
        sig = rng.choice(_SIGNATURES)
        row.update(
            {
                "type": "utm",
                "subtype": "ips",
                "logid": "0419016384",
                "level": "alert",
                "eventtype": "signature",
                "attack": sig,
                "attackid": str(10_000 + zlib.crc32(sig.encode()) % 90_000),
                "severity": rng.choice(("critical", "high", "medium", "low")),
                "action": rng.choice(("dropped", "dropped", "dropped", "detected")),
                "srccountry": rng.choice(_COUNTRIES),
                "ref": "https://www.example.com/ips/signature",
            }
        )
    elif logtype == "webfilter":
        cat, hostname, action = rng.choice(_WEB_CATEGORIES)
        row.update(
            {
                "type": "utm",
                "subtype": "webfilter",
                "logid": "0316013056",
                "level": "warning" if action == "blocked" else "notice",
                "eventtype": "ftgd_blk" if action == "blocked" else "ftgd_allow",
                "hostname": hostname,
                "url": f"/{rng.choice(('', 'index.html', 'api/v1/items', 'watch'))}",
                "catdesc": cat,
                "action": action,
                "dstport": "443",
                "service": "HTTPS",
            }
        )
    elif logtype == "app-ctrl":
        row.update(
            {
                "type": "utm",
                "subtype": "app-ctrl",
                "logid": "1059028704",
                "level": "information",
                "eventtype": "signature",
                "app": app,
                "appcat": appcat,
                "action": "pass",
            }
        )
    else:  # event: admin logins against the FortiGate itself
        ok = rng.random() > 0.15
        row.update(
            {
                "type": "event",
                "subtype": "system",
                "logid": "0100032001" if ok else "0100032002",
                "level": "information" if ok else "alert",
                "action": "login",
                "status": "success" if ok else "failed",
                "user": rng.choice(("admin", "netops", "svc-backup")),
                "ui": rng.choice(("https", "ssh")),
                "dstip": dev.ip,
                "dstport": rng.choice(("443", "22")),
                "service": rng.choice(("HTTPS", "SSH")),
                "msg": "Administrator login " + ("successful" if ok else "failed"),
            }
        )
    return row


def _base_rows(site_host, logtype, devices, start, end, newest_first):
    """Background traffic for the whole site, one candidate row per
    ``_ROW_STEP_SECONDS`` bucket. Each bucket draws from its own seeded Random,
    so a bucket yields the same row whichever direction it is walked in."""
    site = _SITES[site_host]
    step = _ROW_STEP_SECONDS
    first = int(start.timestamp()) // step
    last = int(end.timestamp()) // step
    buckets = range(last, first - 1, -1) if newest_first else range(first, last + 1)
    for bucket in itertools.islice(buckets, _MAX_SCAN):
        rng = _rng(site_host, logtype, bucket)
        dev = rng.choice(site.devices)
        if dev not in devices or rng.random() < 0.55:
            continue
        ts = datetime.datetime.fromtimestamp(
            bucket * step + rng.randint(0, step - 1), datetime.timezone.utc
        )
        if dev.silent_for_minutes and ts > _now() - datetime.timedelta(
            minutes=dev.silent_for_minutes
        ):
            continue  # a silent device sends nothing recent
        if not (start <= ts <= end):
            continue
        yield _row(site, dev, logtype, ts, rng)


# ── Featured hosts ───────────────────────────────────────────────────────────
#
# Background rows pick a random LAN address each time, so no single host has a
# story. These few fixed hosts recur across several firewalls with a steady
# pattern, so the Connection Timeline has something to show. Same rules as the
# rest of the demo: private and documentation addresses only, made-up names.


@dataclass(frozen=True)
class Flow:
    weight: float
    devices: tuple[str, ...]  # one is picked per row
    peer: str  # an address, or "a.b.c.lo-hi" for a range of last octets
    service: tuple[str, int, int, str, str]  # service, dstport, proto, app, appcat
    action: str  # accept / deny (accept rows end as accept, close or timeout)
    policy: tuple[int, str]
    host_is_src: bool = True


@dataclass(frozen=True)
class FeaturedHost:
    ip: str
    site: str
    description: str
    step: int  # seconds between candidate rows
    keep: float  # chance a step yields a row
    flows: tuple[Flow, ...]
    burst: tuple[Flow, ...] = ()  # replaces ``flows`` during a burst
    burst_every: int = 0  # seconds; a burst opens each period
    burst_for: int = 0  # seconds the burst lasts


_SSH = ("SSH", 22, 6, "SSH", "Remote.Access")
_RDP = ("RDP", 3389, 6, "RDP", "Remote.Access")
_SMB = ("SMB", 445, 6, "SMB", "Network.Service")
_HTTPS = ("HTTPS", 443, 6, "HTTPS.BROWSER", "Web.Client")
_DNS = ("DNS", 53, 17, "DNS", "Network.Service")
_NTP = ("NTP", 123, 17, "NTP", "Network.Service")
_RTSP = ("RTSP", 554, 6, "RTSP", "Video/Audio")
_IMPLICIT_DENY = (0, "")
_HQ_CORES = ("GC-HQ-CORE-01", "GC-HQ-CORE-02")

FEATURED_HOSTS: tuple[FeaturedHost, ...] = (
    FeaturedHost(
        ip="10.10.20.50",
        site="faz-hq.demo.invalid",
        description="HQ jump server: steady SSH and RDP, a denied SMB sweep every 3 hours",
        step=20,
        keep=0.8,
        flows=(
            Flow(45, _HQ_CORES, "10.10.10.21-26", _SSH, "accept", (30, "Jump-to-Servers")),
            Flow(25, _HQ_CORES, "10.10.10.31-34", _RDP, "accept", (30, "Jump-to-Servers")),
            Flow(15, ("GC-HQ-EDGE",), "192.0.2.80", _HTTPS, "accept", (1, "LAN-to-Internet")),
            Flow(15, ("GC-HQ-CORE-02",), "10.10.10.53", _DNS, "accept", (5, "Servers-Out")),
        ),
        burst=(
            Flow(75, ("GC-HQ-EDGE",), "10.10.30.10-60", _SMB, "deny", _IMPLICIT_DENY),
            Flow(25, _HQ_CORES, "10.10.10.21-26", _SSH, "accept", (30, "Jump-to-Servers")),
        ),
        burst_every=3 * 3600,
        burst_for=15 * 60,
    ),
    FeaturedHost(
        ip="10.10.10.53",
        site="faz-hq.demo.invalid",
        description="HQ DNS server: busy (over 1,000 logs an hour), inbound probes denied",
        step=2,
        keep=0.75,
        flows=(
            Flow(
                55, ("GC-HQ-CORE-02",), "10.10.20.10-200", _DNS, "accept", (5, "Servers-Out"), False
            ),
            Flow(30, ("GC-HQ-EDGE",), "198.51.100.53", _DNS, "accept", (1, "LAN-to-Internet")),
            Flow(5, ("GC-HQ-CORE-01",), "10.10.10.1", _NTP, "accept", (5, "Servers-Out")),
            Flow(10, ("GC-HQ-EDGE",), "203.0.113.10-250", _DNS, "deny", _IMPLICIT_DENY, False),
        ),
    ),
    FeaturedHost(
        ip="10.20.2.40",
        site="faz-branches.demo.invalid",
        description="Branch camera: streams to the recorder, its internet calls are denied",
        step=30,
        keep=0.9,
        flows=(
            Flow(50, ("GC-BR-SOUTH",), "198.51.100.77", _HTTPS, "deny", _IMPLICIT_DENY),
            Flow(
                35,
                ("GC-BR-SOUTH", "GC-BR-NORTH"),
                "10.20.1.20",
                _RTSP,
                "accept",
                (12, "Cameras-to-NVR"),
            ),
            Flow(15, ("GC-BR-SOUTH",), "192.0.2.123", _NTP, "accept", (20, "Guest")),
        ),
    ),
)


def featured_hosts(site_host: str) -> list[FeaturedHost]:
    return [h for h in FEATURED_HOSTS if h.site == site_host]


def _pick_peer(spec: str, rng: random.Random) -> str:
    if "-" not in spec:
        return spec
    prefix, _, span = spec.rpartition(".")
    lo, _, hi = span.partition("-")
    return f"{prefix}.{rng.randint(int(lo), int(hi))}"


def _featured_row(site, host: FeaturedHost, flow: Flow, dev: Device, ts, rng) -> dict:
    row = _row(site, dev, "traffic", ts, rng)
    peer = _pick_peer(flow.peer, rng)
    service, port, proto, app, appcat = flow.service
    deny = flow.action == "deny"
    src, dst = (host.ip, peer) if flow.host_is_src else (peer, host.ip)
    row.update(
        {
            "srcip": src,
            "dstip": dst,
            "dstport": str(port),
            "proto": str(proto),
            "service": service,
            "app": app,
            "appcat": appcat,
            "action": "deny" if deny else rng.choice(("accept", "close", "close", "timeout")),
            "policyid": str(flow.policy[0]),
            "policyname": flow.policy[1],
            "srccountry": "Reserved" if src.startswith("10.") else rng.choice(_COUNTRIES),
            "dstcountry": "Reserved" if dst.startswith("10.") else rng.choice(_COUNTRIES),
        }
    )
    if deny:
        row.update(
            {"sentbyte": "0", "rcvdbyte": "0", "sentpkt": "0", "rcvdpkt": "0", "trandisp": "noop"}
        )
    if not flow.policy[1]:
        row.pop("policyname", None)  # the implicit deny has no name on a FortiGate
    return row


def _featured_rows(site_host, host: FeaturedHost, devices, start, end, newest_first):
    site = _SITES[site_host]
    by_name = {d.name: d for d in site.devices}
    first = int(start.timestamp()) // host.step
    last = int(end.timestamp()) // host.step
    steps = range(last, first - 1, -1) if newest_first else range(first, last + 1)
    for k in itertools.islice(steps, _MAX_FEATURED_SCAN):
        rng = _rng(site_host, "featured", host.ip, k)
        if rng.random() >= host.keep:
            continue
        t = k * host.step + rng.randint(0, host.step - 1)
        in_burst = host.burst_every and t % host.burst_every < host.burst_for
        flows = host.burst if in_burst else host.flows
        flow = rng.choices(flows, weights=[f.weight for f in flows])[0]
        dev = by_name[rng.choice(flow.devices)]
        ts = datetime.datetime.fromtimestamp(t, datetime.timezone.utc)
        if dev not in devices or not (start <= ts <= end):
            continue
        yield _featured_row(site, host, flow, dev, ts, rng)


_MAX_FEATURED_SCAN = 150_000  # steps per featured host per search


def generate_logs(
    site_host: str,
    logtype: str,
    devid: str,
    predicate,
    start: datetime.datetime,
    end: datetime.datetime,
    limit: int,
    newest_first: bool = True,
) -> list[dict]:
    """Log rows in [start, end] for ``devid`` (or All_FortiGate) that match
    ``predicate``, at most ``limit``: newest first, or oldest first."""
    site = _SITES[site_host]
    if logtype not in GENERATED_LOGTYPES or not site.devices:
        return []
    devices = [d for d in site.devices if devid in ("All_FortiGate", "", None) or d.sn == devid]
    if not devices:
        return []
    sources = [_base_rows(site_host, logtype, devices, start, end, newest_first)]
    if logtype == "traffic":
        sources += [
            _featured_rows(site_host, h, devices, start, end, newest_first)
            for h in featured_hosts(site_host)
        ]
    stamp = (lambda r: -int(r["itime_t"])) if newest_first else (lambda r: int(r["itime_t"]))
    matching = (r for r in heapq.merge(*sources, key=stamp) if predicate(r))
    return list(itertools.islice(matching, limit))


# ── FortiView ────────────────────────────────────────────────────────────────


def _hour_rng(host: str, view: str, *extra):
    return _rng(host, view, int(_now().timestamp() // 3600), *extra)


def _fortiview_rows(site_host: str, view: str, params: dict) -> list[dict]:
    site = _SITES[site_host]
    start, end = _window(params)
    hours = max((end - start).total_seconds() / 3600, 0.0)
    scale = hours / 24
    rng = _hour_rng(site_host, view)
    fleet = len(site.devices)
    limit = int(params.get("limit") or 1000)
    filt = str(params.get("filter") or "")

    if view == "top-type":
        ips = int(rng.randint(160, 220) * fleet * scale)
        rows = [
            {"type": "ips", "count": ips, "blockedsessions": int(ips * rng.uniform(0.88, 0.95))},
            {"type": "webfilter", "count": int(ips * 2.4), "blockedsessions": int(ips * 0.3)},
            {"type": "app-ctrl", "count": int(ips * 5.1), "blockedsessions": int(ips * 0.1)},
            {"type": "virus", "count": int(ips * 0.04), "blockedsessions": int(ips * 0.04)},
        ]
    elif view == "top-threats":
        if filt and filt != "type==ips":
            raise _Error(_INVALID_PARAMS, f"Invalid params: filter '{filt}' not supported.")
        rows = [
            {
                "threatname": sig,
                "threatlevel": 4 - i // 2,
                "count": int(rng.randint(40, 90) * fleet * scale / (i + 1)),
            }
            for i, sig in enumerate(_SIGNATURES)
        ]
    elif view == "top-countries":
        rows = [
            {"srccountry": c, "count": int(rng.randint(50, 120) * fleet * scale / (i + 1))}
            for i, c in enumerate(_COUNTRIES)
        ]
    elif view == "admin-logins":
        rows = []
        for dev in site.devices:
            logins = max(int(round(rng.uniform(0.15, 0.35) * hours)), 0)
            rows.append(
                {
                    "fortigate": dev.name,
                    "f_user": "admin",
                    "login_num": logins + dev.failed_admin_logins,
                    "login_fail_num": dev.failed_admin_logins if hours >= 12 else 0,
                }
            )
    elif view == "failed-authentication-attempts":
        rows = [
            {
                "fortigate": dev.name,
                "src_ip": f"{_EXTERNAL[i % 3]}.{40 + i * 7}",
                "total_num": int(rng.randint(3, 25) * scale) + dev.failed_admin_logins,
            }
            for i, dev in enumerate(site.devices)
        ]
    elif view == "site-to-site-ipsec":
        now_ts = int(_now().timestamp())
        rows = [
            {
                "vpnname": "to-HQ" if site.adom != "root" else f"to-{dev.name}",
                "dvid": dev.sn,
                "s_time": now_ts - 86_000,
                "e_time": now_ts - 3 * 3600 if dev.tunnel_down else 0,
                "traffic_in": rng.randint(10**7, 10**9),
                "traffic_out": rng.randint(10**7, 10**9),
            }
            for dev in site.devices
        ]
    elif view == "ssl-dialup-ipsec":
        edge = site.devices[-1] if site.devices else None
        rows = [
            {
                "f_user": user,
                "dvid": edge.sn if edge else "",
                "remip": f"{_EXTERNAL[i % 3]}.{120 + i}",
                "end_time": 0 if i % 4 != 3 else int(_now().timestamp()) - 1800,
            }
            for i, user in enumerate(site.ssl_vpn_users)
        ]
    elif view == "sdwan-dev-stats":
        rows = [
            {"devname": dev.name, "interface": wan, "status": "up"}
            for dev in site.devices
            for wan in dev.wan
        ]
    elif view in (
        "sdwan-intf-sla-status-line",
        "sdwan-perf-stats-line",
        "sdwan-intf-bandwidth-line",
    ):
        rows = _sdwan_rows(site_host, site, view, start, end)
    else:
        raise _Error(_SERVER_ERROR, f"Cannot find FortiView '{view}'")
    return rows[:limit]


_SDWAN_STEP = 900  # one sample per 15 minutes


def _sdwan_rows(site_host, site, view, start, end) -> list[dict]:
    rows = []
    first = int(start.timestamp()) // _SDWAN_STEP + 1
    last = int(end.timestamp()) // _SDWAN_STEP
    for dev in site.devices:
        if dev.silent_for_minutes:
            continue  # no logs, so no SD-WAN rows either
        for idx, wan in enumerate(dev.wan):
            degraded = dev.degraded_wan == wan
            base_latency = (14.0 if idx == 0 else 38.0) + (95.0 if degraded else 0.0)
            for slot in range(first, last + 1):
                ts = slot * _SDWAN_STEP
                rng = _rng(site_host, dev.name, wan, slot)
                # Recent trouble on the degraded link: the last three hours.
                hot = degraded and ts > end.timestamp() - 3 * 3600
                latency = base_latency + rng.uniform(-3, 6) + (60 if hot else 0)
                loss = rng.uniform(0, 0.4) + (rng.uniform(2.5, 5.0) if hot else 0)
                row = {"devname": dev.name, "interface": wan, "timescale": ts}
                if view == "sdwan-intf-bandwidth-line":
                    peak = 1.0 + 0.8 * ((ts // 3600) % 24 in range(13, 23))
                    row["inbandwidth"] = round(rng.uniform(8_000, 42_000) * peak / (idx + 1))
                    row["outbandwidth"] = round(rng.uniform(2_000, 11_000) * peak / (idx + 1))
                else:
                    row["sla"] = "web-sla"
                    if view == "sdwan-perf-stats-line":
                        row["latency"] = round(latency, 2)
                        row["jitter"] = round(rng.uniform(0.8, 4.5) + (6 if hot else 0), 2)
                        row["packetloss"] = round(loss, 2)
                    else:
                        row["sla_available"] = 0 if (latency > 150 or loss > 2) else 1
                rows.append(row)
    return rows


# ── Transport ────────────────────────────────────────────────────────────────


class _Error(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _load_logfields() -> dict:
    return json.loads((DATA_DIR / "logfields.json").read_text())


_ADOM_URL = re.compile(r"^/(?P<module>[a-z]+)/adom/(?P<adom>[^/]+)/(?P<rest>.+)$")


class DemoFAZ:
    """Answers FAZClient JSON-RPC bodies for one demo host. Never does I/O."""

    # Shared, so a task id survives the client that submitted it.
    _tasks: dict[int, tuple[str, str, dict]] = {}
    _tids = itertools.count(7_000_001)
    _tasks_lock = threading.Lock()

    def __init__(self, host: str):
        key = (host or "").lower()
        if key not in _SITES:
            raise ValueError(f"unknown demo host {host!r}")
        self.host = key
        self.site = _SITES[key]

    # ``FAZClient._post`` signature
    def post(self, body: dict) -> dict:
        if self.site.offline:
            raise requests.exceptions.ConnectionError(
                f"HTTPSConnectionPool(host='{self.host}', port=443): Connection refused"
            )
        rid = body.get("id", 1)
        method = body.get("method")
        params = (body.get("params") or [{}])[0] or {}
        try:
            result = self._dispatch(method, str(params.get("url", "")), params)
        except _Error as exc:
            return {
                "id": rid,
                "jsonrpc": "2.0",
                "error": {"code": exc.code, "message": exc.message},
            }
        return {"id": rid, "jsonrpc": "2.0", "result": result}

    def _dispatch(self, method: str, url: str, params: dict):
        if method == "get" and url == "/sys/status":
            return [
                {"data": self._sys_status(), "status": {"code": 0, "message": "OK"}, "url": url}
            ]
        m = _ADOM_URL.match(url)
        if not m:
            raise _Error(-6, f"Invalid url: {url}")
        if m.group("adom") != self.site.adom:
            raise _Error(_NO_PERMISSION, "No permission for the resource")
        module, rest = m.group("module"), m.group("rest")
        if method == "get" and module == "dvmdb" and rest == "device":
            return [{"data": self._devices(), "status": {"code": 0, "message": "OK"}, "url": url}]
        if method == "get" and module == "logview" and rest == "logfields":
            return {"data": [{"field": self._logfields(params.get("logtype", "traffic"))}]}
        if method == "get" and module == "logview" and rest == "logstats":
            return {"data": {"devs": self._logstats()}}
        if method == "get" and module == "eventmgmt" and rest == "alerts/count":
            return {"data": [{"count": str(self._alert_count(str(params.get("filter", ""))))}]}
        if module in ("fortiview", "logview"):
            return self._task(method, module, rest, params)
        raise _Error(-6, f"Invalid url: {url}")

    # -- tasks (FortiView runs and log searches: submit, then fetch) ----------

    def _task(self, method: str, module: str, rest: str, params: dict):
        if method == "add" and (rest.endswith("/run") or rest == "logsearch"):
            if module == "fortiview":
                view = rest[: -len("/run")]
                rows = _fortiview_rows(self.host, view, params)  # raises on a bad view
                payload = {"rows": rows, "matched": len(rows)}
            else:
                payload = self._log_search(params)
            with DemoFAZ._tasks_lock:
                tid = next(DemoFAZ._tids)
                DemoFAZ._tasks[tid] = (self.host, module, payload)
                self._trim_tasks()
            return {"tid": tid}
        count_match = re.fullmatch(r"logsearch/count/(\d+)", rest)
        tid_match = re.search(r"/(\d+)$", rest)
        if method in ("get", "delete") and tid_match:
            tid = int(tid_match.group(1))
            with DemoFAZ._tasks_lock:
                task = DemoFAZ._tasks.get(tid)
                if task is not None and task[0] == self.host and method == "delete":
                    DemoFAZ._tasks.pop(tid, None)
            if task is None or task[0] != self.host:
                raise _Error(-3, "Object does not exist")
            if method == "delete":
                return {"status": {"code": 0, "message": "succeeded"}}
            payload = task[2]
            if count_match:
                return {
                    "matched-logs": payload["matched"],
                    "progress-percent": 100,
                    "total-logs": payload["matched"],
                    "scanned-logs": payload["matched"],
                    "elapsed-time-ms": 40,
                    "estimated-remain-sec": 0,
                    "status": {"code": 0, "message": "succeeded"},
                }
            rows = payload["rows"]
            if module == "logview":
                # Paged like a FortiAnalyzer task: offset and limit pick the slice.
                offset = max(int(params.get("offset") or 0), 0)
                rows = rows[offset : offset + int(params.get("limit") or 50)]
            return {
                "data": rows,
                "percentage": 100,
                "return-lines": len(rows),
                "total-count": payload["matched"],
                "status": {"code": 0, "message": "succeeded"},
            }
        raise _Error(-6, f"Invalid url: /{module}/adom/{self.site.adom}/{rest}")

    def _log_search(self, params: dict) -> dict:
        """Run a log search up front and keep its rows for paging. Unlike the
        submit limit (1,000 at most), the demo keeps up to ``_TASK_ROWS`` so
        offset pages past it, as the 7.6 spec implies (scripts/
        check_faz_paging.py checks what a real FortiAnalyzer does)."""
        try:
            predicate = compile_filter(str(params.get("filter", "")))
        except ValueError as exc:
            raise _Error(_INVALID_PARAMS, f"Invalid params: {exc}") from exc
        device = (params.get("device") or [{}])[0].get("devid", "All_FortiGate")
        start, end = _window(params)
        newest_first = params.get("time-order", "desc") != "asc"
        rows = generate_logs(
            self.host,
            str(params.get("logtype", "traffic")),
            device,
            predicate,
            start,
            end,
            _TASK_ROWS,
            newest_first=newest_first,
        )
        matched = len(rows)
        if matched >= _TASK_ROWS:
            # Stopped early: extrapolate the synthetic total from the part of
            # the window the kept rows cover.
            edge = end if newest_first else start
            covered = abs(int(rows[-1]["itime_t"]) - edge.timestamp())
            window = (end - start).total_seconds()
            if covered > 0:
                matched = max(matched, int(matched * window / covered))
        return {"rows": rows, "matched": matched}

    @staticmethod
    def _trim_tasks() -> None:
        """Keep task memory bounded (caller holds the lock): oldest go first."""
        tasks = DemoFAZ._tasks
        while len(tasks) > 1 and (
            len(tasks) > 500 or sum(len(t[2]["rows"]) for t in tasks.values()) > _STORED_ROWS
        ):
            tasks.pop(min(tasks), None)

    # -- static-ish resources ---------------------------------------------------

    def _sys_status(self) -> dict:
        s = self.site
        now = _now()
        return {
            "Admin Domain Configuration": "Enabled",
            "BIOS version": "04000002",
            "Branch Point": s.build,
            "Build": s.build,
            "Current Time": now.strftime("%a %b %d %H:%M:%S UTC %Y"),
            "Daylight Time Saving": "No",
            "Disk Usage": s.disk,
            "FIPS Mode": "Disabled",
            "Hostname": s.hostname,
            "License Status": "Valid",
            "Major": s.major,
            "Max Number of Admin Domains": 10,
            "Minor": s.minor,
            "Patch": s.patch,
            "Platform Full Name": "FortiAnalyzer-VM64",
            "Platform Type": "FAZVM64",
            "Release Version Information": " (GA.M)",
            "Serial Number": s.serial,
            "TZ": "UTC",
            "Time Zone": "(GMT+0:00) Coordinated Universal Time.",
            "Version": s.version,
            "x86-64 Applications": "Yes",
        }

    def _devices(self) -> list[dict]:
        return [
            {
                "name": d.name,
                "sn": d.sn,
                "platform_str": d.platform,
                "ip": d.ip,
                "os_ver": 7,
                "mr": 4,
                "patch": 7,
                "conn_status": 2 if d.silent_for_minutes else 1,
                "adm_usr": "",
                "adm_pass": "<redacted>",
                "desc": "Gatecrest Labs demo device",
            }
            for d in self.site.devices
        ]

    def _logfields(self, logtype: str) -> list[dict]:
        if logtype == "traffic":
            return _load_logfields()["traffic"]
        if logtype not in GENERATED_LOGTYPES:
            return []
        dev = self.site.devices[0]
        sample = _row(self.site, dev, logtype, _now(), _rng("fields", logtype))
        return [
            {"defaultshow": 1, "desc": k, "logfldgrp": 0, "name": k, "type": 5}
            for k in sorted(sample)
        ]

    def _logstats(self) -> list[dict]:
        now = int(_now().timestamp())
        out = []
        for i, d in enumerate(self.site.devices):
            last = now - (d.silent_for_minutes * 60 if d.silent_for_minutes else 20 + i * 7)
            rate = (
                0.0
                if d.silent_for_minutes
                else round(_hour_rng(self.host, d.sn).uniform(1.5, 9.0), 3)
            )
            out.append(
                {
                    "devid": d.sn,
                    "devname": d.name,
                    "is-ha": 0,
                    "status": 2,
                    "vdoms": [
                        {
                            "vdom": "root",
                            "last-log-timestamp": last,
                            "lograte": rate,
                            "log-db-size": 50_000_000 + i * 7_000_000,
                        }
                    ],
                }
            )
        return out

    def _alert_count(self, filt: str) -> int:
        sev = re.search(r"severity\s*=\s*(\w+)", filt)
        alerts = self.site.alerts
        if sev:
            return int(alerts.get(sev.group(1).lower(), 0))
        return int(sum(alerts.values()))
