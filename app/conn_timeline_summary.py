"""Connection Timeline quick summary: what FortiView says about one IP, in seconds.

Reading every traffic log for a very busy IP costs a log search per 1,000 logs. FortiView
aggregates on the FortiAnalyzer, so these sections come back in a few seconds whatever the
volume (``docs/conn-timeline-fortiview.md``). The counts are **sessions**, not logs: a
long-lived connection writes several logs, so they never match the raw timeline's numbers
and must not be merged with them. FortiView has no ports and no time axis.

Each section is one call to :func:`summarize`. The host is the *source* in role ``src``
(``srcip==HOST``; its peers are destinations) and the *destination* in role ``dst``; the
"either direction" choice runs both and merges.
"""

from __future__ import annotations

from app.faz_client import FAZError

SECTIONS = ("peers", "policies", "applications", "countries")
PEER_CAP = 2000  # most peer rows read per role (two FortiView pages)
PEER_ROWS = 100  # most peer rows handed to the page
PAGE = 1000  # FortiView rows per page

_UNAVAILABLE_MARKERS = ("Cannot find FortiView", "not supported")


def roles(direction: str) -> tuple[str, ...]:
    """The roles the host plays for a direction choice (``either``, ``src``, ``dst``)."""
    return {"either": ("src", "dst"), "src": ("src",), "dst": ("dst",)}[direction]


def role_filter(host: str, role: str) -> str:
    return f"{'srcip' if role == 'src' else 'dstip'}=={host}"


def _int(value) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return 0


def _run(client, view, time_range, host, role, devices, *, limit=PAGE, offset=0):
    return client.run_fortiview_page(
        client.adom,
        view,
        time_range,
        filter=role_filter(host, role),
        devices=devices,
        limit=limit,
        offset=offset,
    )


def _peers(client, host, direction, time_range, devices) -> dict:
    merged: dict[str, dict] = {}
    truncated = False
    for role in roles(direction):
        view, field = ("top-destinations", "dstip") if role == "src" else ("top-sources", "srcip")
        offset, total = 0, None
        while offset < PEER_CAP:
            page, page_total = _run(
                client, view, time_range, host, role, devices,
                limit=min(PAGE, PEER_CAP - offset), offset=offset,
            )  # fmt: skip
            if page_total is not None:
                total = page_total
            for row in page:
                peer = str(row.get(field, ""))
                entry = merged.setdefault(
                    peer, {"peer": peer, "allowed": 0, "denied": 0, "sessions": 0, "roles": []}
                )
                entry["allowed"] += _int(row.get("session_pass"))
                entry["denied"] += _int(row.get("session_block"))
                entry["sessions"] += _int(row.get("sessions"))
                if role not in entry["roles"]:
                    entry["roles"].append(role)
            offset += len(page)
            if not page or (total is not None and offset >= total):
                break
        if total is not None and offset < total:
            truncated = True
    rows = sorted(merged.values(), key=lambda r: (-r["sessions"], r["peer"]))
    return {"rows": rows[:PEER_ROWS], "total": len(rows), "truncated": truncated}


def _policies(client, host, direction, time_range, devices) -> dict:
    merged: dict[tuple, dict] = {}
    for role in roles(direction):
        rows, _ = _run(client, "policy-hits", time_range, host, role, devices)
        for row in rows:
            firewall, policy_id = str(row.get("fortigate", "")), str(row.get("agg_policyid", ""))
            entry = merged.setdefault(
                (firewall, policy_id),
                {
                    "firewall": firewall,
                    "policy_id": policy_id,
                    "policy": str(row.get("policy", "")),
                    "allowed": 0,
                    "denied": 0,
                    "hits": 0,
                },
            )
            entry["allowed"] += _int(row.get("count_pass"))
            entry["denied"] += _int(row.get("count_block"))
            entry["hits"] += _int(row.get("counts"))
    rows = sorted(merged.values(), key=lambda r: (-r["hits"], r["firewall"], r["policy_id"]))
    firewalls: dict[str, dict] = {}
    for r in rows:
        fw = firewalls.setdefault(
            r["firewall"], {"firewall": r["firewall"], "allowed": 0, "denied": 0}
        )
        fw["allowed"] += r["allowed"]
        fw["denied"] += r["denied"]
    return {
        "rows": rows,
        "totals": {
            "allowed": sum(r["allowed"] for r in rows),
            "denied": sum(r["denied"] for r in rows),
        },
        "firewalls": sorted(
            firewalls.values(), key=lambda f: (-(f["allowed"] + f["denied"]), f["firewall"])
        ),
    }


def _grouped(client, view, key_of, time_range, host, direction, devices) -> list[dict]:
    """Rows of a session view, merged by ``key_of(row, role)`` across the roles."""
    merged: dict[tuple, dict] = {}
    for role in roles(direction):
        rows, _ = _run(client, view, time_range, host, role, devices)
        for row in rows:
            key = key_of(row, role)
            entry = merged.setdefault(key, {"allowed": 0, "denied": 0, "sessions": 0, "_key": key})
            entry["allowed"] += _int(row.get("session_pass"))
            entry["denied"] += _int(row.get("session_block"))
            entry["sessions"] += _int(row.get("sessions"))
    return sorted(merged.values(), key=lambda e: (-e["sessions"], e["_key"]))


def _applications(client, host, direction, time_range, devices) -> dict:
    rows = _grouped(
        client, "top-applications",
        lambda r, role: (str(r.get("app_group", "")), str(r.get("appcat", ""))),
        time_range, host, direction, devices,
    )  # fmt: skip
    return {
        "rows": [
            {"app": e["_key"][0], "category": e["_key"][1]}
            | {k: e[k] for k in ("allowed", "denied", "sessions")}
            for e in rows
        ]
    }


def _countries(client, host, direction, time_range, devices) -> dict:
    def country(row, role):
        first, second = (
            ("dstcountry", "srccountry") if role == "src" else ("srccountry", "dstcountry")
        )
        return (str(row.get(first) or row.get(second) or ""),)

    rows = _grouped(client, "top-countries", country, time_range, host, direction, devices)
    return {
        "rows": [
            {"country": e["_key"][0]} | {k: e[k] for k in ("allowed", "denied", "sessions")}
            for e in rows
        ]
    }


_BUILDERS = {
    "peers": _peers,
    "policies": _policies,
    "applications": _applications,
    "countries": _countries,
}


def summarize(
    client,
    section: str,
    host: str,
    direction: str,
    time_range: tuple[str, str],
    devices: list[dict] | None,
) -> dict:
    """One section of the summary for ``host`` (shapes: see the tests and the design doc).

    A view this FortiAnalyzer does not have, or a filter it rejects for the view, gives
    ``{"unavailable": reason}`` so the other sections can still be shown; any other
    FortiAnalyzer error propagates."""
    if section not in _BUILDERS:
        raise ValueError(f"Unknown summary section '{section}'")
    try:
        return _BUILDERS[section](client, host, direction, time_range, devices)
    except FAZError as exc:
        if any(marker in str(exc) for marker in _UNAVAILABLE_MARKERS):
            return {"unavailable": str(exc)[:200]}
        raise
