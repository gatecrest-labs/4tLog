"""Tolerant normalizer for FortiAnalyzer SD-WAN FortiView rows.

Turns the raw rows of the SD-WAN ``*-line`` views into one entry per
``(device, interface)`` with latest/min/avg/max stats and downsampled series
for charts.

The exact row keys and units of these views are UNCONFIRMED: the lab
FortiAnalyzer has no SD-WAN data and the vendored spec's row schema is a
generic placeholder. So this module is deliberately conservative:

  * key lookup is case-insensitive and tries a short list of aliases;
  * a row without an interface or a time is dropped;
  * a value that is not numeric is ignored (never turned into ``0``);
  * no unit conversion is done -- values are passed through as reported.

Revisit once a real capture from a FortiAnalyzer with SD-WAN data exists.
"""

from __future__ import annotations

import math

MAX_SERIES_POINTS = 48

# Candidate key names per logical field, in preference order (lower-case).
_ALIASES: dict[str, tuple[str, ...]] = {
    "interface": ("interface", "intf"),
    "device": ("dvid", "devid", "dev"),
    "time": ("time", "timescale"),
    "latency": ("latency",),
    "jitter": ("jitter",),
    "packetloss": ("packetloss",),
    "in_bw": ("inbandwidth", "inbandwidthused"),
    "out_bw": ("outbandwidth", "outbandwidthused"),
    "sla": ("sla_available", "intf_available"),
}

_METRICS = ("latency", "jitter", "packetloss", "in_bw", "out_bw")
_SLA_VIEW = "sdwan-intf-sla-status-line"


def _lookup(row: dict, field: str):
    lowered = {str(k).lower(): v for k, v in row.items()}
    for alias in _ALIASES[field]:
        if alias in lowered and lowered[alias] not in (None, ""):
            return lowered[alias]
    return None


def _num(value) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _stat(points: list[tuple[str, float]]) -> dict | None:
    if not points:
        return None
    values = [v for _, v in points]
    return {
        "latest": points[-1][1],
        "min": min(values),
        "avg": sum(values) / len(values),
        "max": max(values),
    }


def _downsample(points: list[tuple[str, float]]) -> list[list]:
    n = len(points)
    if n <= MAX_SERIES_POINTS:
        return [[t, v] for t, v in points]
    out: list[list] = []
    for i in range(MAX_SERIES_POINTS):
        bucket = points[i * n // MAX_SERIES_POINTS : (i + 1) * n // MAX_SERIES_POINTS]
        out.append([bucket[0][0], sum(v for _, v in bucket) / len(bucket)])
    return out


def _sla(points: list[tuple[str, float]]) -> tuple[str | None, float | None]:
    """SLA status and % met from ``sla_available`` samples (time-ordered).

    UNCONFIRMED encoding heuristic: if every sample is within 0..1 it is a
    fraction (x100 for percent, ok when the latest sample is 1); otherwise the
    samples are taken to already be percentages (ok when the latest is 100).
    """
    if not points:
        return None, None
    values = [v for _, v in points]
    is_fraction = all(0 <= v <= 1 for v in values)
    scale, full = (100.0, 1.0) if is_fraction else (1.0, 100.0)
    pct = sum(values) / len(values) * scale
    status = "ok" if values[-1] >= full else "fail"
    return status, pct


def worst_first_key(entry: dict) -> tuple:
    """Sort key putting the least healthy interfaces first."""
    has_stats = entry["sla_status"] is not None or any(entry[m] for m in _METRICS)
    loss = (entry["packetloss"] or {}).get("latest", 0.0)
    latency = (entry["latency"] or {}).get("latest", 0.0)
    return (
        0 if has_stats else 1,
        0 if entry["sla_status"] == "fail" else 1,
        -loss,
        -latency,
        entry["device"],
        entry["interface"],
    )


def parse_interfaces(view_rows: dict[str, list[dict]]) -> list[dict]:
    """Normalize ``{view name: raw rows}`` into per-interface entries, worst first."""
    # (device, interface) -> metric -> [(time, value)]
    grouped: dict[tuple[str, str], dict[str, list[tuple[str, float]]]] = {}

    for view, rows in view_rows.items():
        for row in rows or []:
            if not isinstance(row, dict):
                continue
            interface = _lookup(row, "interface")
            time = _lookup(row, "time")
            if interface is None or time is None:
                continue
            device = _lookup(row, "device")
            key = (str(device) if device is not None else "", str(interface))
            metrics = grouped.setdefault(key, {})
            for metric in _METRICS:
                value = _num(_lookup(row, metric))
                if value is not None:
                    metrics.setdefault(metric, []).append((str(time), value))
            if view == _SLA_VIEW:
                value = _num(_lookup(row, "sla"))
                if value is not None:
                    metrics.setdefault("sla", []).append((str(time), value))

    entries = []
    for (device, interface), metrics in grouped.items():
        ordered = {m: sorted(pts, key=lambda p: p[0]) for m, pts in metrics.items()}
        sla_status, sla_pct = _sla(ordered.get("sla", []))
        entry = {
            "device": device,
            "interface": interface,
            "sla_status": sla_status,
            "sla_met_pct": sla_pct,
            "series": {m: _downsample(ordered.get(m, [])) for m in _METRICS},
        }
        for metric in _METRICS:
            entry[metric] = _stat(ordered.get(metric, []))
        entries.append(entry)

    return sorted(entries, key=worst_first_key)
