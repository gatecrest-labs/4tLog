"""FortiAnalyzer API self-test.

Runs a registry of read-only FortiAnalyzer calls — the same requests the app
makes — and reports per call whether it works and which app feature depends on
it. It answers two questions quickly after a FortiAnalyzer upgrade or a token
change:

  * Did the API behaviour change? (``error`` results, with the appliance's own
    message, e.g. "filter 'type' not supported")
  * Is the API token allowed to do everything the app needs? (``denied``, the
    appliance's code -11)

Strictly read-only: it only issues ``get`` calls and queries (log search and
FortiView runs are read-only submit/poll queries), and never changes anything.
"""

from __future__ import annotations

import datetime
import time

from app.faz_client import FAZError
from app.sdwan_cache import VIEWS as SDWAN_VIEWS

NO_PERMISSION = -11  # "No permission for the resource"


def _describe(result) -> str:
    if isinstance(result, (list, tuple, set)):
        return f"{len(result)} item(s)"
    if isinstance(result, dict):
        return f"{len(result)} field(s)"
    if isinstance(result, bool) or result is None:
        return ""
    return str(result)


def _pick_sample(client) -> dict:
    sample = {"adom": getattr(client, "adom", None), "device": None, "time_range": None}
    try:
        devices = client.get_devices()
        sample["device"] = next((d.get("devid") for d in devices if d.get("devid")), None)
    except Exception:
        pass
    now = datetime.datetime.now(datetime.timezone.utc)
    start = (now - datetime.timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    end = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        sample["time_range"] = client.local_time_range(start, end)
    except Exception:
        sample["time_range"] = (start, end)
    return sample


def _fortiview(view, **kwargs):
    return lambda c, s: c.run_fortiview(s["adom"], view, s["time_range"], limit=5, **kwargs)


def _log_search(client, sample):
    start, end = sample["time_range"]
    return client.search_logs("traffic", sample["device"], "", start, end, limit=1, timeout=30.0)


# id, label, app feature that depends on it, sample keys needed, call.
_CHECKS = [
    (
        "system_status",
        "System status",
        "Dashboard health cards (version, serial, disk); log-search time zone",
        (),
        lambda c, s: c.get_sys_status(),
    ),
    (
        "preflight",
        "Log view access",
        "Log Search, log-usage endpoint",
        (),
        lambda c, s: c.preflight(),
    ),
    (
        "log_fields",
        "Log field list",
        "Log Search field picker",
        (),
        lambda c, s: c.get_log_fields(),
    ),
    ("devices", "Device list", "Log Search device picker", (), lambda c, s: c.get_devices()),
    (
        "log_stats",
        "Per-device log stats",
        "Silent-device detection, executive summary",
        (),
        lambda c, s: c.get_log_stats(),
    ),
    (
        "alert_counts",
        "Alert counts",
        "Threat stats: unacknowledged alerts",
        (),
        lambda c, s: c.get_alert_counts(s["adom"], "ackflag=no"),
    ),
    (
        "fortiview_top_type",
        "FortiView top-type",
        "Threat stats: IPS detections/blocked",
        ("time_range",),
        _fortiview("top-type"),
    ),
    (
        "fortiview_top_threats",
        "FortiView top-threats (type==ips)",
        "Threat stats: top IPS signatures (list left empty if the filter is rejected)",
        ("time_range",),
        _fortiview("top-threats", filter="type==ips"),
    ),
    (
        "fortiview_top_countries",
        "FortiView top-countries (type==ips)",
        "Threat stats: top source countries (list left empty if the filter is rejected)",
        ("time_range",),
        _fortiview("top-countries", filter="type==ips"),
    ),
    (
        "fortiview_admin_logins",
        "FortiView admin-logins",
        "Threat stats: admin login failures / outside business hours",
        ("time_range",),
        _fortiview("admin-logins"),
    ),
    (
        "fortiview_failed_auth",
        "FortiView failed-authentication-attempts",
        "Threat stats: top failed-login sources",
        ("time_range",),
        _fortiview("failed-authentication-attempts"),
    ),
    (
        "fortiview_site_to_site_ipsec",
        "FortiView site-to-site-ipsec",
        "Threat stats: IPsec tunnels total/down",
        ("time_range",),
        _fortiview("site-to-site-ipsec"),
    ),
    (
        "fortiview_ssl_dialup_ipsec",
        "FortiView ssl-dialup-ipsec",
        "Threat stats: SSL VPN users connected now",
        ("time_range",),
        _fortiview("ssl-dialup-ipsec"),
    ),
    *[
        (
            view.replace("-", "_"),
            f"FortiView {view}",
            "SD-WAN tab: link health (a view this release lacks is left out of the tab)",
            ("time_range",),
            _fortiview(view),
        )
        for view in SDWAN_VIEWS
    ],
    (
        "log_search",
        "Log search (1 row, last 24h)",
        "Log Search, log-usage endpoint",
        ("device", "time_range"),
        _log_search,
    ),
]


def _entry(check_id, label, feature, status, started, code=None, message=""):
    return {
        "id": check_id,
        "label": label,
        "feature": feature,
        "status": status,  # ok | denied | error | skipped
        "code": code,
        "message": message,
        "ms": int((time.monotonic() - started) * 1000),
    }


def _run_one(client, check, sample) -> dict:
    check_id, label, feature, needs, call = check
    started = time.monotonic()
    missing = [k for k in needs if not sample.get(k)]
    if missing:
        return _entry(
            check_id,
            label,
            feature,
            "skipped",
            started,
            message=f"No sample {', '.join(missing)} available on this FortiAnalyzer",
        )
    try:
        result = call(client, sample)
    except Exception as exc:
        code = exc.code if isinstance(exc, FAZError) else None
        status = "denied" if code == NO_PERMISSION else "error"
        return _entry(check_id, label, feature, status, started, code=code, message=str(exc))
    return _entry(check_id, label, feature, "ok", started, message=_describe(result))


def run_selftest(client) -> dict:
    """Run every check against ``client`` and return a JSON-serialisable report."""
    version = getattr(client, "version", None)
    sample = _pick_sample(client)
    checks = [_run_one(client, check, sample) for check in _CHECKS]
    summary = {"ok": 0, "denied": 0, "error": 0, "skipped": 0}
    for c in checks:
        summary[c["status"]] += 1
    tr = sample.get("time_range")
    return {
        "faz_version": f"{version.major}.{version.minor}.{version.patch}" if version else None,
        "train": version.train if version else None,
        "sample": {
            "adom": sample["adom"],
            "device": sample["device"],
            "time_range": list(tr) if tr else None,
        },
        "summary": summary,
        "checks": checks,
    }
