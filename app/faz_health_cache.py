"""Background cache for FortiAnalyzer Dashboard health cards.

Each poll cycle, for every app.faz_targets entry: calls FAZClient.preflight()
+ get_sys_status() for connectivity/hostname/version/serial/HA, and (if
Config.SNMP_ENABLED) an SNMPv3 GET for CPU/mem. Results land in a
lock-guarded in-memory dict keyed by target label; app/routes/dashboard_routes.py
reads a snapshot via get_all_cached() and never blocks on a live poll.

SNMP OIDs below are FortiAnalyzer's fmSystem group
(1.3.6.1.4.1.12356.103.2.1.*), confirmed against real FAZ hardware
(v7.4.10) in /Users/alanw/code/github/web/4thealth's infra_health_cache.py —
same used-KB/total-KB computed-percentage pattern as FortiManager, since
FAZ has no native memory-percentage OID.
"""

from __future__ import annotations

import asyncio
import datetime
import threading

from flask import Flask
from pysnmp.hlapi.v3arch.asyncio import (
    USM_AUTH_HMAC96_SHA,
    USM_AUTH_HMAC192_SHA256,
    USM_AUTH_HMAC384_SHA512,
    USM_PRIV_CFB128_AES,
    USM_PRIV_CFB192_AES,
    USM_PRIV_CFB256_AES,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    get_cmd,
)

from app.app_logger import app_log
from app.config import Config
from app.faz_client import FAZClient, FAZError, summarize_connection_error
from app.faz_targets import list_targets

_lock = threading.RLock()
_cache: dict[str, dict] = {}

OID_CPU = "1.3.6.1.4.1.12356.103.2.1.1.0"
OID_MEM_USED = "1.3.6.1.4.1.12356.103.2.1.2.0"
OID_MEM_TOTAL = "1.3.6.1.4.1.12356.103.2.1.3.0"

_AUTH_PROTOCOLS = {
    "SHA": USM_AUTH_HMAC96_SHA,
    "SHA256": USM_AUTH_HMAC192_SHA256,
    "SHA512": USM_AUTH_HMAC384_SHA512,
}
_PRIV_PROTOCOLS = {
    "AES": USM_PRIV_CFB128_AES,
    "AES192": USM_PRIV_CFB192_AES,
    "AES256": USM_PRIV_CFB256_AES,
}


class SnmpTimeout(Exception):
    pass


class SnmpQueryError(Exception):
    pass


def _resolve_snmp_creds(target: dict) -> dict:
    return {
        "user": target.get("snmp_user", Config.SNMP_USER),
        "auth_key": target.get("snmp_auth_key", Config.SNMP_AUTH_KEY),
        "priv_key": target.get("snmp_priv_key", Config.SNMP_PRIV_KEY),
        "auth_protocol": target.get("snmp_auth_protocol", Config.SNMP_AUTH_PROTOCOL),
        "priv_protocol": target.get("snmp_priv_protocol", Config.SNMP_PRIV_PROTOCOL),
    }


async def _snmp_get(host: str, oids: list[str], creds: dict) -> list[float]:
    engine = SnmpEngine()
    auth_data = UsmUserData(
        creds["user"],
        authKey=creds["auth_key"],
        privKey=creds["priv_key"],
        authProtocol=_AUTH_PROTOCOLS.get(creds["auth_protocol"], USM_AUTH_HMAC96_SHA),
        privProtocol=_PRIV_PROTOCOLS.get(creds["priv_protocol"], USM_PRIV_CFB128_AES),
    )
    udp_target = await UdpTransportTarget.create(
        (host, Config.SNMP_PORT), timeout=Config.SNMP_TIMEOUT, retries=Config.SNMP_RETRIES
    )
    error_indication, error_status, _error_index, var_binds = await get_cmd(
        engine,
        auth_data,
        udp_target,
        ContextData(),
        *(ObjectType(ObjectIdentity(oid)) for oid in oids),
    )
    if error_indication:
        message = str(error_indication)
        if "timeout" in message.lower():
            raise SnmpTimeout(message)
        raise SnmpQueryError(message)
    if error_status:
        raise SnmpQueryError(str(error_status))
    return [float(var_bind[1]) for var_bind in var_binds]


def _poll_snmp(target: dict) -> tuple[float | None, float | None, str]:
    """Returns (cpu, mem, snmp_status)."""
    if not Config.SNMP_ENABLED:
        return None, None, "disabled"
    creds = _resolve_snmp_creds(target)
    try:
        cpu, mem_used, mem_total = asyncio.run(
            _snmp_get(target["host"], [OID_CPU, OID_MEM_USED, OID_MEM_TOTAL], creds)
        )
        mem = (mem_used / mem_total * 100) if mem_total else 0.0
        return cpu, mem, "ok"
    except SnmpTimeout:
        return None, None, "timeout"
    except Exception:
        return None, None, "error"


def _classify_status(cpu: float | None, mem: float | None) -> str:
    """Three-tier health classification. green when no SNMP data is
    available (health call still succeeded, just no CPU/mem to gauge)."""
    if cpu is None and mem is None:
        return "green"
    cpu = cpu or 0.0
    mem = mem or 0.0
    if cpu >= Config.CPU_CRIT or mem >= Config.MEM_CRIT:
        return "red"
    if cpu >= Config.CPU_WARN or mem >= Config.MEM_WARN:
        return "yellow"
    return "green"


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _poll_target(target: dict) -> dict:
    label = target["label"]
    host = target["host"]
    adom = target.get("adom", "root")
    entry = {
        "label": label,
        "host": host,
        "adom": adom,
        "status": "offline",
        "hostname": "n/a",
        "version": "n/a",
        "serial": "n/a",
        "ha_mode": "n/a",
        "ha_role": "n/a",
        "disk_used": "n/a",
        "cpu": None,
        "mem": None,
        "snmp_status": "disabled",
        "error": None,
        "last_updated": _now(),
    }
    try:
        with FAZClient(
            host=host,
            token=target.get("token", ""),
            adom=adom,
            verify_ssl=Config.FAZ_VERIFY_SSL,
            timeout=Config.FAZ_REQUEST_TIMEOUT,
        ) as client:
            client.preflight()
            sys_status = client.get_sys_status()
    except FAZError as exc:
        entry["error"] = str(exc)
        return entry
    except Exception as exc:  # network errors, timeouts, DNS failures, etc.
        entry["error"] = summarize_connection_error(exc)
        app_log("WARN", "faz_health_cache", f"Poll failed for {label} ({host}): {exc}")
        return entry

    # Field names confirmed live against 192.168.64.4 (FAZVM64-KVM v7.6.7-build3737):
    # /sys/status returns title-case keys ("Hostname", "Version", "Serial Number",
    # "Disk Usage"), not the lowercase/hyphenated names the Swagger-adjacent specs
    # in api-info/ would suggest (that module isn't covered by those specs at all).
    # HA fields are absent entirely in standalone mode, so ha_mode/ha_role fall
    # back to "n/a" until an HA pair can be observed.
    entry["hostname"] = sys_status.get("Hostname", sys_status.get("hostname", "n/a"))
    entry["version"] = sys_status.get("Version", sys_status.get("version", "n/a"))
    entry["serial"] = sys_status.get("Serial Number", sys_status.get("serial", "n/a"))
    entry["ha_mode"] = sys_status.get(
        "HA Mode", sys_status.get("ha-mode", sys_status.get("ha_mode", "n/a"))
    )
    entry["ha_role"] = sys_status.get(
        "HA Role", sys_status.get("ha-role", sys_status.get("ha_role", "n/a"))
    )
    entry["disk_used"] = sys_status.get(
        "Disk Usage", sys_status.get("disk-usage", sys_status.get("disk_usage", "n/a"))
    )

    cpu, mem, snmp_status = _poll_snmp(target)
    entry["cpu"] = round(cpu, 1) if cpu is not None else None
    entry["mem"] = round(mem, 1) if mem is not None else None
    entry["snmp_status"] = snmp_status
    entry["status"] = _classify_status(cpu, mem)
    entry["last_updated"] = _now()
    return entry


def poll_all_targets() -> None:
    for target in list_targets():
        label = target.get("label")
        if not label:
            continue
        try:
            result = _poll_target(target)
        except Exception as exc:
            # A malformed entry (e.g. hand-edited faz_targets.json missing
            # "host") must not abort the whole poll cycle — that would
            # freeze every OTHER target's cache at its last-known state.
            # Record this target as offline and move on to the next one.
            result = {
                "label": label,
                "host": target.get("host", ""),
                "adom": target.get("adom", "root"),
                "status": "offline",
                "hostname": "n/a",
                "version": "n/a",
                "serial": "n/a",
                "ha_mode": "n/a",
                "ha_role": "n/a",
                "disk_used": "n/a",
                "cpu": None,
                "mem": None,
                "snmp_status": "disabled",
                "error": f"Malformed target entry: {exc}",
                "last_updated": _now(),
            }
        with _lock:
            _cache[label] = result


def get_cached(label: str) -> dict | None:
    with _lock:
        entry = _cache.get(label)
        return dict(entry) if entry is not None else None


def get_all_cached() -> list[dict]:
    """Snapshot for every currently-configured target, in faz_targets.json
    order. A target with no cache entry yet (first poll still pending)
    shows as status 'gray' rather than being omitted."""
    with _lock:
        cache_snapshot = dict(_cache)
    result = []
    for target in list_targets():
        label = target.get("label")
        cached = cache_snapshot.get(label)
        if cached is not None:
            result.append(cached)
        else:
            result.append(
                {
                    "label": label,
                    "host": target.get("host", ""),
                    "adom": target.get("adom", "root"),
                    "status": "gray",
                    "hostname": "n/a",
                    "version": "n/a",
                    "serial": "n/a",
                    "ha_mode": "n/a",
                    "ha_role": "n/a",
                    "disk_used": "n/a",
                    "cpu": None,
                    "mem": None,
                    "snmp_status": "disabled",
                    "error": None,
                    "last_updated": None,
                }
            )
    return result


def poll_now() -> None:
    """Kick off a non-blocking poll of all targets in a daemon thread."""
    t = threading.Thread(target=poll_all_targets, name="faz_health_poll_now", daemon=True)
    t.start()


def init_scheduler(app: Flask) -> None:
    """Register a recurring APScheduler job and run the first poll immediately.

    No-op if Config.FAZ_HEALTH_POLL_DISABLED (set by tests/conftest.py) —
    keeps the test suite from starting real background network/SNMP
    polling threads.
    """
    if Config.FAZ_HEALTH_POLL_DISABLED:
        return

    from apscheduler.schedulers.background import BackgroundScheduler

    poll_now()

    scheduler = BackgroundScheduler()
    scheduler.add_job(
        func=poll_all_targets,
        trigger="interval",
        seconds=Config.SNMP_POLL_INTERVAL,
        id="faz_health_poll",
        replace_existing=True,
        max_instances=1,
    )
    scheduler.start()
