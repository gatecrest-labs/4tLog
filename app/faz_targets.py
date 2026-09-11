"""FortiAnalyzer target list — local store backed by faz_targets.json.

Stored as a JSON array (not a dict keyed by label) to match the shape
documented in the Phase 2 design spec and 4thealth's infra_targets.json
convention. Each entry:

  label   str   unique display name, used as the CRUD key
  host    str   hostname or IP of the FortiAnalyzer appliance
  adom    str   ADOM to query (default "root")
  token   str   bearer token for app.faz_client.FAZClient

Optional per-entry SNMP overrides (each falls back to the matching
Config.SNMP_* default when absent):
  snmp_user, snmp_auth_key, snmp_priv_key, snmp_auth_protocol, snmp_priv_protocol

This module intentionally re-reads the file on every call rather than
caching in memory, so admin edits via the CRUD routes (Task 6) are picked
up by the next background poll cycle (Task 4) without an app restart.
"""

import json
import sys
import threading
from pathlib import Path

from app.app_logger import app_log

FAZ_TARGETS_FILE = Path(__file__).parent.parent / "faz_targets.json"
_lock = threading.Lock()

_SNMP_FIELDS = (
    "snmp_user",
    "snmp_auth_key",
    "snmp_priv_key",
    "snmp_auth_protocol",
    "snmp_priv_protocol",
)


def _load() -> list[dict]:
    if not FAZ_TARGETS_FILE.exists():
        return []
    try:
        with FAZ_TARGETS_FILE.open() as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        message = f"Failed to load {FAZ_TARGETS_FILE}: {exc}"
        try:
            app_log("ERROR", "faz_targets", message)
        except Exception:
            print(f"[faz_targets] ERROR: {message}", file=sys.stderr)
        return []


def _save(targets: list[dict]) -> None:
    with FAZ_TARGETS_FILE.open("w") as f:
        json.dump(targets, f, indent=2)


def list_targets() -> list[dict]:
    with _lock:
        return _load()


def get_target(label: str) -> dict | None:
    with _lock:
        targets = _load()
    for t in targets:
        if t.get("label") == label:
            return t
    return None


def _build_entry(
    label: str, host: str, adom: str, token: str, snmp_overrides: dict | None, threat_poll_enabled: bool
) -> dict:
    entry = {
        "label": label,
        "host": host,
        "adom": adom,
        "token": token,
        "threat_poll_enabled": threat_poll_enabled,
    }
    for key, value in (snmp_overrides or {}).items():
        if key in _SNMP_FIELDS and value:
            entry[key] = value
    return entry


def create_target(
    label: str,
    host: str,
    adom: str = "root",
    token: str = "",
    snmp_overrides: dict | None = None,
    threat_poll_enabled: bool = True,
) -> bool:
    """Returns False if a target with this label already exists."""
    label = label.strip()
    if not label:
        raise ValueError("Target label cannot be empty.")
    with _lock:
        targets = _load()
        if any(t.get("label") == label for t in targets):
            return False
        targets.append(_build_entry(label, host, adom, token, snmp_overrides, threat_poll_enabled))
        _save(targets)
    return True


def update_target(
    label: str,
    host: str,
    adom: str,
    token: str,
    snmp_overrides: dict | None = None,
    threat_poll_enabled: bool = True,
) -> bool:
    """Returns False if no target with this label exists.

    Fields the caller doesn't explicitly provide are preserved from the
    existing stored entry rather than being wiped: a blank/omitted `token`
    keeps the previously stored token, and any SNMP field in _SNMP_FIELDS
    not present in `snmp_overrides` keeps its previously stored value. This
    matters because the Admin UI's edit modal has no SNMP fields and (as of
    the token-masking fix) leaves the token input blank unless the admin is
    deliberately changing it — without this, every UI-driven edit would
    silently drop SNMP credential overrides and/or the bearer token.
    """
    with _lock:
        targets = _load()
        for i, t in enumerate(targets):
            if t.get("label") == label:
                effective_token = token if token else t.get("token", "")
                merged_overrides = {key: t[key] for key in _SNMP_FIELDS if key in t}
                merged_overrides.update(snmp_overrides or {})
                targets[i] = _build_entry(
                    label, host, adom, effective_token, merged_overrides, threat_poll_enabled
                )
                _save(targets)
                return True
    return False


def delete_target(label: str) -> bool:
    with _lock:
        targets = _load()
        remaining = [t for t in targets if t.get("label") != label]
        if len(remaining) == len(targets):
            return False
        _save(remaining)
    return True
