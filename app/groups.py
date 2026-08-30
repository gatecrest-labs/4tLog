"""Group management — local store backed by groups.json.

A group has:
  name           str   unique identifier
  members        list  of local username strings (users.json accounts)
  ad_groups      list  of AD/RADIUS group name strings (reserved for a future
                       RADIUS/AD integration; unused while RADIUS_ENABLED stays
                       false, but kept in the schema so groups.json does not
                       need a breaking migration later)
  allowed_tabs   list  of tab keys (see KNOWN_TABS)
  adom_restrict  bool  when True, only ADOMs/targets in allowed_adoms are
                       accessible (reserved for Phase 2's FAZ-target access
                       control; unused by any route in Phase 1)
  allowed_adoms  list  of ADOM/target name strings (only used when
                       adom_restrict=True)

Tab keys are the canonical identifiers the nav uses. When a new route/tab is
added to the app, register it via app.registry.register() — it will appear
automatically in KNOWN_TABS once app/__init__.py syncs the registry.
"""

import json
import threading
from pathlib import Path

GROUPS_FILE = Path(__file__).parent.parent / "groups.json"
_lock = threading.Lock()

# Populated at startup by app/__init__.py from app.registry.
KNOWN_TABS: dict[str, str] = {}


def _load() -> dict:
    if not GROUPS_FILE.exists():
        return {}
    with GROUPS_FILE.open() as f:
        return json.load(f)


def _save(data: dict) -> None:
    with GROUPS_FILE.open("w") as f:
        json.dump(data, f, indent=2)


def _group_to_dict(name: str, g: dict) -> dict:
    return {
        "name": name,
        "members": g.get("members", []),
        "ad_groups": g.get("ad_groups", []),
        "allowed_tabs": g.get("allowed_tabs", []),
        "adom_restrict": bool(g.get("adom_restrict", False)),
        "allowed_adoms": g.get("allowed_adoms", []),
    }


def list_groups() -> list[dict]:
    with _lock:
        groups = _load()
    return [_group_to_dict(name, g) for name, g in groups.items()]


def get_group(name: str) -> dict | None:
    with _lock:
        groups = _load()
    g = groups.get(name)
    if g is None:
        return None
    return _group_to_dict(name, g)


def create_group(
    name: str,
    members: list[str] | None = None,
    ad_groups: list[str] | None = None,
    allowed_tabs: list[str] | None = None,
    adom_restrict: bool = False,
    allowed_adoms: list[str] | None = None,
) -> bool:
    """Returns False if the group name already exists."""
    name = name.strip()
    if not name:
        raise ValueError("Group name cannot be empty.")
    with _lock:
        groups = _load()
        if name in groups:
            return False
        groups[name] = {
            "members": list(members or []),
            "ad_groups": list(ad_groups or []),
            "allowed_tabs": list(allowed_tabs or []),
            "adom_restrict": bool(adom_restrict),
            "allowed_adoms": list(allowed_adoms or []),
        }
        _save(groups)
    return True


def update_group(
    name: str,
    members: list[str],
    allowed_tabs: list[str],
    adom_restrict: bool = False,
    allowed_adoms: list[str] | None = None,
    ad_groups: list[str] | None = None,
) -> bool:
    """Returns False if the group does not exist."""
    with _lock:
        groups = _load()
        if name not in groups:
            return False
        groups[name]["members"] = list(members)
        groups[name]["ad_groups"] = list(ad_groups or [])
        if KNOWN_TABS:
            groups[name]["allowed_tabs"] = [t for t in allowed_tabs if t in KNOWN_TABS]
        else:
            groups[name]["allowed_tabs"] = list(allowed_tabs)
        groups[name]["adom_restrict"] = bool(adom_restrict)
        groups[name]["allowed_adoms"] = list(allowed_adoms or [])
        _save(groups)
    return True


def delete_group(name: str) -> bool:
    with _lock:
        groups = _load()
        if name not in groups:
            return False
        del groups[name]
        _save(groups)
    return True


def get_allowed_tabs(
    username: str, ad_groups: list[str] | None = None, role: str | None = None
) -> set[str]:
    """Return the set of tab keys the user may access.

    - Admins always get all currently-registered tabs.
    - Non-admins get the union of allowed_tabs across all groups they belong to
      (membership by username in group['members'] OR ad_groups overlap).
    - Users in no group get no tabs.
    """
    from app.auth import _load_users

    if role == "admin":
        return set(KNOWN_TABS.keys())

    users = _load_users()
    user_entry = users.get(username, {})
    if user_entry.get("role") == "admin":
        return set(KNOWN_TABS.keys())

    with _lock:
        groups = _load()

    ad_set = set(ad_groups or [])
    tabs: set[str] = set()
    for g in groups.values():
        if username in g.get("members", []) or ad_set & set(g.get("ad_groups", [])):
            tabs.update(g.get("allowed_tabs", []))
    return tabs


def user_can_access_tab(username: str, tab_key: str) -> bool:
    return tab_key in get_allowed_tabs(username)


def get_allowed_adoms(
    username: str, ad_groups: list[str] | None = None, role: str | None = None
) -> list[str] | None:
    """Return the list of ADOM/target names the user may access, or None for
    unrestricted. Not consumed by any route until Phase 2, but implemented
    now so groups.json's schema is stable across phases.
    """
    from app.auth import _load_users

    if role == "admin":
        return None

    users = _load_users()
    user_entry = users.get(username, {})
    if user_entry.get("role") == "admin":
        return None

    with _lock:
        groups = _load()

    ad_set = set(ad_groups or [])
    user_groups = [
        g
        for g in groups.values()
        if username in g.get("members", []) or ad_set & set(g.get("ad_groups", []))
    ]

    if not user_groups:
        return []

    if any(not g.get("adom_restrict", False) for g in user_groups):
        return None

    allowed: set[str] = set()
    for g in user_groups:
        allowed.update(g.get("allowed_adoms", []))
    return sorted(allowed)


def user_can_access_adom(username: str, adom: str, ad_groups: list[str] | None = None) -> bool:
    allowed = get_allowed_adoms(username, ad_groups=ad_groups)
    if allowed is None:
        return True
    return adom in allowed
