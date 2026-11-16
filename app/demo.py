"""Demo mode (``DEMO_MODE=true``): run 4tlog with no FortiAnalyzer at all.

What it changes, and nothing else:

* **Data** -- users, groups, FAZ targets, settings and API tokens are read from
  the seed files in ``app/demo_data/`` instead of the operator's own
  ``users.json``/``faz_targets.json``/..., so a demo never reads or writes real
  configuration (:func:`activate`).
* **FortiAnalyzer** -- every :class:`~app.faz_client.FAZClient` talks to the
  synthetic appliance in :mod:`app.demo_faz`. A client for any host that is not
  a ``*.demo.invalid`` demo host is refused before it can send a request, so a
  real target can never be contacted in demo mode.
* **SNMP** -- health cards get synthetic CPU/memory readings; no SNMP is sent.
* **Writes** -- every change through the Admin API (and 4tSuite group pushes)
  answers 403; read-only actions such as the API self-test still work
  (:func:`blocked_write`).
* **UI** -- a banner on every page, and the demo sign-ins on the login page.
"""

from __future__ import annotations

import json
from pathlib import Path

DEMO_DATA_DIR = Path(__file__).parent / "demo_data"

# Public on purpose: shown on the login page in demo mode, valid only against
# the seed users in app/demo_data/users.json.
DEMO_USERS = (("demo-admin", "admin"), ("demo-analyst", "viewer"))
DEMO_PASSWORD = "gatecrest-demo"

WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
# Mutating-method endpoints that change nothing and stay available in demo mode.
READ_ONLY_POST_ENDPOINTS = frozenset({"admin.api_faz_selftest"})
BLOCKED_MESSAGE = "Demo mode: changes are disabled. This instance runs on synthetic data."


def _seed(name: str) -> Path:
    return DEMO_DATA_DIR / name


def activate(set_attr=setattr) -> None:
    """Point every JSON-backed store at the demo seed files.

    ``set_attr`` exists for tests (pass ``monkeypatch.setattr``). Refuses to
    activate if a seeded target is not a demo host.
    """
    from app import api_tokens, app_settings, auth, faz_targets, groups
    from app.demo_faz import is_demo_host

    targets = json.loads(_seed("faz_targets.json").read_text())
    real = [t.get("host") for t in targets if not is_demo_host(t.get("host", ""))]
    if real:
        raise RuntimeError(f"Demo seed lists non-demo FortiAnalyzer hosts: {real}")

    set_attr(auth, "USERS_FILE", _seed("users.json"))
    set_attr(groups, "GROUPS_FILE", _seed("groups.json"))
    set_attr(faz_targets, "FAZ_TARGETS_FILE", _seed("faz_targets.json"))
    set_attr(app_settings, "_SETTINGS_PATH", _seed("app_settings.json"))
    set_attr(api_tokens, "_TOKENS_PATH", _seed("api_tokens.json"))


def blocked_write(method: str, path: str, endpoint: str | None) -> bool:
    """True if this request would change state and demo mode must refuse it."""
    if method.upper() not in WRITE_METHODS or endpoint in READ_ONLY_POST_ENDPOINTS:
        return False
    return path.startswith("/admin/api/") or path.startswith("/4tsuite/")
