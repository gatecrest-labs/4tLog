"""Picking an ADOM on a FortiAnalyzer target.

A target's configured ADOM is the default; Log Search and the Connection
Timeline let the user pick another ADOM the target's API token can read.
Group limits stay per target, so a group that can use a target can pick any of
its ADOMs. The name goes into a FortiAnalyzer URL path, so it is checked first.
"""

from __future__ import annotations

import re

_ADOM_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class AdomError(ValueError):
    """An ADOM name that can't be one, with a message fit to show the user."""


def parse_adom(raw, target: dict) -> str:
    """The ADOM to use: ``raw`` if given and valid, else the target's own."""
    value = str(raw).strip() if raw is not None else ""
    if not value:
        return target.get("adom", "root")
    if not _ADOM_NAME.match(value):
        raise AdomError("Invalid ADOM name.")
    return value


def with_adom(target: dict, adom: str) -> dict:
    """The target, querying ``adom`` instead of its configured one."""
    return {**target, "adom": adom}
