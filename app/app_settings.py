"""Application settings — persistent key/value store backed by app_settings.json."""

from __future__ import annotations

import json
import threading
from pathlib import Path

_SETTINGS_PATH = Path(__file__).parent.parent / "app_settings.json"
_DEFAULTS: dict = {"external_api_enabled": False}
_lock = threading.Lock()


def _load() -> dict:
    if not _SETTINGS_PATH.exists():
        return dict(_DEFAULTS)
    try:
        with _SETTINGS_PATH.open() as f:
            data = json.load(f)
        return {**_DEFAULTS, **data}
    except (json.JSONDecodeError, OSError):
        return dict(_DEFAULTS)


def _save(data: dict) -> None:
    with _SETTINGS_PATH.open("w") as f:
        json.dump(data, f, indent=2)


def get_setting(key: str, default=None):
    with _lock:
        data = _load()
    return data.get(key, default)


def set_setting(key: str, value) -> None:
    with _lock:
        data = _load()
        data[key] = value
        _save(data)
