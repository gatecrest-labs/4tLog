"""Bearer token management for the external API. Tokens are SHA-256-hashed
in api_tokens.json (gitignored); the plaintext is returned exactly once,
at creation, and never stored. Follows the plain json.dump pattern already
established in app/faz_targets.py (this repo has no atomic-write helper)."""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
import uuid
from pathlib import Path

_TOKENS_PATH = Path(__file__).parent.parent / "api_tokens.json"
_lock = threading.Lock()

TOKEN_PREFIX = "4tl_"


def _load() -> list[dict]:
    if not _TOKENS_PATH.exists():
        return []
    try:
        with _TOKENS_PATH.open() as f:
            return json.load(f).get("tokens", [])
    except (json.JSONDecodeError, OSError):
        return []


def _save(tokens: list[dict]) -> None:
    with _TOKENS_PATH.open("w") as f:
        json.dump({"tokens": tokens}, f, indent=2)


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def create_token(name: str) -> tuple[str, dict]:
    """Create a new token. Returns (plaintext, record) — plaintext is shown once."""
    raw = TOKEN_PREFIX + secrets.token_hex(32)
    record = {
        "id": str(uuid.uuid4()),
        "name": name.strip(),
        "token_hash": _hash(raw),
        "enabled": True,
    }
    with _lock:
        tokens = _load()
        tokens.append(record)
        _save(tokens)
    safe = {k: v for k, v in record.items() if k != "token_hash"}
    return raw, safe


def list_tokens() -> list[dict]:
    with _lock:
        tokens = _load()
    return [{k: v for k, v in t.items() if k != "token_hash"} for t in tokens]


def revoke_token(token_id: str) -> bool:
    with _lock:
        tokens = _load()
        remaining = [t for t in tokens if t.get("id") != token_id]
        if len(remaining) == len(tokens):
            return False
        _save(remaining)
    return True


def validate_token(raw: str) -> dict | None:
    if not raw:
        return None
    h = _hash(raw)
    with _lock:
        tokens = _load()
    for t in tokens:
        if t.get("token_hash") == h and t.get("enabled", True):
            return {k: v for k, v in t.items() if k != "token_hash"}
    return None
