import os
import sys
from pathlib import Path

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")
os.environ.setdefault("FAZ_HEALTH_POLL_DISABLED", "true")
os.environ.setdefault("LOG_STATS_POLL_DISABLED", "true")
os.environ.setdefault("THREAT_STATS_POLL_DISABLED", "true")
os.environ.setdefault("HOST_METRICS_POLL_DISABLED", "true")
os.environ.setdefault("APP_LOAD_DOTENV", "false")
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _isolated_collector_store(tmp_path, monkeypatch):
    """Every test gets its own empty app.collector_store SQLite file, so a
    cache module's SQLite read-through fallback (see
    app/log_stats_cache.py::get_cached(), etc.) never reads a snapshot
    left behind by a different, unrelated test."""
    import app.collector_store as store_mod

    monkeypatch.setattr(store_mod, "DB_PATH", tmp_path / "collector_state.db")
    yield
