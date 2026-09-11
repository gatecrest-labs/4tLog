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
