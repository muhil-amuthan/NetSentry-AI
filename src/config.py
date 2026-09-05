"""
Central configuration for NetSentry-AI.

All tunable values live here so the rest of the codebase can import them
from a single place instead of hard-coding values across modules.
"""

import os
from pathlib import Path

# Project root directory (one level above src/).
BASE_DIR = Path(__file__).resolve().parent.parent

APP_NAME = "NetSentry-AI"
APP_DESCRIPTION = "Telecom Network Incident Triage Assistant"
VERSION = "0.1.0"

# Server settings. 0.0.0.0 binds to all interfaces, so the app is reachable
# both at http://localhost:8000 and from the local network.
HOST = os.getenv("NETSENTRY_HOST", "0.0.0.0")
PORT = int(os.getenv("NETSENTRY_PORT", "8000"))

# Filesystem locations.
FRONTEND_DIR = BASE_DIR / "frontend"
DATA_DIR = BASE_DIR / "data"
RUNBOOKS_DIR = DATA_DIR / "runbooks"

TOPOLOGY_FILE = DATA_DIR / "topology.json"
SAMPLE_ALERTS_FILE = DATA_DIR / "sample_alerts.json"
