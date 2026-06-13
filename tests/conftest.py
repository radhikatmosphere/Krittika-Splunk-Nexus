# tests/conftest.py — Shared pytest fixtures for Krittika-Splunk Nexus
# RADHIKATMOSPHERE

import os
import sys
from pathlib import Path

# Ensure repo root is on sys.path when pytest is invoked from elsewhere
sys.path.insert(0, str(Path(__file__).parent.parent))

# Disable jitter for deterministic backoff tests
os.environ.setdefault("KRITTIKA_DISABLE_JITTER", "1")
