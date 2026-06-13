# agent_core/api_server.py — Sovereign Fleet API
# RADHIKATMOSPHERE / Krittika-Splunk Nexus
#
# Lightweight HTTP API that exposes fleet status for the web frontend.
# Runs as a daemon thread inside the orchestrator process.
# Routes: api.radhikachain.xyz (via Cloudflare Tunnel)

import json
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
from typing import Any

logger = logging.getLogger("krittika.api")

# Thread-safe shared state — updated by the orchestrator each episode
_fleet_state: dict[str, Any] = {
    "status": "initializing",
    "episode": 0,
    "latency_ms": 0,
    "threat_count": 0,
    "karma_score": 0,
    "validator_id": "unknown",
    "healthy": True,
    "last_action": "none",
    "audit_last_hash": "0" * 64,
    "remediation_summary": {},
}


def update_state(**kwargs):
    _fleet_state.update(kwargs)


class FleetAPIHandler(BaseHTTPRequestHandler):
    """Serves fleet status as JSON for the web frontend."""

    def _json(self, data: dict, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode())

    def do_GET(self):
        if self.path == "/health":
            self._json({"status": "ok", "service": "krittika-agent"})
        elif self.path == "/api/fleet/status":
            self._json(_fleet_state)
        elif self.path == "/api/fleet/health":
            self._json({
                "healthy": _fleet_state.get("healthy", True),
                "episode": _fleet_state.get("episode", 0),
                "latency_ms": _fleet_state.get("latency_ms", 0),
                "threat_count": _fleet_state.get("threat_count", 0),
                "karma_score": _fleet_state.get("karma_score", 0),
                "validator_id": _fleet_state.get("validator_id", "unknown"),
            })
        elif self.path == "/api/fleet/audit":
            self._json({
                "last_hash": _fleet_state.get("audit_last_hash", "0" * 64),
                "corrections": _fleet_state.get("correction_count", 0),
                "remediation_summary": _fleet_state.get("remediation_summary", {}),
            })
        else:
            self._json({"error": "not_found", "path": self.path}, 404)

    def log_message(self, fmt, *args):
        logger.debug(fmt % args)


class FleetAPIServer:
    """Daemon thread wrapper for the HTTP server."""

    def __init__(self, host: str = "0.0.0.0", port: int = 8080):
        self.host = host
        self.port = port
        self._server = HTTPServer((host, port), FleetAPIHandler)
        self._thread = Thread(target=self._server.serve_forever, daemon=True)

    def start(self):
        self._thread.start()
        logger.info(f"Fleet API server listening on {self.host}:{self.port}")

    def stop(self):
        self._server.shutdown()
