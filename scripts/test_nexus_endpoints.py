#!/usr/bin/env python3
"""
Krittika-Splunk Nexus Connectivity Test Script

Tests connectivity to Splunk Web (via Cloudflare tunnel), HEC endpoint, and MCP server.
Reads configuration from .env file with fallback defaults for local development.
"""

import os
import sys
import json
import requests
from typing import Dict, Any

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv is optional


def get_env(key: str, default: str) -> str:
    """Get environment variable with fallback."""
    return os.getenv(key, default)


def test_splunk_web(url: str) -> Dict[str, Any]:
    """Test Splunk Web accessibility via Cloudflare tunnel."""
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        if response.status_code in (200, 302, 401, 403):
            return {
                "status": "OK",
                "message": f"Splunk Web accessible via Cloudflare (Status: {response.status_code})",
                "code": response.status_code
            }
        return {
            "status": "WARN",
            "message": f"Splunk Web returned unexpected status: {response.status_code}",
            "code": response.status_code
        }
    except requests.exceptions.SSLError as e:
        return {
            "status": "WARN",
            "message": f"SSL error (expected if using self-signed cert): {e}",
            "code": None
        }
    except requests.exceptions.RequestException as e:
        return {
            "status": "FAIL",
            "message": f"Connection error to Splunk Web: {e}",
            "code": None
        }


def test_hec_endpoint(url: str, token: str) -> Dict[str, Any]:
    """Test HTTP Event Collector (HEC) endpoint authentication and indexing."""
    headers = {"Authorization": f"Splunk {token}"}
    test_event = {
        "sourcetype": "connectivity_test",
        "event": {
            "message": "Krittika verification probe active",
            "status": "HEALTHY",
            "test_id": "nexus-connectivity-check"
        }
    }

    try:
        response = requests.post(
            url,
            json=test_event,
            headers=headers,
            verify=False,
            timeout=10
        )
        try:
            response_data = response.json()
        except json.JSONDecodeError:
            response_data = {"raw": response.text}

        if response.status_code == 200 and response_data.get("text") == "Success":
            return {
                "status": "OK",
                "message": "HTTP Event Collector (HEC) authenticated and indexing correctly",
                "code": response.status_code,
                "response": response_data
            }
        return {
            "status": "FAIL",
            "message": f"HEC rejected token or index. Response: {response_data}",
            "code": response.status_code,
            "response": response_data
        }
    except requests.exceptions.RequestException as e:
        return {
            "status": "FAIL",
            "message": f"Cannot connect to HEC endpoint: {e}",
            "code": None
        }


def test_mcp_endpoint(url: str, token: str) -> Dict[str, Any]:
    """Test MCP server connectivity."""
    headers = {"Authorization": f"Bearer {token}"} if token else {}

    try:
        response = requests.get(
            f"{url}/health",
            headers=headers,
            verify=False,
            timeout=10
        )
        if response.status_code == 200:
            return {
                "status": "OK",
                "message": "MCP Server reachable",
                "code": response.status_code
            }
        return {
            "status": "WARN",
            "message": f"MCP Server returned status: {response.status_code}",
            "code": response.status_code
        }
    except requests.exceptions.RequestException as e:
        return {
            "status": "WARN",
            "message": f"MCP Server not reachable (may be expected): {e}",
            "code": None
        }


def main():
    print("=" * 60)
    print("  Krittika-Splunk Nexus — Connectivity Audit")
    print("=" * 60)
    print()

    # Configuration from environment
    SPLUNK_WEB_URL = get_env("SPLUNK_WEB_URL", "https://splunk.radhikachain.xyz")
    SPLUNK_HEC_URL = get_env("SPLUNK_HEC_URL", "https://hec.radhikachain.xyz/services/collector")
    HEC_TOKEN = get_env("SPLUNK_HEC_TOKEN", "TU_TOKEN_HEC_AQUÍ")
    MCP_ENDPOINT = get_env("MCP_ENDPOINT", "https://mcp.radhikachain.xyz")
    MCP_TOKEN = get_env("MCP_TOKEN", "")

    print(f"Target Splunk Web: {SPLUNK_WEB_URL}")
    print(f"Target HEC:        {SPLUNK_HEC_URL}")
    print(f"Target MCP:        {MCP_ENDPOINT}")
    print()

    all_ok = True

    # Test 1: Splunk Web via Cloudflare
    print("📡 [1/3] Testing Splunk Web accessibility via Cloudflare tunnel...")
    result = test_splunk_web(SPLUNK_WEB_URL)
    status_icon = {"OK": "✅", "WARN": "⚠️", "FAIL": "❌"}[result["status"]]
    print(f"   {status_icon} {result['message']}")
    if result["status"] == "FAIL":
        all_ok = False
    print()

    # Test 2: HEC Endpoint
    print("📡 [2/3] Testing HTTP Event Collector (HEC) ingestion channel...")
    if not HEC_TOKEN or HEC_TOKEN == "DEFAULT_TOKEN":
        print("   ⚠️  SPLUNK_HEC_TOKEN not set — skipping HEC authentication test")
        print("   Set SPLUNK_HEC_TOKEN in .env to enable this test")
    else:
        result = test_hec_endpoint(SPLUNK_HEC_URL, HEC_TOKEN)
        status_icon = {"OK": "✅", "WARN": "⚠️", "FAIL": "❌"}[result["status"]]
        print(f"   {status_icon} {result['message']}")
        if result["status"] == "FAIL":
            all_ok = False
    print()

    # Test 3: MCP Endpoint
    print("📡 [3/3] Testing MCP Server connectivity...")
    result = test_mcp_endpoint(MCP_ENDPOINT, MCP_TOKEN)
    status_icon = {"OK": "✅", "WARN": "⚠️", "FAIL": "❌"}[result["status"]]
    print(f"   {status_icon} {result['message']}")
    print()

    print("=" * 60)
    if all_ok:
        print("  ✅ ALL CRITICAL CHECKS PASSED")
    else:
        print("  ❌ SOME CRITICAL CHECKS FAILED")
    print("=" * 60)

    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()