# tests/test_splunk_mcp_client.py — Tests for the SplunkMCPClient retry integration
# RADHIKATMOSPHERE / Krittika-Splunk Nexus
#
# Verifies:
# - TransientError is raised on 5xx / 408 / 429
# - PermanentError is raised on 401 / 403 / 400 / 404 / 422
# - call_with_retry retries transient and exhausts budget
# - run_query(retry=False) skips retry layer (back-compat)

import os

os.environ["KRITTIKA_DISABLE_JITTER"] = "1"

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from agent_core.retry import (
    PermanentError,
    RetryPolicy,
    TransientError,
)
from agent_core.splunk_mcp_client import SplunkMCPClient


@pytest.fixture
def client():
    """Client with mock HTTP layer (skips real network)."""
    c = SplunkMCPClient(retry_policy=RetryPolicy(max_retries=2, initial_backoff_s=0.0, max_backoff_s=0.0))
    c._client = MagicMock()
    return c


# ---------------------------------------------------------------------------
# _call_mcp_tool error classification
# ---------------------------------------------------------------------------


class TestCallMcpToolErrorMapping:
    @pytest.mark.parametrize("code", [429, 500, 502, 503, 504, 408])
    def test_transient_5xx_and_friends_raise_transient(self, client, code):
        mock_response = MagicMock()
        mock_response.status_code = code
        mock_response.text = "boom"
        client._client.post = AsyncMock(return_value=mock_response)

        async def _run():
            with pytest.raises(TransientError):
                await client._call_mcp_tool("splunk_run_query", {"query": "*"})
        asyncio.run(_run())

    @pytest.mark.parametrize("code", [400, 401, 403, 404, 405, 422])
    def test_permanent_codes_raise_permanent(self, client, code):
        mock_response = MagicMock()
        mock_response.status_code = code
        mock_response.text = "no"
        client._client.post = AsyncMock(return_value=mock_response)

        async def _run():
            with pytest.raises(PermanentError):
                await client._call_mcp_tool("splunk_run_query", {"query": "*"})
        asyncio.run(_run())

    def test_connect_error_is_transient(self, client):
        client._client.post = AsyncMock(side_effect=httpx.ConnectError("refused"))

        async def _run():
            with pytest.raises(TransientError):
                await client._call_mcp_tool("splunk_run_query", {"query": "*"})
        asyncio.run(_run())

    def test_timeout_is_transient(self, client):
        client._client.post = AsyncMock(side_effect=httpx.TimeoutException("slow"))

        async def _run():
            with pytest.raises(TransientError):
                await client._call_mcp_tool("splunk_run_query", {"query": "*"})
        asyncio.run(_run())

    def test_successful_response_passes_through(self, client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"jsonrpc": "2.0", "result": {"rows": [1]}}
        client._client.post = AsyncMock(return_value=mock_response)

        async def _run():
            return await client._call_mcp_tool("splunk_run_query", {"query": "*"})
        result = asyncio.run(_run())
        assert result == {"success": True, "result": {"rows": [1]}}

    def test_jsonrpc_error_field_returned_as_failure_dict(self, client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "jsonrpc": "2.0",
            "error": {"code": -32600, "message": "bad payload"},
        }
        client._client.post = AsyncMock(return_value=mock_response)

        async def _run():
            return await client._call_mcp_tool("splunk_run_query", {"query": "*"})
        result = asyncio.run(_run())
        assert result["success"] is False
        assert "error" in result


# ---------------------------------------------------------------------------
# call_with_retry budget
# ---------------------------------------------------------------------------


class TestCallWithRetry:
    def test_succeeds_after_transient_burst(self, client):
        mock_response_500 = MagicMock(status_code=503, text="down")
        mock_response_500.raise_for_status = MagicMock()
        mock_response_ok = MagicMock(status_code=200, json=lambda: {"result": {"rows": []}})
        mock_response_ok.raise_for_status = MagicMock()

        # Two 503s then a 200
        client._client.post = AsyncMock(side_effect=[
            mock_response_500,
            mock_response_500,
            mock_response_ok,
        ])

        async def _run():
            return await client.call_with_retry("splunk_run_query", {"query": "*"})
        result = asyncio.run(_run())
        assert result == {"success": True, "result": {"rows": []}}
        assert client.retry_policy.successes_after_retry == 1

    def test_exhausts_budget_on_persistent_5xx(self, client):
        mock_response_500 = MagicMock(status_code=500, text="forever")
        client._client.post = AsyncMock(return_value=mock_response_500)

        async def _run():
            with pytest.raises(TransientError):
                await client.call_with_retry("splunk_run_query", {"query": "*"})
        asyncio.run(_run())

    def test_permanent_error_does_not_retry(self, client):
        mock_response_401 = MagicMock(status_code=401, text="no token")
        client._client.post = AsyncMock(return_value=mock_response_401)

        async def _run():
            with pytest.raises(PermanentError):
                await client.call_with_retry("splunk_run_query", {"query": "*"})
        asyncio.run(_run())
        # 1 attempt only — no retries on PermanentError
        assert client._client.post.await_count == 1


# ---------------------------------------------------------------------------
# run_query retry toggle
# ---------------------------------------------------------------------------


class TestRunQueryToggle:
    def test_retry_true_uses_retry_layer(self, client):
        mock_response_ok = MagicMock(status_code=200, json=lambda: {"result": {"rows": []}})
        mock_response_ok.raise_for_status = MagicMock()
        client._client.post = AsyncMock(return_value=mock_response_ok)

        async def _run():
            return await client.run_query("*", retry=True)
        result = asyncio.run(_run())
        assert result["success"] is True

    def test_retry_false_skips_retry_layer(self, client):
        mock_response_503 = MagicMock(status_code=503, text="down")
        client._client.post = AsyncMock(return_value=mock_response_503)

        async def _run():
            with pytest.raises(TransientError):
                await client.run_query("*", retry=False)
        asyncio.run(_run())
        # 1 attempt only — retry layer disabled
        assert client._client.post.await_count == 1

    def test_permanent_failure_returns_friendly_dict(self, client):
        mock_response_401 = MagicMock(status_code=401, text="nope")
        client._client.post = AsyncMock(return_value=mock_response_401)

        async def _run():
            return await client.run_query("*", retry=True)
        result = asyncio.run(_run())
        # run_query(retry=True) catches PermanentError and returns failure dict
        assert result["success"] is False
        assert "permanent MCP failure" in result["error"]
