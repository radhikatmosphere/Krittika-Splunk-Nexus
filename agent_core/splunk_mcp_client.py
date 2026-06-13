# agent_core/splunk_mcp_client.py — Splunk MCP Client
# RADHIKATMOSPHERE / Krittika-Splunk Nexus
#
# Connects to the official Splunk MCP Server (installed from Splunkbase)
# via HTTP streamable protocol. Uses encrypted tokens for authentication.
# Provides typed wrappers around splunk_run_query and other MCP tools.

import json
import logging
import os
from typing import Any, Optional

import httpx

logger = logging.getLogger("krittika.mcp_client")


class SplunkMCPClient:
    """
    Client for the official Splunk MCP Server.

    Connects via HTTP to the MCP endpoint exposed by the Splunk MCP Server app.
    Uses encrypted token authentication as documented in Splunk's MCP Server setup.

    Available tools:
    - splunk_run_query: Execute SPL searches
    - splunk_get_info: System information
    - splunk_get_indexes: List available indexes
    - splunk_get_metadata: Discover hosts/sources/sourcetypes
    - splunk_run_saved_search: Execute pre-saved searches (beta)
    """

    def __init__(
        self,
        mcp_endpoint: Optional[str] = None,
        mcp_token: Optional[str] = None,
        timeout: float = 60.0,
    ):
        self.mcp_endpoint = mcp_endpoint or os.environ.get(
            "MCP_ENDPOINT", "https://localhost:8089/services/mcp"
        )
        self.mcp_token = mcp_token or os.environ.get("MCP_TOKEN", "")
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        self._client = httpx.AsyncClient(
            base_url=self.mcp_endpoint,
            timeout=self.timeout,
            verify=False,
            headers={
                "Authorization": f"Bearer {self.mcp_token}",
                "Content-Type": "application/json",
            },
        )
        return self

    async def __aexit__(self, *args):
        if self._client:
            await self._client.aclose()

    async def _call_mcp_tool(self, tool_name: str, arguments: dict) -> dict:
        """
        Call an MCP tool via the streamable HTTP protocol.
        Uses JSON-RPC 2.0 format as specified by the MCP standard.
        """
        if not self._client:
            raise RuntimeError("Client not initialized. Use async context manager.")

        request_id = id(tool_name)
        payload = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments,
            },
            "id": request_id,
        }

        try:
            response = await self._client.post("/", json=payload)
            response.raise_for_status()
            result = response.json()

            if "error" in result:
                logger.error(f"MCP tool {tool_name} error: {result['error']}")
                return {"success": False, "error": result["error"]}

            return {"success": True, "result": result.get("result", {})}

        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error calling {tool_name}: {e.response.status_code}")
            return {"success": False, "error": str(e)}
        except Exception as e:
            logger.error(f"Failed to call {tool_name}: {e}")
            return {"success": False, "error": str(e)}

    async def run_query(self, spl_query: str, earliest: str = "-5m", latest: str = "now") -> dict:
        """
        Execute a Splunk search query via splunk_run_query tool.
        Returns structured results for agent reasoning.
        """
        return await self._call_mcp_tool("splunk_run_query", {
            "query": spl_query,
            "earliest": earliest,
            "latest": latest,
        })

    async def get_info(self) -> dict:
        """Get comprehensive Splunk instance information."""
        return await self._call_mcp_tool("splunk_get_info", {})

    async def get_indexes(self) -> dict:
        """List all available Splunk indexes."""
        return await self._call_mcp_tool("splunk_get_indexes", {})

    async def get_index_info(self, index_name: str) -> dict:
        """Get detailed information about a specific index."""
        return await self._call_mcp_tool("splunk_get_index_info", {"index": index_name})

    async def get_metadata(self, metadata_type: str = "hosts", index: str = "*") -> dict:
        """
        Retrieve metadata about hosts, sources, or sourcetypes.
        metadata_type: 'hosts', 'sources', or 'sourcetypes'
        """
        return await self._call_mcp_tool("splunk_get_metadata", {
            "metadata_type": metadata_type,
            "index": index,
        })

    async def run_saved_search(self, search_name: str) -> dict:
        """Execute a pre-saved Splunk search (beta feature)."""
        return await self._call_mcp_tool("splunk_run_saved_search", {
            "search_name": search_name,
        })

    async def generate_spl(self, natural_language_query: str) -> dict:
        """Generate SPL from natural language (requires Splunk AI Assistant)."""
        return await self._call_mcp_tool("saia_generate_spl", {
            "query": natural_language_query,
        })

    async def explain_spl(self, spl_query: str) -> dict:
        """Explain an SPL query in natural language."""
        return await self._call_mcp_tool("saia_explain_spl", {"spl": spl_query})

    async def optimize_spl(self, spl_query: str) -> dict:
        """Optimize an SPL search for performance."""
        return await self._call_mcp_tool("saia_optimize_spl", {"spl": spl_query})
