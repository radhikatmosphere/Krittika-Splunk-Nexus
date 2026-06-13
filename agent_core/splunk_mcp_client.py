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

from .retry import (
    PermanentError,
    RetryPolicy,
    TransientError,
    aretry,
    classify_mcp_error,
)

logger = logging.getLogger("krittika.mcp_client")


# Production SPL query catalog for the RadhikaChain Sovereign Fleet
# Each query targets the consolidated sovereign_fleet index
QUERIES = {
    "HEALTH_KARMA": (
        'index=sovereign_fleet sourcetype=karma_consensus_logs '
        '| stats avg(karma_score) as avg_karma, '
        '       stdev(karma_score) as sigma_karma '
        '  by host '
        '| where avg_karma < 70 OR sigma_karma > 15 '
        '| eval alert_level="CRITICAL" '
        '| table host, avg_karma, sigma_karma, alert_level'
    ),
    "LATENCY_MESH": (
        'index=sovereign_fleet sourcetype=ebpf_traffic '
        '| timechart span=1m avg(network_latency_ms) as latency by source_node '
        '| where latency > 250 '
        '| lookup validator_nodes host as source_node OUTPUT cluster_role '
        '| table _time, source_node, cluster_role, latency'
    ),
    "SECURITY_THREAT": (
        'index=sovereign_fleet sourcetype=ebpf_kernel_events '
        '| regex process_name="(?i)(bash|sh|nc|nmap|python3 -c)" '
        '| stats count by host, process_name, user '
        '| where count > 5 '
        '| sort - count'
    ),
    "CONSENSUS_QUORUM": (
        'index=sovereign_fleet sourcetype=karma_consensus_logs '
        '| stats dc(validator_id) as active_validators '
        '| eval total_validators=7 '
        '| eval quorum_pct=round(active_validators/total_validators*100,1)'
    ),
    "CHAIN_INTEGRITY": (
        'index=sovereign_fleet sourcetype=krittika:audit '
        '| sort _time '
        '| streamstats current=f last(current_hash) as expected_prev_hash '
        '| eval chain_valid=if(isnull(expected_prev_hash), "GENESIS", '
        '  if(expected_prev_hash==prev_hash, "VALID", "BROKEN")) '
        '| stats count as total, '
        '       count(eval(chain_valid=="VALID")) as valid, '
        '       count(eval(chain_valid=="BROKEN")) as broken '
        '| eval integrity_pct=round((valid+genesis)/total*100,2) '
        '| eval status=if(broken>0, "COMPROMISED", "INTACT")'
    ),
}


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
        retry_policy: Optional[RetryPolicy] = None,
    ):
        self.mcp_endpoint = mcp_endpoint or os.environ.get(
            "MCP_ENDPOINT", "https://localhost:8089/services/mcp"
        )
        self.mcp_token = mcp_token or os.environ.get("MCP_TOKEN", "")
        self.timeout = timeout
        self.retry_policy = retry_policy or RetryPolicy()
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

        On HTTP / network errors, raises TransientError or PermanentError
        so the caller's retry layer can classify + back off.
        Returns well-formed success / no-result responses as dicts.
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
            if response.status_code in (429, 500, 502, 503, 504, 408):
                raise classify_mcp_error(response.status_code, response.text)
            if response.status_code in (400, 401, 403, 404, 405, 422):
                raise classify_mcp_error(response.status_code, response.text)
            response.raise_for_status()
            result = response.json()

            if "error" in result:
                logger.error(f"MCP tool {tool_name} error: {result['error']}")
                return {"success": False, "error": result["error"]}

            return {"success": True, "result": result.get("result", {})}

        except httpx.TimeoutException as e:
            raise TransientError(f"MCP {tool_name} timeout: {e}") from e
        except httpx.ConnectError as e:
            raise TransientError(f"MCP {tool_name} connect error: {e}") from e
        except httpx.HTTPStatusError as e:
            raise classify_mcp_error(e.response.status_code, e.response.text) from e
        except (PermanentError, TransientError):
            raise
        except Exception as e:
            raise TransientError(f"MCP {tool_name} unexpected error: {e}") from e

    async def call_with_retry(
        self, tool_name: str, arguments: dict, *, policy: Optional[RetryPolicy] = None,
    ) -> dict:
        """Call an MCP tool with retry + backoff (self-correction layer).

        Uses the supplied policy (or self.retry_policy) to budget retries
        and apply exponential backoff. TransientError is retried;
        PermanentError is raised immediately.
        """
        p = policy or self.retry_policy
        return await aretry(
            lambda: self._call_mcp_tool(tool_name, arguments),
            policy=p,
            error_msg=f"MCP {tool_name}",
        )

    async def run_query(
        self,
        spl_query: str,
        earliest: str = "-5m",
        latest: str = "now",
        *,
        retry: bool = True,
    ) -> dict:
        """Execute a Splunk search query via splunk_run_query tool.

        Returns structured results for agent reasoning.
        When retry=True (default), transient MCP failures are retried
        with exponential backoff via call_with_retry().
        """
        call_kwargs = {
            "query": spl_query,
            "earliest": earliest,
            "latest": latest,
        }
        if retry:
            try:
                return await self.call_with_retry("splunk_run_query", call_kwargs)
            except PermanentError:
                return {"success": False, "error": "permanent MCP failure", "query": spl_query}
        return await self._call_mcp_tool("splunk_run_query", call_kwargs)

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
