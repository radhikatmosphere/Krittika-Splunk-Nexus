# agent_core/splunk_mcp_client.py — Splunk MCP Client
# RADHIKATMOSPHERE / Krittika-Splunk Nexus
#
# Connects to the official Splunk MCP Server (installed from Splunkbase)
# via HTTP streamable protocol. Uses encrypted tokens for authentication.
# Provides typed wrappers around splunk_run_query and other MCP tools.
#
# Self-correction features added in this version:
#   * RetryPolicy / TransientError / PermanentError — for transport errors
#   * FIELD_ALIASES + autofix_spl_query() — for schema-mismatch errors
#     (e.g. an LLM hallucinates "process=" when the field is "process_name=")

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple

import httpx

from .retry import (
    RetryPolicy,
    TransientError,
    PermanentError,
    aretry,
    classify_mcp_error,
)

logger = logging.getLogger("krittika.mcp_client")


# Production SPL query catalog for the RadhikaChain Sovereign Fleet
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


# ---------------------------------------------------------------------------
# Field-name auto-correction (self-correction for LLM-hallucinated schemas)
# ---------------------------------------------------------------------------
#
# When an LLM agent generates an SPL query it may pick a field name that
# doesn't exist in the actual schema (e.g. `process=` instead of
# `process_name=`). Splunk returns:
#
#   "Error: Field 'X' does not exist. Did you mean 'Y'?"
#
# This map provides the canonical fix-up so the agent can self-correct
# without a second roundtrip to the LLM. Keys are the wrong names, values
# are the correct ones (taken from `splunk_configs/props.conf`,
# `splunk_configs/transforms.conf`). Many entries are intentionally
# idempotent (key == value) so the regex pass is a no-op for them; this
# makes future schema additions trivial — just add the correct name.
FIELD_ALIASES: Dict[str, str] = {
    # Process / exe synonyms
    "process":            "process_name",
    "processname":        "process_name",
    "process_name":       "process_name",   # idempotent
    "exe":                "process_name",
    "executable":         "process_name",
    "binary":             "comm",
    "proc":               "process_name",
    "comm":               "comm",           # idempotent
    # PID synonyms
    "pid":                "pid",
    "processid":          "pid",
    # Host synonyms
    "hostname":           "host",
    "system":             "host",
    "machine":            "host",
    "node":               "host",
    "target":             "host",
    "host":               "host",           # idempotent
    "host_name":          "host",
    # User synonyms
    "user":               "user",           # idempotent
    "username":           "user",
    "uid":                "uid",            # idempotent
    # Network synonyms
    "source_ip":          "src_ip",
    "src_ip":             "src_ip",         # idempotent
    "dest_ip":            "dst_ip",
    "dst_ip":             "dst_ip",         # idempotent
    "destination_ip":     "dst_ip",
    "source_port":        "src_port",
    "src_port":           "src_port",       # idempotent
    "dest_port":          "dst_port",
    "dst_port":           "dst_port",       # idempotent
    "destination_port":   "dst_port",
    # IP/protocol
    "ip":                 "src_ip",
    "proto":              "proto",          # idempotent
    "protocol":           "proto",
    "tcp_flags":          "tcp_flags",      # idempotent
    "pkt_size":           "pkt_size",       # idempotent
    "packet_size":        "pkt_size",
    "ttl":                "ttl",            # idempotent
    # Timestamp synonyms
    "ts":                 "_time",
    "timestamp":          "_time",
    "_time":              "_time",          # idempotent
    "time":               "_time",
    "@timestamp":         "_time",
    # Validator fields
    "validator_id":       "validator_id",   # idempotent
    "validator":          "validator_id",
    # Karma / score
    "karma":              "karma_score",
    "score":              "karma_score",
    "karma_score":        "karma_score",    # idempotent
    "reputation":         "karma_score",
    # Latency
    "latency":            "latency_ms",
    "latency_ms":         "latency_ms",     # idempotent
    "rtt":                "latency_ms",
    # Block / chain
    "block_height":       "block_height",   # idempotent
    "block":              "block_height",
    # Anomaly detection
    "alert":              "anomaly",
    "attack":             "anomaly",
    "incident":           "anomaly",
    "anomaly":            "anomaly",        # idempotent
}


# Pattern to extract Splunk's hint: "Field 'X' does not exist. Did you mean 'Y'?"
_FIELD_DNE_RE = re.compile(
    r"Field\s+['\"]?(?P<wrong>[^'\"]+)['\"]?\s+does not exist"
    r".*?(?:Did you mean|fould_mean|suggestion)\s+['\"]?(?P<right>[^'\"]+?)['\"]?\?",
    re.IGNORECASE | re.DOTALL,
)


def autofix_spl_query(
    query: str,
    error_msg: str,
    aliases: Optional[Dict[str, str]] = None,
) -> Tuple[str, List[Tuple[str, str, int]]]:
    """Apply a single-pass field-name autofix to `query` based on `error_msg`.

    Strategy (deterministic, no LLM call):
      1. Parse `error_msg` with `_FIELD_DNE_RE` to extract the wrong field
         and Splunk's suggested right one.
      2. Substitute `wrong_field=value` with the alias for the suggested
         right one (falling back to the suggested field as-is).
      3. Also opportunistically substitute every wrong alias present in
         the query that maps to a known canonical name — protects against
         cascade typos in long queries.

    Returns (new_query, fixes_applied). `fixes_applied` is a list of
    `(wrong, right, n_replacements)` for observability.
    """
    aliases = aliases or FIELD_ALIASES
    fixes: List[Tuple[str, str, int]] = []
    new_query = query

    # 1. Splunk's explicit hint
    m = _FIELD_DNE_RE.search(error_msg)
    explicit_wrong = m["wrong"] if m else None
    explicit_right = m["right"] if m else None

    candidates: List[Tuple[str, str]] = []
    if explicit_wrong and explicit_right:
        candidates.append((explicit_wrong, explicit_right))
    # 2. Opportunistic — every alias in the map
    for wrong, right in aliases.items():
        if wrong == right:
            continue
        if wrong in (explicit_wrong, explicit_right):
            continue
        candidates.append((wrong, right))

    for wrong, right in candidates:
        try:
            pattern = re.compile(rf"\b{re.escape(wrong)}\s*=")
            new_query, count = pattern.subn(f"{right}=", new_query)
        except re.error:
            count = 0
        if count > 0:
            fixes.append((wrong, right, count))

    return new_query, fixes


# ---------------------------------------------------------------------------
# SplunkMCPClient
# ---------------------------------------------------------------------------


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

    Self-correction: use `run_query_with_autofix()` to auto-fix SPL field
    names that the LLM-hallucinated. See module docstring for details.
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
        """Call an MCP tool via the streamable HTTP protocol.
        Uses JSON-RPC 2.0 format. On HTTP / network errors, raises
        TransientError or PermanentError so the retry layer can react."""
        if not self._client:
            raise RuntimeError("Client not initialized. Use async context manager.")

        request_id = id(tool_name)
        payload = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
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
        """Call an MCP tool with retry + backoff (transport self-correction)."""
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
        When retry=True (default), transient MCP failures are retried
        with exponential backoff via call_with_retry()."""
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

    async def run_query_with_autofix(
        self,
        spl_query: str,
        earliest: str = "-5m",
        latest: str = "now",
        *,
        max_autofix_passes: int = 2,
        retry: bool = True,
    ) -> dict:
        """Auto-correction wrapper for `run_query` (schema self-correction).

        If Splunk returns a "Field X does not exist. Did you mean Y?"
        error, parse the message, replace the wrong field name with the
        right one, and re-submit the query — without an LLM roundtrip.
        """
        traces: List[Dict[str, Any]] = []
        current_query = spl_query
        all_fixes: List[Tuple[str, str, int]] = []

        for attempt in range(max_autofix_passes + 1):
            result = await self.run_query(
                current_query, earliest=earliest, latest=latest, retry=retry,
            )
            traces.append({
                "attempt": attempt + 1,
                "query": current_query,
                "result_success": result.get("success", False),
            })

            if result.get("success"):
                result["query"] = current_query
                result["autofix_passes"] = attempt
                result["fixes"] = all_fixes
                result["reasoning"] = self._build_reasoning(traces, all_fixes)
                return result

            err_text = self._stringify_error(result.get("error"))
            if "does not exist" not in err_text.lower():
                # Non-schema error — transport/query parsing. Don't autofix.
                result["query"] = current_query
                result["autofix_passes"] = attempt
                result["fixes"] = all_fixes
                result["reasoning"] = self._build_reasoning(traces, all_fixes)
                return result
            if attempt >= max_autofix_passes:
                result["query"] = current_query
                result["autofix_passes"] = attempt
                result["fixes"] = all_fixes
                result["reasoning"] = self._build_reasoning(traces, all_fixes)
                return result

            new_query, fixes = autofix_spl_query(current_query, err_text)
            if not fixes or new_query == current_query:
                result["query"] = current_query
                result["autofix_passes"] = attempt
                result["fixes"] = all_fixes
                result["reasoning"] = self._build_reasoning(traces, all_fixes)
                return result

            current_query = new_query
            all_fixes.extend(fixes)
            logger.info(
                f"[autofix] pass {attempt + 1}: applied {len(fixes)} field fix(es); "
                f"new query: {current_query[:120]}..."
            )

        # Defensive — should not reach here
        return {
            "success": False,
            "query": current_query,
            "autofix_passes": max_autofix_passes,
            "fixes": all_fixes,
            "reasoning": self._build_reasoning(traces, all_fixes),
        }

    @staticmethod
    def _stringify_error(err: Any) -> str:
        """Best-effort stringification of MCP error field (dict or str)."""
        if isinstance(err, str):
            return err
        if isinstance(err, dict):
            return json.dumps(err)
        return str(err)

    @staticmethod
    def _build_reasoning(traces: List[Dict], fixes: List[Tuple[str, str, int]]) -> str:
        """Produce a short human-readable reasoning trace for the agent log."""
        if not fixes:
            return "Query executed on first attempt, no field corrections needed."
        out = [
            "Initial SPL query used hallucinated field name(s). "
            "Splunk returned 'Field does not exist' with a hint. "
            "Applied self-correction without LLM roundtrip:\n"
        ]
        for i, trace in enumerate(traces):
            label = "Round 1" if i == 0 else f"Retry {i}"
            status = "FAILED (field typo)" if not trace["result_success"] else "OK"
            out.append(f"  [{i+1}] {label}: query=\"{trace['query'][:120]}\" → {status}")
        for wrong, right, count in fixes:
            out.append(f"  - replaced {wrong!r} → {right!r} ({count}x)")
        return "\n".join(out)

    async def get_info(self) -> dict:
        return await self._call_mcp_tool("splunk_get_info", {})

    async def get_indexes(self) -> dict:
        return await self._call_mcp_tool("splunk_get_indexes", {})

    async def get_index_info(self, index_name: str) -> dict:
        return await self._call_mcp_tool("splunk_get_index_info", {"index": index_name})

    async def get_metadata(self, metadata_type: str = "hosts", index: str = "*") -> dict:
        return await self._call_mcp_tool("splunk_get_metadata", {
            "metadata_type": metadata_type,
            "index": index,
        })

    async def run_saved_search(self, search_name: str) -> dict:
        return await self._call_mcp_tool("splunk_run_saved_search", {
            "search_name": search_name,
        })

    async def generate_spl(self, natural_language_query: str) -> dict:
        return await self._call_mcp_tool("saia_generate_spl", {
            "query": natural_language_query,
        })

    async def explain_spl(self, spl_query: str) -> dict:
        return await self._call_mcp_tool("saia_explain_spl", {"spl": spl_query})

    async def optimize_spl(self, spl_query: str) -> dict:
        return await self._call_mcp_tool("saia_optimize_spl", {"spl": spl_query})
