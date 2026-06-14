# tests/test_autofix_spl.py — Tests for field-name self-correction in
# agent_core/splunk_mcp_client.autofix_spl_query + run_query_with_autofix.
# RADHIKATMOSPHERE / Krittika-Splunk Nexus

import os

os.environ["KRITTIKA_DISABLE_JITTER"] = "1"

import asyncio
import json
import re
from unittest.mock import AsyncMock, MagicMock

import pytest

from agent_core.splunk_mcp_client import (
    FIELD_ALIASES,
    SplunkMCPClient,
    _FIELD_DNE_RE,
    autofix_spl_query,
)


# ---------------------------------------------------------------------------
# Pure-function autofix
# ---------------------------------------------------------------------------


class TestAutofixSplQuery:
    def test_replaces_process_with_process_name_via_hint(self):
        q = "index=ebpf_traffic host=validator-3 process=python3"
        err = "Error: Field 'process' does not exist. Did you mean 'process_name'?"
        new_q, fixes = autofix_spl_query(q, err)
        assert new_q == "index=ebpf_traffic host=validator-3 process_name=python3"
        assert ("process", "process_name", 1) in fixes

    def test_replaces_without_hint_via_opportunistic(self):
        # The error message includes the wrong field, but no "did you mean" hint
        q = "index=ebpf_traffic source_ip=10.0.1.10 process_name=python3"
        err = "Error: Field 'source_ip' does not exist."
        new_q, fixes = autofix_spl_query(q, err)
        assert "src_ip=" in new_q
        assert ("source_ip", "src_ip", 1) in fixes

    def test_multiple_field_typos_in_one_query(self):
        q = "index=x host=v3 process=p3 source_ip=1.2.3.4 dest_port=443 latency=99"
        err = "Error: Field 'process' does not exist. Did you mean 'process_name'?"
        new_q, fixes = autofix_spl_query(q, err)
        # The hint fixes process → process_name;
        # opportunistic pass fixes source_ip, dest_port, latency.
        assert "process_name=" in new_q
        assert "src_ip=" in new_q
        assert "dst_port=" in new_q
        assert "latency_ms=" in new_q
        # We don't care about ORDER of fixes — at least 4 fixes applied
        assert len(fixes) >= 4

    def test_no_changes_for_correct_query(self):
        q = "index=ebpf_traffic process_name=python3"
        err = "Error: Field 'process_name' does not exist."
        new_q, fixes = autofix_spl_query(q, err)
        # No wrong alias maps to anything different; idempotent entries skip
        assert new_q == q
        assert fixes == []

    def test_does_not_substring_match_partial_words(self):
        # "process" substring inside "process_name" should not re-rewrite
        q = "index=x process_name=python3"
        # Tricky case: if "process" typo were present, regex with \b boundary
        # correctly leaves "process_name" alone.
        new_q, fixes = autofix_spl_query(q, "Error: irrelevant")
        assert new_q == q

    def test_handles_nested_quoted_hint(self):
        # Splunk sometimes uses double quotes
        q = "index=x process=python"
        err = 'Error: Field "process" does not exist. Did you mean "process_name"?'
        new_q, fixes = autofix_spl_query(q, err)
        assert new_q == "index=x process_name=python"
        assert ("process", "process_name", 1) in fixes

    def test_idempotent_pass_after_first_fix(self):
        q = "index=x process=python"
        err = "Field 'process' does not exist. Did you mean 'process_name'?"
        _, fixes = autofix_spl_query(q, err)
        # Re-run on result — should be a no-op
        fixed = "index=x process_name=python"
        _, fixes2 = autofix_spl_query(fixed, err)
        assert fixes2 == []


# ---------------------------------------------------------------------------
# Regex parser
# ---------------------------------------------------------------------------


class TestFieldDoesNotExistParser:
    @pytest.mark.parametrize("msg,expected", [
        ("Field 'foo' does not exist. Did you mean 'bar'?",
         {"wrong": "foo", "right": "bar"}),
        ('Field "process" does not exist. Did you mean "process_name"?',
         {"wrong": "process", "right": "process_name"}),
        ("Field process does not exist. Did you mean process_name?",
         {"wrong": "process", "right": "process_name"}),
    ])
    def test_parses_hint(self, msg, expected):
        m = _FIELD_DNE_RE.search(msg)
        assert m is not None
        assert m["wrong"] == expected["wrong"]
        assert m["right"] == expected["right"]

    def test_returns_none_for_unrelated_error(self):
        assert _FIELD_DNE_RE.search("Error: 401 Unauthorized") is None


# ---------------------------------------------------------------------------
# Aliases canonical invariant
# ---------------------------------------------------------------------------


class TestFieldAliases:
    def test_idempotent_keys_present(self):
        # Every "correct" field name should appear at least once as a key
        canonical_fields = [
            "process_name", "pid", "host", "src_ip", "dst_ip",
            "src_port", "dst_port", "_time", "validator_id",
            "karma_score", "latency_ms", "anomaly", "comm",
        ]
        for f in canonical_fields:
            assert f in FIELD_ALIASES, f"missing canonical key: {f}"

    def test_aliases_map_to_canonical(self):
        for wrong, right in FIELD_ALIASES.items():
            assert isinstance(wrong, str)
            assert isinstance(right, str)
            # Either it's idempotent (wrong == right) or it points to a canonical name
            assert right in FIELD_ALIASES or right in {
                "process_name", "pid", "host", "src_ip", "dst_ip",
                "src_port", "dst_port", "_time", "validator_id",
                "karma_score", "latency_ms", "anomaly", "comm",
            }


# ---------------------------------------------------------------------------
# run_query_with_autofix (async)
# ---------------------------------------------------------------------------


def _make_response(status_code: int, body_json: str):
    """Build a real httpx.Response-shaped object for _call_mcp_tool."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = body_json
    resp.raise_for_status = MagicMock()
    resp.json = MagicMock(return_value=json.loads(body_json))
    return resp


def _success_response(rows):
    return _make_response(200, json.dumps({"jsonrpc": "2.0", "result": {"rows": rows or []}}))


def _error_response(message: str):
    return _make_response(200, json.dumps({"jsonrpc": "2.0", "error": {"code": -32602, "message": message}}))


def _mock_response(success: bool, error=None, rows=None):
    """Construct an MCP response shape (legacy helper)."""
    if success:
        return _success_response(rows)
    return _error_response(error or "Error: Field 'foo' does not exist.")


def _make_client_with_sequence(responses: list) -> SplunkMCPClient:
    """Build a client whose _call_mcp_tool returns successive responses."""
    c = SplunkMCPClient(retry_policy=None)
    c._client = MagicMock()
    c._client.post = AsyncMock(side_effect=[
        _mock_response(**r) if "_" not in str(r) else _mock_response(False, str(r))
        for r in responses
    ])
    return c


class TestRunQueryWithAutofix:
    def test_succeeds_on_first_try_no_fixes(self):
        client = SplunkMCPClient(retry_policy=None)
        client._client = MagicMock()
        client._client.post = AsyncMock(return_value=_success_response([{"a": 1}]))

        async def _run():
            return await client.run_query_with_autofix("index=x host=v1 process_name=python3")
        result = asyncio.run(_run())
        assert result["success"] is True
        assert result["autofix_passes"] == 0
        assert result["fixes"] == []

    def test_autofixes_process_then_succeeds(self):
        client = SplunkMCPClient(retry_policy=None)
        client._client = MagicMock()
        # Round 1: error; Round 2: success
        client._client.post = AsyncMock(side_effect=[
            _error_response("Error: Field 'process' does not exist. Did you mean 'process_name'?"),
            _success_response([{"row": "data"}]),
        ])

        async def _run():
            return await client.run_query_with_autofix(
                "index=ebpf_traffic host=validator-3 process=python3"
            )
        result = asyncio.run(_run())
        assert result["success"] is True
        assert result["autofix_passes"] == 1
        assert ("process", "process_name", 1) in result["fixes"]
        assert "process_name=" in result["query"]
        assert "self-correction" in result["reasoning"].lower()

    def test_non_schema_error_no_autofix(self):
        client = SplunkMCPClient(retry_policy=None)
        client._client = MagicMock()
        client._client.post = AsyncMock(return_value=_error_response("Error: 401 Unauthorized"))

        async def _run():
            return await client.run_query_with_autofix("index=x host=v1 process_name=python3")
        result = asyncio.run(_run())
        assert result["success"] is False
        assert result["autofix_passes"] == 0
        assert result["fixes"] == []

    def test_exhausts_max_passes_yields_failure(self):
        # Two distinct typos so each pass applies at least one fix.
        client = SplunkMCPClient(retry_policy=None)
        client._client = MagicMock()
        # First error: process typo; Second error: source_ip typo
        client._client.post = AsyncMock(side_effect=[
            _error_response("Error: Field 'process' does not exist. Did you mean 'process_name'?"),
            _error_response("Error: Field 'source_ip' does not exist. Did you mean 'src_ip'?"),
        ])

        async def _run():
            return await client.run_query_with_autofix(
                "index=x process=foo source_ip=1.2.3.4", max_autofix_passes=2
            )
        result = asyncio.run(_run())
        assert result["success"] is False
        assert result["autofix_passes"] >= 1
        assert len(result["fixes"]) >= 2  # one fix per pass at minimum
