# tests/test_retry.py — Tests for the self-correction retry layer
# RADHIKATMOSPHERE / Krittika-Splunk Nexus
#
# Verifies:
# - TransientError triggers retries, PermanentError does not
# - Exponential backoff math is correct and capped
# - aretry (async) mirrors with_retry (sync)
# - classify_mcp_error maps HTTP codes to the right error type
# - classify_spl_response distinguishes transport from semantic failures
# - RetryPolicy.statistics are recorded correctly

import asyncio
import os

os.environ["KRITTIKA_DISABLE_JITTER"] = "1"

import pytest

from agent_core.retry import (
    PermanentError,
    RetryPolicy,
    TransientError,
    aretry,
    classify_mcp_error,
    classify_spl_response,
    with_retry,
)


# ---------------------------------------------------------------------------
# RetryPolicy math
# ---------------------------------------------------------------------------


class TestRetryPolicy:
    def test_default_max_retries(self):
        p = RetryPolicy()
        assert p.max_retries == 3

    def test_backoff_grows_exponentially(self):
        p = RetryPolicy(initial_backoff_s=2.0, backoff_factor=2.0, max_backoff_s=100.0)
        # Jitter disabled in conftest.py → deterministic
        assert p.backoff(1) == pytest.approx(2.0, abs=0.01)
        assert p.backoff(2) == pytest.approx(4.0, abs=0.01)
        assert p.backoff(3) == pytest.approx(8.0, abs=0.01)
        assert p.backoff(4) == pytest.approx(16.0, abs=0.01)

    def test_backoff_respects_cap(self):
        p = RetryPolicy(initial_backoff_s=10.0, backoff_factor=10.0, max_backoff_s=30.0)
        assert p.backoff(1) == pytest.approx(10.0, abs=0.01)
        assert p.backoff(2) == pytest.approx(30.0, abs=0.01)  # capped
        assert p.backoff(3) == pytest.approx(30.0, abs=0.01)  # capped

    def test_record_increments_permanent(self):
        p = RetryPolicy()
        p.record("permanent")
        assert p.permanent_failures == 1
        assert p.successes_after_retry == 0

    def test_record_increments_success_after_retry(self):
        p = RetryPolicy()
        p.record("success_after_retry")
        assert p.successes_after_retry == 1
        assert p.permanent_failures == 0


# ---------------------------------------------------------------------------
# Error classification — HTTP codes
# ---------------------------------------------------------------------------


class TestClassifyMcpError:
    @pytest.mark.parametrize("code", [408, 429, 500, 502, 503, 504])
    def test_transient_codes(self, code):
        e = classify_mcp_error(code, "boom")
        assert isinstance(e, TransientError)
        assert not isinstance(e, PermanentError)

    @pytest.mark.parametrize("code", [400, 401, 403, 404, 405, 422])
    def test_permanent_codes(self, code):
        e = classify_mcp_error(code, "boom")
        assert isinstance(e, PermanentError)
        assert not isinstance(e, TransientError)

    def test_unknown_code_defaults_to_transient(self):
        e = classify_mcp_error(518, "weird")
        assert isinstance(e, TransientError)


# ---------------------------------------------------------------------------
# Error classification — semantically well-formed responses
# ---------------------------------------------------------------------------


class TestClassifySplResponse:
    def test_healthy_response_passes(self):
        err = classify_spl_response({"success": True, "result": [1, 2, 3]})
        assert err is None

    def test_success_false_without_error_detail_is_transient(self):
        err = classify_spl_response({"success": False})
        assert isinstance(err, TransientError)

    def test_jsonrpc_style_error_with_permanent_code_is_permanent(self):
        err = classify_spl_response({
            "success": False,
            "error": {"code": 401, "message": "unauthorized"},
        })
        assert isinstance(err, PermanentError)

    def test_jsonrpc_style_error_with_transient_code_is_transient(self):
        err = classify_spl_response({
            "success": False,
            "error": {"code": 503, "message": "still starting"},
        })
        assert isinstance(err, TransientError)

    def test_missing_required_keys_is_permanent(self):
        # success=True but missing the required 'result' key
        err = classify_spl_response({"success": True}, required_keys=("success", "result"))
        assert isinstance(err, PermanentError)

    def test_non_dict_response_is_transient(self):
        err = classify_spl_response("not a dict")
        assert isinstance(err, TransientError)


# ---------------------------------------------------------------------------
# with_retry — sync
# ---------------------------------------------------------------------------


class TestSyncRetry:
    def test_returns_immediately_on_first_success(self):
        p = RetryPolicy()
        calls = []

        def fn():
            calls.append(1)
            return "ok"

        result = with_retry(fn, p)
        assert result == "ok"
        assert len(calls) == 1

    def test_retries_on_transient_then_succeeds(self):
        p = RetryPolicy(initial_backoff_s=0.0, max_backoff_s=0.0)
        calls = []

        def fn():
            calls.append(1)
            if len(calls) < 3:
                raise TransientError("network blip")
            return "ok"

        result = with_retry(fn, p)
        assert result == "ok"
        assert len(calls) == 3
        assert p.successes_after_retry == 1

    def test_permanent_error_no_retry(self):
        p = RetryPolicy()
        calls = []

        def fn():
            calls.append(1)
            raise PermanentError("bad query")

        with pytest.raises(PermanentError):
            with_retry(fn, p)
        assert len(calls) == 1
        assert p.permanent_failures == 1

    def test_exhausts_budget_on_persistent_transient(self):
        p = RetryPolicy(max_retries=2, initial_backoff_s=0.0, max_backoff_s=0.0)
        calls = []

        def fn():
            calls.append(1)
            raise TransientError("still down")

        with pytest.raises(TransientError):
            with_retry(fn, p)
        # 1 initial + 2 retries = 3 total
        assert len(calls) == 3


# ---------------------------------------------------------------------------
# aretry — async
# ---------------------------------------------------------------------------


class TestAsyncRetry:
    def test_returns_immediately_on_first_success(self):
        p = RetryPolicy()
        calls = []

        async def coro_factory():
            calls.append(1)
            return "ok"

        result = asyncio.run(aretry(coro_factory, p))
        assert result == "ok"
        assert len(calls) == 1

    def test_retries_on_transient_then_succeeds(self):
        p = RetryPolicy(initial_backoff_s=0.0, max_backoff_s=0.0)
        calls = []

        async def coro_factory():
            calls.append(1)
            if len(calls) < 3:
                raise TransientError("network blip")
            return "ok"

        result = asyncio.run(aretry(coro_factory, p))
        assert result == "ok"
        assert len(calls) == 3
        assert p.successes_after_retry == 1

    def test_permanent_error_no_retry(self):
        p = RetryPolicy()
        calls = []

        async def coro_factory():
            calls.append(1)
            raise PermanentError("bad query")

        with pytest.raises(PermanentError):
            asyncio.run(aretry(coro_factory, p))
        assert len(calls) == 1
        assert p.permanent_failures == 1

    def test_exhausts_budget_on_persistent_transient(self):
        p = RetryPolicy(max_retries=2, initial_backoff_s=0.0, max_backoff_s=0.0)
        calls = []

        async def coro_factory():
            calls.append(1)
            raise TransientError("still down")

        with pytest.raises(TransientError):
            asyncio.run(aretry(coro_factory, p))
        assert len(calls) == 3

    def test_fresh_awaitable_each_retry(self):
        """Regression: aretry must create a new awaitable each attempt, not
        await the same coroutine twice (which raises RuntimeError)."""
        p = RetryPolicy(max_retries=2, initial_backoff_s=0.0, max_backoff_s=0.0)
        attempts = [0]

        def coro_factory():
            attempts[0] += 1
            async def _coro():
                if attempts[0] < 2:
                    raise TransientError("retry me")
                return attempts[0]
            return _coro()

        result = asyncio.run(aretry(coro_factory, p))
        assert result == 2
        assert attempts[0] == 2
