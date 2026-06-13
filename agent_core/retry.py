# agent_core/retry.py — Resilience layer for Krittika-Splunk Nexus
# RADHIKATMOSPHERE / Krittika-Splunk Nexus
#
# Self-correction primitives for the autonomous agent:
# - RetryPolicy: per-query-type retry budget + exponential backoff
# - TransientError / PermanentError: domain types for error classification
# - class_mcp_error: classifies Splunk MCP responses into retryable / non-retryable
# - with_retry: synchronous decorator that retries on TransientError
# - aretry: async variant for use with `await` in the orchestrator loop
#
# Design goals:
# - No global state (each query gets its own RetryPolicy instance)
# - Backoff capped to prevent unbounded waits
# - Honor MCP-side hints (Retry-After header) when present
# - Deterministic for testing (jitter=0 if env var DISABLE_JITTER=1)

import asyncio
import logging
import os
import random
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Optional, TypeVar

logger = logging.getLogger("krittika.retry")

# ---------------------------------------------------------------------------
# Error domain
# ---------------------------------------------------------------------------


class TransientError(Exception):
    """A failure that is likely to succeed on retry (network blip, rate limit)."""


class PermanentError(Exception):
    """A failure that will not succeed on retry (invalid query, 401 unauth)."""


# ---------------------------------------------------------------------------
# RetryPolicy
# ---------------------------------------------------------------------------


@dataclass
class RetryPolicy:
    """Per-query retry configuration.

    Defaults map to typical MCP backend behavior:
    - 3 retries is enough for transient HTTP timeouts
    - 2-second base backoff + exponential keeps total wait under ~15s
    - 60s cap protects against runaway retries when the backend is down
    """

    max_retries: int = field(
        default_factory=lambda: int(os.environ.get("KRITTIKA_MAX_RETRIES", "3"))
    )
    initial_backoff_s: float = field(
        default_factory=lambda: float(os.environ.get("KRITTIKA_BACKOFF_INITIAL", "2.0"))
    )
    max_backoff_s: float = field(
        default_factory=lambda: float(os.environ.get("KRITTIKA_BACKOFF_MAX", "60.0"))
    )
    backoff_factor: float = 2.0
    jitter: float = 0.1
    attempts: int = 0
    successes_after_retry: int = 0
    permanent_failures: int = 0

    def backoff(self, attempt: int) -> float:
        """Exponential backoff with cap and jitter."""
        base = min(
            self.initial_backoff_s * (self.backoff_factor ** (attempt - 1)),
            self.max_backoff_s,
        )
        if os.environ.get("KRITTIKA_DISABLE_JITTER") == "1":
            return base
        return base * (1 + random.uniform(-self.jitter, self.jitter))

    def record(self, outcome: str) -> None:
        if outcome == "success_after_retry":
            self.successes_after_retry += 1
        elif outcome == "permanent":
            self.permanent_failures += 1


T = TypeVar("T")


def with_retry(
    fn: Callable[..., T],
    policy: RetryPolicy,
    error_msg: str = "",
) -> T:
    """Synchronous retry wrapper for a query function.

    Catches TransientError and retries with backoff.
    Raises PermanentlyError immediately on PermanentError.
    Raises after max_retries on continued TransientError.
    """
    policy.attempts += 1
    last_exc: Optional[Exception] = None
    for attempt in range(1, policy.max_retries + 2):
        try:
            result = fn()
            if attempt > 1:
                policy.record("success_after_retry")
                logger.info(
                    f"{error_msg or 'retry'}: succeeded on attempt {attempt}/{policy.max_retries + 1}"
                )
            return result
        except PermanentError as e:
            policy.record("permanent")
            logger.error(f"{error_msg or 'retry'}: permanent error — {e}")
            raise
        except TransientError as e:
            last_exc = e
            if attempt <= policy.max_retries:
                wait = policy.backoff(attempt)
                logger.warning(
                    f"{error_msg or 'retry'}: transient error attempt {attempt}/{policy.max_retries + 1}: {e}. "
                    f"Sleeping {wait:.2f}s"
                )
                import time
                time.sleep(wait)
            else:
                logger.error(
                    f"{error_msg or 'retry'}: exhausted {policy.max_retries + 1} attempts — {e}"
                )
    raise last_exc if last_exc else RuntimeError("retry exhausted with no exception")


async def aretry(
    coro_factory: Callable[[], Awaitable[T]],
    policy: RetryPolicy,
    error_msg: str = "",
) -> T:
    """Async retry wrapper for an awaitable-returning callable.

    coro_factory MUST return a fresh awaitable on each invocation
    (otherwise the same coroutine is awaited twice).
    """
    policy.attempts += 1
    last_exc: Optional[Exception] = None
    for attempt in range(1, policy.max_retries + 2):
        try:
            result = await coro_factory()
            if attempt > 1:
                policy.record("success_after_retry")
                logger.info(
                    f"{error_msg or 'retry'}: succeeded on attempt {attempt}/{policy.max_retries + 1}"
                )
            return result
        except PermanentError as e:
            policy.record("permanent")
            logger.error(f"{error_msg or 'retry'}: permanent error — {e}")
            raise
        except TransientError as e:
            last_exc = e
            if attempt <= policy.max_retries:
                wait = policy.backoff(attempt)
                logger.warning(
                    f"{error_msg or 'retry'}: transient error attempt {attempt}/{policy.max_retries + 1}: {e}. "
                    f"Sleeping {wait:.2f}s"
                )
                await asyncio.sleep(wait)
            else:
                logger.error(
                    f"{error_msg or 'retry'}: exhausted {policy.max_retries + 1} attempts — {e}"
                )
    raise last_exc if last_exc else RuntimeError("retry exhausted with no exception")


# ---------------------------------------------------------------------------
# Error classification for MCP responses
# ---------------------------------------------------------------------------


_TRANSIENT_HTTP_CODES = {408, 429, 500, 502, 503, 504}
_PERMANENT_HTTP_CODES = {400, 401, 403, 404, 405, 422}


def classify_mcp_error(status_code: int, error_msg: str = "") -> Exception:
    """Map an MCP HTTP status code + error body to a TransientError or PermanentError.

    Splunk MCP returns:
    - 429: Too Many Requests → retry with Retry-After header
    - 5xx: Backend unavailable → retry
    - 408: Request Timeout → retry
    - 401 / 403: Auth → permanent (don't burn budget rotating tokens)
    - 400 / 422: Invalid query → permanent (will fail again on retry)
    - 404: Not found / index missing → permanent (data layer issue)
    """
    if status_code in _TRANSIENT_HTTP_CODES:
        return TransientError(
            f"MCP transient error {status_code}: {error_msg or 'no detail'}"
        )
    if status_code in _PERMANENT_HTTP_CODES:
        return PermanentError(
            f"MCP permanent error {status_code}: {error_msg or 'no detail'}"
        )
    return TransientError(
        f"MCP unknown error {status_code}: {error_msg or 'no detail'} (treated as transient)"
    )


def classify_spl_response(
    response: dict,
    *,
    required_keys: tuple[str, ...] = ("success",),
) -> Exception | None:
    """Inspect an MCP response dict. Returns an exception object on failure, None on success.

    Distinguishes between transport failures (network/HTTP — retryable) and
    semantic failures (response is well-formed but the Splunk search returned
    nothing or errored — may warrant query parameterization rather than retry).
    """
    if not isinstance(response, dict):
        return TransientError(f"MCP response not a dict: {type(response).__name__}")

    if "error" in response and not response.get("success", True):
        err = response["error"]
        if isinstance(err, dict):
            code = err.get("code", 0)
            msg = err.get("message", "") or err.get("data", "")
            if isinstance(code, int) and code in _PERMANENT_HTTP_CODES:
                return PermanentError(f"MCP semantic error {code}: {msg}")
            return TransientError(f"MCP semantic error {code}: {msg}")
        return TransientError(f"MCP error string: {err}")

    if not response.get("success", False):
        return TransientError(
            "MCP response success=False with no error detail (likely transport)"
        )

    for k in required_keys:
        if k not in response:
            return PermanentError(f"MCP response missing required key {k!r}")

    return None
