from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, TypeVar


T = TypeVar("T")


_FATAL_MARKERS = (
    "api key",
    "authentication",
    "unauthorized",
    "invalid api",
    "permission denied",
    "forbidden",
    "status code: 401",
    "status code: 403",
    "status code: 400",
    "http 401",
    "http 403",
    "http 400",
)
_RETRY_MARKERS = (
    "429",
    "500",
    "502",
    "503",
    "504",
    "rate limit",
    "timeout",
    "timed out",
    "connection reset",
    "connection aborted",
    "temporarily unavailable",
    "overloaded",
)


@dataclass
class RetryPolicy:
    attempts: int = 3
    base_delay: float = 0.5
    max_delay: float = 4.0
    tool_attempts: int = 1

    def model(self, call: Callable[[], T], *, deadline: float | None = None) -> T:
        last: Exception | None = None
        for attempt in range(max(1, self.attempts)):
            try:
                return call()
            except Exception as exc:
                last = exc
                kind = classify_model_error(exc)
                if kind == "fatal":
                    raise
                if kind != "retryable" or attempt + 1 >= self.attempts:
                    raise
                delay = self._delay(attempt, exc)
                remaining = None if deadline is None else max(0.0, deadline - time.monotonic())
                if remaining is not None and remaining <= delay:
                    raise TimeoutError("model deadline reached during retry") from exc
                time.sleep(delay)
        assert last is not None
        raise last

    def tool(self, call: Callable[[], T], *, deadline: float | None = None) -> T:
        last: Exception | None = None
        for attempt in range(max(1, self.tool_attempts)):
            try:
                return call()
            except Exception as exc:
                last = exc
                if classify_tool_error(exc) != "retryable" or attempt + 1 >= self.tool_attempts:
                    raise
                if deadline is not None and time.monotonic() >= deadline:
                    raise
                time.sleep(min(0.2, max(0.0, (deadline or 0) - time.monotonic())))
        assert last is not None
        raise last

    async def model_async(
        self,
        call: Callable[[], Awaitable[T]],
        *,
        deadline: float | None = None,
    ) -> T:
        last: Exception | None = None
        for attempt in range(max(1, self.attempts)):
            try:
                return await call()
            except Exception as exc:
                last = exc
                kind = classify_model_error(exc)
                if kind == "fatal":
                    raise
                if kind != "retryable" or attempt + 1 >= self.attempts:
                    raise
                delay = self._delay(attempt, exc)
                remaining = None if deadline is None else max(0.0, deadline - time.monotonic())
                if remaining is not None and remaining <= delay:
                    raise TimeoutError("model deadline reached during retry") from exc
                await asyncio.sleep(delay)
        assert last is not None
        raise last

    async def tool_async(
        self,
        call: Callable[[], Awaitable[T]],
        *,
        deadline: float | None = None,
    ) -> T:
        last: Exception | None = None
        for attempt in range(max(1, self.tool_attempts)):
            try:
                return await call()
            except Exception as exc:
                last = exc
                if classify_tool_error(exc) != "retryable" or attempt + 1 >= self.tool_attempts:
                    raise
                if deadline is not None and time.monotonic() >= deadline:
                    raise
                await asyncio.sleep(min(0.2, max(0.0, (deadline or 0) - time.monotonic())))
        assert last is not None
        raise last

    def _delay(self, attempt: int, error: Exception) -> float:
        retry_after = _retry_after(error)
        if retry_after is not None:
            return min(self.max_delay, max(0.0, retry_after))
        base = self.base_delay * (2**attempt)
        return min(self.max_delay, base) + random.uniform(0, 0.1)


def classify_model_error(error: Exception) -> str:
    if isinstance(error, (TimeoutError, asyncio.TimeoutError)):
        return "retryable"
    status = _status_code(error)
    if status in {400, 401, 403}:
        return "fatal"
    if status in {408, 409, 425, 429, 500, 502, 503, 504}:
        return "retryable"
    text = str(error).lower()
    if any(marker in text for marker in _FATAL_MARKERS):
        return "fatal"
    if any(marker in text for marker in _RETRY_MARKERS):
        return "retryable"
    return "unknown"


def classify_tool_error(error: Exception) -> str:
    text = str(error).lower()
    if any(marker in text for marker in ("timeout", "timed out", "connection reset", "temporarily")):
        return "retryable"
    return "unknown"


def _status_code(error: Exception) -> int | None:
    value = getattr(error, "status_code", None)
    if value is None:
        response = getattr(error, "response", None)
        value = getattr(response, "status_code", None)
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _retry_after(error: Exception) -> float | None:
    response = getattr(error, "response", None)
    headers = getattr(response, "headers", None)
    if not headers:
        return None
    value = headers.get("Retry-After") or headers.get("retry-after")
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
