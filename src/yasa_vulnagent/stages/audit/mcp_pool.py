"""Stage-scoped shared YASA MCP session pool for the audit graph.

The outer audit LangGraph runs synchronously while recon, trace, and verify
each execute inside their own ``run_coroutine`` event loops. ``SharedYasaMcp``
hosts one lazily opened MCP ``ClientSession`` on a dedicated background event
loop thread and proxies ``call_tool`` calls safely across loops, collapsing up
to 7 subprocess spawns (recon + multi-wave trace/verify) down to at most 1.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from contextlib import AsyncExitStack, asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator, Callable

from ..discover.screen.mcp import open_yasa_mcp

logger = logging.getLogger(__name__)


class _ProxiedMcpSession:
    """Async session proxy forwarding calls to the shared MCP background loop."""

    def __init__(self, session: Any, loop: asyncio.AbstractEventLoop) -> None:
        self._session = session
        self._loop = loop

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        future = asyncio.run_coroutine_threadsafe(
            self._session.call_tool(name, arguments),
            self._loop,
        )
        return await asyncio.wrap_future(future)

    async def list_tools(self) -> Any:
        future = asyncio.run_coroutine_threadsafe(
            self._session.list_tools(),
            self._loop,
        )
        return await asyncio.wrap_future(future)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._session, name)


class SharedYasaMcp:
    """Lazily opened, thread-safe YASA MCP session shared across audit nodes."""

    def __init__(
        self,
        settings: Any,
        repository: Path,
        *,
        opener: Callable[[Any, Path], Any] | None = None,
    ) -> None:
        self._settings = settings
        self._repository = Path(repository)
        self._opener = opener or open_yasa_mcp
        self._lock = threading.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._stack: AsyncExitStack | None = None
        self._session: Any | None = None
        self._initialized = False
        self._closed = False

    @property
    def is_open(self) -> bool:
        with self._lock:
            return self._initialized and not self._closed and self._session is not None

    async def acquire(self) -> Any | None:
        """Return a loop-safe proxy to the shared MCP session, opening lazily."""
        if self._closed:
            return None
        if not self._initialized:
            await asyncio.to_thread(self._ensure_started)
        with self._lock:
            if self._closed or self._session is None or self._loop is None:
                return None
            return _ProxiedMcpSession(self._session, self._loop)

    def _ensure_started(self) -> None:
        with self._lock:
            if self._closed or self._initialized:
                return
            ready = threading.Event()
            loop = asyncio.new_event_loop()

            def _runner() -> None:
                asyncio.set_event_loop(loop)
                ready.set()
                try:
                    loop.run_forever()
                finally:
                    loop.close()

            thread = threading.Thread(
                target=_runner,
                name="audit-yasa-mcp",
                daemon=True,
            )
            thread.start()
            if not ready.wait(timeout=10.0):
                logger.warning("shared YASA MCP event loop failed to start in time")
                self._initialized = True
                return

            async def _open() -> tuple[AsyncExitStack, Any | None]:
                stack = AsyncExitStack()
                try:
                    session = await stack.enter_async_context(
                        self._opener(self._settings, self._repository)
                    )
                    return stack, session
                except Exception:
                    await stack.aclose()
                    raise

            timeout = max(15, int(getattr(self._settings, "yasa_mcp_timeout", 60) or 60) + 15)
            try:
                stack, session = asyncio.run_coroutine_threadsafe(_open(), loop).result(
                    timeout=timeout
                )
            except Exception as exc:
                logger.warning("shared YASA MCP open failed: %s", exc, exc_info=True)
                loop.call_soon_threadsafe(loop.stop)
                thread.join(timeout=5.0)
                self._initialized = True
                return

            if session is None:
                try:
                    asyncio.run_coroutine_threadsafe(stack.aclose(), loop).result(timeout=5.0)
                except Exception:
                    pass
                loop.call_soon_threadsafe(loop.stop)
                thread.join(timeout=5.0)
                self._initialized = True
                return

            self._loop = loop
            self._thread = thread
            self._stack = stack
            self._session = session
            self._initialized = True

    def close(self) -> None:
        """Close the shared MCP session and stop its background event loop."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            loop = self._loop
            thread = self._thread
            stack = self._stack
            self._loop = None
            self._thread = None
            self._stack = None
            self._session = None

        if loop is not None and not loop.is_closed():
            if stack is not None:
                try:
                    asyncio.run_coroutine_threadsafe(stack.aclose(), loop).result(timeout=10.0)
                except Exception as exc:
                    logger.warning("shared YASA MCP shutdown failed: %s", exc, exc_info=True)
            try:
                loop.call_soon_threadsafe(loop.stop)
            except RuntimeError:
                pass
        if thread is not None and thread.is_alive():
            thread.join(timeout=5.0)


@asynccontextmanager
async def use_yasa_mcp(
    context: Any,
    repository: Path,
    *,
    fallback_opener: Callable[[Any, Path], Any] | None = None,
) -> AsyncIterator[Any | None]:
    """Use the stage-shared MCP pool when present, else open a local session."""
    pool = getattr(context, "yasa_mcp", None)
    if pool is not None:
        session = await pool.acquire()
        yield session
        return
    opener = fallback_opener or open_yasa_mcp
    async with opener(context.settings, repository) as session:
        yield session
