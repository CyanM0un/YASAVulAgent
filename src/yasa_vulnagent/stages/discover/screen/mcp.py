from __future__ import annotations

import asyncio
import logging
import os
import sys
from contextlib import AsyncExitStack, asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator

from ....config import DEFAULT_YASA_BIN_PATH, DEFAULT_YASA_SOURCE_PATH, resolve_project_path


logger = logging.getLogger(__name__)


def _environment(source_path: Path, bin_path: Path) -> dict[str, str]:
    environment = os.environ.copy()
    source = str(source_path / "src")
    existing = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = source if not existing else source + os.pathsep + existing
    environment["YASA_MCP_BIN_DIR"] = str(bin_path)
    return environment


def _runtime_cwd(bin_path: Path) -> Path:
    if not bin_path.is_dir():
        return bin_path
    for platform_root in sorted(bin_path.iterdir()):
        candidate = platform_root / "yasa"
        if (candidate / "node_modules").is_dir():
            return candidate
    return bin_path


async def _drain(stack: AsyncExitStack) -> None:
    """Close the MCP stack; teardown errors are logged, never raised into the caller."""
    try:
        await stack.aclose()
    except Exception as exc:
        logger.warning("discover screen YASA MCP shutdown failed: %s", exc, exc_info=True)


@asynccontextmanager
async def open_yasa_mcp(
    settings: Any,
    repository: Path,
) -> AsyncIterator[Any | None]:
    """Open one read-only YASA MCP session for a screen wave.

    The MCP connection is runtime-only. If the bundled source or native cache
    is unavailable, the caller receives ``None`` and can fall back to source
    reads while retaining the gap in the durable task receipt.
    """
    source_path = resolve_project_path(
        getattr(settings, "yasa_source_path", DEFAULT_YASA_SOURCE_PATH)
    ).expanduser().resolve()
    bin_path = resolve_project_path(
        getattr(settings, "yasa_bin_path", DEFAULT_YASA_BIN_PATH)
    ).expanduser().resolve()
    if not (source_path / "src" / "yasa_mcp").is_dir() or not bin_path.is_dir():
        logger.info(
            "discover screen YASA MCP unavailable source=%s bin=%s",
            source_path,
            bin_path,
        )
        yield None
        return

    try:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
    except ImportError:
        logger.warning("discover screen YASA MCP unavailable: Python mcp package is missing")
        yield None
        return

    server = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "yasa_mcp",
            "server",
            "--transport",
            "stdio",
            "--bin",
            str(bin_path),
        ],
        env=_environment(source_path, bin_path),
        cwd=str(_runtime_cwd(bin_path)),
    )
    stack = AsyncExitStack()
    try:
        read_stream, write_stream = await stack.enter_async_context(stdio_client(server))
        session = await stack.enter_async_context(ClientSession(read_stream, write_stream))
        timeout = max(1, int(getattr(settings, "yasa_mcp_timeout", 60)))
        await asyncio.wait_for(session.initialize(), timeout=timeout)
        listed = await asyncio.wait_for(session.list_tools(), timeout=timeout)
    except Exception as exc:
        logger.warning("discover screen YASA MCP failed: %s", exc, exc_info=True)
        await _drain(stack)
        yield None
        return
    names = {tool.name for tool in listed.tools}
    missing = {"search_symbol", "get_function", "get_class_by_name", "get_import_by_file"} - names
    if missing:
        logger.warning("discover screen YASA MCP missing tools=%s", sorted(missing))
        await _drain(stack)
        yield None
        return
    logger.info(
        "discover screen YASA MCP ready repository=%s tools=%s",
        repository,
        len(names),
    )
    try:
        yield session
    finally:
        await _drain(stack)
