from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from yasa_vulnagent.stages.discover.screen.mcp import open_yasa_mcp

_REQUIRED_TOOLS = ("search_symbol", "get_function", "get_class_by_name", "get_import_by_file")


class _FakeStdio:
    def __init__(self, *_args: object, **_kwargs: object) -> None:
        pass

    async def __aenter__(self):
        return SimpleNamespace(), SimpleNamespace()

    async def __aexit__(self, *_exc: object) -> bool:
        return False


class _FakeSession:
    tool_names: tuple[str, ...] = _REQUIRED_TOOLS
    initialize_error: Exception | None = None

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        return False

    async def initialize(self) -> None:
        if self.initialize_error is not None:
            raise self.initialize_error

    async def list_tools(self):
        return SimpleNamespace(tools=[SimpleNamespace(name=name) for name in self.tool_names])


class YasaMcpOpenTest(unittest.TestCase):
    def _settings(self, root: Path) -> SimpleNamespace:
        return SimpleNamespace(
            yasa_source_path=str(root / "source"),
            yasa_bin_path=str(root / "bin"),
            yasa_mcp_timeout=5,
        )

    def _prepare(self, root: Path) -> Path:
        (root / "source" / "src" / "yasa_mcp").mkdir(parents=True)
        (root / "bin").mkdir()
        return root / "repository"

    def test_consumer_exception_propagates_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = self._prepare(root)

            async def run() -> None:
                async with open_yasa_mcp(self._settings(root), repository) as session:
                    self.assertIsNotNone(session)
                    raise ValueError("boom")

            with patch("mcp.client.stdio.stdio_client", _FakeStdio), patch(
                "mcp.ClientSession", _FakeSession
            ):
                with self.assertRaises(ValueError) as captured:
                    asyncio.run(run())
            self.assertEqual(str(captured.exception), "boom")

    def test_setup_failure_yields_none(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = self._prepare(root)

            class _BrokenSession(_FakeSession):
                initialize_error = RuntimeError("no handshake")

            async def run() -> None:
                async with open_yasa_mcp(self._settings(root), repository) as session:
                    self.assertIsNone(session)

            with patch("mcp.client.stdio.stdio_client", _FakeStdio), patch(
                "mcp.ClientSession", _BrokenSession
            ):
                asyncio.run(run())

    def test_missing_tools_yields_none(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = self._prepare(root)

            class _PartialSession(_FakeSession):
                tool_names = ("search_symbol",)

            async def run() -> None:
                async with open_yasa_mcp(self._settings(root), repository) as session:
                    self.assertIsNone(session)

            with patch("mcp.client.stdio.stdio_client", _FakeStdio), patch(
                "mcp.ClientSession", _PartialSession
            ):
                asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
