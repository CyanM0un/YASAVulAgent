from __future__ import annotations

import asyncio
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from yasa_vulnagent.config import PROJECT_ROOT
from yasa_vulnagent.stages.init.yasa.runner import YasaError, YasaRunner, _mcp_content_json


class YasaRunnerTest(unittest.TestCase):
    def _runner(self, **kwargs: int) -> YasaRunner:
        return YasaRunner(Path("tools/yasa-mcp"), Path("tools/yasa"), **kwargs)

    def test_run_orders_initialization_status_and_probe(self) -> None:
        events: list[str] = []
        runner = self._runner()
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            with (
                patch.object(runner, "_check_paths", side_effect=lambda: events.append("check")),
                patch.object(runner, "initialize", side_effect=lambda _: events.append("init")),
                patch.object(
                    runner,
                    "status",
                    side_effect=lambda _: events.append("status") or {"valid": True},
                ),
                patch.object(
                    runner,
                    "probe_mcp",
                    side_effect=lambda _: events.append("probe")
                    or {"tool": "get_function", "result_count": 0},
                ),
            ):
                result = runner.run(repository)

        self.assertEqual(events, ["check", "init", "status", "probe"])
        self.assertEqual(result["mcp_result_count"], 0)

    def test_state_relative_tool_paths_are_anchored_to_project_root(self) -> None:
        runner = YasaRunner.from_state(
            {
                "config": {
                    "yasa_source_path": "tools/yasa-mcp",
                    "yasa_bin_path": "tools/yasa",
                }
            }
        )

        self.assertEqual(runner.source_path, (PROJECT_ROOT / "tools/yasa-mcp").resolve())
        self.assertEqual(runner.bin_path, (PROJECT_ROOT / "tools/yasa").resolve())

    def test_invalid_status_stops_before_mcp_probe(self) -> None:
        runner = self._runner()
        completed = subprocess.CompletedProcess(
            ["status"], 0, '{"valid": false, "state": "无分析结果"}', ""
        )
        with patch.object(runner, "_run_cli", return_value=completed), self.assertRaises(YasaError):
            runner.status(Path("/tmp/repository"))

    def test_empty_mcp_result_is_accepted(self) -> None:
        runner = self._runner()
        with patch.object(
            runner,
            "_probe_mcp",
            new=AsyncMock(return_value={"tool": "get_function", "result_count": 0}),
        ):
            result = runner.probe_mcp(Path("/tmp/repository"))

        self.assertEqual(result, {"tool": "get_function", "result_count": 0})

    def test_probe_timeout_becomes_yasa_error(self) -> None:
        runner = self._runner(mcp_timeout=1)

        async def never_finishes(_repository):
            await asyncio.sleep(10)

        with patch.object(runner, "_probe_mcp", side_effect=never_finishes), self.assertRaisesRegex(
            YasaError, "timed out"
        ):
            runner.probe_mcp(Path("/tmp/repository"))

    def test_mcp_payload_reader_accepts_structured_content(self) -> None:
        class Result:
            structuredContent = {"results": []}
            content = []

        self.assertEqual(_mcp_content_json(Result()), {"results": []})

    def test_mcp_payload_reader_accepts_json_text(self) -> None:
        class Item:
            text = json.dumps({"results": []})

        class Result:
            content = [Item()]

        self.assertEqual(_mcp_content_json(Result()), {"results": []})


if __name__ == "__main__":
    unittest.main()
