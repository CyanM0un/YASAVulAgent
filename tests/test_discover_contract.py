from __future__ import annotations

import inspect
import unittest
from importlib.resources import files

from yasa_vulnagent.agent.tools import render_result
from yasa_vulnagent.config import Settings
from yasa_vulnagent.agent.tokens import TokenCounter
from yasa_vulnagent.stages.discover.confirm import node as confirm_node
from yasa_vulnagent.stages.discover.review import node as review_node
from yasa_vulnagent.stages.discover.screen import graph as screen_graph
from yasa_vulnagent.stages.discover.screen import model as screen_model
from yasa_vulnagent.stages.discover.screen import planner


class DiscoverContractTest(unittest.TestCase):
    def test_discover_modules_use_the_shared_agent_loop(self) -> None:
        for module in (screen_graph, confirm_node, review_node, planner):
            source = inspect.getsource(module)
            self.assertIn("run_task_agent", source, module.__name__)
        self.assertFalse(hasattr(screen_model, "invoke_model"))
        self.assertFalse(hasattr(screen_model, "load_skill"))
        self.assertIn("discover_request_timeout", inspect.getsource(screen_model.build_configured_model))

    def test_screen_prompt_is_the_single_contract_source(self) -> None:
        prompt = files("yasa_vulnagent.stages.discover.screen").joinpath(
            "prompts", "screen.md"
        ).read_text(encoding="utf-8")
        for key in (
            "scope_status",
            "negative_results",
            "deferred_items",
            "feature_observations",
            "save_note",
            "must not read one another's conclusions",
        ):
            self.assertIn(key, prompt)
        skill = files("yasa_vulnagent.stages.discover.screen").joinpath(
            "SKILL.md"
        ).read_text(encoding="utf-8")
        self.assertLess(len(skill), 1500)
        self.assertNotIn("```json", skill)

    def test_discover_settings_have_harness_defaults(self) -> None:
        settings = Settings(api_key=None, base_url="http://localhost", model="m")
        self.assertGreater(settings.discover_context_tokens, 0)
        self.assertEqual(settings.discover_request_timeout, 180)
        self.assertEqual(settings.discover_notes_max, 20)
        self.assertEqual(settings.discover_note_chars, 2000)
        self.assertGreater(settings.discover_search_max_file_bytes, 0)
        self.assertGreater(settings.discover_search_max_scan_files, 0)

    def test_loop_receipts_keep_total_lines(self) -> None:
        counter = TokenCounter("gpt-4o-mini", 1.0)
        _, receipt = render_result(
            tool="read_file",
            arguments={"path": "a.py"},
            result={
                "status": "ok",
                "path": "a.py",
                "start_line": 1,
                "end_line": 10,
                "total_lines": 10,
                "text": "x",
            },
            counter=counter,
            max_tokens=100,
            store=None,
        )
        self.assertEqual(receipt["total_lines"], 10)
        self.assertEqual(receipt["tool"], "read_file")


if __name__ == "__main__":
    unittest.main()
