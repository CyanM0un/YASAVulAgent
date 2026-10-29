from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from yasa_vulnagent.config import Settings
from yasa_vulnagent.stages.discover.ledger import DiscoverLedger
from yasa_vulnagent.stages.discover.schema import empty_state
from yasa_vulnagent.stages.discover.screen.node import _select_tasks, screen
from yasa_vulnagent.stages.discover.screen.planner import validate_new_tasks
from yasa_vulnagent.stages.discover.screen.repo_map import PlannerToolbox
from yasa_vulnagent.workflow.state import RunContext


class _Response:
    def __init__(self, content: str) -> None:
        self.content = content
        self.tool_calls = []


class _Model:
    def __init__(self, planner_responses: list[str] | None = None) -> None:
        self.planner_responses = list(planner_responses or [])
        self.prompts: list[str] = []

    def bind_tools(self, tools):
        self.tools = {tool.name: tool for tool in tools}
        return self

    def invoke(self, messages):
        prompt = str(messages[-1].content)
        self.prompts.append(prompt)
        if '"work_board"' in prompt:
            return _Response(self.planner_responses.pop(0) if self.planner_responses else "not json")
        return _Response(
            json.dumps(
                {
                    "scope_status": "complete",
                    "summary": "checked",
                    "candidates": [],
                    "negative_results": [],
                    "unknowns": [],
                    "follow_up": [],
                }
            )
        )


class DiscoverPlannerTest(unittest.TestCase):
    def _state(self, root: Path):
        repository = root / "repository"
        (repository / "src").mkdir(parents=True)
        (repository / "src" / "config.py").write_text("value = input()\n", encoding="utf-8")
        artifact_dir = root / "artifacts"
        state = empty_state(
            str(repository),
            str(artifact_dir),
            str(artifact_dir / "state.json"),
            {"status": "partial"},
        )
        state["screen"] = {"initial_wave_complete": True, "wave": 1}
        with DiscoverLedger.open(artifact_dir / "ledger.sqlite") as ledger:
            ledger.replace_inventory(
                [
                    {
                        "path": "src/config.py",
                        "size": 16,
                        "status": "pending",
                        "usage_hint": "production-candidate",
                        "content_type": "text",
                    }
                ],
                [],
            )
        settings = Settings(
            api_key="test-key",
            base_url="https://example.invalid",
            model="test-model",
            yasa_source_path=root / "missing-yasa",
            yasa_bin_path=root / "missing-bin",
            screen_wave_timeout=10,
        )
        return state, settings

    def test_planner_creates_grounded_bounded_task_and_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, settings = self._state(root)
            model = _Model(
                [
                    json.dumps(
                        {
                            "selected_task_ids": [],
                            "new_tasks": [
                                {
                                    "source": "coverage_debt",
                                    "source_refs": ["file:src/config.py"],
                                    "paths": ["src/config.py"],
                                    "question": "Check configuration loading.",
                                    "reason": "Unread file.",
                                }
                            ],
                            "notes": "",
                        }
                    )
                ]
            )
            result = screen(
                state,
                SimpleNamespace(context=RunContext(settings=settings, model=model)),
            )
            with DiscoverLedger.open(Path(result["ledger_file"])) as ledger:
                tasks = ledger.list_tasks()
            created = [task for task in tasks if task.get("kind") == "screen_coverage"]
            self.assertEqual(len(created), 1)
            self.assertEqual(created[0]["scope_type"], "explicit")
            self.assertEqual(created[0]["scope_count"], 1)
            self.assertTrue(created[0]["coverage_required"])
            self.assertEqual(result["screen"]["planner"]["status"], "planned")
            artifact = root / "artifacts" / "screen" / "plans" / "wave-0002.json"
            self.assertTrue(artifact.is_file())
            self.assertTrue((root / "artifacts" / "screen" / "repo-map.json").is_file())

    def test_planner_failure_does_not_generate_fallback_tasks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, settings = self._state(root)
            model = _Model(["not json", "still not json"])
            result = screen(
                state,
                SimpleNamespace(context=RunContext(settings=settings, model=model)),
            )
            with DiscoverLedger.open(Path(result["ledger_file"])) as ledger:
                tasks = ledger.list_tasks()
            self.assertFalse(tasks)
            self.assertEqual(result["screen"]["planner"]["status"], "failed")
            artifact = json.loads(
                (root / "artifacts" / "screen" / "plans" / "wave-0002.json").read_text()
            )
            self.assertEqual(artifact["status"], "failed")
            self.assertFalse(artifact["fallback"])
            self.assertEqual(len([prompt for prompt in model.prompts if "work_board" in prompt]), 2)


    def test_stagnation_stops_planner_without_inventing_tasks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, settings = self._state(root)
            state["screen"]["waves_without_new_candidate"] = 3
            model = _Model()
            result = screen(
                state,
                SimpleNamespace(context=RunContext(settings=settings, model=model)),
            )
            with DiscoverLedger.open(Path(result["ledger_file"])) as ledger:
                self.assertFalse(ledger.list_tasks())
            self.assertEqual(model.prompts, [])
            self.assertEqual(result["screen"]["planner"]["status"], "skipped")
            self.assertEqual(result["next_action"], "review")

    def test_existing_pending_tasks_keep_slots_before_new_tasks(self) -> None:
        pending = [
            {"task_id": "screen-0002", "status": "pending"},
            {"task_id": "screen-0003", "status": "pending"},
        ]
        selected = _select_tasks(pending, ["screen-0003"], 2)
        self.assertEqual([task["task_id"] for task in selected], ["screen-0003", "screen-0002"])

    def test_planner_tools_expose_summaries_not_source(self) -> None:
        toolbox = PlannerToolbox(None, {})
        names = {tool.name for tool in toolbox.langchain_tools()}
        self.assertIn("repo_overview", names)
        self.assertNotIn("read_file", names)
        self.assertNotIn("search_text", names)

    def test_new_task_validation_rejects_ungrounded_or_oversized_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with DiscoverLedger.open(root / "ledger.sqlite") as ledger:
                ledger.replace_inventory(
                    [
                        {
                            "path": "main.py",
                            "size": 50000,
                            "status": "pending",
                            "usage_hint": "production-candidate",
                            "content_type": "text",
                        }
                    ],
                    [],
                )
                tasks, rejected = validate_new_tasks(
                    [
                        {
                            "source": "coverage_debt",
                            "source_refs": ["file:main.py"],
                            "paths": ["main.py"],
                            "question": "Too large",
                        }
                    ],
                    ledger=ledger,
                    next_number=1,
                    wave=2,
                    max_new_tasks=2,
                    max_files=8,
                    max_chars=40000,
                )
                self.assertFalse(tasks)
                self.assertTrue(rejected)


if __name__ == "__main__":
    unittest.main()
