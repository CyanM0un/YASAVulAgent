from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from yasa_vulnagent.config import Settings
from yasa_vulnagent.stages.discover.schema import empty_state
from yasa_vulnagent.stages.discover.ledger import DiscoverLedger
from yasa_vulnagent.stages.discover import graph as discover_graph
from yasa_vulnagent.stages.discover.screen import harness
from yasa_vulnagent.stages.discover.screen.node import (
    _replay_unprocessed_tasks,
    _restore_completed_tasks,
    screen,
)
from yasa_vulnagent.stages.discover.screen.tools import SourceToolbox
from yasa_vulnagent.stages.discover.screen.graph import validate_response
from yasa_vulnagent.stages.discover.storage import write_json
from yasa_vulnagent.workflow.state import RunContext


class _Response:
    def __init__(self, content: str, tool_calls=None) -> None:
        self.content = content
        self.tool_calls = tool_calls or []


class _Model:
    def __init__(self, *, read_file: bool = False) -> None:
        self.prompts: list[str] = []
        self.read_file = read_file

    def bind_tools(self, tools):
        self.tools = {tool.name: tool for tool in tools}
        return self

    def invoke(self, messages):
        self.prompts.append(str(messages[-1].content))
        if self.read_file and len(messages) == 2:
            return _Response(
                "",
                [{"id": "read-1", "name": "read_file", "args": {"path": "src/main.py"}}],
            )
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


class DiscoverScreenTest(unittest.TestCase):
    def _state(self, root: Path):
        repository = root / "repository"
        (repository / "src").mkdir(parents=True)
        (repository / "src" / "main.py").write_text("value = input()\n", encoding="utf-8")
        artifact_dir = root / "artifacts"
        state = empty_state(
            str(repository),
            str(artifact_dir),
            str(artifact_dir / "state.json"),
            {"status": "partial"},
        )
        with DiscoverLedger.open(artifact_dir / "ledger.sqlite") as ledger:
            ledger.replace_inventory(
                [
                    {
                        "path": "src/main.py",
                        "status": "pending",
                        "usage_hint": "production-candidate",
                        "content_type": "text",
                    }
                ],
                [],
            )
        return state

    def _context(self, root: Path, model: _Model) -> RunContext:
        settings = Settings(
            api_key="test-key",
            base_url="https://example.invalid",
            model="test-model",
            yasa_source_path=root / "missing-yasa",
            yasa_bin_path=root / "missing-bin",
            screen_wave_timeout=10,
        )
        return RunContext(settings=settings, model=model)

    def test_first_wave_runs_three_isolated_views_and_persists_tasks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            model = _Model()
            state = self._state(root)
            result = screen(state, SimpleNamespace(context=self._context(root, model)))

            with DiscoverLedger.open(Path(result["ledger_file"])) as ledger:
                tasks = ledger.list_tasks()
            views = {task["view"] for task in tasks}
            self.assertTrue(
                {"component-runtime", "input-boundary", "independent-exploration"}.issubset(views)
            )
            self.assertTrue(
                all(
                    task["status"] == "complete"
                    for task in tasks
                    if task.get("view") in {"component-runtime", "input-boundary", "independent-exploration"}
                )
            )
            self.assertTrue(result["screen"]["initial_wave_complete"])
            self.assertTrue((root / "artifacts" / "screen" / "waves" / "wave-0001.json").is_file())
            contexts = [json.loads(prompt) for prompt in model.prompts]
            self.assertEqual(sum("init_context" in item for item in contexts), 2)
            self.assertEqual(sum("init_context" not in item for item in contexts), 1)

    def test_read_receipt_closes_file_only_after_full_source_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            model = _Model(read_file=True)
            result = screen(
                self._state(root),
                SimpleNamespace(context=self._context(root, model)),
            )
            with DiscoverLedger.open(Path(result["ledger_file"])) as ledger:
                tasks = ledger.list_tasks()
            self.assertTrue(
                all(
                    not task["result"]["coverage_complete"]
                    for task in tasks
                    if task.get("view") in {"component-runtime", "input-boundary", "independent-exploration"}
                )
            )
            with DiscoverLedger.open(Path(result["ledger_file"])) as ledger:
                self.assertEqual(ledger.get_file("src/main.py")["status"], "screened")
            self.assertTrue(
                all(any(item["tool"] == "read_file" for item in task["tool_receipts"]) for task in tasks)
            )

    def test_completed_task_artifact_is_restored_without_rerunning(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            model = _Model()
            state = self._state(root)
            first = screen(state, SimpleNamespace(context=self._context(root, model)))
            resumed = dict(first)
            with DiscoverLedger.open(Path(first["ledger_file"])) as ledger:
                for task in ledger.list_tasks():
                    if task.get("view") not in {"component-runtime", "input-boundary", "independent-exploration"}:
                        task["status"] = "complete"
                        ledger.put_task(task)
                        continue
                    task["status"] = "running"
                    ledger.put_task(task)
            second_model = _Model()
            second = screen(resumed, SimpleNamespace(context=self._context(root, second_model)))
            with DiscoverLedger.open(Path(second["ledger_file"])) as ledger:
                tasks = ledger.list_tasks()
            self.assertTrue(all(task["status"] == "complete" for task in tasks))
            self.assertEqual(len(second_model.prompts), 1)
            self.assertIn("work_board", second_model.prompts[0])

    def test_source_toolbox_rejects_outside_paths_and_records_truncation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            (repository / "main.py").write_text("x" * 1500 + "\n", encoding="utf-8")
            toolbox = SourceToolbox(repository, ["main.py"], max_output_chars=20)
            self.assertIn("error", toolbox.read_file("../outside.py"))
            payload = toolbox.read_file("main.py")
            self.assertTrue(payload["truncated"])
            self.assertTrue(any(item.get("tool") == "read_file" for item in toolbox.receipts))


    def test_query_scope_outside_the_task_is_dropped_not_widened(self) -> None:
        response = json.dumps(
            {
                "scope_status": "complete",
                "summary": "checked",
                "candidates": [],
                "negative_results": [],
                "unknowns": [],
                "deferred_items": [],
                "feature_observations": [
                    {
                        "kind": "text",
                        "name": "input",
                        "role": "source",
                        "definition": {
                            "path": "src/main.py",
                            "line_start": 1,
                            "line_end": 1,
                        },
                        "evidence_refs": ["source:src/main.py:1-1"],
                        "query": {
                            "kind": "text",
                            "target": "input",
                            "regex": False,
                            "scope": ["outside.py"],
                        },
                    }
                ],
            }
        )
        result = validate_response(
            response,
            {"task_id": "screen-0001"},
            allowed_paths={"src/main.py"},
        )
        self.assertEqual(result["feature_observations"], [])

    def test_outer_guard_stops_an_unchanged_review_cycle(self) -> None:
        state = discover_graph._record_transition({}, "screen", "confirm")
        state = discover_graph._record_transition(state, "confirm", "review")
        state = discover_graph._record_transition(state, "review", "screen")
        state = discover_graph._record_transition(state, "screen", "confirm")
        state = discover_graph._record_transition(state, "confirm", "review")
        state = discover_graph._record_transition(state, "review", "screen")
        self.assertEqual(state["next_action"], "finalize")
        self.assertEqual(state["stop_reason"], "no_progress")


if __name__ == "__main__":
    unittest.main()


class _FeatureModel(_Model):
    def __init__(self, *, read: bool = True) -> None:
        super().__init__()
        self.read = read

    def invoke(self, messages):
        self.prompts.append(str(messages[-1].content))
        if self.read and len(messages) == 2:
            return _Response(
                "",
                [{"id": "read-1", "name": "read_file", "args": {"path": "src/main.py"}}],
            )
        return _Response(
            json.dumps(
                {
                    "scope_status": "partial",
                    "summary": "found annotation",
                    "candidates": [],
                    "negative_results": [],
                    "unknowns": [],
                    "follow_up": [],
                    "deferred_items": [],
                    "feature_observations": [
                        {
                            "kind": "text",
                            "name": "input",
                            "role": "source",
                            "definition": {
                                "path": "src/main.py",
                                "line_start": 1,
                                "line_end": 1,
                            },
                            "evidence_refs": ["source:src/main.py:1-1"],
                            "query": {
                                "kind": "text",
                                "target": "input",
                                "regex": False,
                                "scope": [],
                                "max_results": 20,
                            },
                        }
                    ],
                }
            )
        )


class DiscoverScreenLimitTest(unittest.TestCase):
    def test_wave_passes_configured_task_rounds(self) -> None:
        captured: dict[str, object] = {}

        class _CaptureExecution:
            def __init__(self, **kwargs):
                captured.update(kwargs)

        class _NullSession:
            async def __aenter__(self):
                return None

            async def __aexit__(self, *_exc):
                return False

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = Settings(
                api_key="test-key",
                base_url="https://example.invalid",
                model="test-model",
                screen_task_max_rounds=7,
            )
            context = RunContext(settings=settings)
            with (
                patch.object(harness, "ScreenExecution", _CaptureExecution),
                patch.object(harness, "build_model", return_value=object()),
                patch.object(harness, "open_yasa_mcp", return_value=_NullSession()),
            ):
                results, metadata = harness.run_wave(
                    [],
                    repository=root,
                    artifact_dir=root,
                    context=context,
                    init_context={},
                    ledger=None,
                )

        self.assertEqual(results, [])
        self.assertEqual(metadata["task_count"], 0)
        self.assertEqual(captured["max_rounds"], 7)


class DiscoverScreenFeatureTest(unittest.TestCase):
    def test_feature_observation_without_a_read_is_dropped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            test = DiscoverScreenTest()
            state = test._state(root)
            model = _FeatureModel(read=False)
            result = screen(state, SimpleNamespace(context=test._context(root, model)))
            with DiscoverLedger.open(Path(result["ledger_file"])) as ledger:
                self.assertEqual(ledger.entries(status="candidate"), [])
                self.assertEqual(ledger.query_rows(), [])
            self.assertEqual(result["screen"]["features"]["candidates"], 0)
            self.assertTrue(
                any(
                    "not read in this task" in item
                    for item in result["screen"]["features"]["warnings"]
                )
            )

    def test_screen_observation_creates_global_candidate_and_confirm_task(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            test = DiscoverScreenTest()
            state = test._state(root)
            model = _FeatureModel()
            result = screen(state, SimpleNamespace(context=test._context(root, model)))
            with DiscoverLedger.open(Path(result["ledger_file"])) as ledger:
                self.assertEqual(len(ledger.entries(status="candidate")), 1)
                tasks = ledger.list_tasks(kind_prefix="confirm")
                self.assertEqual(len(tasks), 1)
                self.assertEqual(tasks[0]["candidate_ids"], [ledger.entries(status="candidate")[0]["entry_id"]])
                self.assertEqual(ledger.query_rows()[0]["target"], "input")
                self.assertGreaterEqual(
                    ledger.connection.execute("SELECT COUNT(*) FROM read_receipts").fetchone()[0],
                    1,
                )
            self.assertEqual(result["next_action"], "confirm")
            self.assertTrue(result["screen"]["features"].get("observations"))


class DiscoverScreenRecoveryTest(unittest.TestCase):
    def test_restore_commits_receipts_and_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = DiscoverScreenTest()._state(root)
            artifact_dir = Path(state["artifact_dir"])
            receipt = {
                "tool": "read_file",
                "path": "src/main.py",
                "start_line": 1,
                "end_line": 1,
                "total_lines": 1,
                "truncated": False,
                "status": "ok",
            }
            saved = {
                "task_id": "screen-0001",
                "kind": "screen",
                "status": "complete",
                "scope_type": "explicit",
                "scope_paths": ["src/main.py"],
                "coverage_required": False,
                "read_ranges": [receipt],
                "tool_receipts": [receipt],
                "candidates": [
                    {
                        "path": "src/main.py",
                        "line_start": 1,
                        "line_end": 1,
                        "kind": "input-candidate",
                        "summary": "restored candidate",
                    }
                ],
                "unknowns": [],
                "deferred": [],
                "follow_up": [],
            }
            with DiscoverLedger.open(Path(state["ledger_file"])) as ledger:
                ledger.put_task(
                    {
                        "task_id": "screen-0001",
                        "kind": "screen",
                        "status": "running",
                        "scope_type": "explicit",
                        "scope_paths": ["src/main.py"],
                        "coverage_required": False,
                    }
                )
            write_json(artifact_dir / "screen" / "tasks" / "screen-0001.json", saved)

            with DiscoverLedger.open(Path(state["ledger_file"])) as ledger:
                restored = _restore_completed_tasks(ledger, artifact_dir)
                receipt_count = ledger.connection.execute(
                    "SELECT COUNT(*) FROM read_receipts"
                ).fetchone()[0]

                self.assertEqual(len(restored), 1)
                self.assertEqual(ledger.get_task("screen-0001")["status"], "complete")
                self.assertEqual(receipt_count, 1)
                self.assertEqual(len(ledger.entries(status="candidate")), 1)
                self.assertFalse(restored[0].get("derived_processed", False))

    def test_unprocessed_feature_observation_is_replayed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = DiscoverScreenTest()._state(root)
            artifact_dir = Path(state["artifact_dir"])
            repository = Path(state["repository"])
            receipt = {
                "tool": "read_file",
                "path": "src/main.py",
                "start_line": 1,
                "end_line": 1,
                "total_lines": 1,
                "truncated": False,
                "status": "ok",
            }
            task = {
                "task_id": "screen-0001",
                "kind": "screen",
                "status": "complete",
                "scope_type": "explicit",
                "scope_paths": ["src/main.py"],
                "coverage_required": False,
                "read_ranges": [receipt],
                "tool_receipts": [receipt],
                "feature_observations": [
                    {
                        "kind": "text",
                        "name": "input",
                        "role": "source",
                        "definition": {
                            "path": "src/main.py",
                            "line_start": 1,
                            "line_end": 1,
                        },
                        "evidence_refs": ["source:src/main.py:1-1"],
                        "query": {
                            "kind": "text",
                            "target": "input",
                            "regex": False,
                            "scope": [],
                            "max_results": 20,
                        },
                    }
                ],
                "candidates": [],
                "unknowns": [],
                "deferred": [],
                "follow_up": [],
            }
            with DiscoverLedger.open(Path(state["ledger_file"])) as ledger:
                ledger.put_task(task)

            with DiscoverLedger.open(Path(state["ledger_file"])) as ledger:
                first = _replay_unprocessed_tasks(
                    ledger,
                    repository,
                    artifact_dir,
                    wave=1,
                    settings=None,
                )
                candidate_count = len(ledger.entries(status="candidate"))
                second = _replay_unprocessed_tasks(
                    ledger,
                    repository,
                    artifact_dir,
                    wave=1,
                    settings=None,
                )

                self.assertEqual(first["tasks"], 1)
                self.assertEqual(ledger.get_task("screen-0001")["derived_processed"], True)
                self.assertEqual(ledger.count_mechanisms(), 1)
                self.assertEqual(ledger.count_feature_queries(), 1)
                self.assertEqual(candidate_count, 1)
                self.assertEqual(second["tasks"], 0)
                self.assertEqual(len(ledger.entries(status="candidate")), candidate_count)
