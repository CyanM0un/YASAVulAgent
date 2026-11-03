from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from langgraph.errors import GraphRecursionError

from yasa_vulnagent.stages.discover import graph as discover_graph
from yasa_vulnagent.stages.discover.ledger import DiscoverLedger
from yasa_vulnagent.stages.discover.node import run_stage
from yasa_vulnagent.config import Settings
from yasa_vulnagent.stages.discover.schema import empty_state
from yasa_vulnagent.workflow.runner import run_discover
from yasa_vulnagent.workflow.state import RunContext


class DiscoverGraphTest(unittest.TestCase):
    def test_nodes_run_in_outer_order(self) -> None:
        events: list[str] = []

        def record(name: str):
            def node(state, runtime=None):
                del state
                del runtime
                events.append(name)
                return {}

            return node

        with (
            patch.object(discover_graph, "prepare", side_effect=record("prepare")),
            patch.object(discover_graph, "screen", side_effect=record("screen")),
            patch.object(discover_graph, "confirm", side_effect=record("confirm")),
            patch.object(discover_graph, "review", side_effect=record("review")),
            patch.object(discover_graph, "finalize", side_effect=record("finalize")),
        ):
            discover_graph.build_discover_graph().invoke({})

        self.assertEqual(events, ["prepare", "screen", "confirm", "review", "finalize"])

    def test_explicit_route_can_loop_back_to_screen(self) -> None:
        events: list[str] = []
        review_calls = 0

        def node(name: str, result=None):
            def run(state, runtime=None):
                del state, runtime
                events.append(name)
                return result or {}

            return run

        def review_node(state, runtime=None):
            del state, runtime
            nonlocal review_calls
            review_calls += 1
            events.append("review")
            return {"next_action": "screen" if review_calls == 1 else "finalize"}

        with (
            patch.object(discover_graph, "prepare", side_effect=node("prepare")),
            patch.object(discover_graph, "screen", side_effect=node("screen")),
            patch.object(discover_graph, "confirm", side_effect=node("confirm")),
            patch.object(discover_graph, "review", side_effect=review_node),
            patch.object(discover_graph, "finalize", side_effect=node("finalize")),
        ):
            discover_graph.build_discover_graph().invoke({})

        self.assertEqual(
            events,
            ["prepare", "screen", "confirm", "review", "screen", "confirm", "review", "finalize"],
        )

    def test_no_progress_forces_finalize(self) -> None:
        first = discover_graph._record_transition({}, "screen", "screen")

        second = discover_graph._record_transition(first, "screen", "screen")

        self.assertEqual(second["next_action"], "finalize")
        self.assertEqual(second["stop_reason"], "no_progress")
        self.assertTrue(second["loop_guard"]["stalled"])
        self.assertTrue(any("without changing" in gap for gap in second["gaps"]))

    def test_confirm_review_cycle_is_stopped(self) -> None:
        state = discover_graph._record_transition({}, "confirm", "review")
        state = discover_graph._record_transition(state, "review", "confirm")
        state = discover_graph._record_transition(state, "confirm", "review")
        state = discover_graph._record_transition(state, "review", "confirm")

        self.assertEqual(state["next_action"], "finalize")
        self.assertEqual(state["stop_reason"], "no_progress")
        self.assertTrue(state["loop_guard"]["stalled"])
        self.assertTrue(any("without changing" in gap for gap in state["gaps"]))

    def test_review_counters_do_not_hide_a_stalled_cycle(self) -> None:
        state = discover_graph._record_transition(
            {"review": {"round": 1, "model_calls": 1}}, "review", "screen"
        )
        state = discover_graph._record_transition(state, "screen", "confirm")
        state = discover_graph._record_transition(state, "confirm", "review")
        state = discover_graph._record_transition(
            {**state, "review": {"round": 2, "model_calls": 7}}, "review", "screen"
        )
        self.assertEqual(state["next_action"], "finalize")
        self.assertEqual(state["stop_reason"], "no_progress")

    def test_review_loop_is_not_limited_to_two_rounds(self) -> None:
        review_calls = 0

        def node(result=None):
            def run(state, runtime=None):
                del state, runtime
                return result or {}

            return run

        def review_node(state, runtime=None):
            del runtime
            nonlocal review_calls
            review_calls += 1
            return {
                "screen": {"review_round": review_calls},
                "tasks": [
                    {"task_id": f"review-task-{review_calls}", "status": "complete"}
                ],
                "next_action": "confirm" if review_calls <= 3 else "finalize",
            }

        with (
            patch.object(discover_graph, "prepare", side_effect=node()),
            patch.object(discover_graph, "screen", side_effect=node()),
            patch.object(discover_graph, "confirm", side_effect=node()),
            patch.object(discover_graph, "review", side_effect=review_node),
            patch.object(discover_graph, "finalize", side_effect=node()),
        ):
            discover_graph.build_discover_graph().invoke({})

        self.assertEqual(review_calls, 4)

    def test_invalid_next_action_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid action"):
            discover_graph._record_transition({}, "screen", "unknown")

    def test_recursion_limit_is_saved_as_partial(self) -> None:
        class RecursingGraph:
            def invoke(self, *_args, **_kwargs):
                raise GraphRecursionError("limit")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            stages_dir = root / "stages"
            state = {
                "repository": str(repository),
                "stages_dir": str(stages_dir),
                "stages": [{"name": "init", "status": "partial"}],
                "run_file": str(root / "run.json"),
            }

            with patch.object(discover_graph, "build_discover_graph", return_value=RecursingGraph()):
                result = run_stage(state)

            self.assertEqual(result["discover"]["status"], "partial")
            self.assertEqual(result["discover"]["stop_reason"], "recursion_limit")
            self.assertTrue(
                any(
                    "recursion limit" in gap
                    for gap in result["discover"]["gaps"]
                )
            )
            artifact_dir = stages_dir / "discover"
            self.assertTrue((artifact_dir / "index.json").is_file())
            self.assertTrue((artifact_dir / "confirmed-entries.json").is_file())
            persisted = json.loads((artifact_dir / "state.json").read_text(encoding="utf-8"))
            self.assertEqual(persisted["current_node"], "finalize")
            self.assertEqual(persisted["status"], "partial")
            self.assertEqual(persisted["stop_reason"], "recursion_limit")

    def test_recursion_limit_comes_from_settings(self) -> None:
        captured: dict[str, object] = {}

        class _Graph:
            def invoke(self, *_args, **kwargs):
                captured.update(kwargs)
                return {"status": "partial"}

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            state = {
                "repository": str(repository),
                "stages_dir": str(root / "stages"),
                "stages": [{"name": "init", "status": "partial"}],
                "run_file": str(root / "run.json"),
            }
            settings = Settings(
                api_key=None,
                base_url="https://example.invalid",
                model="test-model",
                discover_recursion_limit=77,
            )
            context = RunContext(settings=settings)
            with (
                patch.object(discover_graph, "build_discover_graph", return_value=_Graph()),
                patch("yasa_vulnagent.stages.discover.node.summarize", return_value={"status": "partial"}),
            ):
                run_stage(state, runtime=SimpleNamespace(context=context))

        self.assertEqual(captured["config"], {"recursion_limit": 77})

    def test_discover_timeout_sets_a_deadline_only_when_configured(self) -> None:
        captured: dict[str, object] = {}

        class _Graph:
            def invoke(self, state, **_kwargs):
                captured["state"] = state
                return {"status": "partial"}

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            state = {
                "repository": str(repository),
                "stages_dir": str(root / "stages"),
                "stages": [{"name": "init", "status": "partial"}],
                "run_file": str(root / "run.json"),
            }

            def run(timeout: int) -> dict[str, object]:
                settings = Settings(
                    api_key=None,
                    base_url="https://example.invalid",
                    model="test-model",
                    discover_timeout=timeout,
                )
                context = RunContext(settings=settings)
                with (
                    patch.object(discover_graph, "build_discover_graph", return_value=_Graph()),
                    patch(
                        "yasa_vulnagent.stages.discover.node.summarize",
                        return_value={"status": "partial"},
                    ),
                ):
                    run_stage(state, runtime=SimpleNamespace(context=context))
                return dict(captured["state"])

            unlimited = run(0)
            self.assertNotIn("discover_deadline", unlimited)

            before = datetime.now(timezone.utc)
            bounded = run(3600)
            deadline = datetime.fromisoformat(str(bounded["discover_deadline"]))
            self.assertGreaterEqual(deadline, before + timedelta(seconds=3590))
            self.assertLessEqual(deadline, datetime.now(timezone.utc) + timedelta(seconds=3610))

    def test_prepare_requires_init_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repository"
            repository.mkdir()
            artifact_dir = Path(temporary) / "artifacts"
            state = empty_state(
                str(repository),
                str(artifact_dir),
                str(artifact_dir / "state.json"),
            )

            with self.assertRaisesRegex(ValueError, "completed or partial init"):
                discover_graph.build_discover_graph().invoke(state)

    def test_outer_graph_persists_inventory_queue_and_index(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            (repository / "src").mkdir()
            (repository / "src" / "main.py").write_text("def main():\n    return 1\n")
            (repository / "application.yaml").write_text("server:\n  port: 8080\n")
            (repository / "tests").mkdir()
            (repository / "tests" / "test_main.py").write_text("def test_main(): pass\n")
            (repository / "vendor").mkdir()
            (repository / "vendor" / "third.py").write_text("pass\n")
            artifact_dir = root / "artifacts"
            state_file = artifact_dir / "state.json"
            state = empty_state(
                str(repository),
                str(artifact_dir),
                str(state_file),
                {"status": "partial"},
            )

            result = discover_graph.build_discover_graph().invoke(state)

            self.assertEqual(result["status"], "partial")
            with DiscoverLedger.open(Path(result["ledger_file"])) as ledger:
                files = list(ledger.iter_files(limit=10))
                tasks = ledger.list_tasks()
            self.assertEqual(
                [item["path"] for item in files],
                ["application.yaml", "src/main.py", "tests/test_main.py"],
            )
            self.assertEqual(files[0]["status"], "pending")
            self.assertEqual(files[2]["usage_hint"], "reference-material")
            self.assertNotIn("tests/test_main.py", tasks[0].get("paths", []))
            self.assertNotIn("version", result)
            self.assertNotIn("inventory_version", result)
            self.assertNotIn("inventory_version", files[0])
            self.assertEqual(tasks[0]["status"], "pending")
            with DiscoverLedger.open(Path(result["ledger_file"])) as ledger:
                excluded = [
                    dict(row)
                    for row in ledger.connection.execute(
                        "SELECT path, reason FROM excluded_files"
                    )
                ]
            self.assertTrue(any(item["path"] == "vendor" for item in excluded))
            self.assertTrue(state_file.is_file())
            persisted = json.loads(state_file.read_text())
            self.assertEqual(persisted["next_action"], "finalize")
            self.assertIn("loop_guard", persisted)
            for key in ("files", "excluded_files", "tasks", "entries", "evidence"):
                self.assertNotIn(key, persisted)
            self.assertEqual(
                json.loads((artifact_dir / "index.json").read_text(encoding="utf-8"))["status"],
                "partial",
            )

    def test_run_stage_exposes_compact_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            (repository / "main.py").write_text("print('ok')\n")
            stages_dir = root / "stages"
            (stages_dir / "discover").mkdir(parents=True)
            state = {
                "repository": str(repository),
                "stages_dir": str(stages_dir),
                "stages": [{"name": "init", "status": "partial"}],
                "run_file": str(root / "run.json"),
            }

            update = run_stage(state)

            self.assertEqual(update["discover"]["file_count"], 1)
            self.assertEqual(update["discover"]["confirmed_entry_count"], 0)
            self.assertEqual(update["stages"][0]["status"], "partial")

    def test_resume_preserves_completed_files_and_requeues_running_tasks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            source = repository / "main.py"
            source.write_text("print('stable')\n")
            artifact_dir = root / "artifacts"
            state_file = artifact_dir / "state.json"
            state = empty_state(
                str(repository),
                str(artifact_dir),
                str(state_file),
                {"status": "partial"},
            )
            first = discover_graph.build_discover_graph().invoke(state)

            checkpoint = dict(first)
            with DiscoverLedger.open(Path(first["ledger_file"])) as ledger:
                files = list(ledger.iter_files(limit=10))
                tasks = ledger.list_tasks()
                ledger.set_file_status(files[0]["path"], "screened")
                tasks[0]["status"] = "running"
                ledger.put_task(tasks[0])
            state_file.write_text(json.dumps(checkpoint), encoding="utf-8")
            second = discover_graph.build_discover_graph().invoke(checkpoint)

            with DiscoverLedger.open(Path(second["ledger_file"])) as ledger:
                files = list(ledger.iter_files(limit=10))
                tasks = ledger.list_tasks()
            self.assertEqual(files[0]["status"], "screened")
            self.assertEqual(tasks[0]["status"], "pending")
            self.assertFalse(any(task.get("status") == "stale" for task in tasks))

    def test_git_inventory_includes_unignored_untracked_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repository"
            repository.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
            (repository / ".gitignore").write_text("ignored.py\n")
            (repository / "tracked.py").write_text("print('tracked')\n")
            subprocess.run(["git", "add", ".gitignore", "tracked.py"], cwd=repository, check=True)
            (repository / "untracked.py").write_text("print('untracked')\n")
            (repository / "ignored.py").write_text("print('ignored')\n")
            artifact_dir = Path(temporary) / "artifacts"
            state = empty_state(
                str(repository),
                str(artifact_dir),
                str(artifact_dir / "state.json"),
                {"status": "partial"},
            )

            result = discover_graph.build_discover_graph().invoke(state)

            with DiscoverLedger.open(Path(result["ledger_file"])) as ledger:
                files = list(ledger.iter_files(limit=10))
            paths = {item["path"] for item in files}
            self.assertIn("tracked.py", paths)
            self.assertIn("untracked.py", paths)
            self.assertNotIn("ignored.py", paths)
            origins = {item["path"]: item["source_origin"] for item in files}
            self.assertEqual(origins["tracked.py"], "git-tracked")
            self.assertEqual(origins["untracked.py"], "git-untracked")

    def test_reference_and_binary_files_are_retained_as_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repository"
            repository.mkdir()
            (repository / "README.md").write_text("# project\n")
            (repository / "tests").mkdir()
            (repository / "tests" / "fixture.py").write_text("assert True\n")
            (repository / "logo.bin").write_bytes(b"\x00\x01\x02")
            (repository / "main").write_text("#!/bin/sh\necho ok\n")
            artifact_dir = Path(temporary) / "artifacts"
            state = empty_state(
                str(repository),
                str(artifact_dir),
                str(artifact_dir / "state.json"),
                {"status": "partial"},
            )

            result = discover_graph.build_discover_graph().invoke(state)

            with DiscoverLedger.open(Path(result["ledger_file"])) as ledger:
                files = list(ledger.iter_files(limit=10))
                tasks = ledger.list_tasks()
            records = {item["path"]: item for item in files}
            self.assertEqual(records["README.md"]["usage_hint"], "reference-material")
            self.assertEqual(records["tests/fixture.py"]["usage_hint"], "reference-material")
            self.assertEqual(records["logo.bin"]["status"], "metadata")
            self.assertEqual(records["logo.bin"]["fingerprint"], "")
            self.assertTrue(tasks)

    def test_standalone_entry_resumes_existing_run(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            (repository / "main.py").write_text("print('ok')\n")
            stages_dir = root / "stages"
            (stages_dir / "discover").mkdir(parents=True)
            run_file = root / "run.json"
            run_file.write_text(
                json.dumps(
                    {
                        "repository": str(repository),
                        "run_file": str(run_file),
                        "stages_dir": str(stages_dir),
                        "stages": [{"name": "init", "status": "partial"}],
                        "status": "running",
                    }
                ),
                encoding="utf-8",
            )

            result = run_discover(run_file)

            self.assertEqual(result["stages"][-1]["name"], "discover")
            self.assertTrue((stages_dir / "discover" / "state.json").is_file())


if __name__ == "__main__":
    unittest.main()
